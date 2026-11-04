// RansomGuard integration baseline: bounded, observation-only file telemetry.
// Events describe PRE-OPERATION ATTEMPTS, not completed writes or renames.
// This driver does not block, suspend, terminate, back up, or restore anything.
#include <fltKernel.h>
#include "../Shared/Common.h"
#include "EntropyDetect.h"

#define ARW_FS_LOG(...) KdPrint(("[Anti_Ransom_FsFilter] " __VA_ARGS__))
#define ARW_FS_EVENT_TAG  'eFRA'
#define ARW_FS_NAME_TAG   'nFRA'
#define ARW_FS_REG_TAG    'rFRA'

// Explicit best-effort budgets. No per-I/O work item or pending-I/O queue exists.
// Separate rename capacity prevents a write burst consuming every rename slot.
#define ARW_FS_MAX_INFLIGHT_EVENTS       32L
#define ARW_FS_WRITES_PER_SECOND         512U
#define ARW_FS_RENAMES_PER_SECOND        256U
#define ARW_FS_ONE_SECOND_100NS          10000000ULL
#define ARW_FS_MAX_RENAME_BYTES          65534U

static PFLT_FILTER gFilterHandle = NULL;
static PCALLBACK_OBJECT gFileEventCallback = NULL;
static volatile LONG gStopping = 0;
static volatile LONG gInflightEvents = 0;
static volatile LONG gUnloadProtect = 0;
static KSPIN_LOCK gBudgetLock;
static ULONGLONG gBudgetWindow = 0;
static ULONG gWriteBudgetUsed = 0;
static ULONG gRenameBudgetUsed = 0;

static volatile LONG64 gNotifications = 0;
static volatile LONG64 gRateDrops = 0;
static volatile LONG64 gCapacityDrops = 0;
static volatile LONG64 gAllocationDrops = 0;
static volatile LONG64 gUnsupportedOperations = 0;
static volatile LONG64 gMissingPaths = 0;
static volatile LONG64 gMissingExtensions = 0;
static volatile LONG64 gUnavailableSamples = 0;
// v0.6.5: bounded stage counters. A successful ExNotifyCallback call is not an
// acknowledgement that the KMDF receiver registered or queued the event.
static volatile LONG64 gDiagPreWrites = 0;
static volatile LONG64 gDiagPreRenames = 0;
static volatile LONG64 gDiagPreparedWrites = 0;
static volatile LONG64 gDiagPreparedRenames = 0;
static volatile LONG64 gDiagNotifiedWrites = 0;
static volatile LONG64 gDiagNotifiedRenames = 0;
static volatile LONG64 gDiagPublishSkipped = 0;

DRIVER_INITIALIZE DriverEntry;
static FLT_PREOP_CALLBACK_STATUS ArwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
static FLT_PREOP_CALLBACK_STATUS ArwPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
static NTSTATUS ArwFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS ArwInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static NTSTATUS ArwInstanceQueryTeardown(
    PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE, 0, ArwPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, ArwPreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0,
    NULL, Callbacks, ArwFilterUnload, ArwInstanceSetup,
    ArwInstanceQueryTeardown, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL
};

// Log only powers of two. Counter updates remain bounded work even under a flood.
static VOID ArwFsCountDiagnostic(volatile LONG64* Counter, PCSTR Reason)
{
    LONG64 value = InterlockedIncrement64(Counter);
    if (value > 0 && (value & (value - 1)) == 0) {
        ARW_FS_LOG("telemetry %s count=%lld\n", Reason, value);
    }
}

static BOOLEAN ArwFsTakeBudget(ULONG Operation)
{
    KIRQL oldIrql;
    ULONGLONG now = KeQueryInterruptTime();
    BOOLEAN granted = FALSE;

    KeAcquireSpinLock(&gBudgetLock, &oldIrql);
    if (now - gBudgetWindow >= ARW_FS_ONE_SECOND_100NS) {
        gBudgetWindow = now;
        gWriteBudgetUsed = 0;
        gRenameBudgetUsed = 0;
    }
    if (Operation == ARW_FILE_OP_WRITE) {
        if (gWriteBudgetUsed < ARW_FS_WRITES_PER_SECOND) {
            ++gWriteBudgetUsed;
            granted = TRUE;
        }
    } else if (gRenameBudgetUsed < ARW_FS_RENAMES_PER_SECOND) {
        ++gRenameBudgetUsed;
        granted = TRUE;
    }
    KeReleaseSpinLock(&gBudgetLock, oldIrql);
    return granted;
}

static PARW_FILE_EVENT ArwFsAllocateEvent(ULONG Type, ULONG Operation, ULONG Pid)
{
    PARW_FILE_EVENT ev;

    if (InterlockedCompareExchange(&gStopping, 0, 0) != 0 ||
        gFileEventCallback == NULL) {
        return NULL;
    }
    if (!ArwFsTakeBudget(Operation)) {
        ArwFsCountDiagnostic(&gRateDrops, "rate-limited");
        return NULL;
    }
    if (InterlockedIncrement(&gInflightEvents) > ARW_FS_MAX_INFLIGHT_EVENTS) {
        InterlockedDecrement(&gInflightEvents);
        ArwFsCountDiagnostic(&gCapacityDrops, "inflight-capacity-drop");
        return NULL;
    }
    ev = (PARW_FILE_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*ev), ARW_FS_EVENT_TAG);
    if (ev == NULL) {
        InterlockedDecrement(&gInflightEvents);
        ArwFsCountDiagnostic(&gAllocationDrops, "allocation-drop");
        return NULL;
    }
    RtlZeroMemory(ev, sizeof(*ev));
    ev->Header.EventType = Type;
    ev->Header.PayloadSize = sizeof(*ev);
    ev->ProcessId = Pid;
    ev->OperationType = Operation;
    ev->Flags = ARW_FILE_FLAG_PREOP_OBSERVATION;
    return ev;
}

static VOID ArwFsPublishAndFree(PARW_FILE_EVENT Event)
{
    // Callback arguments are synchronous and borrowed for this call only.
    // The main driver's sink copies the record before returning and stamps its
    // common header. ExNotifyCallback has no delivery acknowledgement: a missing
    // sink is a no-op, so this counter means "notified", not "durably delivered".
    if (InterlockedCompareExchange(&gStopping, 0, 0) == 0 &&
        gFileEventCallback != NULL) {
        ExNotifyCallback(gFileEventCallback, Event, NULL);
        InterlockedIncrement64(&gNotifications);
        if (Event->OperationType == ARW_FILE_OP_WRITE) {
            ArwFsCountDiagnostic(&gDiagNotifiedWrites, "diag-notify-write");
        } else if (Event->OperationType == ARW_FILE_OP_RENAME) {
            ArwFsCountDiagnostic(&gDiagNotifiedRenames, "diag-notify-rename");
        }
    } else {
        ArwFsCountDiagnostic(&gDiagPublishSkipped, "diag-publish-skipped");
    }
    ExFreePoolWithTag(Event, ARW_FS_EVENT_TAG);
    InterlockedDecrement(&gInflightEvents);
}

// Source is an immutable FltMgr name object, not an application-owned pointer.
// Length is bytes excluding NUL. Keep a NUL for diagnostic consumers and never
// split a UTF-16 surrogate pair when a name is truncated to the wire capacity.
static VOID ArwFsCopyUnicode(
    PUNICODE_STRING Source, PWCHAR Target, ULONG TargetChars,
    PULONG TargetBytes, PULONG Flags, ULONG TruncatedFlag)
{
    ULONG bytes = Source->Length;
    ULONG capacity = (TargetChars - 1U) * (ULONG)sizeof(WCHAR);

    if (bytes > capacity) {
        bytes = capacity;
        *Flags |= TruncatedFlag;
        if (bytes >= sizeof(WCHAR)) {
            WCHAR last = Source->Buffer[(bytes / sizeof(WCHAR)) - 1U];
            if (last >= 0xD800 && last <= 0xDBFF) {
                bytes -= sizeof(WCHAR);
            }
        }
    }
    if (bytes != 0) {
        RtlCopyMemory(Target, Source->Buffer, bytes);
    }
    Target[bytes / sizeof(WCHAR)] = L'\0';
    *TargetBytes = bytes;
}

static VOID ArwFsCaptureSourcePath(PFLT_CALLBACK_DATA Data, PARW_FILE_EVENT Event)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    NTSTATUS status;

    // OPENED deliberately describes the pre-operation source path. It does not
    // claim a normalized final name after a rename (including name tunneling).
    // DEFAULT lets FltMgr reject unsafe file-system name queries.
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (NT_SUCCESS(status) && name != NULL && name->Name.Buffer != NULL &&
        name->Name.Length != 0 && (name->Name.Length % sizeof(WCHAR)) == 0) {
        ArwFsCopyUnicode(&name->Name, Event->FilePath, ARW_MAX_EXTENDED_PATH,
            &Event->FilePathLength, &Event->Flags, ARW_FILE_FLAG_PATH_TRUNCATED);
    } else {
        Event->Flags |= ARW_FILE_FLAG_PATH_UNAVAILABLE;
        ArwFsCountDiagnostic(&gMissingPaths, "source-path-unavailable");
    }
    if (name != NULL) {
        FltReleaseFileNameInformation(name);
    }
}

static BOOLEAN ArwFsSampleEntropy(PFLT_CALLBACK_DATA Data, PULONG EntropyQ8)
{
    PMDL* mdlAddress = NULL;
    PVOID* bufferAddress = NULL;
    PULONG lengthAddress = NULL;
    PMDL mdl = NULL;
    PVOID source = NULL;
    ULONG length;
    UCHAR sample[ARW_ENTROPY_SAMPLE_BYTES];
    BOOLEAN probe = FALSE;
    NTSTATUS status;

    *EntropyQ8 = 0;
    if (Data->Iopb->Parameters.Write.Length < ARW_ENTROPY_MIN_WRITE_BYTES) {
        return FALSE;
    }
    status = FltDecodeParameters(Data, &mdlAddress, &bufferAddress,
        &lengthAddress, NULL);
    if (!NT_SUCCESS(status) || lengthAddress == NULL ||
        *lengthAddress < ARW_ENTROPY_MIN_WRITE_BYTES) {
        return FALSE;
    }
    length = min(*lengthAddress, ARW_ENTROPY_SAMPLE_BYTES);
    if (mdlAddress != NULL) {
        mdl = *mdlAddress;
    }
    if (mdl != NULL) {
        if (MmGetMdlByteCount(mdl) < length) {
            return FALSE;
        }
        source = MmGetSystemAddressForMdlSafe(
            mdl, NormalPagePriority | MdlMappingNoExecute);
    } else {
        if (bufferAddress == NULL) {
            return FALSE;
        }
        source = *bufferAddress;
        if (!FLT_IS_SYSTEM_BUFFER(Data)) {
            // No reference to a raw application buffer survives this callback.
            // If not in its process context, keep the path observation and skip
            // only the optional sample. Never attach to an arbitrary process.
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
                return FALSE;
            }
            if (Data->RequestorMode == UserMode) {
                if (FltGetRequestorProcess(Data) != PsGetCurrentProcess()) {
                    return FALSE;
                }
                probe = TRUE;
            }
        }
    }
    if (source == NULL) {
        return FALSE;
    }
    __try {
        if (probe) {
            ProbeForRead(source, length, 1);
        }
        RtlCopyMemory(sample, source, length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    // Pure per-sample statistic. No PID accumulator, lifetime ambiguity, or kill.
    *EntropyQ8 = ArwEntropyQ8(sample, length);
    return TRUE;
}

static VOID ArwFsCaptureRenameExtension(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
    PARW_FILE_EVENT Event)
{
    PFILE_RENAME_INFORMATION input;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    ULONG bufferBytes = Data->Iopb->Parameters.SetFileInformation.Length;
    ULONG nameBytes = 0;
    ULONG prefixBytes = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    HANDLE rootDirectory = NULL;
    PWCHAR nameCopy = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    // FILE_RENAME_INFORMATION and FileRenameInformationEx have the same
    // RootDirectory/FileNameLength/FileName layout. We never interpret Flags.
    // Capture the length/handle once, then make a bounded immutable name copy.
    // No pointer from InfoBuffer is retained or passed to a later callback.
    if (bufferBytes < prefixBytes ||
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL ||
        IoGetTopLevelIrp() != NULL || KeAreAllApcsDisabled()) {
        goto Cleanup;
    }
    if (Data->RequestorMode == UserMode &&
        FltGetRequestorProcess(Data) != PsGetCurrentProcess()) {
        goto Cleanup; // RootDirectory can be a requestor-process handle.
    }
    input = (PFILE_RENAME_INFORMATION)
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    __try {
        nameBytes = input->FileNameLength;
        rootDirectory = input->RootDirectory;
        if (nameBytes == 0 || (nameBytes % sizeof(WCHAR)) != 0 ||
            nameBytes > bufferBytes - prefixBytes ||
            nameBytes > ARW_FS_MAX_RENAME_BYTES) {
            __leave;
        }
        // At most 32 outstanding copies of at most 65534 bytes, independently
        // bounded by event-slot reservation and the rename rate budget.
        nameCopy = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_PAGED, nameBytes, ARW_FS_NAME_TAG);
        if (nameCopy == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        RtlCopyMemory(nameCopy, input->FileName, nameBytes);
        status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance, FltObjects->FileObject, rootDirectory,
        nameCopy, nameBytes,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &destination);
    if (!NT_SUCCESS(status) || destination == NULL) {
        if (NT_SUCCESS(status)) { status = STATUS_UNSUCCESSFUL; }
        goto Cleanup;
    }
    status = FltParseFileNameInformation(destination);
    if (!NT_SUCCESS(status) ||
        (destination->Extension.Length % sizeof(WCHAR)) != 0 ||
        (destination->Extension.Length != 0 && destination->Extension.Buffer == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }
    ArwFsCopyUnicode(&destination->Extension, Event->NewExtension,
        ARW_MAX_EXTENSION_LENGTH, &Event->NewExtensionLength,
        &Event->Flags, ARW_FILE_FLAG_EXT_TRUNCATED);

Cleanup:
    if (!NT_SUCCESS(status)) {
        // An unavailable extension is different from a valid extensionless name.
        Event->Flags |= ARW_FILE_FLAG_EXT_UNAVAILABLE;
        ArwFsCountDiagnostic(&gMissingExtensions, "rename-extension-unavailable");
    }
    if (destination != NULL) {
        FltReleaseFileNameInformation(destination);
    }
    if (nameCopy != NULL) {
        ExFreePoolWithTag(nameCopy, ARW_FS_NAME_TAG);
    }
}

static FLT_PREOP_CALLBACK_STATUS ArwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    ULONG pid;
    ULONG entropyQ8;
    PARW_FILE_EVENT ev;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    ArwFsCountDiagnostic(&gDiagPreWrites, "diag-prewrite-enter");
    if (!FLT_IS_IRP_OPERATION(Data) || KeGetCurrentIrql() > APC_LEVEL ||
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO) ||
        Data->Iopb->MinorFunction != IRP_MN_NORMAL) {
        ArwFsCountDiagnostic(&gUnsupportedOperations, "unsupported-write-path");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->Iopb->Parameters.Write.Length == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    pid = FltGetRequestorProcessId(Data);
    if (pid == 0) {
        ArwFsCountDiagnostic(&gUnsupportedOperations, "unattributed-write");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    ev = ArwFsAllocateEvent(EVENT_TYPE_FILE_WRITE, ARW_FILE_OP_WRITE, pid);
    if (ev == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    ArwFsCountDiagnostic(&gDiagPreparedWrites, "diag-prewrite-prepared");
    ArwFsCaptureSourcePath(Data, ev);
    if (Data->Iopb->Parameters.Write.Length >= ARW_ENTROPY_MIN_WRITE_BYTES) {
        if (ArwFsSampleEntropy(Data, &entropyQ8)) {
            if (entropyQ8 >= ARW_ENTROPY_THRESHOLD_Q8) {
                ev->Flags |= ARW_FILE_FLAG_HIGH_ENTROPY;
            }
        } else {
            ArwFsCountDiagnostic(&gUnavailableSamples, "entropy-sample-unavailable");
        }
    }
    ArwFsPublishAndFree(ev);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS ArwPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    ULONG pid;
    PARW_FILE_EVENT ev;

    *CompletionContext = NULL;
    if (!FLT_IS_IRP_OPERATION(Data) || KeGetCurrentIrql() > APC_LEVEL) {
        ArwFsCountDiagnostic(&gUnsupportedOperations, "unsupported-setinfo-path");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass != FileRenameInformation && infoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    ArwFsCountDiagnostic(&gDiagPreRenames, "diag-prerename-enter");
    pid = FltGetRequestorProcessId(Data);
    if (pid == 0) {
        ArwFsCountDiagnostic(&gUnsupportedOperations, "unattributed-rename");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    ev = ArwFsAllocateEvent(EVENT_TYPE_FILE_RENAME, ARW_FILE_OP_RENAME, pid);
    if (ev == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    ArwFsCountDiagnostic(&gDiagPreparedRenames, "diag-prerename-prepared");
    ArwFsCaptureSourcePath(Data, ev);
    ArwFsCaptureRenameExtension(Data, FltObjects, ev);
    ArwFsPublishAndFree(ev);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS ArwInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM ||
        VolumeFilesystemType != FLT_FSTYPE_NTFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    ARW_FS_LOG("Attached to NTFS disk volume; observation only.\n");
    return STATUS_SUCCESS;
}

static NTSTATUS ArwInstanceQueryTeardown(
    PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    return STATUS_SUCCESS;
}

static NTSTATUS ArwFsReadRegistryDword(
    PUNICODE_STRING RegistryPath, PCWSTR ValueName, PULONG Value)
{
    NTSTATUS status;
    UNICODE_STRING path, valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key = NULL;
    PWCHAR pathBuffer = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
    ULONG bytes, resultBytes = 0;

    PAGED_CODE();
    *Value = 0;
    bytes = (ULONG)RegistryPath->Length + (ULONG)sizeof(L"\\Parameters");
    if (bytes > MAXUSHORT) {
        return STATUS_NAME_TOO_LONG;
    }
    pathBuffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, bytes, ARW_FS_REG_TAG);
    if (pathBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    path.Buffer = pathBuffer;
    path.Length = 0;
    path.MaximumLength = (USHORT)bytes;
    status = RtlAppendUnicodeStringToString(&path, RegistryPath);
    if (NT_SUCCESS(status)) {
        status = RtlAppendUnicodeToString(&path, L"\\Parameters");
    }
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InitializeObjectAttributes(&attributes, &path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&key, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    bytes = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG);
    info = (PKEY_VALUE_PARTIAL_INFORMATION)
        ExAllocatePool2(POOL_FLAG_PAGED, bytes, ARW_FS_REG_TAG);
    if (info == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlInitUnicodeString(&valueName, ValueName);
    status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation,
        info, bytes, &resultBytes);
    if (NT_SUCCESS(status)) {
        if (info->Type == REG_DWORD && info->DataLength == sizeof(ULONG)) {
            RtlCopyMemory(Value, info->Data, sizeof(ULONG));
        } else {
            status = STATUS_OBJECT_TYPE_MISMATCH;
        }
    }
Cleanup:
    if (info != NULL) { ExFreePoolWithTag(info, ARW_FS_REG_TAG); }
    if (key != NULL) { ZwClose(key); }
    ExFreePoolWithTag(pathBuffer, ARW_FS_REG_TAG);
    return status;
}

static NTSTATUS ArwFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    PAGED_CODE();
    if (!FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY) &&
        InterlockedCompareExchange(&gUnloadProtect, 0, 0) != 0) {
        ARW_FS_LOG("Unload refused; disable registry protection then reboot.\n");
        return STATUS_FLT_DO_NOT_DETACH;
    }
    InterlockedExchange(&gStopping, 1);
    if (gFilterHandle != NULL) {
        // All callbacks finish before the borrowed callback-object reference is
        // released. No user buffer or event allocation is held asynchronously.
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    if (gFileEventCallback != NULL) {
        ObDereferenceObject(gFileEventCallback);
        gFileEventCallback = NULL;
    }
    ARW_FS_LOG("Unload telemetry: notifications=%lld rateDrops=%lld "
        "capacityDrops=%lld allocationDrops=%lld unsupported=%lld\n",
        gNotifications, gRateDrops, gCapacityDrops, gAllocationDrops,
        gUnsupportedOperations);
    ARW_FS_LOG("Unload metadata: pathUnavailable=%lld extensionUnavailable=%lld "
        "sampleUnavailable=%lld inflight=%ld\n",
        gMissingPaths, gMissingExtensions, gUnavailableSamples, gInflightEvents);
    ARW_FS_LOG("v0.6.5 FILE_DIAG summary: preWrite=%lld preRename=%lld "
        "preparedWrite=%lld preparedRename=%lld notifiedWrite=%lld "
        "notifiedRename=%lld publishSkipped=%lld\n",
        gDiagPreWrites, gDiagPreRenames, gDiagPreparedWrites,
        gDiagPreparedRenames, gDiagNotifiedWrites, gDiagNotifiedRenames,
        gDiagPublishSkipped);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING callbackName;
    OBJECT_ATTRIBUTES callbackAttributes;
    ULONG unloadProtection = 0;

    KeInitializeSpinLock(&gBudgetLock);
    gBudgetWindow = KeQueryInterruptTime();
    if (NT_SUCCESS(ArwFsReadRegistryDword(
        RegistryPath, L"EnableUnloadProtection", &unloadProtection))) {
        InterlockedExchange(&gUnloadProtect, unloadProtection != 0 ? 1 : 0);
    }
    RtlInitUnicodeString(&callbackName, ARW_FILE_EVENT_CALLBACK_NAME);
    InitializeObjectAttributes(&callbackAttributes, &callbackName,
        OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ExCreateCallback(&gFileEventCallback, &callbackAttributes, TRUE, TRUE);
    if (!NT_SUCCESS(status)) {
        ARW_FS_LOG("Cannot create telemetry callback object: 0x%08X\n", status);
        return status;
    }
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(gFileEventCallback);
        gFileEventCallback = NULL;
        return status;
    }
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&gStopping, 1);
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        ObDereferenceObject(gFileEventCallback);
        gFileEventCallback = NULL;
        return status;
    }
    ARW_FS_LOG("v0.6.5 FILE_DIAG enabled: stage counters log at powers of two.\n");
    ARW_FS_LOG("Loaded OBSERVATION_ONLY: preop attempts, no file containment; "
        "write budget=%lu/s rename budget=%lu/s inflight<=%ld.\n",
        (ULONG)ARW_FS_WRITES_PER_SECOND, (ULONG)ARW_FS_RENAMES_PER_SECOND,
        ARW_FS_MAX_INFLIGHT_EVENTS);
    return STATUS_SUCCESS;
}
