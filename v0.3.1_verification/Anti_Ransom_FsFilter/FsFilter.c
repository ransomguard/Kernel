// ===========================================================================
// File: Anti_Ransom_FsFilter/FsFilter.c
// Developer: CHOI HWAN
// ---------------------------------------------------------------------------
// 독립 미니필터 본체. 방어 대상 4개 중 "파일 대량 암호화"를 실시간 탐지·대응.
// 기존 Anti_Ransom_Driver 와 완전 분리(두 드라이버 간 통신 없음, 자기완결).
//
// 역할 분담:
//   - 판정(엔트로피 계산 + PID별 누적 카운트)  : EntropyDetect.c
//   - 임계 프로세스 여부(종료 금지 화이트리스트): ../Shared/CriticalProcess.h
//   - 등록/관찰/대응(이 파일)                   : FsFilter.c
//
// 핵심 설계 원칙(MINIFILTER_DESIGN.md 준수):
//   1) pre-write 콜백은 쓰기 I/O 를 절대 거부하지 않는다. 관찰·카운트만 한다.
//      오탐이 나도 정상 앱의 쓰기는 그대로 통과 -> 데모가 앱을 망가뜨리지 않음.
//   2) 실제 종료(SeLocateProcessImageName·paged pool·ZwTerminateProcess, 전부
//      PASSIVE 전용)는 pre-write hot path 에서 하지 않고 FltQueueGenericWorkItem
//      으로 PASSIVE 워커에 미룬다. FltMgr 가 워크아이템 동안 언로드를 막아주므로
//      use-after-unload 가 없다.
// ===========================================================================
#include <fltKernel.h>
#include "EntropyDetect.h"
#include "../Shared/CriticalProcess.h"   // fltKernel.h(=ntifs.h 포함) 이후에 올 것

// ---------------------------------------------------------------------------
// 로깅 / 상수 / 종료 코드
// ---------------------------------------------------------------------------
#define ARW_FS_LOG(...)  KdPrint(("[Anti_Ransom_FsFilter] " __VA_ARGS__))

#define ARW_FS_KILL_TAG  'kFRA'   // WinDbg "ARFk" — 종료 요청 컨텍스트 풀 태그

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

// 종료 코드. 덤프/이벤트 로그에서 '백신이 죽였다'는 사실이 드러나도록
// 일반 실패 코드 대신 명시적인 값을 쓴다(ResponseEngine.c 와 동일 관례).
#ifndef STATUS_VIRUS_INFECTED
#define STATUS_VIRUS_INFECTED ((NTSTATUS)0xC0000906L)
#endif

// ---------------------------------------------------------------------------
// 전역 상태
// ---------------------------------------------------------------------------
static PFLT_FILTER     gFilterHandle = NULL;
static volatile LONG64 g_ArwFsTerminations = 0;   // 데모 지표: 종료시킨 프로세스 수

// PASSIVE 워커로 넘기는 종료 요청. PID 단독이 아니라 (PID + 생성시각) 쌍으로
// 식별해 트리거~워커 실행 사이의 PID 재사용 오종료를 막는다.
typedef struct _ARW_KILL_REQUEST {
    HANDLE  Pid;
    ULONG64 CreateTime;
} ARW_KILL_REQUEST;

// ---------------------------------------------------------------------------
// 전방 선언
// ---------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;

static NTSTATUS ArwInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

static NTSTATUS ArwInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

static NTSTATUS ArwFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS ArwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static VOID ArwpQueueTermination(_In_ HANDLE Pid, _In_ ULONG64 CreateTime);

static VOID ArwpTerminateWorker(
    _In_ PFLT_GENERIC_WORKITEM WorkItem,
    _In_ PVOID FltObject,
    _In_opt_ PVOID Context);

// ---------------------------------------------------------------------------
// 콜백 등록 테이블
// ---------------------------------------------------------------------------
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE, 0, ArwPreWrite, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // ContextRegistration
    Callbacks,                          // OperationRegistration
    ArwFilterUnload,                    // FilterUnloadCallback
    ArwInstanceSetup,                   // InstanceSetupCallback
    ArwInstanceQueryTeardown,           // InstanceQueryTeardownCallback
    NULL,                               // InstanceTeardownStartCallback
    NULL,                               // InstanceTeardownCompleteCallback
    NULL, NULL, NULL, NULL, NULL        // Name provider / 기타 미사용
};

// ===========================================================================
// 인스턴스 setup — NTFS 고정(디스크) 볼륨에만 attach.
// 그 외(네트워크/CD/ReFS/FAT 등)는 STATUS_FLT_DO_NOT_ATTACH 로 붙지 않는다.
// [주의] 착탈식 NTFS(USB)는 여기서 별도로 걸러지지 않는다 — 데모 범위상 허용.
// ===========================================================================
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS ArwInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    ARW_FS_LOG("Attaching to an NTFS disk volume.\n");
    return STATUS_SUCCESS;
}

// ===========================================================================
// 인스턴스 query-teardown — 항상 허용(수동 detach·언로드 편의, 데모).
// ===========================================================================
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS ArwInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    return STATUS_SUCCESS;
}

// ===========================================================================
// 언로드 — FltUnregisterFilter 후 성공. (fltmc unload 가능)
// FltMgr 는 큐잉된 워크아이템이 끝날 때까지 언로드를 진행하지 않으므로,
// 여기서 별도 배수(drain) 처리를 하지 않아도 워커가 참조하는 자원은 안전하다.
// ===========================================================================
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS ArwFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    ARW_FS_LOG("Unloading. Total terminations issued: %lld\n",
        (LONG64)g_ArwFsTerminations);

    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    return STATUS_SUCCESS;
}

// ===========================================================================
// pre-write 콜백 — 관찰 전용. 절대 쓰기를 완료/거부하지 않는다.
//
// hot path 이므로 가벼운 판단만 한다:
//   1) IRP 기반 쓰기 + 비(非)페이징 IO 만 대상
//   2) 쓰기 버퍼 앞부분을 SEH 로 안전하게 샘플 -> ArwEntropyQ8
//   3) ArwEntropyTrackWrite 로 PID별 누적, 임계 초과 시 딱 1회 TRUE
//   4) TRUE -> 종료를 PASSIVE 워커로 큐잉(여기서 직접 종료하지 않음)
// 항상 FLT_PREOP_SUCCESS_NO_CALLBACK 을 반환한다(post-op 불필요).
// ===========================================================================
static FLT_PREOP_CALLBACK_STATUS ArwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    ULONG     length;
    PVOID     src;
    PMDL      mdl;
    ULONG     pid;
    KIRQL     irql;
    ULONG     q8;
    ULONG     sampleLen;
    ULONG64   createTime;
    PEPROCESS proc;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // 1) IRP 기반 쓰기만(fast-IO/FS 필터 op 제외). IrpFlags 는 IRP op 에서만 유효.
    if (!FLT_IS_IRP_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // 2) 페이징 IO 제외(맵드파일/페이지파일 write — 유저의 '저장'이 아니고 노이즈).
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    length = Data->Iopb->Parameters.Write.Length;
    if (length < ARW_ENTROPY_MIN_WRITE_BYTES) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = FltGetRequestorProcessId(Data);
    if (pid == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // FLT pre-op 은 보통 <= APC. 방어적으로 상한을 확인한다.
    irql = KeGetCurrentIrql();
    if (irql > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 버퍼 주소 확보. MDL 매핑은 시스템 주소라 APC 에서도 안전.
    mdl = Data->Iopb->Parameters.Write.MdlAddress;
    if (mdl != NULL) {
        src = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
    }
    else {
        // 원시 유저 버퍼: 페이지폴트 가능 -> PASSIVE 에서만(요청자 스레드 컨텍스트 가정).
        if (irql > PASSIVE_LEVEL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        src = Data->Iopb->Parameters.Write.WriteBuffer;
    }
    if (src == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    sampleLen = (length > ARW_ENTROPY_SAMPLE_BYTES) ? ARW_ENTROPY_SAMPLE_BYTES : length;

    // 샘플링은 SEH 로 감싼다. 유저 버퍼가 도중에 무효화돼도 크래시 대신 조용히 포기.
    __try {
        q8 = ArwEntropyQ8((const UCHAR*)src, sampleLen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 3) PID별 누적. 임계 초과가 '처음'일 때만 TRUE(PID당 정확히 1회).
    if (!ArwEntropyTrackWrite((HANDLE)(ULONG_PTR)pid, q8, length)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 4) 종료를 PASSIVE 워커로. PID 재사용 방지를 위해 생성시각을 지금 캡처.
    //    FltGetRequestorProcess 는 참조를 추가하지 않지만 콜백 동안 유효하므로
    //    여기서 생성시각만 읽어 값으로 보관한다(포인터는 보관하지 않는다).
    createTime = 0;
    proc = FltGetRequestorProcess(Data);
    if (proc != NULL) {
        createTime = (ULONG64)PsGetProcessCreateTimeQuadPart(proc);
    }
    ArwpQueueTermination((HANDLE)(ULONG_PTR)pid, createTime);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;   // ★ 쓰기 I/O 는 절대 막지 않는다
}

// ===========================================================================
// 종료 요청 큐잉 — FltQueueGenericWorkItem 으로 PASSIVE 워커에 위임.
// 어떤 단계든 실패하면 해당 PID 추적을 비워(ArwEntropyForgetPid) 다음 쓰기부터
// 다시 누적·재시도되게 한다(한 번의 자원 실패로 그 PID 를 영구히 놓치지 않도록).
// ===========================================================================
_IRQL_requires_max_(APC_LEVEL)
static VOID ArwpQueueTermination(_In_ HANDLE Pid, _In_ ULONG64 CreateTime)
{
    PFLT_GENERIC_WORKITEM item;
    ARW_KILL_REQUEST*     req;
    NTSTATUS              status;

    item = FltAllocateGenericWorkItem();
    if (item == NULL) {
        ArwEntropyForgetPid(Pid);
        return;
    }

    req = (ARW_KILL_REQUEST*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*req), ARW_FS_KILL_TAG);
    if (req == NULL) {
        FltFreeGenericWorkItem(item);
        ArwEntropyForgetPid(Pid);
        return;
    }

    req->Pid = Pid;
    req->CreateTime = CreateTime;

    // FltObject = gFilterHandle: FltMgr 가 워크아이템 수명 동안 필터에 rundown
    // 참조를 걸어 언로드를 막는다. DelayedWorkQueue = PASSIVE_LEVEL 실행.
    status = FltQueueGenericWorkItem(
        item, gFilterHandle, ArwpTerminateWorker, DelayedWorkQueue, req);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(req, ARW_FS_KILL_TAG);
        FltFreeGenericWorkItem(item);
        ArwEntropyForgetPid(Pid);
    }
}

// ===========================================================================
// 종료 워커(PASSIVE) — 자기완결 종료 경로.
// ResponseEngine.c 의 검증된 순서를 그대로 따른다:
//   PID 0/4 거부 -> 참조 획득 -> PID 재사용 검증 -> 이미 종료중? ->
//   임계 프로세스(fail-closed, 공유 헤더) -> 커널 핸들 -> ZwTerminateProcess.
// ===========================================================================
_IRQL_requires_(PASSIVE_LEVEL)
static VOID ArwpTerminateWorker(
    _In_ PFLT_GENERIC_WORKITEM WorkItem,
    _In_ PVOID FltObject,
    _In_opt_ PVOID Context)
{
    ARW_KILL_REQUEST* req = (ARW_KILL_REQUEST*)Context;
    PEPROCESS proc = NULL;
    HANDLE    h = NULL;
    NTSTATUS  status;
    ULONG     pidVal;

    UNREFERENCED_PARAMETER(FltObject);
    PAGED_CODE();

    if (req == NULL) {
        FltFreeGenericWorkItem(WorkItem);
        return;
    }
    pidVal = (ULONG)(ULONG_PTR)req->Pid;

    // 1) 자명한 임계 PID (System/Idle). BSOD 직결이므로 무조건 거부.
    if (req->Pid == NULL || pidVal == 4) {
        goto Cleanup;
    }

    // 2) PEPROCESS 참조 획득. 없으면 이미 사라진 것.
    status = PsLookupProcessByProcessId(req->Pid, &proc);
    if (!NT_SUCCESS(status)) {
        ARW_FS_LOG("PID %lu already gone (0x%08X).\n", pidVal, status);
        goto Cleanup;
    }

    // 3) PID 재사용 검증. 트리거 시점과 생성시각이 다르면 다른 프로세스다.
    if (req->CreateTime != 0 &&
        (ULONG64)PsGetProcessCreateTimeQuadPart(proc) != req->CreateTime) {
        ARW_FS_LOG("PID %lu create-time mismatch; reused. Skipping.\n", pidVal);
        goto Cleanup;
    }

    // 4) 이미 종료 중이면 성공으로 간주.
    if (PsGetProcessExitStatus(proc) != STATUS_PENDING) {
        goto Cleanup;
    }

    // 5) 임계 시스템 프로세스 최종 방어선(공유 헤더, fail-closed).
    //    csrss/lsass/services/... 이면 여기서 거부 -> CRITICAL_PROCESS_DIED 방지.
    if (ArwCpIsProtectedSystemProcess(proc)) {
        ARW_FS_LOG("Refused: PID %lu is a protected system process.\n", pidVal);
        goto Cleanup;
    }

    // 6) 커널 핸들 획득 후 종료.
    //    OBJ_KERNEL_HANDLE: 유저 핸들 테이블에 노출 안 됨(대상이 훔치거나 못 닫음).
    //    KernelMode: 위에서 우리 정책으로 충분히 검증했으므로 보안검사 우회.
    status = ObOpenObjectByPointer(
        proc, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE,
        *PsProcessType, KernelMode, &h);
    if (!NT_SUCCESS(status)) {
        ARW_FS_LOG("ObOpenObjectByPointer failed PID %lu (0x%08X)\n", pidVal, status);
        goto Cleanup;
    }

    status = ZwTerminateProcess(h, STATUS_VIRUS_INFECTED);
    if (status == STATUS_PROCESS_IS_TERMINATING) {
        status = STATUS_SUCCESS;   // 경쟁적으로 이미 종료 시작 — 실패 아님.
    }

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_ArwFsTerminations);
        ARW_FS_LOG("Terminated ransomware PID %lu (high-entropy bulk write).\n", pidVal);
    }
    else {
        ARW_FS_LOG("ZwTerminateProcess failed PID %lu (0x%08X)\n", pidVal, status);
    }

Cleanup:
    if (h != NULL) {
        ZwClose(h);
    }
    if (proc != NULL) {
        ObDereferenceObject(proc);
    }
    // 이 PID 추적 슬롯을 비운다(종료 성공이든 거부든 동일 — 재시도/재사용 대비).
    ArwEntropyForgetPid(req->Pid);
    ExFreePoolWithTag(req, ARW_FS_KILL_TAG);
    FltFreeGenericWorkItem(WorkItem);
}

// ===========================================================================
// DriverEntry — 필터 등록 후 필터링 시작.
// ===========================================================================
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    // 판정 테이블/스핀락 초기화 — FltStartFiltering 전에 반드시 1회.
    ArwEntropyInit();

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        ARW_FS_LOG("FltRegisterFilter failed (0x%08X)\n", status);
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        ARW_FS_LOG("FltStartFiltering failed (0x%08X)\n", status);
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    ARW_FS_LOG("Loaded. Watching for high-entropy bulk writes.\n");
    return STATUS_SUCCESS;
}
