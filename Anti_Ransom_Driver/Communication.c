// ===========================================================================
// File: Communication.c
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "Communication.h"
#include "ResponseEngine.h"
#include "SelfProtect.h"
#include "EventQueue.h"

static WDFDEVICE g_ControlDevice = NULL;
static WDFQUEUE  g_DefaultQueue = NULL;
static WDFQUEUE  g_PendingEventQueue = NULL;   // inverted call 전용 manual 큐

// 등록된 유저 모드 엔진. 0이면 미등록 상태.
static volatile LONG  g_EngineProcessId = 0;
static ULONG64        g_EngineCreateTime = 0;

// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG ArwGetEngineProcessId(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_EngineProcessId, 0, 0);
}

// ---------------------------------------------------------------------------
// 초기화
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwInitializeCommunication(_In_ WDFDRIVER Driver)
{
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE controlDevice = NULL;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttr;
    WDF_FILEOBJECT_CONFIG fileConfig;
    BOOLEAN deviceCreated = FALSE;

    DECLARE_CONST_UNICODE_STRING(ntDeviceName, ARW_NTDEVICE_NAME_STRING);
    DECLARE_CONST_UNICODE_STRING(symbolicName, ARW_SYMBOLIC_NAME_STRING);

    PAGED_CODE();

    // =======================================================================
    // [보안 수정 - 최우선]
    //
    // 기존: SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R
    //   → 이름 그대로 WORLD(Everyone)에게 읽기/쓰기를 허용한다.
    //     저권한 사용자 프로세스가 CreateFile("\\\\.\\RansomGuard") 후
    //     IOCTL_RG_TERMINATE_PROCESS 를 던지면 임의 PID를 종료할 수 있다.
    //     백신을 만들면서 BYOVD(Bring Your Own Vulnerable Driver) 공격에
    //     그대로 쓰일 'process killer driver'를 동봉하는 셈이다.
    //
    // 변경: SDDL_DEVOBJ_SYS_ALL_ADM_ALL — SYSTEM + Administrators 전용.
    // =======================================================================
    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = WdfDeviceInitAssignName(deviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("WdfDeviceInitAssignName failed (0x%08X)\n", status);
        goto Cleanup;
    }

    // FILE_DEVICE_SECURE_OPEN:
    // 이게 없으면 "\\.\RansomGuard\anything" 처럼 하위 경로를 붙여 여는 방식으로
    // 디바이스 ACL 검사를 우회할 수 있다. 소프트웨어 디바이스는 사실상 필수.
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    // 엔진이 죽거나 핸들을 닫으면 등록을 자동 해제한다.
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig,
        WDF_NO_EVENT_CALLBACK,   // EvtDeviceFileCreate
        WDF_NO_EVENT_CALLBACK,   // EvtFileClose
        ArwEvtFileCleanup);      // EvtFileCleanup
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig,
        WDF_NO_OBJECT_ATTRIBUTES);

    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &controlDevice);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("WdfDeviceCreate failed (0x%08X)\n", status);
        goto Cleanup;   // WdfDeviceCreate 실패 시에만 deviceInit 를 직접 해제
    }

    // [중요] 이 시점부터 deviceInit 소유권은 프레임워크로 넘어갔다.
    // 이후 실패 경로에서 WdfDeviceInitFree 를 호출하면 이중 해제가 된다.
    deviceInit = NULL;
    deviceCreated = TRUE;

    status = WdfDeviceCreateSymbolicLink(controlDevice, &symbolicName);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("WdfDeviceCreateSymbolicLink failed (0x%08X)\n", status);
        goto Cleanup;
    }

    // -----------------------------------------------------------------------
    // 기본 큐: Parallel
    //
    // 기존 Sequential 이었으나, 역방향 통신 요청(GET_EVENT)이 한 개라도
    // 대기하면 후속 종료 명령까지 전부 막히는 구조적 결함이 있었다.
    // GET_EVENT 는 manual 큐로 이관하고, 기본 큐는 병렬 처리로 둔다.
    // -----------------------------------------------------------------------
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = ArwEvtIoDeviceControl;

    // [중요] KMDF는 기본적으로 IRQL <= DISPATCH_LEVEL 에서 큐 콜백을 호출할 수 있다.
    // 그러나 ResponseEngine 은 SeLocateProcessImageName / 페이지드 풀 할당 등
    // PASSIVE_LEVEL 전용 API를 쓴다. 실행 수준을 명시적으로 고정하지 않으면
    // 재현이 어려운 IRQL_NOT_LESS_OR_EQUAL 로 간헐 크래시한다.
    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttr);
    queueAttr.ExecutionLevel = WdfExecutionLevelPassive;

    status = WdfIoQueueCreate(controlDevice, &queueConfig,
        &queueAttr, &g_DefaultQueue);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("WdfIoQueueCreate (default) failed (0x%08X)\n", status);
        goto Cleanup;
    }

    // -----------------------------------------------------------------------
    // manual 큐: 커널 -> 유저 이벤트 전달용 (inverted call)
    // -----------------------------------------------------------------------
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.EvtIoCanceledOnQueue = ArwEvtIoCanceledOnQueue;

    status = WdfIoQueueCreate(controlDevice, &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES, &g_PendingEventQueue);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("WdfIoQueueCreate (pending) failed (0x%08X)\n", status);
        goto Cleanup;
    }

    status = ArwEventQueueInitialize(g_PendingEventQueue);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    g_ControlDevice = controlDevice;

    // 이 호출 이후부터 유저 모드가 디바이스를 열 수 있다.
    WdfControlFinishInitializing(controlDevice);

    ARW_LOG("Communication module initialized (%ws).\n", ARW_SYMBOLIC_NAME_STRING);
    return STATUS_SUCCESS;

Cleanup:
    if (deviceInit != NULL) {
        WdfDeviceInitFree(deviceInit);
    }
    if (deviceCreated) {
        // [수정] 기존 코드는 심볼릭 링크/큐 생성 실패 시 그냥 return 했다.
        // 그러면 WdfControlFinishInitializing 을 못 받은 제어 디바이스가
        // '초기화 미완료' 상태로 남아 드라이버 언로드를 방해한다.
        WdfObjectDelete(controlDevice);
    }
    g_DefaultQueue = NULL;
    g_PendingEventQueue = NULL;
    return status;
}

// ---------------------------------------------------------------------------
// 해제
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwUninitializeCommunication(VOID)
{
    PAGED_CODE();

    ArwEventQueueUninitialize();

    if (g_ControlDevice != NULL) {
        // Non-PnP KMDF 드라이버는 제어 디바이스를 직접 삭제해야 한다.
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }

    g_DefaultQueue = NULL;
    g_PendingEventQueue = NULL;
    InterlockedExchange(&g_EngineProcessId, 0);
    g_EngineCreateTime = 0;

    ARW_LOG("Communication module uninitialized.\n");
}

// ---------------------------------------------------------------------------
// 공통 헤더 검증 (Magic + Version)
// ---------------------------------------------------------------------------
static BOOLEAN ArwpValidateHeader(_In_ ULONG Magic, _In_ ULONG Version)
{
    if (Magic != ARW_HEADER_MAGIC) {
        ARW_LOG("Invalid magic 0x%08X\n", Magic);
        return FALSE;
    }
    if (Version != ARW_DRIVER_VERSION) {
        // 버전 불일치는 구조체 레이아웃 불일치를 뜻한다.
        // 여기서 막지 않으면 엉뚱한 오프셋의 값을 PID로 해석해 종료하게 된다.
        ARW_LOG("Version mismatch: user=0x%08X kernel=0x%08X\n",
            Version, ARW_DRIVER_VERSION);
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// 호출자가 등록된 엔진인지 확인
//
// [설계 근거] SDDL로 관리자 전용까지는 막았지만, 관리자 권한을 얻은
// 랜섬웨어라면 여전히 디바이스를 열 수 있다. 등록된 엔진 PID 하나만
// 명령을 내릴 수 있게 좁혀 공격 표면을 한 단계 더 줄인다.
// 매직 넘버는 이 역할을 대신할 수 없다 — 바이너리에서 바로 추출되는 상수다.
// ---------------------------------------------------------------------------
static BOOLEAN ArwpIsCallerRegisteredEngine(VOID)
{
    ULONG caller = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ULONG engine = ArwGetEngineProcessId();

    if (engine == 0) {
        ARW_LOG("Command rejected: no engine registered.\n");
        return FALSE;
    }
    if (caller != engine) {
        ARW_LOG("Command rejected: caller PID %lu != engine PID %lu\n",
            caller, engine);
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// 엔진 등록
// ---------------------------------------------------------------------------
static NTSTATUS ArwpHandleRegisterEngine(_In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PARW_REGISTER_REQUEST req = NULL;
    size_t bufferSize = 0;
    PEPROCESS caller;
    ULONG callerPid;

    status = WdfRequestRetrieveInputBuffer(Request,
        sizeof(ARW_REGISTER_REQUEST), (PVOID*)&req, &bufferSize);
    if (!NT_SUCCESS(status) || bufferSize < sizeof(ARW_REGISTER_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!ArwpValidateHeader(req->Magic, req->Version)) {
        return STATUS_REVISION_MISMATCH;
    }

    // 이미 등록된 엔진이 있으면 거부한다.
    // 선점 등록을 허용하면 악성코드가 먼저 등록해 정상 엔진을 밀어낼 수 있다.
    if (ArwGetEngineProcessId() != 0) {
        ARW_LOG("Engine already registered (PID %lu).\n", ArwGetEngineProcessId());
        return STATUS_ALREADY_REGISTERED;
    }

    // [핵심] PID를 유저 버퍼에서 받지 않는다. 커널이 직접 확인한다.
    caller = PsGetCurrentProcess();
    callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    g_EngineCreateTime = (ULONG64)PsGetProcessCreateTimeQuadPart(caller);
    InterlockedExchange(&g_EngineProcessId, (LONG)callerPid);

    // 자기 보호 모듈이 켜져 있으면 보호 대상을 이 프로세스로 지정한다.
    if (g_ArwSelfProtectEnabled) {
        NTSTATUS spStatus = ArwSelfProtectSetTarget(PsGetCurrentProcessId());
        if (!NT_SUCCESS(spStatus)) {
            ARW_LOG("SelfProtectSetTarget failed (0x%08X)\n", spStatus);
        }
    }

    ARW_LOG("Engine registered: PID %lu\n", callerPid);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 엔진 등록 해제
// ---------------------------------------------------------------------------
static VOID ArwpUnregisterEngine(VOID)
{
    if (ArwGetEngineProcessId() == 0) {
        return;
    }

    ARW_LOG("Engine unregistered (PID %lu).\n", ArwGetEngineProcessId());

    InterlockedExchange(&g_EngineProcessId, 0);
    g_EngineCreateTime = 0;

    ArwSelfProtectClearTarget();
    ArwEventQueueFlush();
}

// ---------------------------------------------------------------------------
// 프로세스 종료 요청
// ---------------------------------------------------------------------------
static NTSTATUS ArwpHandleTerminate(
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
)
{
    NTSTATUS status;
    NTSTATUS termStatus;
    PARW_TERMINATE_REQUEST req = NULL;
    PARW_TERMINATE_RESPONSE resp = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    ULONG targetPid;
    ULONG64 expectedCreateTime;
    ULONG reason;

    *BytesReturned = 0;

    status = WdfRequestRetrieveInputBuffer(Request,
        sizeof(ARW_TERMINATE_REQUEST), (PVOID*)&req, &inSize);
    if (!NT_SUCCESS(status) || inSize < sizeof(ARW_TERMINATE_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!ArwpValidateHeader(req->Magic, req->Version)) {
        return STATUS_REVISION_MISMATCH;
    }

    // METHOD_BUFFERED 라 커널 복사본이지만, 검증 중 값이 바뀌는 상황을
    // 애초에 배제하기 위해 로컬로 스냅샷한 뒤 사용한다(TOCTOU 습관화).
    targetPid = req->TargetProcessId;
    expectedCreateTime = req->ExpectedCreateTime;
    reason = req->Reason;

    termStatus = ArwTerminateRansomwareProcess(targetPid, expectedCreateTime, reason);

    // 결과 회신은 선택 사항. 출력 버퍼를 준 경우에만 채운다.
    status = WdfRequestRetrieveOutputBuffer(Request,
        sizeof(ARW_TERMINATE_RESPONSE), (PVOID*)&resp, &outSize);
    if (NT_SUCCESS(status) && outSize >= sizeof(ARW_TERMINATE_RESPONSE)) {
        resp->Magic = ARW_HEADER_MAGIC;
        resp->Version = ARW_DRIVER_VERSION;
        resp->TargetProcessId = targetPid;
        resp->ResultStatus = (LONG32)termStatus;
        *BytesReturned = sizeof(ARW_TERMINATE_RESPONSE);
    }

    // 요청 '처리'는 성공했으므로 IOCTL 자체는 성공으로 완료한다.
    // 종료 성공/실패는 응답 구조체의 ResultStatus 로 전달한다.
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 정책 갱신
// ---------------------------------------------------------------------------
static NTSTATUS ArwpHandleUpdatePolicy(_In_ WDFREQUEST Request)
{
    NTSTATUS status;
    PARW_POLICY_REQUEST req = NULL;
    size_t bufferSize = 0;

    status = WdfRequestRetrieveInputBuffer(Request,
        sizeof(ARW_POLICY_REQUEST), (PVOID*)&req, &bufferSize);
    if (!NT_SUCCESS(status) || bufferSize < sizeof(ARW_POLICY_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!ArwpValidateHeader(req->Magic, req->Version)) {
        return STATUS_REVISION_MISMATCH;
    }

    if (req->FastPathMode > ARW_FASTPATH_MODE_BLOCK) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedExchange(&g_ArwFastPathMode, (LONG)req->FastPathMode);
    InterlockedExchange(&g_ArwProcessMonitorEnabled,
        (req->EnableProcessMonitor != 0) ? 1 : 0);

    // [주의] 자기 보호는 런타임 '끄기'만 허용하고 '켜기'는 허용하지 않는다.
    // 켜기는 ObRegisterCallbacks 재등록을 수반해 실패 경로가 복잡하고,
    // 무엇보다 레지스트리 킬 스위치를 IOCTL로 무력화할 수 있게 되면
    // 킬 스위치의 의미가 사라진다.
    if (req->EnableSelfProtect == 0 && g_ArwSelfProtectEnabled) {
        ArwUninitializeSelfProtect();
        InterlockedExchange(&g_ArwSelfProtectEnabled, 0);
        ARW_LOG("SelfProtect disabled at runtime by engine.\n");
    }

    ARW_LOG("Policy updated: FastPathMode=%lu ProcMon=%lu\n",
        req->FastPathMode, req->EnableProcessMonitor);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 상태 조회
// ---------------------------------------------------------------------------
static NTSTATUS ArwpHandleGetStatus(
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
)
{
    NTSTATUS status;
    PARW_STATUS_RESPONSE resp = NULL;
    size_t outSize = 0;

    *BytesReturned = 0;

    status = WdfRequestRetrieveOutputBuffer(Request,
        sizeof(ARW_STATUS_RESPONSE), (PVOID*)&resp, &outSize);
    if (!NT_SUCCESS(status) || outSize < sizeof(ARW_STATUS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(resp, sizeof(ARW_STATUS_RESPONSE));
    resp->Magic = ARW_HEADER_MAGIC;
    resp->Version = ARW_DRIVER_VERSION;
    resp->EngineProcessId = ArwGetEngineProcessId();
    resp->FastPathMode = (ULONG)g_ArwFastPathMode;
    resp->SelfProtectEnabled = (ULONG)g_ArwSelfProtectEnabled;
    resp->QueueDepth = ArwEventQueueGetDepth();
    resp->EventsGenerated = (ULONG64)g_ArwStatEventsGenerated;
    resp->EventsDropped = (ULONG64)g_ArwStatEventsDropped;
    resp->ProcessesBlocked = (ULONG64)g_ArwStatProcessesBlocked;
    resp->ProcessesTerminated = (ULONG64)g_ArwStatProcessesTerminated;

    *BytesReturned = sizeof(ARW_STATUS_RESPONSE);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL 분기
// ---------------------------------------------------------------------------
VOID ArwEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesReturned = 0;
    BOOLEAN requestForwarded = FALSE;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {

    case IOCTL_RG_REGISTER_ENGINE:
        status = ArwpHandleRegisterEngine(Request);
        break;

    case IOCTL_RG_UNREGISTER_ENGINE:
        if (!ArwpIsCallerRegisteredEngine()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        ArwpUnregisterEngine();
        status = STATUS_SUCCESS;
        break;

    case IOCTL_RG_TERMINATE_PROCESS:
        if (!ArwpIsCallerRegisteredEngine()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = ArwpHandleTerminate(Request, &bytesReturned);
        break;

    case IOCTL_RG_UPDATE_POLICY:
        if (!ArwpIsCallerRegisteredEngine()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = ArwpHandleUpdatePolicy(Request);
        break;

    case IOCTL_RG_GET_STATUS:
        if (!ArwpIsCallerRegisteredEngine()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = ArwpHandleGetStatus(Request, &bytesReturned);
        break;

    case IOCTL_RG_GET_EVENT:
        // -------------------------------------------------------------------
        // 역방향 통신. 요청을 완료하지 않고 manual 큐로 이관한다.
        // 이벤트가 발생하면 EventQueue 가 이 요청을 완료시킨다.
        // -------------------------------------------------------------------
        if (!ArwpIsCallerRegisteredEngine()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (OutputBufferLength < sizeof(ARW_PROCESS_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (g_PendingEventQueue == NULL) {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        status = WdfRequestForwardToIoQueue(Request, g_PendingEventQueue);
        if (NT_SUCCESS(status)) {
            requestForwarded = TRUE;
            // 이관 직후 적체분이 있으면 즉시 흘려보낸다.
            ArwEventQueueDrain();
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    // 이관된 요청은 이 함수가 완료해서는 안 된다. 이중 완료는 즉시 크래시다.
    if (!requestForwarded) {
        WdfRequestCompleteWithInformation(Request, status, bytesReturned);
    }
}

// ---------------------------------------------------------------------------
// 엔진 프로세스가 핸들을 닫거나 비정상 종료한 경우
// ---------------------------------------------------------------------------
VOID ArwEvtFileCleanup(_In_ WDFFILEOBJECT FileObject)
{
    ULONG caller = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    UNREFERENCED_PARAMETER(FileObject);

    // 등록했던 엔진이 사라진 경우에만 정리한다.
    if (caller != 0 && caller == ArwGetEngineProcessId()) {
        ARW_LOG("Engine handle closed - auto unregistering.\n");
        ArwpUnregisterEngine();
    }
}