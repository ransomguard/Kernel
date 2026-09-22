// ===========================================================================
// File: Driver.c
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "Communication.h"
#include "ProcessMonitor.h"
#include "SelfProtect.h"
#include "EventQueue.h"

// ---------------------------------------------------------------------------
// 전역 정의
// ---------------------------------------------------------------------------
EX_RUNDOWN_REF g_ArwRundownRef;
WDFDRIVER      g_ArwDriver = NULL;

volatile LONG  g_ArwFastPathMode = ARW_FASTPATH_MODE_BLOCK;
volatile LONG  g_ArwSelfProtectEnabled = 0;   // 기본 비활성. 아래 참고.
volatile LONG  g_ArwProcessMonitorEnabled = 1;

volatile LONG64 g_ArwStatEventsGenerated = 0;
volatile LONG64 g_ArwStatEventsDelivered = 0;
volatile LONG64 g_ArwStatEventsFlushed = 0;
volatile LONG64 g_ArwStatEventsDropped = 0;
volatile LONG64 g_ArwStatProcessesBlocked = 0;
volatile LONG64 g_ArwStatProcessesTerminated = 0;

static BOOLEAN g_RundownInitialized = FALSE;
static BOOLEAN g_ProcessMonitorStarted = FALSE;
static BOOLEAN g_SelfProtectStarted = FALSE;
static BOOLEAN g_CommunicationStarted = FALSE;

// ---------------------------------------------------------------------------
// 레지스트리 DWORD 읽기
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ArwReadRegistryDword(
    _In_  PUNICODE_STRING RegistryPath,
    _In_  PCWSTR          ValueName,
    _Out_ PULONG          Value
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle = NULL;
    UNICODE_STRING paramPath;
    UNICODE_STRING valueNameStr;
    PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
    ULONG resultLength = 0;
    USHORT bufferBytes;
    PWCH pathBuffer = NULL;

    PAGED_CODE();

    *Value = 0;

    // RegistryPath + L"\\Parameters" 문자열 구성
    bufferBytes = RegistryPath->Length + (USHORT)(sizeof(L"\\Parameters"));
    pathBuffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, bufferBytes, ARW_POOL_TAG);
    if (pathBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    paramPath.Buffer = pathBuffer;
    paramPath.Length = 0;
    paramPath.MaximumLength = bufferBytes;

    status = RtlAppendUnicodeStringToString(&paramPath, RegistryPath);
    if (NT_SUCCESS(status)) {
        status = RtlAppendUnicodeToString(&paramPath, L"\\Parameters");
    }
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    InitializeObjectAttributes(&objAttr,
        &paramPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        // Parameters 키가 없는 것은 정상(기본값 사용). 에러로 취급하지 않는다.
        goto Cleanup;
    }

    RtlInitUnicodeString(&valueNameStr, ValueName);

    resultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG);
    info = (PKEY_VALUE_PARTIAL_INFORMATION)
        ExAllocatePool2(POOL_FLAG_PAGED, resultLength, ARW_POOL_TAG);
    if (info == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    status = ZwQueryValueKey(keyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        info,
        resultLength,
        &resultLength);

    if (NT_SUCCESS(status) &&
        info->Type == REG_DWORD &&
        info->DataLength == sizeof(ULONG)) {
        RtlCopyMemory(Value, info->Data, sizeof(ULONG));
    }
    else if (NT_SUCCESS(status)) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
    }

Cleanup:
    if (info != NULL) {
        ExFreePoolWithTag(info, ARW_POOL_TAG);
    }
    if (keyHandle != NULL) {
        ZwClose(keyHandle);
    }
    if (pathBuffer != NULL) {
        ExFreePoolWithTag(pathBuffer, ARW_POOL_TAG);
    }
    return status;
}

// ---------------------------------------------------------------------------
// 정책 초기 로드
// ---------------------------------------------------------------------------
static VOID ArwpLoadPolicyFromRegistry(_In_ PUNICODE_STRING RegistryPath)
{
    ULONG value = 0;

    PAGED_CODE();

    if (NT_SUCCESS(ArwReadRegistryDword(RegistryPath, L"FastPathMode", &value))) {
        if (value <= ARW_FASTPATH_MODE_BLOCK) {
            InterlockedExchange(&g_ArwFastPathMode, (LONG)value);
        }
    }

    // [킬 스위치] EnableSelfProtect 를 명시적으로 1로 두지 않으면 자기 보호는
    // 켜지지 않는다. 기본 비활성인 이유:
    //   ObRegisterCallbacks 로 핸들 권한을 박탈하기 시작하면 개발자 자신의
    //   디버거 부착, 프로세스 종료, 드라이버 언로드가 함께 막혀 VM 스냅샷
    //   복구 외에는 빠져나올 방법이 없어진다.
    // 기능 검증이 끝난 뒤 마지막 단계에서 켜는 것이 원래 구현 순서였다.
    if (NT_SUCCESS(ArwReadRegistryDword(RegistryPath, L"EnableSelfProtect", &value))) {
        InterlockedExchange(&g_ArwSelfProtectEnabled, (value != 0) ? 1 : 0);
    }

    if (NT_SUCCESS(ArwReadRegistryDword(RegistryPath, L"EnableProcessMonitor", &value))) {
        InterlockedExchange(&g_ArwProcessMonitorEnabled, (value != 0) ? 1 : 0);
    }

    ARW_LOG("Policy loaded: FastPathMode=%d, SelfProtect=%d, ProcMon=%d\n",
        g_ArwFastPathMode, g_ArwSelfProtectEnabled, g_ArwProcessMonitorEnabled);
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver = NULL;

    ARW_LOG("DriverEntry: initialization started (version 0x%08X).\n",
        ARW_DRIVER_VERSION);

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    // [수정 핵심] 하드웨어가 없는 소프트웨어 전용 드라이버임을 KMDF에 명시한다.
    //
    // 이 플래그가 없으면 프레임워크는 PnP 드라이버로 간주해
    // EvtDriverUnload 를 아예 호출하지 않는다. 결과적으로 sc stop 으로
    // 드라이버를 내릴 수 없어 수정할 때마다 VM 재부팅이 강제된다.
    // 개발 생산성에 가장 직접적으로 영향을 주는 한 줄이다.
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

    // [수정] WDF_NO_HANDLE -> &driver.
    // Communication 모듈이 제어 디바이스를 만들려면 WDFDRIVER 핸들이 필요하다.
    status = WdfDriverCreate(DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver);

    if (!NT_SUCCESS(status)) {
        ARW_LOG("WdfDriverCreate failed (0x%08X)\n", status);
        return status;
    }

    g_ArwDriver = driver;

    // 콜백 배수 보호 초기화. 반드시 어떤 콜백도 등록하기 전에 수행한다.
    ExInitializeRundownProtection(&g_ArwRundownRef);
    g_RundownInitialized = TRUE;

    ArwpLoadPolicyFromRegistry(RegistryPath);

    // =======================================================================
    // 모듈 초기화 — 실패 시 '초기화의 역순'으로 롤백한다.
    // =======================================================================

    // 1) 통신 계층 (제어 디바이스 + 큐 + 이벤트 큐)
    //    다른 모듈이 이벤트를 밀어넣을 대상이므로 가장 먼저 준비되어야 한다.
    status = ArwInitializeCommunication(driver);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("Communication init failed (0x%08X)\n", status);
        goto RollBack;
    }
    g_CommunicationStarted = TRUE;

    // 2) 프로세스 감시
    if (g_ArwProcessMonitorEnabled) {
        status = ArwInitializeProcessMonitor();
        if (!NT_SUCCESS(status)) {
            ARW_LOG("ProcessMonitor init failed (0x%08X)\n", status);
            goto RollBack;
        }
        g_ProcessMonitorStarted = TRUE;
    }

    // 3) 자기 보호 — 레지스트리 킬 스위치로 명시 활성화한 경우에만.
    //    실패해도 드라이버 전체를 내리지는 않는다(탐지 기능은 계속 유효).
    if (g_ArwSelfProtectEnabled) {
        status = ArwInitializeSelfProtect(DriverObject);
        if (NT_SUCCESS(status)) {
            g_SelfProtectStarted = TRUE;
        }
        else {
            ARW_LOG("SelfProtect init failed (0x%08X) - continuing without it.\n",
                status);
            InterlockedExchange(&g_ArwSelfProtectEnabled, 0);
        }
    }
    else {
        ARW_LOG("SelfProtect disabled by policy (kill switch).\n");
    }

    ARW_LOG("Driver loaded successfully.\n");
    return STATUS_SUCCESS;

RollBack:
    // 등록된 것만 정확히 역순으로 해제한다.
    if (g_ProcessMonitorStarted) {
        ArwUninitializeProcessMonitor();
        g_ProcessMonitorStarted = FALSE;
    }
    if (g_RundownInitialized) {
        ExWaitForRundownProtectionRelease(&g_ArwRundownRef);
        g_RundownInitialized = FALSE;
    }
    ArwFinalizeProcessMonitor();
    if (g_CommunicationStarted) {
        ArwUninitializeCommunication();
        g_CommunicationStarted = FALSE;
    }

    // WDFDRIVER 객체는 DriverEntry 가 실패 코드를 반환하면
    // 프레임워크가 알아서 정리하므로 직접 삭제하지 않는다.
    return status;
}

// ---------------------------------------------------------------------------
// EvtDriverUnload
//
// [순서가 곧 BSOD 여부를 결정한다]
//   1. 신규 콜백 진입 차단 (콜백 등록 해제)
//   2. 실행 중인 콜백이 모두 빠져나갈 때까지 대기 (rundown)
//   3. 그제서야 콜백이 참조하던 자원을 해제
// 2번을 건너뛰면 다른 CPU에서 실행 중인 콜백이 이미 해제된 이벤트 큐를
// 참조해 즉시 크래시한다.
// ---------------------------------------------------------------------------
VOID
EvtDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    ARW_LOG("DriverUnload: starting cleanup...\n");

    // 1) 자기 보호 먼저 해제한다.
    //    이게 남아 있으면 이후 정리 과정에서 핸들 접근이 막힐 수 있다.
    if (g_SelfProtectStarted) {
        ArwUninitializeSelfProtect();
        g_SelfProtectStarted = FALSE;
    }

    // 2) 프로세스 콜백 등록 해제 (신규 진입 차단)
    if (g_ProcessMonitorStarted) {
        ArwUninitializeProcessMonitor();
        g_ProcessMonitorStarted = FALSE;
    }

    // 3) 실행 중인 콜백 배수 대기
    if (g_RundownInitialized) {
        ExWaitForRundownProtectionRelease(&g_ArwRundownRef);
        g_RundownInitialized = FALSE;
        ARW_LOG("All in-flight callbacks drained.\n");
    }

    // 3-1) 배수가 끝난 뒤에야 콜백이 쓰던 lookaside 를 삭제할 수 있다.
    ArwFinalizeProcessMonitor();

    // 4) 이제 안전하게 통신/이벤트 자원 해제
    if (g_CommunicationStarted) {
        ArwUninitializeCommunication();
        g_CommunicationStarted = FALSE;
    }

    ARW_LOG("DriverUnload: cleanup complete. "
        "Stats: generated=%lld dropped=%lld blocked=%lld terminated=%lld\n",
        g_ArwStatEventsGenerated,
        g_ArwStatEventsDropped,
        g_ArwStatProcessesBlocked,
        g_ArwStatProcessesTerminated);
}