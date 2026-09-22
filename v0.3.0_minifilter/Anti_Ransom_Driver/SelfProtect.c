// ===========================================================================
// File: SelfProtect.c
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "SelfProtect.h"

// ---------------------------------------------------------------------------
// 프로세스 접근 권한 상수 (WDK 헤더에 없을 수 있어 명시)
// ---------------------------------------------------------------------------
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           (0x0001)
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD       (0x0002)
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION        (0x0008)
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ             (0x0010)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE            (0x0020)
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE          (0x0040)
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA           (0x0100)
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION     (0x0200)
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME      (0x0800)
#endif

// ---------------------------------------------------------------------------
// 스레드 접근 권한 상수
// ---------------------------------------------------------------------------
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE            (0x0001)
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME       (0x0002)
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT          (0x0010)
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION      (0x0020)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN     (0x0080)
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE          (0x0100)
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION (0x0200)
#endif

// ===========================================================================
// 박탈할 권한 집합
//
// 기존 코드는 PROCESS_TERMINATE 와 PROCESS_VM_WRITE 만 제거했다.
// 남아 있던 우회 경로:
//   PROCESS_SUSPEND_RESUME  → 죽이지 않고 엔진 전체를 정지시켜 무력화
//   PROCESS_CREATE_THREAD   → 원격 스레드 주입 후 내부에서 ExitProcess
//   PROCESS_VM_OPERATION    → 코드 영역을 PAGE_NOACCESS 로 바꿔 크래시 유도
//   PROCESS_DUP_HANDLE      → 핸들 복제로 권한 우회
//   PROCESS_SET_INFORMATION → 우선순위/쿼터 조작으로 기아 상태 유발
//
// [의도적으로 남기는 권한]
//   PROCESS_QUERY_INFORMATION / PROCESS_VM_READ 는 박탈하지 않는다.
//   작업 관리자, 성능 모니터, 백업 도구 등 정상 조회 경로를 막으면
//   오탐 민원이 폭증하고, 조회만으로는 엔진을 무력화할 수 없다.
// ===========================================================================
#define ARW_DENIED_PROCESS_ACCESS  \
    (PROCESS_TERMINATE       |     \
     PROCESS_CREATE_THREAD   |     \
     PROCESS_VM_OPERATION    |     \
     PROCESS_VM_WRITE        |     \
     PROCESS_DUP_HANDLE      |     \
     PROCESS_SET_QUOTA       |     \
     PROCESS_SET_INFORMATION |     \
     PROCESS_SUSPEND_RESUME)

// ===========================================================================
// 스레드 권한 박탈이 필요한 이유
//
// 프로세스 핸들만 막아도 공격자는 CreateToolhelp32Snapshot 으로 대상
// 프로세스의 '스레드'를 열거한 뒤 OpenThread(THREAD_TERMINATE) 로
// 전 스레드를 종료해 프로세스를 사실상 죽일 수 있다.
// PsThreadType 을 함께 등록하지 않으면 자기 보호에 정면으로 구멍이 뚫린다.
// ===========================================================================
#define ARW_DENIED_THREAD_ACCESS       \
    (THREAD_TERMINATE            |     \
     THREAD_SUSPEND_RESUME       |     \
     THREAD_SET_CONTEXT          |     \
     THREAD_SET_INFORMATION      |     \
     THREAD_SET_THREAD_TOKEN     |     \
     THREAD_IMPERSONATE          |     \
     THREAD_DIRECT_IMPERSONATION)

// ---------------------------------------------------------------------------
// 상태
// ---------------------------------------------------------------------------
static PVOID     g_ObRegistrationHandle = NULL;
static PEPROCESS g_ProtectedProcess = NULL;   // 참조 보유
static EX_SPIN_LOCK g_TargetLock = 0;
static volatile LONG64 g_StripCount = 0;

// ---------------------------------------------------------------------------
// 초기화
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwInitializeSelfProtect(_In_ PDRIVER_OBJECT DriverObject)
{
    // [수정] 배열 2개. 프로세스 + 스레드 객체를 모두 감시한다.
    OB_OPERATION_REGISTRATION obOperationReg[2];
    OB_CALLBACK_REGISTRATION  obCallbackReg;
    NTSTATUS status;
    UNICODE_STRING altitude;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_ObRegistrationHandle != NULL) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(obOperationReg, sizeof(obOperationReg));
    RtlZeroMemory(&obCallbackReg, sizeof(obCallbackReg));

    // [0] 프로세스 객체
    obOperationReg[0].ObjectType = PsProcessType;
    obOperationReg[0].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOperationReg[0].PreOperation = ArwObPreOperationCallback;
    obOperationReg[0].PostOperation = NULL;

    // [1] 스레드 객체
    obOperationReg[1].ObjectType = PsThreadType;
    obOperationReg[1].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOperationReg[1].PreOperation = ArwObPreOperationCallback;
    obOperationReg[1].PostOperation = NULL;

    // Altitude 충돌 시 STATUS_FLT_INSTANCE_ALTITUDE_COLLISION 이 반환된다.
    // 그 경우 값을 조정할 것. 상용 배포 시에는 Microsoft 로부터 고유
    // Altitude 를 발급받아야 한다.
    RtlInitUnicodeString(&altitude, L"320000");

    obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    obCallbackReg.OperationRegistrationCount = 2;   // [수정] 1 -> 2
    obCallbackReg.Altitude = altitude;
    obCallbackReg.RegistrationContext = NULL;
    obCallbackReg.OperationRegistration = obOperationReg;

    status = ObRegisterCallbacks(&obCallbackReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        g_ObRegistrationHandle = NULL;

        
        
        ("ObRegisterCallbacks failed (0x%08X)%s\n",
            status,
            (status == STATUS_ACCESS_DENIED)
            ? " - check /INTEGRITYCHECK linker option!" : "");
        return status;
    }

    ARW_LOG("Self-protect module initialized (process + thread).\n");
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 해제
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwUninitializeSelfProtect(VOID)
{
    PAGED_CODE();

    if (g_ObRegistrationHandle != NULL) {
        // ObUnRegisterCallbacks 는 내부적으로 진행 중인 콜백을 배수한다.
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
        ARW_LOG("Self-protect unregistered (stripped %lld times).\n",
            g_StripCount);
    }

    // 콜백 해제 후에 참조를 놓는다. 순서를 뒤집으면 콜백이
    // 이미 해제된 PEPROCESS 를 참조할 수 있다.
    ArwSelfProtectClearTarget();
}

// ---------------------------------------------------------------------------
// 보호 대상 지정
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwSelfProtectSetTarget(_In_ HANDLE ProcessId)
{
    NTSTATUS status;
    PEPROCESS newTarget = NULL;
    PEPROCESS oldTarget = NULL;
    KIRQL oldIrql;

    PAGED_CODE();

    status = PsLookupProcessByProcessId(ProcessId, &newTarget);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // PsLookupProcessByProcessId 가 참조를 1 올려 주므로 그대로 보관한다.

    oldIrql = ExAcquireSpinLockExclusive(&g_TargetLock);
    oldTarget = g_ProtectedProcess;
    g_ProtectedProcess = newTarget;
    ExReleaseSpinLockExclusive(&g_TargetLock, oldIrql);

    if (oldTarget != NULL) {
        ObDereferenceObject(oldTarget);
    }

    ARW_LOG("Self-protect target set: PID %lu\n",
        (ULONG)(ULONG_PTR)ProcessId);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 보호 대상 해제
// ---------------------------------------------------------------------------
_IRQL_requires_max_(APC_LEVEL)
VOID ArwSelfProtectClearTarget(VOID)
{
    PEPROCESS oldTarget;
    KIRQL oldIrql;

    oldIrql = ExAcquireSpinLockExclusive(&g_TargetLock);
    oldTarget = g_ProtectedProcess;
    g_ProtectedProcess = NULL;
    ExReleaseSpinLockExclusive(&g_TargetLock, oldIrql);

    if (oldTarget != NULL) {
        ObDereferenceObject(oldTarget);
        ARW_LOG("Self-protect target cleared.\n");
    }
}

// ---------------------------------------------------------------------------
// 사전 검사 콜백
//
// [성능] 이 콜백은 시스템의 모든 프로세스/스레드 핸들 생성 경로에서 돈다.
// 대상이 아니면 최소 비용으로 즉시 빠져나가는 것이 설계 목표다.
// 로깅은 ARW_TRACE_HOT 으로 묶어 기본 비활성화한다.
// ---------------------------------------------------------------------------
OB_PREOP_CALLBACK_STATUS ArwObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    PEPROCESS targetProcess = NULL;
    PEPROCESS protectedProcess;
    ACCESS_MASK deniedMask;
    KIRQL oldIrql;
    BOOLEAN isThreadOp;

    UNREFERENCED_PARAMETER(RegistrationContext);

    // 1) 커널 내부의 정당한 접근은 건드리지 않는다.
    //    막으면 시스템 서비스가 깨져 크래시로 이어진다.
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    // 2) 보호 대상 스냅샷.
    //    콜백 실행 중 대상이 바뀌어도 안전하도록 참조를 하나 더 잡는다.
    oldIrql = ExAcquireSpinLockShared(&g_TargetLock);
    protectedProcess = g_ProtectedProcess;
    if (protectedProcess != NULL) {
        ObReferenceObject(protectedProcess);
    }
    ExReleaseSpinLockShared(&g_TargetLock, oldIrql);

    if (protectedProcess == NULL) {
        return OB_PREOP_SUCCESS;
    }

    // 3) 대상 객체가 보호 프로세스(또는 그 스레드)인지 판정
    if (OperationInformation->ObjectType == *PsProcessType) {
        isThreadOp = FALSE;
        targetProcess = (PEPROCESS)OperationInformation->Object;
    }
    else if (OperationInformation->ObjectType == *PsThreadType) {
        isThreadOp = TRUE;
        // 스레드가 속한 프로세스를 얻어 비교한다.
        targetProcess = PsGetThreadProcess((PETHREAD)OperationInformation->Object);
    }
    else {
        goto Exit;
    }

    // [핵심] PID 비교가 아니라 커널 객체 포인터 비교.
    // PID 재사용을 이용해 엉뚱한 프로세스를 보호하게 만드는 공격이 불가능해진다.
    if (targetProcess != protectedProcess) {
        goto Exit;
    }

    // 4) [오탐 방지] 보호 대상이 자기 자신에 접근하는 경우는 허용한다.
    //    이 검사가 없으면 엔진의 정상 종료 루틴과 자기 재시작(업데이트)
    //    경로까지 막혀 좀비 프로세스가 남는다.
    if (PsGetCurrentProcess() == protectedProcess) {
        goto Exit;
    }

    // 5) 권한 선택적 박탈
    //    핸들 요청 자체를 실패시키지 않는 이유는, 전면 차단이
    //    작업 관리자 조회 등 정상 도구의 오탐을 유발하기 때문이다.
    deniedMask = isThreadOp ? ARW_DENIED_THREAD_ACCESS : ARW_DENIED_PROCESS_ACCESS;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess
            &= ~deniedMask;
    }
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess
            &= ~deniedMask;
    }

    InterlockedIncrement64(&g_StripCount);

    ARW_TRACE_HOT("Stripped 0x%08X from PID %lu -> protected (%s)\n",
        deniedMask,
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
        isThreadOp ? "thread" : "process");

Exit:
    ObDereferenceObject(protectedProcess);
    return OB_PREOP_SUCCESS;
}