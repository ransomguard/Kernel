// ===========================================================================
// File: ProcessMonitor.c
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "ProcessMonitor.h"
#include "EventQueue.h"
#include "FastPathPolicy.h"

static BOOLEAN           g_MonitorRegistered = FALSE;
static LOOKASIDE_LIST_EX g_EventLookaside;
static BOOLEAN           g_LookasideReady = FALSE;

// Fast-path classifier lives in FastPathPolicy.c, shared with a native C test.
// Rule IDs 1001..1008 may deny creation in BLOCK mode. Rule 1009 is AUDIT ONLY.
// Parent executable names are NEVER used as an unconditional bypass: a caller
// can spoof ParentProcessId, and even service-spawned VSS deletion is dangerous.
// The classifier gates rules on the ACTUAL image (CreateInfo->ImageFileName),
// not strings such as "echo vssadmin delete shadows" in unrelated command lines.

// ---------------------------------------------------------------------------
// 초기화
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwInitializeProcessMonitor(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_MonitorRegistered) {
        return STATUS_ALREADY_INITIALIZED;
    }

    // [수정] ARW_PROCESS_EVENT 는 약 1.6KB 다.
    // 기존 코드처럼 커널 스택에 직접 올리면, ARW_MAX_PATH_LENGTH 를 키우는
    // 순간 x64 커널 스택(12KB)을 넘겨 원인 파악이 거의 불가능한
    // 스택 오버플로 BSOD가 난다. 처음부터 lookaside 할당으로 간다.
    status = ExInitializeLookasideListEx(
        &g_EventLookaside, NULL, NULL,
        NonPagedPoolNx, 0, sizeof(ARW_PROCESS_EVENT), ARW_POOL_TAG, 0);

    if (!NT_SUCCESS(status)) {
        ARW_LOG("ProcessMonitor lookaside init failed (0x%08X)\n", status);
        return status;
    }
    g_LookasideReady = TRUE;

    status = PsSetCreateProcessNotifyRoutineEx(ArwProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("PsSetCreateProcessNotifyRoutineEx failed (0x%08X)%s\n",
            status,
            (status == STATUS_ACCESS_DENIED)
            ? " - check /INTEGRITYCHECK linker option!" : "");

        ExDeleteLookasideListEx(&g_EventLookaside);
        g_LookasideReady = FALSE;
        return status;
    }

    g_MonitorRegistered = TRUE;
    ARW_LOG("Process monitor initialized (v0.8.0 image-bound fast-path rules).\n");

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 해제
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwUninitializeProcessMonitor(VOID)
{
    PAGED_CODE();

    if (g_MonitorRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ArwProcessNotifyRoutineEx, TRUE);
        g_MonitorRegistered = FALSE;
    }

    // [중요] lookaside 삭제는 여기서 하지 않는다.
    // 이 함수가 리턴한 시점에도 다른 CPU에서 콜백 본문이 실행 중일 수 있다.
    // Driver.c 의 EvtDriverUnload 가 ExWaitForRundownProtectionRelease 로
    // 배수를 끝낸 뒤 아래 Finalize 를 호출한다.
    ARW_LOG("Process monitor unregistered.\n");
}

// 배수 완료 후 호출 (Driver.c 에서 간접 호출되도록 노출)
// [주의] 헤더의 SAL 주석과 정확히 일치해야 한다.
// 한쪽에만 _IRQL_requires_ 를 붙이면 /WX 빌드에서 C28167 로 실패한다.
_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwFinalizeProcessMonitor(VOID)
{
    if (g_LookasideReady) {
        ExDeleteLookasideListEx(&g_EventLookaside);
        g_LookasideReady = FALSE;
    }
}

// ---------------------------------------------------------------------------
// 프로세스 생성/종료 콜백
//
// [성능 주의] 이 콜백은 시스템의 '모든' 프로세스 생성 경로에서 호출된다.
// 여기서의 지연은 시스템 전역 지연으로 나타난다. 따라서
//   - hot path 로깅은 ARW_TRACE_HOT 으로 묶어 기본 비활성
//   - 문자열 처리는 할당 없는 제한된 명령줄 단일 스캔으로 제한
//   - 부모 이름 기반 면제를 금지하여 부모 PID 위조에 따른 우회를 제거
// ---------------------------------------------------------------------------
VOID ArwProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    PARW_PROCESS_EVENT ev = NULL;
    RG_FP_RESULT fastPath = { 0 };
    ULONG matchedRule = 0;
    BOOLEAN creationBlocked = FALSE;

    // 언로드 경로와의 경합 차단.
    // 획득에 실패하면 드라이버가 내려가는 중이므로 즉시 빠져나간다.
    if (!ExAcquireRundownProtection(&g_ArwRundownRef)) {
        return;
    }

    if (!g_ArwProcessMonitorEnabled) {
        goto Exit;
    }

    // Assess the full immutable creation input BEFORE allocating an event.
    // A failed telemetry allocation must not disable an otherwise valid
    // process-creation denial. The parser uses no kernel pool or callback IPC.
    if (CreateInfo != NULL && g_ArwFastPathMode != ARW_FASTPATH_MODE_OFF &&
        CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL &&
        CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Buffer != NULL) {

        fastPath = RgFastPathEvaluate(
            (const RG_FP_CHAR*)CreateInfo->ImageFileName->Buffer,
            (unsigned int)(CreateInfo->ImageFileName->Length / sizeof(WCHAR)),
            (const RG_FP_CHAR*)CreateInfo->CommandLine->Buffer,
            (unsigned int)(CreateInfo->CommandLine->Length / sizeof(WCHAR)));
        matchedRule = (ULONG)fastPath.RuleId;

        if (matchedRule != 0 && fastPath.AllowBlock != 0 &&
            g_ArwFastPathMode == ARW_FASTPATH_MODE_BLOCK) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            creationBlocked = TRUE;
            InterlockedIncrement64(&g_ArwStatProcessesBlocked);
            ARW_LOG("BLOCKED PID %lu by image-bound rule %lu\n",
                (ULONG)(ULONG_PTR)ProcessId, matchedRule);
        }
    }

    if (!g_LookasideReady) {
        goto Exit;
    }

    ev = (PARW_PROCESS_EVENT)ExAllocateFromLookasideListEx(&g_EventLookaside);
    if (ev == NULL) {
        InterlockedIncrement64(&g_ArwStatEventsDropped);
        goto Exit;
    }

    RtlZeroMemory(ev, sizeof(ARW_PROCESS_EVENT));
    ev->ProcessId = (ULONG)(ULONG_PTR)ProcessId;

    // =======================================================================
    // 프로세스 종료
    // =======================================================================
    if (CreateInfo == NULL) {
        ArwEventInitializeHeader(&ev->Header,
            EVENT_TYPE_PROCESS_TERMINATE, sizeof(ARW_PROCESS_EVENT));

        ev->ProcessCreateTime = (ULONG64)PsGetProcessCreateTimeQuadPart(Process);

        ARW_TRACE_HOT("[TERMINATE] PID %lu\n", ev->ProcessId);
        ArwEventQueuePush(&ev->Header);
        goto Exit;
    }

    // =======================================================================
    // 프로세스 생성
    // =======================================================================
    ArwEventInitializeHeader(&ev->Header,
        EVENT_TYPE_PROCESS_CREATE, sizeof(ARW_PROCESS_EVENT));

    ev->ParentProcessId = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;

    // [추가] 실제 생성자 PID.
    // ParentProcessId 는 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 로 위조할 수 있다.
    // 랜섬웨어가 explorer.exe 자식으로 위장하는 고전적 기법이므로
    // 실제 생성 스레드의 소속 프로세스를 별도로 실어 엔진이 대조하게 한다.
    ev->CreatorProcessId =
        (ULONG)(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess;

    if (ev->ParentProcessId != ev->CreatorProcessId) {
        ev->Flags |= ARW_PROC_FLAG_PARENT_SPOOF_SUSP;
    }

    ev->ProcessCreateTime = (ULONG64)PsGetProcessCreateTimeQuadPart(Process);

    // -----------------------------------------------------------------------
    // 이미지 경로
    // -----------------------------------------------------------------------
    // [추가] FileOpenNameAvailable 이 FALSE 면 ImageFileName 은 정규화된
    // 전체 경로가 아닐 수 있다. 이 사실을 플래그로 전달해야 엔진이
    // 경로 기반 화이트리스트의 신뢰도를 낮출 수 있다.
    if (!CreateInfo->FileOpenNameAvailable) {
        ev->Flags |= ARW_PROC_FLAG_PATH_UNAVAILABLE;
    }

    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Buffer != NULL) {

        ULONG copyBytes = CreateInfo->ImageFileName->Length;
        const ULONG maxBytes = (ARW_MAX_PATH_LENGTH - 1) * sizeof(WCHAR);

        if (copyBytes > maxBytes) {
            copyBytes = maxBytes;
            ev->Flags |= ARW_PROC_FLAG_PATH_TRUNCATED;
        }

        RtlCopyMemory(ev->ImagePath, CreateInfo->ImageFileName->Buffer, copyBytes);
        ev->ImagePathLength = copyBytes;   // 단위: 바이트 (Common.h 규약)
        ev->ImagePath[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    // -----------------------------------------------------------------------
    // 명령줄
    // -----------------------------------------------------------------------
    if (CreateInfo->CommandLine != NULL &&
        CreateInfo->CommandLine->Buffer != NULL) {

        ULONG copyBytes = CreateInfo->CommandLine->Length;
        const ULONG maxBytes = (ARW_MAX_CMDLINE_LENGTH - 1) * sizeof(WCHAR);

        if (copyBytes > maxBytes) {
            copyBytes = maxBytes;
            ev->Flags |= ARW_PROC_FLAG_CMDLINE_TRUNCATED;
        }

        RtlCopyMemory(ev->CommandLine, CreateInfo->CommandLine->Buffer, copyBytes);
        ev->CommandLineLength = copyBytes;
        ev->CommandLine[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    if (matchedRule != 0) {
        ev->Flags |= ARW_PROC_FLAG_FASTPATH_HIT;
        ev->MatchedRuleId = matchedRule;
        if (creationBlocked) {
            ev->Flags |= ARW_PROC_FLAG_BLOCKED;
            ev->Header.EventType = EVENT_TYPE_PROCESS_BLOCKED;
        }
        else {
            ARW_LOG("AUDIT PID %lu matched rule %lu (eligibleForBlock=%u, mode=%d)\n",
                ev->ProcessId, matchedRule, fastPath.AllowBlock, g_ArwFastPathMode);
        }
    }
    else {
        ARW_TRACE_HOT("[CREATE] PID %lu PPID %lu\n",
            ev->ProcessId, ev->ParentProcessId);
    }

    ArwEventQueuePush(&ev->Header);

Exit:
    if (ev != NULL && g_LookasideReady) {
        ExFreeToLookasideListEx(&g_EventLookaside, ev);
    }
    ExReleaseRundownProtection(&g_ArwRundownRef);
}
