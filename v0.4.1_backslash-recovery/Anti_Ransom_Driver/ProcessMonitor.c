// ===========================================================================
// File: ProcessMonitor.c
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "ProcessMonitor.h"
#include "EventQueue.h"

static BOOLEAN           g_MonitorRegistered = FALSE;
static LOOKASIDE_LIST_EX g_EventLookaside;
static BOOLEAN           g_LookasideReady = FALSE;

// ===========================================================================
// Fast-path 규칙 테이블
//
// [설계 근거]
// 기획의 핵심 원칙은 "고신뢰 신호는 누적 점수를 우회해 즉시 차단"이었다.
// 모든 판단을 Python 상관분석에 위임하면 두 가지가 깨진다.
//   1) 왕복 지연(수백 ms) 동안 VSS는 이미 삭제된다. 복구 수단이 먼저 사라진다.
//   2) 엔진이 죽으면 커널이 완전히 무력해진다 — 단일 실패 지점.
// 따라서 커널 단독으로 동작하는 최소 규칙 집합을 유지한다.
//
// 모든 토큰이 명령줄에 '전부' 포함될 때만(AND) 매칭된다.
// 비교 전에 명령줄 전체를 소문자로 정규화하므로 토큰은 소문자로 적는다.
// ===========================================================================
typedef struct _ARW_FASTPATH_RULE {
    ULONG   RuleId;
    PCWSTR  Description;
    PCWSTR  Tokens[4];
    ULONG   TokenCount;
} ARW_FASTPATH_RULE;

static const ARW_FASTPATH_RULE g_FastPathRules[] = {
    // 그림자 복사본 삭제 — 랜섬웨어가 암호화보다 먼저 수행하는 1순위 행위
    { 1001, L"vssadmin shadow deletion",
      { L"vssadmin", L"delete", L"shadow" }, 3 },

    { 1002, L"vssadmin resize (shadow eviction)",
      { L"vssadmin", L"resize", L"shadowstorage" }, 3 },

    { 1003, L"wmic shadowcopy deletion",
      { L"shadowcopy", L"delete" }, 2 },

      // 백업 카탈로그 / 시스템 상태 백업 삭제
      { 1004, L"wbadmin catalog deletion",
        { L"wbadmin", L"delete" }, 2 },

        // 복구 환경 무력화
        { 1005, L"bcdedit recovery disable",
          { L"bcdedit", L"recoveryenabled", L"no" }, 3 },

        { 1006, L"bcdedit boot status policy tamper",
          { L"bcdedit", L"bootstatuspolicy", L"ignoreallfailures" }, 3 },

          // 이벤트 로그 말소 (포렌식 방해)
          { 1007, L"event log wipe",
            { L"wevtutil", L"cl" }, 2 },

            // 슬랙 영역 와이핑 — 삭제 파일 복구를 원천 차단
            { 1008, L"cipher free-space wipe",
              { L"cipher", L"/w" }, 2 },

              // PowerShell 기반 그림자 복사본 제거
              { 1009, L"powershell shadowcopy removal",
                { L"win32_shadowcopy", L"delete" }, 2 },
};

#define ARW_FASTPATH_RULE_COUNT \
    (sizeof(g_FastPathRules) / sizeof(g_FastPathRules[0]))

// ===========================================================================
// [오탐 방지 - 화이트리스트]
//
// 위 규칙은 관리자의 정상 유지보수 작업과 구분이 불가능한 경우가 있다.
// 예: 백업 솔루션이 오래된 그림자 복사본을 정리하는 스케줄 작업.
//
// 실무적 대응은 3단계다.
//  1) 단계적 모드: AUDIT 모드로 배포해 실제 환경의 오탐률을 먼저 측정한다.
//     (IOCTL_RG_UPDATE_POLICY 로 런타임 전환. 발표용 정량 지표의 근거가 된다.)
//  2) 부모 체인 검사: 아래 경로에서 실행된 것은 신뢰도를 낮춘다.
//  3) 서명 검증: 정식 구현은 미니필터에서 이미지 서명을 확인하는 것이다.
//
// 여기서는 2)만 구현한다. 부모가 신뢰 경로면 차단하지 않고 이벤트만 올린다.
// ===========================================================================
static const PCWSTR g_TrustedParentSuffixes[] = {
    L"\\windows\\system32\\svchost.exe",       // 작업 스케줄러 경유 유지보수
    L"\\windows\\system32\\wbem\\wmiprvse.exe",
};

#define ARW_TRUSTED_PARENT_COUNT \
    (sizeof(g_TrustedParentSuffixes) / sizeof(g_TrustedParentSuffixes[0]))

// ---------------------------------------------------------------------------
// 소문자 정규화된 버퍼에서 부분 문자열 탐색
// ---------------------------------------------------------------------------
static BOOLEAN ArwpContainsW(
    _In_reads_(HayChars) PCWSTR Hay,
    _In_ ULONG HayChars,
    _In_ PCWSTR Needle
)
{
    ULONG needleChars = 0;
    ULONG i, j;

    while (Needle[needleChars] != L'\0') {
        needleChars++;
    }
    if (needleChars == 0 || needleChars > HayChars) {
        return FALSE;
    }

    for (i = 0; i + needleChars <= HayChars; i++) {
        for (j = 0; j < needleChars; j++) {
            if (Hay[i + j] != Needle[j]) {
                break;
            }
        }
        if (j == needleChars) {
            return TRUE;
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// 소문자 정규화 (제자리)
// ---------------------------------------------------------------------------
static VOID ArwpDowncaseInPlace(_Inout_updates_(Chars) PWCH Buffer, _In_ ULONG Chars)
{
    ULONG i;
    for (i = 0; i < Chars; i++) {
        Buffer[i] = RtlDowncaseUnicodeChar(Buffer[i]);
    }
}

// ---------------------------------------------------------------------------
// Fast-path 규칙 평가. 매칭된 RuleId 반환(0 = 없음).
// ---------------------------------------------------------------------------
static ULONG ArwpEvaluateFastPath(
    _In_reads_(CmdChars) PCWSTR LowerCmdLine,
    _In_ ULONG CmdChars
)
{
    ULONG r, t;

    if (CmdChars == 0) {
        return 0;
    }

    for (r = 0; r < ARW_FASTPATH_RULE_COUNT; r++) {
        BOOLEAN allMatched = TRUE;

        for (t = 0; t < g_FastPathRules[r].TokenCount; t++) {
            if (!ArwpContainsW(LowerCmdLine, CmdChars, g_FastPathRules[r].Tokens[t])) {
                allMatched = FALSE;
                break;
            }
        }

        if (allMatched) {
            return g_FastPathRules[r].RuleId;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 부모 프로세스가 신뢰 경로인지 확인
// ---------------------------------------------------------------------------
static BOOLEAN ArwpIsTrustedParent(_In_ HANDLE ParentProcessId)
{
    NTSTATUS status;
    PEPROCESS parent = NULL;
    PUNICODE_STRING imageName = NULL;
    BOOLEAN trusted = FALSE;
    ULONG i;

    if (ParentProcessId == NULL) {
        return FALSE;
    }

    status = PsLookupProcessByProcessId(ParentProcessId, &parent);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = SeLocateProcessImageName(parent, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL) {

        ULONG chars = imageName->Length / sizeof(WCHAR);
        PWCH lower = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED,
            imageName->Length, ARW_POOL_TAG);

        if (lower != NULL) {
            RtlCopyMemory(lower, imageName->Buffer, imageName->Length);
            ArwpDowncaseInPlace(lower, chars);

            for (i = 0; i < ARW_TRUSTED_PARENT_COUNT; i++) {
                if (ArwpContainsW(lower, chars, g_TrustedParentSuffixes[i])) {
                    trusted = TRUE;
                    break;
                }
            }
            ExFreePoolWithTag(lower, ARW_POOL_TAG);
        }
    }

    if (imageName != NULL) {
        // SeLocateProcessImageName 이 할당한 버퍼는 호출자가 해제해야 한다.
        ExFreePool(imageName);
    }
    ObDereferenceObject(parent);

    return trusted;
}

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
    ARW_LOG("Process monitor initialized (%u fast-path rules).\n",
        (ULONG)ARW_FASTPATH_RULE_COUNT);

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
//   - 문자열 처리는 명령줄 1회 정규화 + 단일 스캔으로 제한
//   - 부모 경로 조회(ArwpIsTrustedParent)는 fast-path 매칭 시에만 수행
// ---------------------------------------------------------------------------
VOID ArwProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    PARW_PROCESS_EVENT ev = NULL;
    PWCH lowerCmd = NULL;
    ULONG lowerCmdChars = 0;
    ULONG matchedRule = 0;
    BOOLEAN trustedParent = FALSE;

    // 언로드 경로와의 경합 차단.
    // 획득에 실패하면 드라이버가 내려가는 중이므로 즉시 빠져나간다.
    if (!ExAcquireRundownProtection(&g_ArwRundownRef)) {
        return;
    }

    if (!g_ArwProcessMonitorEnabled) {
        goto Exit;
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
        ArwEventQueuePush(ev);
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

    // -----------------------------------------------------------------------
    // Fast-path 평가
    // -----------------------------------------------------------------------
    if (g_ArwFastPathMode != ARW_FASTPATH_MODE_OFF &&
        ev->CommandLineLength > 0) {

        lowerCmdChars = ev->CommandLineLength / sizeof(WCHAR);

        lowerCmd = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            ev->CommandLineLength, ARW_POOL_TAG);

        if (lowerCmd != NULL) {
            RtlCopyMemory(lowerCmd, ev->CommandLine, ev->CommandLineLength);
            ArwpDowncaseInPlace(lowerCmd, lowerCmdChars);

            matchedRule = ArwpEvaluateFastPath(lowerCmd, lowerCmdChars);

            ExFreePoolWithTag(lowerCmd, ARW_POOL_TAG);
            lowerCmd = NULL;
        }
    }

    if (matchedRule != 0) {
        ev->Flags |= ARW_PROC_FLAG_FASTPATH_HIT;
        ev->MatchedRuleId = matchedRule;

        // 오탐 방지: 신뢰 부모에서 파생된 경우 차단하지 않고 보고만 한다.
        trustedParent = ArwpIsTrustedParent(CreateInfo->ParentProcessId);

        if (g_ArwFastPathMode == ARW_FASTPATH_MODE_BLOCK && !trustedParent) {

            // ===============================================================
            // [수정 핵심] 프로세스 생성 자체를 거부한다.
            //
            // PsSetCreateProcessNotifyRoutineEx 를 쓰는 이유의 절반이
            // 바로 이 CreationStatus 다. 기존 코드는 로깅만 하고 있었으므로
            // 기획서의 "fast-path process denial"이 구현되어 있지 않았다.
            //
            // 여기서 막으면 vssadmin 이 '실행되기도 전에' 실패한다.
            // 상관분석 왕복을 기다리는 것과 달리 그림자 복사본이 살아남는다.
            // ===============================================================
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

            ev->Flags |= ARW_PROC_FLAG_BLOCKED;
            ev->Header.EventType = EVENT_TYPE_PROCESS_BLOCKED;

            InterlockedIncrement64(&g_ArwStatProcessesBlocked);

            ARW_LOG("BLOCKED PID %lu by rule %lu (parent %lu)\n",
                ev->ProcessId, matchedRule, ev->ParentProcessId);
        }
        else {
            ARW_LOG("AUDIT PID %lu matched rule %lu (trustedParent=%d, mode=%d)\n",
                ev->ProcessId, matchedRule, trustedParent, g_ArwFastPathMode);
        }
    }
    else {
        ARW_TRACE_HOT("[CREATE] PID %lu PPID %lu\n",
            ev->ProcessId, ev->ParentProcessId);
    }

    ArwEventQueuePush(ev);

Exit:
    if (ev != NULL && g_LookasideReady) {
        ExFreeToLookasideListEx(&g_EventLookaside, ev);
    }
    ExReleaseRundownProtection(&g_ArwRundownRef);
}