// ===========================================================================
// File: ResponseEngine.c
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "ResponseEngine.h"
#include "Communication.h"
#include "CriticalProcess.h"   // Shared/ — 임계 프로세스 공유 판정(ntifs.h 이후에 올 것)

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

// 종료 코드. 이벤트 로그와 덤프에서 '백신이 죽였다'는 사실이 드러나도록
// 일반 실패 코드 대신 명시적인 값을 쓴다.
#ifndef STATUS_VIRUS_INFECTED
#define STATUS_VIRUS_INFECTED ((NTSTATUS)0xC0000906L)
#endif

// ===========================================================================
// [필수] 시스템 임계 프로세스 화이트리스트
//
// [이관] 목록(g_CriticalImageSuffixes)과 판정 로직은 Shared/CriticalProcess.h 로
// 옮겨 g_ArwCpCriticalSuffixes / ArwCpIsProtectedSystemProcess 가 됐다.
// 미니필터(Anti_Ransom_FsFilter)도 종료 직전 같은 판정을 해야 하는데,
// 두 드라이버가 목록을 각자 가지면 한쪽만 갱신되어 CRITICAL_PROCESS_DIED
// 위험이 되살아난다. 단일 출처로 유지한다.
//
// 기존 코드는 PID 0/4 만 막았다. 그러나 csrss/wininit/services/smss/lsass 는
// critical 로 표시되어 있어 종료 시 즉시 CRITICAL_PROCESS_DIED 버그체크가 난다.
//
// [원칙] 커널은 유저 모드의 판단을 신뢰하지 않는다.
// 엔진이 무엇을 지시하든 이 목록에 걸리면 커널이 최종적으로 거부한다.
// ===========================================================================

// ---------------------------------------------------------------------------
// 임계 프로세스 판정 — 공유 구현으로 위임하는 얇은 래퍼.
//
// 공개 심볼 ArwIsProtectedSystemProcess 는 그대로 내보낸다. 때문에
// ResponseEngine.h 의 선언과 ArwTerminateRansomwareProcess 의 6단계 호출부는
// 한 줄도 바뀔 필요가 없다. fail-closed 동작은 공유 헤더에 보존돼 있다.
//
// 문자열 부분문자열 탐색은 헤더의 ArwCpContainsW 가 대신하므로,
// 이 파일에 있던 static ArwpContainsW 는 삭제했다.
// (ProcessMonitor.c 의 동명 static 함수는 용도가 달라 그대로 둔다.)
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN ArwIsProtectedSystemProcess(_In_ PEPROCESS Process)
{
    PAGED_CODE();
    return ArwCpIsProtectedSystemProcess(Process);
}

// ---------------------------------------------------------------------------
// 프로세스 종료
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ArwTerminateRansomwareProcess(
    _In_ ULONG   TargetProcessId,
    _In_ ULONG64 ExpectedCreateTime,
    _In_ ULONG   Reason
)
{
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    HANDLE processHandle = NULL;
    ULONG64 actualCreateTime;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    // -----------------------------------------------------------------------
    // 1) 자명한 임계 PID
    // -----------------------------------------------------------------------
    if (TargetProcessId == 0 || TargetProcessId == 4) {
        ARW_LOG("Refused: PID %lu is System/Idle.\n", TargetProcessId);
        return STATUS_ACCESS_DENIED;
    }

    // -----------------------------------------------------------------------
    // 2) 엔진 자기 자신 보호
    //    엔진이 오탐으로 자기 PID를 올려보내면 자해가 된다.
    // -----------------------------------------------------------------------
    if (TargetProcessId == ArwGetEngineProcessId()) {
        ARW_LOG("Refused: target is the registered engine itself (PID %lu).\n",
            TargetProcessId);
        return STATUS_ACCESS_DENIED;
    }

    // -----------------------------------------------------------------------
    // 3) PEPROCESS 참조 획득
    //
    // [변경] ZwOpenProcess(PID) 대신 PsLookupProcessByProcessId 를 쓴다.
    //  - 생성 시각 검증을 하려면 어차피 PEPROCESS 가 필요하다.
    //  - 참조를 잡아두면 검증~종료 사이에 객체가 소멸하지 않는다.
    //  - ZwOpenProcess 는 ntifs.h 소속이라 ntddk.h 만 포함하면 빌드도 깨진다.
    // -----------------------------------------------------------------------
    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetProcessId, &targetProcess);

    if (!NT_SUCCESS(status)) {
        ARW_LOG("Refused: PID %lu not found (0x%08X). Already gone?\n",
            TargetProcessId, status);
        return status;
    }

    // -----------------------------------------------------------------------
    // 4) [핵심] PID 재사용 검증
    // -----------------------------------------------------------------------
    actualCreateTime = (ULONG64)PsGetProcessCreateTimeQuadPart(targetProcess);

    if (ExpectedCreateTime != 0 && actualCreateTime != ExpectedCreateTime) {
        ARW_LOG("Refused: PID %lu create-time mismatch "
            "(expected %llu, actual %llu). PID was reused.\n",
            TargetProcessId, ExpectedCreateTime, actualCreateTime);
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    if (ExpectedCreateTime == 0) {
        // 운영 경로에서 이 로그가 보이면 엔진 구현이 잘못된 것이다.
        ARW_LOG("WARNING: PID %lu terminated without create-time validation.\n",
            TargetProcessId);
    }

    // -----------------------------------------------------------------------
    // 5) 이미 종료 중인지 확인
    // -----------------------------------------------------------------------
    if (PsGetProcessExitStatus(targetProcess) != STATUS_PENDING) {
        ARW_LOG("PID %lu is already terminating. Treating as success.\n",
            TargetProcessId);
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    // -----------------------------------------------------------------------
    // 6) 임계 시스템 프로세스 최종 방어선
    // -----------------------------------------------------------------------
    if (ArwIsProtectedSystemProcess(targetProcess)) {
        ARW_LOG("Refused: PID %lu is a protected system process.\n",
            TargetProcessId);
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    // -----------------------------------------------------------------------
    // 7) 커널 핸들 획득 후 종료
    //
    // OBJ_KERNEL_HANDLE: 유저 모드 핸들 테이블에 노출되지 않아
    // 대상 프로세스가 핸들을 훔치거나 닫을 수 없다.
    // AccessMode 를 KernelMode 로 주어 보안 검사를 우회한다
    // (이미 위에서 우리 정책으로 충분히 검증했다).
    // -----------------------------------------------------------------------
    status = ObOpenObjectByPointer(
        targetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE,
        *PsProcessType,
        KernelMode,
        &processHandle);

    if (!NT_SUCCESS(status)) {
        ARW_LOG("ObOpenObjectByPointer failed for PID %lu (0x%08X)\n",
            TargetProcessId, status);
        goto Cleanup;
    }

    status = ZwTerminateProcess(processHandle, STATUS_VIRUS_INFECTED);

    if (status == STATUS_PROCESS_IS_TERMINATING) {
        // 경쟁적으로 이미 종료가 시작된 것이므로 실패가 아니다.
        status = STATUS_SUCCESS;
    }

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_ArwStatProcessesTerminated);
        ARW_LOG("Terminated PID %lu (reason=%lu).\n", TargetProcessId, Reason);
    }
    else {
        ARW_LOG("ZwTerminateProcess failed for PID %lu (0x%08X)\n",
            TargetProcessId, status);
    }

Cleanup:
    if (processHandle != NULL) {
        ZwClose(processHandle);          // 핸들 누수 방지
    }
    if (targetProcess != NULL) {
        ObDereferenceObject(targetProcess);  // 참조 누수 방지
    }
    return status;
}