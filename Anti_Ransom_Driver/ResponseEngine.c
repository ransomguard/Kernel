// ===========================================================================
// File: ResponseEngine.c
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "ResponseEngine.h"
#include "Communication.h"

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
// 기존 코드는 PID 0/4 만 막았다. 그러나 csrss/wininit/services/smss/lsass 는
// critical 로 표시되어 있어 종료 시 즉시 CRITICAL_PROCESS_DIED 버그체크가 난다.
// 랜섬웨어가 lsass 에 인젝션한 상태에서 Python 엔진이 해당 PID를 지목하면
// 백신이 스스로 시스템을 내려버리는 셈이다.
//
// [원칙] 커널은 유저 모드의 판단을 신뢰하지 않는다.
// 엔진이 무엇을 지시하든 이 목록에 걸리면 커널이 최종적으로 거부한다.
//
// [경로까지 검사하는 이유]
// 이름만 비교하면 C:\Temp\csrss.exe 로 자신을 위장한 랜섬웨어가 보호받는다.
// SeLocateProcessImageName 이 돌려주는 전체 NT 경로의 접미사를 비교한다.
//   예: \Device\HarddiskVolume3\Windows\System32\csrss.exe
// ===========================================================================
static const PCWSTR g_CriticalImageSuffixes[] = {
    L"\\windows\\system32\\smss.exe",
    L"\\windows\\system32\\csrss.exe",
    L"\\windows\\system32\\wininit.exe",
    L"\\windows\\system32\\winlogon.exe",
    L"\\windows\\system32\\services.exe",
    L"\\windows\\system32\\lsass.exe",
    L"\\windows\\system32\\lsaiso.exe",
    L"\\windows\\system32\\svchost.exe",
    L"\\windows\\system32\\wininit.exe",
    L"\\windows\\system32\\fontdrvhost.exe",
    // Windows Defender. 이것까지 죽일 수 있게 두면 우리 드라이버가
    // 다른 보안 제품을 무력화하는 도구가 된다.
    L"\\windows\\defender\\msmpeng.exe",
    L"\\programdata\\microsoft\\windows defender\\platform\\",
};

#define ARW_CRITICAL_IMAGE_COUNT \
    (sizeof(g_CriticalImageSuffixes) / sizeof(g_CriticalImageSuffixes[0]))

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
// 임계 프로세스 판정
//
// [Fail-closed 설계] 이미지 경로를 얻지 못하면 '보호 대상'으로 간주해
// 종료를 거부한다. 판정 불가 상태에서 종료를 강행하면 최악의 경우 BSOD다.
// 놓친 랜섬웨어 한 건보다 시스템 다운이 훨씬 큰 사고다.
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN ArwIsProtectedSystemProcess(_In_ PEPROCESS Process)
{
    NTSTATUS status;
    PUNICODE_STRING imageName = NULL;
    PWCH lower = NULL;
    ULONG chars;
    BOOLEAN critical = TRUE;   // 기본값 = 보호 (fail-closed)
    ULONG i;

    PAGED_CODE();

    status = SeLocateProcessImageName(Process, &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL || imageName->Buffer == NULL) {
        
        
        ("SeLocateProcessImageName failed (0x%08X) - treating as protected.\n",
            status);
        goto Cleanup;
    }

    chars = imageName->Length / sizeof(WCHAR);
    if (chars == 0) {
        goto Cleanup;
    }

    lower = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, imageName->Length, ARW_POOL_TAG);
    if (lower == NULL) {
        goto Cleanup;
    }

    RtlCopyMemory(lower, imageName->Buffer, imageName->Length);
    for (i = 0; i < chars; i++) {
        lower[i] = RtlDowncaseUnicodeChar(lower[i]);
    }

    critical = FALSE;
    for (i = 0; i < ARW_CRITICAL_IMAGE_COUNT; i++) {
        if (ArwpContainsW(lower, chars, g_CriticalImageSuffixes[i])) {
            critical = TRUE;
            break;
        }
    }

Cleanup:
    if (lower != NULL) {
        ExFreePoolWithTag(lower, ARW_POOL_TAG);
    }
    if (imageName != NULL) {
        ExFreePool(imageName);
    }
    return critical;
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