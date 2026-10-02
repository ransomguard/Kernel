#pragma once
// ===========================================================================
// File: Shared/CriticalProcess.h
// Developer: CHOI HWAN
// ---------------------------------------------------------------------------
// 종료 금지(임계) 프로세스 판정 — 양쪽 드라이버 공유, static 헤더(구현 포함).
//
// [출처] v0.2.0 Anti_Ransom_Driver/ResponseEngine.c 에서 검증 완료된
//   g_CriticalImageSuffixes + 경로 비교 + fail-closed 로직을 그대로 이관한 것.
//   Anti_Ransom_Driver(ResponseEngine.c)와 Anti_Ransom_FsFilter(FsFilter.c)가
//   각각 종료 직전 이 헤더로 보호 대상 여부를 확인한다.
//
// [include 순서] 이 헤더는 시스템 헤더를 스스로 포함하지 않는다(Common.h 규약과 동일).
//   반드시 ntifs.h/ntddk.h 계열이 이미 포함된 뒤에 include 할 것.
//     - 드라이버: Common.h -> Driver.h 이후
//     - 미니필터: <fltKernel.h> 이후
//
// [이름 규약] 모든 심볼은 ArwCp / g_ArwCp 접두사를 쓴다.
//   ResponseEngine.c 와 ProcessMonitor.c 에 각각 static 으로 존재하는 기존
//   ArwpContainsW 와 절대 충돌하지 않도록 하기 위함(PROJECT_STATE §2 경고 대응).
// ===========================================================================

// 로깅: 드라이버에 ARW_LOG 가 있으면 재사용, 없으면(미니필터) KdPrint 폴백.
#ifndef ARW_CP_LOG
#  ifdef ARW_LOG
#    define ARW_CP_LOG ARW_LOG
#  else
#    define ARW_CP_LOG(...) KdPrint(("[RG-CP] " __VA_ARGS__))
#  endif
#endif

// 풀 태그: Common.h 에 의존하지 않도록 자체 정의(WinDbg 표시 "ARCp").
#ifndef ARW_CP_POOL_TAG
#  define ARW_CP_POOL_TAG 'pCRA'
#endif

// ---------------------------------------------------------------------------
// 임계 이미지 경로 접미사 목록.
// 이 중 하나라도 죽이면 CRITICAL_PROCESS_DIED 버그체크(BSOD)로 직결된다.
// 이름만이 아니라 전체 NT 경로로 비교하므로 C:\Temp\csrss.exe 위장은 걸러진다.
//   예: \Device\HarddiskVolume3\Windows\System32\csrss.exe
// ---------------------------------------------------------------------------
static const PCWSTR g_ArwCpCriticalSuffixes[] = {
    L"\\windows\\system32\\smss.exe",
    L"\\windows\\system32\\csrss.exe",
    L"\\windows\\system32\\wininit.exe",
    L"\\windows\\system32\\winlogon.exe",
    L"\\windows\\system32\\services.exe",
    L"\\windows\\system32\\lsass.exe",
    L"\\windows\\system32\\lsaiso.exe",
    L"\\windows\\system32\\svchost.exe",
    L"\\windows\\system32\\fontdrvhost.exe",
    // Windows Defender. 다른 보안 제품을 무력화하는 도구가 되지 않도록 보호.
    L"\\windows\\defender\\msmpeng.exe",
    L"\\programdata\\microsoft\\windows defender\\platform\\",
};

#define ARW_CP_CRITICAL_COUNT \
    (sizeof(g_ArwCpCriticalSuffixes) / sizeof(g_ArwCpCriticalSuffixes[0]))

// ---------------------------------------------------------------------------
// 소문자 정규화된 버퍼에서 부분 문자열 탐색.
//
// [의도적 보존] v0.2.0 의 검증된 동작을 그대로 유지한다 — 엄격한 '접미사'가
// 아니라 '부분 문자열' 매칭이다. 즉 과도하게 포함(over-inclusive)한다.
// 확실히 무해하다고 단정할 수 없는 프로세스는 보호 쪽에 남겨 BSOD를 피하는 것이
// 이 안전장치의 목적이므로, 종료 경로 재검증 없이 조이지 말 것.
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN ArwCpContainsW(
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
// 임계 프로세스 판정.
//
// [Fail-closed] 이미지 경로를 얻지 못하거나 메모리 할당이 실패하면 '보호 대상'
// (TRUE)으로 간주해 종료를 거부한다. 판정 불가 상태에서 종료를 강행하면 최악의
// 경우 BSOD다. 놓친 랜섬웨어 한 건보다 시스템 다운이 훨씬 큰 사고다.
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN ArwCpIsProtectedSystemProcess(_In_ PEPROCESS Process)
{
    NTSTATUS status;
    PUNICODE_STRING imageName = NULL;
    PWCH lower = NULL;
    ULONG chars, i;
    BOOLEAN critical = TRUE;   // 기본값 = 보호 (fail-closed)

    PAGED_CODE();

    status = SeLocateProcessImageName(Process, &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL || imageName->Buffer == NULL) {
        // [수정] v0.2.0 원본은 이 자리에 식별자 없는 ("...", status); 만 있어
        // 진단 로그가 유실됐다. 추출하며 ARW_CP_LOG 로 복원한다(동작 불변).
        ARW_CP_LOG("SeLocateProcessImageName failed (0x%08X) - treating as protected.\n",
            status);
        goto Cleanup;
    }

    chars = imageName->Length / sizeof(WCHAR);
    if (chars == 0) {
        goto Cleanup;
    }

    lower = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, imageName->Length, ARW_CP_POOL_TAG);
    if (lower == NULL) {
        goto Cleanup;   // 할당 실패 = 보호 유지(fail-closed)
    }

    RtlCopyMemory(lower, imageName->Buffer, imageName->Length);
    for (i = 0; i < chars; i++) {
        lower[i] = RtlDowncaseUnicodeChar(lower[i]);
    }

    critical = FALSE;
    for (i = 0; i < ARW_CP_CRITICAL_COUNT; i++) {
        if (ArwCpContainsW(lower, chars, g_ArwCpCriticalSuffixes[i])) {
            critical = TRUE;
            break;
        }
    }

Cleanup:
    if (lower != NULL) {
        ExFreePoolWithTag(lower, ARW_CP_POOL_TAG);
    }
    if (imageName != NULL) {
        ExFreePool(imageName);   // SeLocateProcessImageName 이 할당한 버퍼
    }
    return critical;
}
