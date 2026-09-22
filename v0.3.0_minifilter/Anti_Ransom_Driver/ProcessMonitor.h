// ===========================================================================
// File: ProcessMonitor.h
// Developer: CHOI HWAN
// ===========================================================================
#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// 초기화 / 해제
//
// [빌드 요구사항] PsSetCreateProcessNotifyRoutineEx 는 드라이버 이미지에
// IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 플래그가 없으면
// STATUS_ACCESS_DENIED(0xC0000022) 를 반환한다.
//   프로젝트 속성 → 링커 → 명령줄 → 추가 옵션: /INTEGRITYCHECK
// 이 옵션은 '카탈로그 서명'이 아니라 '임베디드 서명'을 요구하므로
//   signtool sign /a /fd sha256 RansomGuard.sys
// 처럼 .sys 파일에 직접 서명해야 한다. 테스트 서명 환경에서도 동일하다.
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwInitializeProcessMonitor(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwUninitializeProcessMonitor(VOID);

// 콜백 배수(rundown)가 끝난 뒤에 호출한다.
// Uninitialize 가 리턴한 시점에도 다른 CPU에서 콜백 본문이 실행 중일 수 있어
// lookaside 삭제를 분리했다. 순서를 지키지 않으면 해제된 풀에 접근한다.
_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwFinalizeProcessMonitor(VOID);

// ---------------------------------------------------------------------------
// 커널이 호출하는 프로세스 생성/종료 콜백
// ---------------------------------------------------------------------------
VOID ArwProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);