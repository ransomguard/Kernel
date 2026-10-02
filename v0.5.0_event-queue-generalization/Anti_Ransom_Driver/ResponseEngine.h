// ===========================================================================
// File: ResponseEngine.h
// Developer: CHOI HWAN
// ===========================================================================
#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// 악성 프로세스 종료
//
// [시그니처 변경 이유 — PID 재사용 레이스]
// 흐름이 '커널 탐지 → Python 상관분석 → IOCTL → 종료'이므로 탐지와 종료
// 사이에 수백 ms ~ 수 초가 흐른다. 그동안 대상이 자진 종료하면 OS는 동일
// PID를 재할당하고, 드라이버는 무고한 프로세스를 죽인다. 랜섬웨어가 이를
// 의도적으로 유발해 백신 프로세스를 대신 죽이게 만드는 것도 가능하다.
//
// 따라서 PID 단독이 아니라 (PID + 프로세스 생성 시각) 쌍으로 식별한다.
// ExpectedCreateTime 에는 ARW_PROCESS_EVENT.ProcessCreateTime 을 그대로 넣는다.
// 0을 넘기면 검증을 생략하지만, 운영 경로에서는 사용하지 말 것.
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ArwTerminateRansomwareProcess(
    _In_ ULONG   TargetProcessId,
    _In_ ULONG64 ExpectedCreateTime,
    _In_ ULONG   Reason
);

// 시스템 임계 프로세스 여부 판정 (단위 테스트/진단용으로 노출)
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN ArwIsProtectedSystemProcess(_In_ PEPROCESS Process);