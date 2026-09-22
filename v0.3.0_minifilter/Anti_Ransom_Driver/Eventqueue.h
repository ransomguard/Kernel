// ===========================================================================
// File: EventQueue.h   (신규)
// Developer: CHOI HWAN
// ---------------------------------------------------------------------------
// 커널 -> 유저 이벤트 전달 계층.
//
// IOCTL은 본질적으로 '유저가 물어보면 커널이 답한다'는 단방향 구조라
// 커널이 먼저 이벤트를 밀어올릴 수 없다. 이를 해결하는 표준 기법이
// inverted call: 엔진이 IOCTL_RG_GET_EVENT 를 미리 걸어두면 커널이
// 그 요청을 manual 큐에 보관했다가 이벤트 발생 시 완료시킨다.
//
// 엔진이 느려 요청을 못 거는 동안의 이벤트는 링에 적재하고,
// 포화 시 가장 오래된 것부터 폐기한다(랜섬웨어 대응은 실시간성이 우선이므로
// 오래된 이벤트를 붙잡고 신규 이벤트를 버리면 안 된다).
// ===========================================================================
#pragma once
#include "Common.h"

// 이벤트 큐 초기화. Communication 모듈이 manual 큐를 만든 직후 호출한다.
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwEventQueueInitialize(_In_ WDFQUEUE PendingQueue);

// 자원 해제. 반드시 모든 콜백이 배수된 뒤에 호출할 것.
_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwEventQueueUninitialize(VOID);

// 이벤트 적재. 콜백 경로에서 호출되므로 DISPATCH_LEVEL 까지 허용한다.
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS ArwEventQueuePush(_In_ PARW_PROCESS_EVENT Event);

// 대기 중인 GET_EVENT 요청과 적재된 이벤트를 매칭시켜 완료 처리한다.
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEventQueueDrain(VOID);

// 엔진 등록 해제/크래시 시 남은 이벤트를 버린다.
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEventQueueFlush(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG ArwEventQueueGetDepth(VOID);

// 이벤트 헤더 공통 필드를 채워주는 헬퍼 (Magic/Version/Size/시각/시퀀스)
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEventInitializeHeader(
    _Out_ PARW_EVENT_HEADER Header,
    _In_  ULONG             EventType,
    _In_  ULONG             PayloadSize
);

// manual 큐에서 취소된 요청을 완료시키는 콜백
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE ArwEvtIoCanceledOnQueue;