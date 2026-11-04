// ===========================================================================
// File: Driver.h
// Developer: CHOI HWAN
// ===========================================================================
#pragma once
#include "Common.h"   // ntifs.h -> ntddk.h -> wdf.h 순서를 여기서 일괄 보장

// ---------------------------------------------------------------------------
// 드라이버 진입점 / 해제 콜백
// ---------------------------------------------------------------------------
DRIVER_INITIALIZE     DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

// ---------------------------------------------------------------------------
// 전역 상태
// ---------------------------------------------------------------------------
// [핵심] 콜백 배수(drain) 보호.
//
// PsSetCreateProcessNotifyRoutineEx(..., TRUE) 가 리턴한 시점에도 다른 CPU에서
// 콜백 '본문'이 실행 중일 수 있다. 그 콜백이 참조하는 이벤트 큐를 먼저 해제하면
// 즉시 크래시한다. 모든 콜백은 진입 시 Acquire, 이탈 시 Release 하고
// 언로드 경로는 ExWaitForRundownProtectionRelease 로 완전히 비워질 때까지 기다린다.
extern EX_RUNDOWN_REF g_ArwRundownRef;

extern WDFDRIVER      g_ArwDriver;

// 정책 전역. InterlockedExchange / ReadNoFence 로만 접근할 것.
extern volatile LONG  g_ArwFastPathMode;        // ARW_FASTPATH_MODE_*
extern volatile LONG  g_ArwSelfProtectEnabled;
extern volatile LONG  g_ArwProcessMonitorEnabled;

// 통계 (발표용 정량 지표 패널에 그대로 쓰인다)
extern volatile LONG64 g_ArwStatEventsGenerated;
extern volatile LONG64 g_ArwStatEventsDelivered;   // GET_EVENT 전달 완료
extern volatile LONG64 g_ArwStatEventsFlushed;     // 엔진 해제·언로드 시 폐기
extern volatile LONG64 g_ArwStatEventsDropped;
extern volatile LONG64 g_ArwStatProcessesBlocked;
extern volatile LONG64 g_ArwStatProcessesTerminated;

// ---------------------------------------------------------------------------
// 레지스트리 기반 킬 스위치 조회 헬퍼
//
// HKLM\System\CurrentControlSet\Services\RansomGuard\Parameters 하위 DWORD를 읽는다.
// 자기 보호 모듈이 개발자 자신을 잠가버렸을 때 안전 모드에서 값을 0으로 바꾸고
// 재부팅하면 빠져나올 수 있는 유일한 탈출구이므로 반드시 유지할 것.
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ArwReadRegistryDword(
    _In_  PUNICODE_STRING RegistryPath,
    _In_  PCWSTR          ValueName,
    _Out_ PULONG          Value
);

// ---------------------------------------------------------------------------
// 로깅 매크로
//
// KdPrint 는 디버거가 붙어 있으면 '동기'로 출력되어 호출 경로 전체를 지연시킨다.
// 프로세스 생성 콜백과 핸들 생성 콜백은 시스템 전역 hot path 이므로
// 해당 경로에서는 ARW_TRACE_HOT 을 쓰고 기본적으로 비활성화한다.
// ---------------------------------------------------------------------------
#define ARW_LOG(...)  KdPrint(("[RansomGuard] " __VA_ARGS__))

#if defined(ARW_ENABLE_HOTPATH_TRACE)
#define ARW_TRACE_HOT(fmt, ...) KdPrint(("[RansomGuard][HOT] " fmt, __VA_ARGS__))
#else
#define ARW_TRACE_HOT(fmt, ...) ((void)0)
#endif