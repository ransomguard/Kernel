// ===========================================================================
// File: Communication.h
// Developer: CHOI HWAN
// ===========================================================================
#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// 제어 디바이스 / 큐 초기화 및 해제
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwInitializeCommunication(_In_ WDFDRIVER Driver);

_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwUninitializeCommunication(VOID);

// ---------------------------------------------------------------------------
// 등록된 유저 모드 엔진 정보 조회
//
// ResponseEngine 이 '엔진 자신을 종료하라'는 명령을 거부할 때 사용한다.
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG ArwGetEngineProcessId(VOID);

// ---------------------------------------------------------------------------
// IOCTL 처리 콜백
// ---------------------------------------------------------------------------
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ArwEvtIoDeviceControl;

// 엔진 프로세스가 핸들을 닫거나 비정상 종료할 때 호출된다.
// 등록 상태를 자동으로 해제하지 않으면, 죽은 PID가 보호 대상으로 남아
// PID 재사용 시 엉뚱한 프로세스를 보호하게 된다.
EVT_WDF_FILE_CLEANUP ArwEvtFileCleanup;