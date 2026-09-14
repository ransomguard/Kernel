// ===========================================================================
// File: SelfProtect.h
// Developer: CHOI HWAN
// ===========================================================================
#pragma once
#include "Common.h"

// ---------------------------------------------------------------------------
// 초기화 / 해제
//
// [빌드 요구사항] ObRegisterCallbacks 도 /INTEGRITYCHECK 를 요구한다.
// 없으면 STATUS_ACCESS_DENIED(0xC0000022) 가 반환된다.
//
// [구현 순서 원칙] 이 모듈은 마지막에 '활성화'한다.
// 핸들 권한 박탈이 동작하기 시작하면 개발자 자신의 디버거 부착과
// 프로세스 종료까지 막혀 VM 스냅샷 복구 외에 빠져나올 방법이 없어진다.
// 활성화는 레지스트리 킬 스위치로만 가능하도록 Driver.c 에서 통제한다.
//   HKLM\System\CurrentControlSet\Services\RansomGuard\Parameters
//     EnableSelfProtect (REG_DWORD) = 1
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwInitializeSelfProtect(_In_ PDRIVER_OBJECT DriverObject);

_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwUninitializeSelfProtect(VOID);

// ---------------------------------------------------------------------------
// 보호 대상 지정 / 해제
//
// [PID 대신 PEPROCESS 를 쓰는 이유]
// PID는 프로세스 종료 후 재할당된다. 공격자가 엔진을 죽이고 PID 재사용을
// 유발하면 드라이버가 '악성 프로세스를 보호'하게 된다. 커널 객체 포인터를
// 참조 카운트와 함께 붙잡아 두고 포인터를 직접 비교한다.
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwSelfProtectSetTarget(_In_ HANDLE ProcessId);

_IRQL_requires_max_(APC_LEVEL)
VOID ArwSelfProtectClearTarget(VOID);

// ---------------------------------------------------------------------------
// 핸들 생성/복제 사전 검사 콜백
// ---------------------------------------------------------------------------
OB_PREOP_CALLBACK_STATUS ArwObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);