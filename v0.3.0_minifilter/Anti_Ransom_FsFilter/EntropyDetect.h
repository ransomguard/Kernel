#pragma once
// ===========================================================================
// File: Anti_Ransom_FsFilter/EntropyDetect.h
// Developer: CHOI HWAN
// ---------------------------------------------------------------------------
// 판단 두뇌: 개별 쓰기의 엔트로피 계산 + PID별 고엔트로피 쓰기 누적 카운트.
// FsFilter.c 의 pre-write 콜백이 호출한다. FltMgr 타입을 쓰므로 fltKernel.h 의존.
// ===========================================================================
#include <fltKernel.h>

// ---------------------------------------------------------------------------
// [민감도 조절 상수 — 전부 여기 한 곳에] 발표 때 값만 바꿔 민감도를 시연한다.
// ---------------------------------------------------------------------------
#define ARW_ENTROPY_SAMPLE_BYTES     512u   // 각 쓰기에서 앞부분 최대 샘플 바이트
#define ARW_ENTROPY_MIN_WRITE_BYTES  512u   // 이보다 작은 쓰기는 무시(노이즈 컷)
#define ARW_ENTROPY_THRESHOLD_Q8     1920   // 7.50 bit/B (= 7.5 * 256). 이상이면 "암호문형"
#define ARW_BULK_TRIGGER_COUNT       50u    // 한 PID의 고엔트로피 쓰기가 이 수를 넘으면 종료
#define ARW_PID_TABLE_SLOTS          128u   // 동시에 추적하는 최대 PID 수

// ---------------------------------------------------------------------------
// 초기화 — DriverEntry 에서 FltStartFiltering 전에 1회.
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEntropyInit(VOID);

// ---------------------------------------------------------------------------
// 버퍼의 Shannon 엔트로피를 Q8 고정소수점(bit/byte * 256, 0..2048)으로 반환.
// 커널에서 부동소수점을 쓰지 않기 위해 정수 log2 LUT 로 계산한다.
// ---------------------------------------------------------------------------
_IRQL_requires_max_(APC_LEVEL)
ULONG ArwEntropyQ8(_In_reads_bytes_(Length) const UCHAR* Buffer, _In_ ULONG Length);

// ---------------------------------------------------------------------------
// 이 PID 의 쓰기 1건을 기록한다. EntropyQ8 이 임계 이상이고 WriteBytes 가
// 최소 크기 이상일 때만 카운트한다.
// 반환값: 이 PID 가 방금 대량 임계를 '처음' 넘겼으면 TRUE(그 PID 당 정확히 1회).
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN ArwEntropyTrackWrite(_In_ HANDLE Pid, _In_ ULONG EntropyQ8, _In_ ULONG WriteBytes);

// ---------------------------------------------------------------------------
// PID 추적 슬롯을 비운다(종료 처리 후, 또는 PID 재사용 대비).
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEntropyForgetPid(_In_ HANDLE Pid);
