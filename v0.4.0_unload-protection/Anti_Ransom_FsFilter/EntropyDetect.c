// ===========================================================================
// File: Anti_Ransom_FsFilter/EntropyDetect.c
// Developer: CHOI HWAN
// ---------------------------------------------------------------------------
// 엔트로피 계산(부동소수점 없이) + PID별 고엔트로피 쓰기 카운트.
// ===========================================================================
#include "EntropyDetect.h"

#define ARW_FS_POOL_TAG 'dERA'   // WinDbg "AREd"

// ---------------------------------------------------------------------------
// 정수 log2 (Q8): log2(x) * 256 을 정수로 반환. x >= 1 가정.
//
// 정수부 = 최상위 비트 위치(floor(log2)). 소수부는 x 를 [1,2) 로 정규화한 뒤
// 16구간 LUT + 선형보간. 커널에서 FP 상태 오염 없이 Shannon 엔트로피를 얻는다.
// ---------------------------------------------------------------------------
static ULONG ArwpLog2Q8(_In_ ULONG x)
{
    // log2(1 + i/16) * 256, i=0..16
    static const USHORT lut[17] = {
        0, 22, 43, 63, 82, 100, 118, 134, 150, 165, 179, 193, 207, 219, 232, 244, 256
    };
    ULONG msb = 0;
    ULONG t;
    ULONG rem, frac, idx, lo, hi, interp;

    if (x == 0) {
        return 0;
    }

    t = x;
    while (t > 1u) {
        t >>= 1;
        msb++;
    }
    if (msb == 0) {
        return 0;   // log2(1) = 0
    }

    // 소수부: frac = (x - 2^msb) / 2^msb  를 Q8 [0,1) 로
    rem = x - (1u << msb);
    frac = (rem << 8) >> msb;         // 0..255
    idx = frac >> 4;                  // 0..15
    lo = lut[idx];
    hi = lut[idx + 1];
    interp = lo + (((hi - lo) * (frac & 0x0Fu)) >> 4);

    return (msb << 8) + interp;
}

// ---------------------------------------------------------------------------
// Shannon 엔트로피 (Q8):
//   H = log2(N) - (1/N) * Σ c_i * log2(c_i)
// 모든 항을 Q8 정수로 계산. c_i = 바이트값 i 의 빈도, N = 샘플 바이트 수.
// 반환 범위 0(단일 바이트) .. 2048(균일분포 = 8.0 bit/B).
// ---------------------------------------------------------------------------
_IRQL_requires_max_(APC_LEVEL)
ULONG ArwEntropyQ8(_In_reads_bytes_(Length) const UCHAR* Buffer, _In_ ULONG Length)
{
    ULONG hist[256];
    ULONG n = Length;
    ULONG i, sumTermsQ8 = 0;

    if (Buffer == NULL || n == 0) {
        return 0;
    }
    if (n > ARW_ENTROPY_SAMPLE_BYTES) {
        n = ARW_ENTROPY_SAMPLE_BYTES;
    }

    RtlZeroMemory(hist, sizeof(hist));
    for (i = 0; i < n; i++) {
        hist[Buffer[i]]++;
    }

    // Σ c_i * log2(c_i)  (Q8)
    for (i = 0; i < 256u; i++) {
        if (hist[i] > 1u) {
            sumTermsQ8 += hist[i] * ArwpLog2Q8(hist[i]);
        }
    }

    // H_q8 = log2(N)*256 - (Σ c_i*log2(c_i)*256) / N
    {
        ULONG logNq8 = ArwpLog2Q8(n);
        ULONG meanQ8 = sumTermsQ8 / n;
        if (meanQ8 >= logNq8) {
            return 0;
        }
        return logNq8 - meanQ8;
    }
}

// ===========================================================================
// PID 추적 테이블 — 고정 슬롯 + 스핀락. 데모 규모라 단순 선형 탐색으로 충분.
// ===========================================================================
typedef struct _ARW_PID_SLOT {
    HANDLE  Pid;         // 0 = 빈 슬롯
    ULONG   HighEntropyHits;
    BOOLEAN Triggered;   // 종료 요청을 이미 1회 보냈는지
} ARW_PID_SLOT;

static ARW_PID_SLOT g_PidTable[ARW_PID_TABLE_SLOTS];
static KSPIN_LOCK   g_PidLock;
static ULONG        g_VictimCursor = 0;   // 테이블 포화 시 축출 커서

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEntropyInit(VOID)
{
    RtlZeroMemory(g_PidTable, sizeof(g_PidTable));
    KeInitializeSpinLock(&g_PidLock);
    g_VictimCursor = 0;
}

// 락을 잡은 상태에서 호출: PID 슬롯을 찾거나(없으면) 만든다. 실패 시 NULL.
static ARW_PID_SLOT* ArwpFindOrInsertLocked(_In_ HANDLE Pid)
{
    ULONG i;
    ARW_PID_SLOT* freeSlot = NULL;

    for (i = 0; i < ARW_PID_TABLE_SLOTS; i++) {
        if (g_PidTable[i].Pid == Pid) {
            return &g_PidTable[i];
        }
        if (freeSlot == NULL && g_PidTable[i].Pid == NULL) {
            freeSlot = &g_PidTable[i];
        }
    }

    if (freeSlot != NULL) {
        freeSlot->Pid = Pid;
        freeSlot->HighEntropyHits = 0;
        freeSlot->Triggered = FALSE;
        return freeSlot;
    }

    // 포화: 라운드로빈으로 한 슬롯을 축출한다(데모: 추적 실패는 허용, BSOD 아님).
    {
        ARW_PID_SLOT* victim = &g_PidTable[g_VictimCursor];
        g_VictimCursor = (g_VictimCursor + 1) % ARW_PID_TABLE_SLOTS;
        victim->Pid = Pid;
        victim->HighEntropyHits = 0;
        victim->Triggered = FALSE;
        return victim;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN ArwEntropyTrackWrite(_In_ HANDLE Pid, _In_ ULONG EntropyQ8, _In_ ULONG WriteBytes)
{
    KIRQL oldIrql;
    BOOLEAN trigger = FALSE;
    ARW_PID_SLOT* slot;

    if (Pid == NULL) {
        return FALSE;
    }
    // 임계 미만이거나 너무 작은 쓰기는 카운트하지 않는다.
    if (EntropyQ8 < (ULONG)ARW_ENTROPY_THRESHOLD_Q8 || WriteBytes < ARW_ENTROPY_MIN_WRITE_BYTES) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_PidLock, &oldIrql);

    slot = ArwpFindOrInsertLocked(Pid);
    if (slot != NULL && !slot->Triggered) {
        slot->HighEntropyHits++;
        if (slot->HighEntropyHits > ARW_BULK_TRIGGER_COUNT) {
            slot->Triggered = TRUE;   // 이후 중복 종료 요청 방지
            trigger = TRUE;
        }
    }

    KeReleaseSpinLock(&g_PidLock, oldIrql);
    return trigger;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEntropyForgetPid(_In_ HANDLE Pid)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_PidLock, &oldIrql);
    for (i = 0; i < ARW_PID_TABLE_SLOTS; i++) {
        if (g_PidTable[i].Pid == Pid) {
            g_PidTable[i].Pid = NULL;
            g_PidTable[i].HighEntropyHits = 0;
            g_PidTable[i].Triggered = FALSE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PidLock, oldIrql);
}
