// ===========================================================================
// File: Anti_Ransom_FsFilter/EntropyDetect.c
// Developer: CHOI HWAN
// ---------------------------------------------------------------------------
// Pure bounded entropy statistic. No PID state and no enforcement decision.
// ===========================================================================
#include "EntropyDetect.h"

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

