#pragma once
#include <fltKernel.h>

// Informational telemetry only: high entropy does not prove ransomware.
// No count is accumulated by PID; process exit/reuse cannot transfer a verdict.
#define ARW_ENTROPY_SAMPLE_BYTES       512U
#define ARW_ENTROPY_MIN_WRITE_BYTES    512U
#define ARW_ENTROPY_THRESHOLD_Q8       1920U

_IRQL_requires_max_(APC_LEVEL)
ULONG ArwEntropyQ8(
    _In_reads_bytes_(Length) const UCHAR* Buffer,
    _In_ ULONG Length);
