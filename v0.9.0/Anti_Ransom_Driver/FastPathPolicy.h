#ifndef RG_FAST_PATH_POLICY_H
#define RG_FAST_PATH_POLICY_H

/*
 * Small, allocation-free and platform-independent process-command classifier.
 * Windows kernel WCHAR is 16-bit. This header deliberately avoids ntddk.h so
 * that exactly the same matcher can be exercised by a native C unit test.
 *
 * This is an image-bound command-line signal, NOT a complete VSS/COM guard.
 */
typedef unsigned short RG_FP_CHAR;

typedef struct _RG_FP_RESULT {
    unsigned int RuleId;
    unsigned int AllowBlock; /* 0 = telemetry/audit only, 1 = eligible for BLOCK mode */
} RG_FP_RESULT;

RG_FP_RESULT RgFastPathEvaluate(
    const RG_FP_CHAR* imagePath, unsigned int imageChars,
    const RG_FP_CHAR* commandLine, unsigned int commandChars);

#endif
