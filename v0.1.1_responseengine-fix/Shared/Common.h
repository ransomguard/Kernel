#pragma once
// ---------------------------------------------------------------
// Toolchain
//   ntifs.h -> ntddk.h -> wdf.h 순서를 여기서 일괄 보장 (Driver.h:6 규약)
//   모든 하위 헤더(Driver.h / Communication.h / Eventqueue.h /
//   ProcessMonitor.h / ResponseEngine.h / SelfProtect.h)가 이 블록에 의존한다.
//   순서를 바꾸거나 항목을 빼면 전 파일에서 WDF 타입이 증발한다.
// ---------------------------------------------------------------
#ifdef _KERNEL_MODE
#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// ---------------------------------------------------------------
// Limits
//   CMDLINE 512 WCHAR 근거: ImagePath 520B + CommandLine 1024B + 스칼라 64B
//   = 1608B. ProcessMonitor.c:231 "약 1.6KB" 와 일치.
//   1024 WCHAR였다면 2632B(2.6KB)가 되어 주석과 어긋남.
// ---------------------------------------------------------------
#define ARW_MAX_PATH_LENGTH        260U    // WCHAR 개수
#define ARW_MAX_CMDLINE_LENGTH     512U    // WCHAR 개수
#define ARW_EVENT_QUEUE_MAX_DEPTH  1024U   // U 접미사: EventQueue.c:193 C4018 해소

#define ARW_POOL_TAG               'pWRA'  // WinDbg 표시: "ARWp"

// ---------------------------------------------------------------
// Device naming
//   DECLARE_CONST_UNICODE_STRING 인자 — 반드시 와이드 리터럴이어야 한다.
//   user-mode: CreateFileW(L"\\\\.\\RansomGuard", ...)
// ---------------------------------------------------------------
#define ARW_NTDEVICE_NAME_STRING   L"\\Device\\RansomGuard"
#define ARW_SYMBOLIC_NAME_STRING   L"\\DosDevices\\RansomGuard"

// ---------------------------------------------------------------
// Protocol
//   ArwpValidateHeader() 에서 '!=' 로 ULONG 과 비교된다.
//   U 접미사 없으면 C4389 (signed/unsigned 불일치) 재발.
// ---------------------------------------------------------------
#define ARW_HEADER_MAGIC     0x41525747U   // 'ARWG'
#define ARW_DRIVER_VERSION   0x00010000U   // major.minor, %08X 로 로깅됨

// ---------------------------------------------------------------
// Event types`
// ---------------------------------------------------------------
#define EVENT_TYPE_PROCESS_CREATE     1U
#define EVENT_TYPE_PROCESS_TERMINATE  2U
#define EVENT_TYPE_PROCESS_BLOCKED    3U

// ---------------------------------------------------------------
// Fast-path mode
//   Driver.c:136 의 '<= ARW_FASTPATH_MODE_BLOCK' 범위 검사로 보아
//   BLOCK 이 최대값. 중간 단계(AUDIT)는 추정.
// ---------------------------------------------------------------
#define ARW_FASTPATH_MODE_OFF      0U
#define ARW_FASTPATH_MODE_AUDIT    1U   // [추정] 원본 명칭 미상
#define ARW_FASTPATH_MODE_BLOCK    2U

// ---------------------------------------------------------------
// ARW_PROCESS_EVENT.Flags
// ---------------------------------------------------------------
#define ARW_PROC_FLAG_PARENT_SPOOF_SUSP  (1U << 0)
#define ARW_PROC_FLAG_PATH_UNAVAILABLE   (1U << 1)
#define ARW_PROC_FLAG_PATH_TRUNCATED     (1U << 2)
#define ARW_PROC_FLAG_CMDLINE_TRUNCATED  (1U << 3)
#define ARW_PROC_FLAG_FASTPATH_HIT       (1U << 4)
#define ARW_PROC_FLAG_BLOCKED            (1U << 5)  

#pragma pack(push, 8)

// ---------------------------------------------------------------
// IOCTL_RG_REGISTER_ENGINE payload
//   PID 는 담지 않는다. ArwpHandleRegisterEngine 이
//   PsGetCurrentProcessId() 로 직접 확인하므로 유저가 신고하는 PID 는
//   신뢰 대상이 아니다.
// ---------------------------------------------------------------
typedef struct _ARW_REGISTER_REQUEST {
    ULONG Magic;      // == ARW_HEADER_MAGIC
    ULONG Version;    // == ARW_DRIVER_VERSION
} ARW_REGISTER_REQUEST, * PARW_REGISTER_REQUEST;
C_ASSERT(sizeof(ARW_REGISTER_REQUEST) == 8);

// ---------------------------------------------------------------
// Event header
//   ArwEventInitializeHeader(&ev->Header, EVENT_TYPE_x, sizeof(...))
//   3인자 시그니처로부터 Type/Size 는 인자, Version/Timestamp 는 내부 설정.
// ---------------------------------------------------------------
typedef struct _ARW_EVENT_HEADER {
    ULONG    Magic;
    ULONG    Version;
    ULONG    EventType;
    ULONG    PayloadSize;
    ULONG64  TimeStamp;       // KeQuerySystemTimePrecise, 100ns
    ULONG64  SequenceNumber;  // InterlockedIncrement64
} ARW_EVENT_HEADER, * PARW_EVENT_HEADER;

// ---------------------------------------------------------------
// Process event
//   PID 는 HANDLE 이 아닌 ULONG.
//   x64 커널 <-> x86 VssComHook 간 레이아웃 일치를 위한 의도적 선택.
//   콜백에서 받은 HANDLE 은 HandleToULong() 경유.
// ---------------------------------------------------------------
typedef struct _ARW_PROCESS_EVENT {
    ARW_EVENT_HEADER Header;                            //    0

    ULONG    ProcessId;                                 //   24
    ULONG    ParentProcessId;                           //   28
    ULONG    CreatorProcessId;                          //   32
    ULONG    Flags;                                     //   36  ARW_PROC_FLAG_*

    LONGLONG ProcessCreateTime;                         //   40  PID 재사용 방어
    ULONG    MatchedRuleId;                             //   48
    ULONG    ImagePathLength;                           //   52  바이트, NUL 제외
    ULONG    CommandLineLength;                         //   56  바이트, NUL 제외
    ULONG    Reserved;                                  //   60  8바이트 정렬 유지

    WCHAR    ImagePath[ARW_MAX_PATH_LENGTH];            //   64  520B
    WCHAR    CommandLine[ARW_MAX_CMDLINE_LENGTH];       //  584 1024B
} ARW_PROCESS_EVENT, * PARW_PROCESS_EVENT;               // total 1608B

C_ASSERT(sizeof(ARW_PROCESS_EVENT) == 1616);            // "약 1.6KB" 검증선
C_ASSERT(FIELD_OFFSET(ARW_PROCESS_EVENT, ProcessCreateTime) % 8 == 0);

// ---------------------------------------------------------------
// Kill request
//   ResponseEngine.h:18 — ExpectedCreateTime 에 위 ProcessCreateTime 을 그대로 전달.
//   ZwTerminateProcess 직전 재확인하여 PID 재사용 오살(誤殺) 차단.
// ---------------------------------------------------------------
typedef struct _ARW_TERMINATE_REQUEST {
    ULONG    Magic;
    ULONG    Version;
    ULONG    TargetProcessId;
    ULONG    Reason;
    LONGLONG ExpectedCreateTime;   // ResponseEngine.h:18 근거
} ARW_TERMINATE_REQUEST, * PARW_TERMINATE_REQUEST;

typedef struct _ARW_TERMINATE_RESPONSE {
    ULONG    Magic;
    ULONG    Version;
    ULONG    TargetProcessId;
    NTSTATUS ResultStatus;
} ARW_TERMINATE_RESPONSE, * PARW_TERMINATE_RESPONSE;

// ---------------------------------------------------------------
// IOCTL_RG_GET_STATUS 출력
// ---------------------------------------------------------------
typedef struct _ARW_STATUS_RESPONSE {
    ULONG   Magic;
    ULONG   Version;
    ULONG   EngineProcessId;
    ULONG   FastPathMode;          // ARW_FASTPATH_MODE_*
    ULONG   SelfProtectEnabled;
    ULONG   QueueDepth;
    ULONG64 EventsGenerated;
    ULONG64 EventsDropped;
    ULONG64 ProcessesBlocked;
    ULONG64 ProcessesTerminated;
} ARW_STATUS_RESPONSE, * PARW_STATUS_RESPONSE;

// ---------------------------------------------------------------
// IOCTL_RG_UPDATE_POLICY 입력
//   FastPathMode 는 ARW_FASTPATH_MODE_BLOCK 이하로 범위 검증된다.
//   Enable* 는 BOOLEAN 이 아닌 ULONG — '!= 0' 으로 비교되고,
//   유저/커널 간 레이아웃을 4바이트로 고정하기 위함.
// ---------------------------------------------------------------
typedef struct _ARW_POLICY_REQUEST {
    ULONG Magic;
    ULONG Version;
    ULONG FastPathMode;           // ARW_FASTPATH_MODE_*
    ULONG EnableProcessMonitor;
    ULONG EnableSelfProtect;
} ARW_POLICY_REQUEST, * PARW_POLICY_REQUEST;

#pragma pack(pop)

// ---------------------------------------------------------------
// IOCTL
//   이름은 Communication.c 의 switch 문에서 확인됨.
//   기능 코드(0x800~ARW_POLICY_REQUEST)는 미확인 — 원본 값이 다르면 유저모드와
//   어긋나 ERROR_INVALID_FUNCTION 이 난다. 엔진 측과 대조 필요.
// ---------------------------------------------------------------
#define RG_DEVICE_TYPE  0x8123

#define IOCTL_RG_REGISTER_ENGINE \
    CTL_CODE(RG_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_RG_UNREGISTER_ENGINE \
    CTL_CODE(RG_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_RG_TERMINATE_PROCESS \
    CTL_CODE(RG_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_RG_UPDATE_POLICY \
    CTL_CODE(RG_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_RG_GET_STATUS \
    CTL_CODE(RG_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA)

// 역방향. 요청이 manual 큐에 적체되었다가 이벤트 발생 시 완료된다.
#define IOCTL_RG_GET_EVENT \
    CTL_CODE(RG_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA)

// user-mode(VssComHook) -> kernel. VssComHook.cpp:35 TODO 근거.
#define IOCTL_RG_REPORT_VSS_ATTEMPT \
    CTL_CODE(RG_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)