#include <windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>    // sprintf_s
#include <cstring>   // strcmp
#include <cerrno>
#include <string>

// C 스타일 심볼 호환을 위해 extern "C" 적용
extern "C" {
#include "../Shared/Common.h" // Single ABI definition; ignore the legacy local copy.
}

// Diagnostic build: print EVERY delivered event, including unmatched process
// events.  Using one narrow UTF-8 output stream avoids losing file-event lines
// when wprintf and std::cout are mixed on the same Windows console.
static const char* ArwEventTypeName(ULONG type)
{
    switch (type) {
    case EVENT_TYPE_PROCESS_CREATE:    return "PROCESS_CREATE";
    case EVENT_TYPE_PROCESS_TERMINATE: return "PROCESS_TERMINATE";
    case EVENT_TYPE_PROCESS_BLOCKED:   return "PROCESS_BLOCKED";
    case EVENT_TYPE_FILE_WRITE:        return "FILE_WRITE";
    case EVENT_TYPE_FILE_RENAME:       return "FILE_RENAME";
    default:                           return "UNKNOWN";
    }
}

static std::string ArwUtf16FieldToUtf8(
    const WCHAR* value, ULONG lengthBytes, size_t capacityBytes)
{
    if (lengthBytes == 0) {
        return "";
    }
    if (value == nullptr || lengthBytes > capacityBytes ||
        lengthBytes % sizeof(WCHAR) != 0) {
        return "<invalid-length>";
    }
    const int characters = static_cast<int>(lengthBytes / sizeof(WCHAR));
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value, characters, nullptr, 0,
        nullptr, nullptr);
    if (required <= 0) {
        return "<invalid-utf16>";
    }
    std::string result(static_cast<size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value, characters, result.data(),
        required, nullptr, nullptr);
    if (written != required) {
        return "<conversion-failed>";
    }
    return result;
}

// 상태 조회 헬퍼 — 성공 시 true
static bool QueryStatus(HANDLE h, ARW_STATUS_RESPONSE& out)
{
    DWORD ret = 0;
    ZeroMemory(&out, sizeof(out));
    return DeviceIoControl(h, IOCTL_RG_GET_STATUS,
        NULL, 0, &out, sizeof(out), &ret, NULL) ? true : false;
}

// 프로세스 종료 요청 (IOCTL_RG_TERMINATE_PROCESS) — 3.2.8 IPC 기반 PID 종료 검증용
//   커널은 IOCTL 자체를 STATUS_SUCCESS 로 완료하고, 실제 종료 성패는
//   ARW_TERMINATE_RESPONSE.ResultStatus(NTSTATUS)로 회신한다 (Communication.c ArwpHandleTerminate).
//   따라서 DeviceIoControl 성공 != 종료 성공. 두 단계를 나눠 출력한다.
//   반환값: 0 = 종료 확인, 1 = 대상 조회/IOCTL 실패, 2 = 커널 거부/응답 오류,
//           3 = 명령 수락 후에도 종료 확인 실패/시간 초과.
static int RequestTerminate(HANDLE h, ULONG targetPid)
{
    // Keep the target object alive while querying its identity and submitting the
    // command. A stale PID must never fall back to ExpectedCreateTime == 0.
    HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
        FALSE, targetPid);
    if (target == NULL) {
        std::cout << "Cannot identify target process. Error=" << GetLastError() << "\n";
        return 1;
    }
    FILETIME created = {}, exited = {}, kernel = {}, user = {};
    if (!GetProcessTimes(target, &created, &exited, &kernel, &user)) {
        std::cout << "GetProcessTimes failed. Error=" << GetLastError() << "\n";
        CloseHandle(target);
        return 1;
    }
    ULARGE_INTEGER creation = {};
    creation.LowPart = created.dwLowDateTime;
    creation.HighPart = created.dwHighDateTime;
    if (creation.QuadPart == 0) {
        CloseHandle(target);
        return 1;
    }

    ARW_TERMINATE_REQUEST req = {};
    req.Magic = ARW_HEADER_MAGIC;
    req.Version = ARW_DRIVER_VERSION;
    req.TargetProcessId = targetPid;
    req.Reason = 1; // Explicit test-client termination request.
    req.ExpectedCreateTime = static_cast<LONGLONG>(creation.QuadPart);
    ARW_TERMINATE_RESPONSE resp = {};
    DWORD returned = 0;

    std::cout << "\nTermination request: PID=" << targetPid
        << " create_time=" << req.ExpectedCreateTime << "\n";
    BOOL ok = DeviceIoControl(h, IOCTL_RG_TERMINATE_PROCESS,
        &req, sizeof(req), &resp, sizeof(resp), &returned, NULL);
    if (!ok) {
        std::cout << "IOCTL failed. Error=" << GetLastError() << "\n";
        CloseHandle(target);
        return 1;
    }
    if (returned != sizeof(resp) || resp.Magic != ARW_HEADER_MAGIC ||
        resp.Version != ARW_DRIVER_VERSION || resp.TargetProcessId != targetPid) {
        std::cout << "Invalid termination response; result is unknown.\n";
        CloseHandle(target);
        return 2;
    }
    char statusHex[16] = {};
    sprintf_s(statusHex, "0x%08lX", static_cast<unsigned long>(resp.ResultStatus));
    std::cout << "ResultStatus=" << statusHex << "\n";
    if (resp.ResultStatus < 0) {
        CloseHandle(target);
        return 2;
    }

    // A successful command is not an exit confirmation. This bounded wait is
    // appropriate for this test client; an engine should track exit asynchronously.
    DWORD waitResult = WaitForSingleObject(target, 5000);
    if (waitResult == WAIT_OBJECT_0) {
        std::cout << "Process exit confirmed.\n";
        CloseHandle(target);
        return 0;
    }
    if (waitResult == WAIT_TIMEOUT) {
        std::cout << "Termination accepted; exit is still unconfirmed after 5 seconds.\n";
    }
    else {
        std::cout << "Exit confirmation failed. Error=" << GetLastError() << "\n";
    }
    CloseHandle(target);
    return 3;
}

static void PrintUsage(const char* exe)
{
    std::cout << "사용법:\n"
        << "  " << exe << " [최대수신건수] [--policy audit|block] [--selfprotect keep|off]\n"
        << "        기존 흐름 (등록→정책→상태→이벤트수신)\n"
        << "  " << exe << " --terminate <PID>\n"
        << "        종료 모드 (등록→종료요청)\n"
        << "    --policy      생략 시 FastPathMode=AUDIT (첫 VM 검증 기본값)\n"
        << "    --selfprotect 생략 시 keep (현재 상태 유지). off 는 커널 자기보호를 런타임에 끔.\n"
        << "                  커널은 IOCTL 로 켜기를 지원하지 않으므로 on 은 없음 (레지스트리 EnableSelfProtect=1 + 재로드).\n";
}

int main(int argc, char** argv) {
    // The test program is built with /utf-8. Make the console match, so both
    // Korean status text and NTFS paths survive the diagnostic printout.
    SetConsoleOutputCP(CP_UTF8);

    // 0. 인자 파싱
    //   --terminate <PID>       : 종료 모드 (등록→종료요청만 수행)
    //   --policy audit|block    : 3단계 정책 전송의 FastPathMode 선택 (기본 AUDIT)
    //   <숫자>                  : 이벤트 최대 수신 건수 (기본 10) — 기존 동작 유지
    bool terminateMode = false;
    ULONG terminatePid = 0;
    ULONG fastPathMode = ARW_FASTPATH_MODE_AUDIT;   // 첫 VM 검증은 관측부터 시작
    const char* fastPathName = "AUDIT";
    // EnableSelfProtect: 커널(Communication.c ArwpHandleUpdatePolicy)은 0일 때만
    // 자기보호를 끄고, 0이 아니면 아무것도 하지 않는다(런타임 켜기 미지원).
    // 따라서 기본 1 = "현재 상태 유지". 레지스트리로 켠 SelfProtect 를 이 클라이언트가
    // 실수로 끄지 않도록 한다. --selfprotect off 일 때만 0을 보낸다.
    ULONG enableSelfProtect = 1;
    const char* selfProtectName = "KEEP";
    int maxFetch = 10;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--terminate") == 0) {
            if (i + 1 >= argc) {
                PrintUsage(argv[0]);
                return 1;
            }
            char* endp = NULL;
            errno = 0;
            unsigned long parsed = strtoul(argv[i + 1], &endp, 10);
            if (argv[i + 1][0] == '-' || errno == ERANGE || parsed == 0 ||
                endp == argv[i + 1] || *endp != '\0') {
                std::cout << "잘못된 PID: " << argv[i + 1] << "\n";
                PrintUsage(argv[0]);
                return 1;
            }
            terminateMode = true;
            terminatePid = (ULONG)parsed;
            i++;
        }
        else if (strcmp(argv[i], "--policy") == 0) {
            if (i + 1 >= argc) {
                PrintUsage(argv[0]);
                return 1;
            }
            if (_stricmp(argv[i + 1], "audit") == 0) {
                fastPathMode = ARW_FASTPATH_MODE_AUDIT;
                fastPathName = "AUDIT";
            }
            else if (_stricmp(argv[i + 1], "block") == 0) {
                fastPathMode = ARW_FASTPATH_MODE_BLOCK;
                fastPathName = "BLOCK";
            }
            else {
                std::cout << "잘못된 정책 모드: " << argv[i + 1] << " (audit | block)\n";
                PrintUsage(argv[0]);
                return 1;
            }
            i++;
        }
        else if (strcmp(argv[i], "--selfprotect") == 0) {
            if (i + 1 >= argc) {
                PrintUsage(argv[0]);
                return 1;
            }
            if (_stricmp(argv[i + 1], "keep") == 0) {
                enableSelfProtect = 1;      // 커널에서 no-op → 현재 상태 유지
                selfProtectName = "KEEP";
            }
            else if (_stricmp(argv[i + 1], "off") == 0) {
                enableSelfProtect = 0;      // 커널이 ObUnRegisterCallbacks 수행
                selfProtectName = "OFF";
            }
            else {
                std::cout << "잘못된 자기보호 옵션: " << argv[i + 1] << " (keep | off)\n";
                PrintUsage(argv[0]);
                return 1;
            }
            i++;
        }
        else {
            // 옵션이 아닌 첫 인자는 기존처럼 최대 수신 건수로 해석
            maxFetch = atoi(argv[i]);
        }
    }

    // 1. 커널 드라이버가 생성한 심볼릭 링크에 접근하여 통신 핸들 개방
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\RansomGuard",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "드라이버 연결 실패. 에러 코드: " << GetLastError() << "\n";
        system("pause");
        return 1;
    }
    std::cout << "드라이버 연결 성공!\n";


    // 2. 엔진 등록 (관문 통과) — Magic/Version 은 Common.h 상수 사용
    ARW_REGISTER_REQUEST reg = { 0 };
    reg.Magic = ARW_HEADER_MAGIC;
    reg.Version = ARW_DRIVER_VERSION;

    DWORD regReturned = 0;
    BOOL regOk = DeviceIoControl(
        hDevice,
        IOCTL_RG_REGISTER_ENGINE,
        &reg, sizeof(reg),
        NULL, 0,
        &regReturned,
        NULL
    );

    if (!regOk) {
        std::cout << "엔진 등록 실패. 에러 코드: " << GetLastError() << "\n";
        CloseHandle(hDevice);
        system("pause");
        return 1;
    }
    std::cout << "엔진 등록 성공!\n";

    // 2-1. 종료 모드 — 등록 직후 종료 요청만 보내고 끝낸다.
    //      커널은 등록된 엔진 PID(현재 프로세스)의 명령만 수락하므로
    //      반드시 2단계(등록) 다음에 위치해야 한다. 정책/상태/이벤트 흐름은 건너뛴다.
    if (terminateMode) {
        int rc = RequestTerminate(hDevice, terminatePid);
        CloseHandle(hDevice);   // 핸들 정리 → EvtFileCleanup 에서 엔진 등록 자동 해제
        system("pause");
        return rc;
    }

    // 3. 정책 업데이트 (IOCTL_RG_UPDATE_POLICY) 전송
    DWORD bytesReturned = 0;

    ARW_POLICY_REQUEST policy = { 0 };
    policy.Magic = ARW_HEADER_MAGIC;
    policy.Version = ARW_DRIVER_VERSION;
    policy.FastPathMode = fastPathMode;               // --policy 인자 (기본 AUDIT)
    policy.EnableProcessMonitor = 1;                  // 프로세스 감시 ON
    policy.EnableSelfProtect = enableSelfProtect;     // --selfprotect 인자 (기본 1 = 유지, 0 = 끄기)

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_RG_UPDATE_POLICY,
        &policy,             // 20바이트 구조체
        sizeof(policy),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (result) {
        std::cout << "정책 업데이트 명령 전송 성공! "
            << "(FastPath=" << fastPathName << ", ProcMon=ON, SelfProtect="
            << selfProtectName << ")\n";
    }
    else {
        std::cout << "정책 업데이트 실패. 에러 코드: " << GetLastError() << "\n";
    }


    // 4. 상태 조회 (IOCTL_RG_GET_STATUS) — 입력 불필요, 출력만 받음
    ARW_STATUS_RESPONSE before = { 0 };
    DWORD stReturned = 0;

    BOOL stOk = DeviceIoControl(
        hDevice,
        IOCTL_RG_GET_STATUS,
        NULL, 0,                 // 입력 없음
        &before, sizeof(before),         // 출력 버퍼
        &stReturned,
        NULL
    );

    if (stOk) {
        std::cout << "\n[커널 상태]\n";
        std::cout << "  EngineProcessId     : " << before.EngineProcessId << "\n";
        std::cout << "  FastPathMode        : " << before.FastPathMode << "\n";
        std::cout << "  SelfProtectEnabled  : " << before.SelfProtectEnabled << "\n";
        std::cout << "  QueueDepth          : " << before.QueueDepth << "\n";
        std::cout << "  EventsGenerated     : " << before.EventsGenerated << "\n";
        std::cout << "  EventsDropped       : " << before.EventsDropped << "\n";
        std::cout << "  ProcessesBlocked    : " << before.ProcessesBlocked << "\n";
        std::cout << "  ProcessesTerminated : " << before.ProcessesTerminated << "\n";
        std::cout << "  EventsDelivered     : " << before.EventsDelivered << "\n";
        std::cout << "  EventsFlushed       : " << before.EventsFlushed << "\n";

        if (before.Magic != ARW_HEADER_MAGIC) {
            std::cout << "  [경고] Magic 불일치\n";
        }
    }
    else {
        std::cout << "상태 조회 실패. 에러 코드: " << GetLastError() << "\n";
    }

    // 5. 이벤트 수신
    const int MAX_FETCH = maxFetch;   // 0단계 인자 파싱 결과 (기본 10)
    int fetched = 0;

    std::cout << "\n[이벤트 수신] 최대 " << MAX_FETCH << "건\n";

    for (int i = 0; i < MAX_FETCH; i++) {
        // 어떤 타입(프로세스 1616B / 파일 2232B)이 나올지 모르므로 최대 크기
        // 버퍼(ARW_EVENT_ANY)를 건다. ARW_PROCESS_EVENT 크기만 걸면 커널이
        // STATUS_BUFFER_TOO_SMALL(Win32 오류 122)로 거부한다 — Common.h 규약.
        ARW_EVENT_ANY any = { 0 };
        DWORD evReturned = 0;

        BOOL evOk = DeviceIoControl(
            hDevice,
            IOCTL_RG_GET_EVENT,
            NULL, 0,
            &any, sizeof(any),
            &evReturned,
            NULL
        );

        if (!evOk) {
            std::cout << "  수신 중단. 에러 코드: " << GetLastError() << "\n";
            break;
        }

        fetched++;

        if (evReturned < sizeof(ARW_EVENT_HEADER)) {
            std::cout << "  [RECV " << fetched << "] INVALID_SHORT_HEADER"
                << " returnedBytes=" << evReturned << "\n";
            continue;
        }

        const ARW_EVENT_HEADER& header = any.Header;
        std::cout << "\n  [RECV " << fetched << "]"
            << " type=" << header.EventType
            << " (" << ArwEventTypeName(header.EventType) << ")"
            << " payloadBytes=" << header.PayloadSize
            << " returnedBytes=" << evReturned
            << " seq=" << header.SequenceNumber << "\n";

        if (header.Magic != ARW_HEADER_MAGIC ||
            header.Version != ARW_DRIVER_VERSION ||
            header.PayloadSize != evReturned) {
            std::cout << "       WARNING: invalid event header/ABI;"
                << " event body not interpreted\n";
            continue;
        }

        // 파일 이벤트(미니필터 Track B). 경로/확장자 길이는 바이트 단위, 점 없음.
        if (any.Header.EventType == EVENT_TYPE_FILE_WRITE ||
            any.Header.EventType == EVENT_TYPE_FILE_RENAME) {
            if (evReturned != sizeof(ARW_FILE_EVENT)) {
                std::cout << "       WARNING: unexpected file-event size\n";
                continue;
            }
            const ARW_FILE_EVENT& fe = any.File;
            std::cout << "       FILE operation="
                << ((fe.OperationType == ARW_FILE_OP_RENAME) ? "RENAME" : "WRITE")
                << " pid=" << fe.ProcessId
                << " flags=" << fe.Flags << "\n";
            std::cout << "       path=" << ArwUtf16FieldToUtf8(
                fe.FilePath, fe.FilePathLength, sizeof(fe.FilePath)) << "\n";
            if (fe.OperationType == ARW_FILE_OP_RENAME) {
                std::cout << "       newExtension=" << ArwUtf16FieldToUtf8(
                    fe.NewExtension, fe.NewExtensionLength,
                    sizeof(fe.NewExtension)) << "\n";
            }
            continue;
        }

        if (header.EventType != EVENT_TYPE_PROCESS_CREATE &&
            header.EventType != EVENT_TYPE_PROCESS_TERMINATE &&
            header.EventType != EVENT_TYPE_PROCESS_BLOCKED) {
            std::cout << "       WARNING: unknown event type\n";
            continue;
        }
        if (evReturned != sizeof(ARW_PROCESS_EVENT)) {
            std::cout << "       WARNING: unexpected process-event size\n";
            continue;
        }

        // Show process events even without a rule hit: otherwise a successful
        // GET_EVENT can appear as an empty console, hiding what was delivered.
        const ARW_PROCESS_EVENT& ev = any.Process;
        std::cout << "       PROCESS pid=" << ev.ProcessId
            << " ppid=" << ev.ParentProcessId
            << " matchedRule=" << ev.MatchedRuleId << "\n";
        if (ev.MatchedRuleId != 0) {
            std::cout << "       RULE HIT " << ev.MatchedRuleId << "\n";

            if (ev.CommandLineLength > 0 &&
                ev.CommandLineLength <= sizeof(ev.CommandLine)) {
                std::cout << "       cmd=" << ArwUtf16FieldToUtf8(
                    ev.CommandLine, ev.CommandLineLength,
                    sizeof(ev.CommandLine)) << "\n";
            }
        }
    }

    std::cout << "\n수신 완료: " << fetched << "건\n";

    // 6. 수신 후 상태 — 큐 깊이가 정확히 감소했는지 검증
    ARW_STATUS_RESPONSE after = { 0 };
    if (QueryStatus(hDevice, after)) {
        std::cout << "\n[수신 후 상태]\n";
        std::cout << "  QueueDepth        : " << after.QueueDepth << "\n";
        std::cout << "  EventsGenerated   : " << after.EventsGenerated << "\n";
        std::cout << "  EventsDropped     : " << after.EventsDropped << "\n";
        std::cout << "  EventsDelivered   : " << after.EventsDelivered << "\n";
        std::cout << "  EventsFlushed     : " << after.EventsFlushed << "\n";

        long long consumed =
            (long long)before.QueueDepth - (long long)after.QueueDepth;
        long long newlyGen =
            (long long)after.EventsGenerated - (long long)before.EventsGenerated;

        std::cout << "\n[검산]\n";
        std::cout << "  큐 감소량         : " << consumed << "\n";
        std::cout << "  수신 건수         : " << fetched << "\n";
        std::cout << "  측정 중 신규 발생 : " << newlyGen << "\n";
        std::cout << "  (큐감소 + 신규발생) = " << (consumed + newlyGen)
            << " / 기대 " << fetched << "\n";

        // The driver's dropped counter is cumulative since DriverEntry.
        // A full queue before this client registered must NOT be mistaken
        // for additional loss while the registered engine was consuming.
        if (after.EventsDropped >= before.EventsDropped) {
            const ULONG64 droppedDuringReceive =
                after.EventsDropped - before.EventsDropped;
            std::cout << "  수신 시작 전 누적 손실 : " << before.EventsDropped << "\n";
            std::cout << "  수신 중 추가 손실     : " << droppedDuringReceive << "\n";
            if (droppedDuringReceive == 0) {
                std::cout << "  [확인] 이번 수신 구간에서 추가 손실 없음\n";
            }
            else {
                std::cout << "  [경고] 수신 중 이벤트 손실 발생; "
                    << "부하/대기 요청/큐 적체를 조사하세요\n";
            }
        }
        else {
            std::cout << "  [경고] 손실 카운터 감소: 상태 스냅샷 또는 "
                << "드라이버 재시작 여부 확인 필요\n";
        }
    }
    else {
        std::cout << "[경고] 수신 후 상태 조회 실패. Error=" << GetLastError() << "\n";
    }

    // 7. 정리
    CloseHandle(hDevice);
    system("pause");   // 콘솔 창이 바로 닫히는 것 방지
    return 0;
}
