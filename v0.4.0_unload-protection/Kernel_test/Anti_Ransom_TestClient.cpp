#include <windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>    // sprintf_s
#include <cstring>   // strcmp

// C 스타일 심볼 호환을 위해 extern "C" 적용
extern "C" {
#include "Common.h" // 경로가 정상 설정되면 정상 인클루드됨[cite: 2]
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
//   반환값: 프로세스 종료 코드 (0 = 종료 성공, 1 = IOCTL 실패, 2 = 커널이 종료 거부/실패)
static int RequestTerminate(HANDLE h, ULONG targetPid)
{
    ARW_TERMINATE_REQUEST req = { 0 };
    req.Magic = ARW_HEADER_MAGIC;
    req.Version = ARW_DRIVER_VERSION;
    req.TargetProcessId = targetPid;
    req.Reason = 1;                 // 임의 값 — 사유 코드 체계는 아직 미정
    req.ExpectedCreateTime = 0;     // 0 = 생성 시각 검증 생략 (기본 종료 경로 우선 확인)

    ARW_TERMINATE_RESPONSE resp = { 0 };
    DWORD returned = 0;

    std::cout << "\n[종료 요청] TargetPID=" << targetPid
        << " Reason=" << req.Reason
        << " ExpectedCreateTime=" << req.ExpectedCreateTime << "\n";

    BOOL ok = DeviceIoControl(
        h,
        IOCTL_RG_TERMINATE_PROCESS,
        &req, sizeof(req),
        &resp, sizeof(resp),
        &returned,
        NULL
    );

    if (!ok) {
        // 여기서 실패하면 커널이 요청 자체를 거절한 것이다.
        //   ERROR_ACCESS_DENIED(5)     : 등록된 엔진 PID가 아님
        //   ERROR_REVISION_MISMATCH    : Magic/Version 불일치
        //   ERROR_INSUFFICIENT_BUFFER  : 입력 버퍼 크기 부족
        std::cout << "  IOCTL 전송 실패. Win32 에러 코드: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "  IOCTL 전송 성공 (응답 " << returned << " bytes)\n";

    if (returned < sizeof(resp)) {
        std::cout << "  [경고] 응답 크기 부족 - ResultStatus 신뢰 불가\n";
        return 2;
    }
    if (resp.Magic != ARW_HEADER_MAGIC) {
        std::cout << "  [경고] 응답 Magic 불일치\n";
    }
    if (resp.TargetProcessId != targetPid) {
        std::cout << "  [경고] 응답 PID 불일치: " << resp.TargetProcessId << "\n";
    }

    // NT_SUCCESS 는 유저 모드 windows.h 에 없으므로 부호 비교로 대체 (NTSTATUS >= 0 이 성공)
    const bool termOk = (resp.ResultStatus >= 0);
    char statusHex[16] = { 0 };
    sprintf_s(statusHex, "0x%08lX", (unsigned long)resp.ResultStatus);

    std::cout << "  ResultStatus : " << statusHex
        << (termOk ? "  (성공 - 종료됨)" : "  (실패 - 커널이 종료 거부 또는 실패)") << "\n";

    if (!termOk) {
        // 자주 나오는 NTSTATUS 만 사람이 읽을 수 있게 병기
        switch ((unsigned long)resp.ResultStatus) {
        case 0xC0000022UL: std::cout << "    → STATUS_ACCESS_DENIED (보호 대상 PID 0/4 또는 권한 거부)\n"; break;
        case 0xC000000DUL: std::cout << "    → STATUS_INVALID_PARAMETER\n"; break;
        case 0xC000010AUL: std::cout << "    → STATUS_PROCESS_IS_TERMINATING (이미 종료 중)\n"; break;
        case 0xC000000BUL: std::cout << "    → STATUS_INVALID_CID (해당 PID 없음)\n"; break;
        case 0xC00000BBUL: std::cout << "    → STATUS_NOT_SUPPORTED\n"; break;
        default: break;
        }
    }

    return termOk ? 0 : 2;
}

static void PrintUsage(const char* exe)
{
    std::cout << "사용법:\n"
        << "  " << exe << " [최대수신건수] [--policy audit|block] [--selfprotect keep|off]\n"
        << "        기존 흐름 (등록→정책→상태→이벤트수신)\n"
        << "  " << exe << " --terminate <PID>\n"
        << "        종료 모드 (등록→종료요청)\n"
        << "    --policy      생략 시 FastPathMode=BLOCK\n"
        << "    --selfprotect 생략 시 keep (현재 상태 유지). off 는 커널 자기보호를 런타임에 끔.\n"
        << "                  커널은 IOCTL 로 켜기를 지원하지 않으므로 on 은 없음 (레지스트리 EnableSelfProtect=1 + 재로드).\n";
}

int main(int argc, char** argv) {
    // 0. 인자 파싱
    //   --terminate <PID>       : 종료 모드 (등록→종료요청만 수행)
    //   --policy audit|block    : 3단계 정책 전송의 FastPathMode 선택 (기본 BLOCK)
    //   <숫자>                  : 이벤트 최대 수신 건수 (기본 10) — 기존 동작 유지
    bool terminateMode = false;
    ULONG terminatePid = 0;
    ULONG fastPathMode = ARW_FASTPATH_MODE_BLOCK;   // 인자 없으면 기존대로 BLOCK
    const char* fastPathName = "BLOCK";
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
            unsigned long parsed = strtoul(argv[i + 1], &endp, 10);
            if (endp == argv[i + 1] || *endp != '\0' || parsed > 0xFFFFFFFFUL) {
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
    policy.FastPathMode = fastPathMode;               // --policy 인자 (기본 BLOCK)
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
        ARW_PROCESS_EVENT ev = { 0 };
        DWORD evReturned = 0;

        BOOL evOk = DeviceIoControl(
            hDevice,
            IOCTL_RG_GET_EVENT,
            NULL, 0,
            &ev, sizeof(ev),
            &evReturned,
            NULL
        );

        if (!evOk) {
            std::cout << "  수신 중단. 에러 코드: " << GetLastError() << "\n";
            break;
        }

        fetched++;

        if (ev.MatchedRuleId != 0) {
            wprintf(L"\n  *** [seq=%llu] RULE %lu HIT  PID=%lu PPID=%lu ***\n",
                ev.Header.SequenceNumber,
                ev.MatchedRuleId,
                ev.ProcessId,
                ev.ParentProcessId);

            if (ev.CommandLineLength > 0 &&
                ev.CommandLineLength <= sizeof(ev.CommandLine)) {
                wprintf(L"       len=%lu bytes (%lu chars)\n",
                    ev.CommandLineLength,
                    ev.CommandLineLength / (ULONG)sizeof(WCHAR));
                wprintf(L"       cmd: %.*s|END\n",
                    (int)(ev.CommandLineLength / sizeof(WCHAR)),
                    ev.CommandLine);
            }
        }
        else if (fetched % 50 == 0) {
            // 진행 상황만 간략히
            std::cout << "  ... " << fetched << "건 수신\n";
        }
    }

    std::cout << "\n수신 완료: " << fetched << "건\n";

    // 6. 수신 후 상태 — 큐 깊이가 정확히 감소했는지 검증
    ARW_STATUS_RESPONSE after = { 0 };
    if (QueryStatus(hDevice, after)) {
        std::cout << "\n[수신 후 상태]\n";
        std::cout << "  QueueDepth        : " << after.QueueDepth << "\n";
        std::cout << "  EventsGenerated   : " << after.EventsGenerated << "\n";

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
    }

    // 7. 정리
    CloseHandle(hDevice);
    system("pause");   // 콘솔 창이 바로 닫히는 것 방지
    return 0;
}
