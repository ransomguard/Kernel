#include <windows.h>
#include <iostream>

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

int main() {
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

    // 3. 정책 업데이트 (IOCTL_RG_UPDATE_POLICY) 전송
    DWORD bytesReturned = 0;

    ARW_POLICY_REQUEST policy = { 0 };
    policy.Magic = ARW_HEADER_MAGIC;
    policy.Version = ARW_DRIVER_VERSION;
    policy.FastPathMode = ARW_FASTPATH_MODE_BLOCK;   // 실제 차단 모드
    policy.EnableProcessMonitor = 1;                  // 프로세스 감시 ON
    policy.EnableSelfProtect = 0;                     // 자기보호 OFF (개발 중)

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
            << "(FastPath=BLOCK, ProcMon=ON)\n";
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

        if (before.Magic != ARW_HEADER_MAGIC) {
            std::cout << "  [경고] Magic 불일치\n";
        }
    }
    else {
        std::cout << "상태 조회 실패. 에러 코드: " << GetLastError() << "\n";
    }

    // 5. 이벤트 수신
    const int MAX_FETCH = 5000;
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