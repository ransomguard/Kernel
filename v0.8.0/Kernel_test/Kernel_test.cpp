#include <windows.h>
#include <iostream>

// C 스타일 심볼 호환을 위해 extern "C" 적용
extern "C" {
#include "Common.h" // 경로가 정상 설정되면 정상 인클루드됨[cite: 2]
}

int main() {
    // 1. 커널 드라이버가 생성한 심볼릭 링크에 접근하여 통신 핸들 개방
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\AntiRansomware",
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

    // 2. 정책 업데이트 명령(IOCTL_RG_UPDATE_POLICY) 전송[cite: 2]
    DWORD bytesReturned = 0;
    ULONG myPid = GetCurrentProcessId(); // 현재 실행 중인 이 콘솔 앱 자기 자신의 PID 획득

    // 현재 커널(Communication.c)에 수신 버퍼 처리 로직은 없지만, 
    // 향후 연동을 위해 자신의 PID를 버퍼에 담아 전송 시도[cite: 3]
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_RG_UPDATE_POLICY,
        &myPid,          // 커널로 전달할 데이터 (PID)
        sizeof(myPid),   // 데이터 크기
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (result) {
        std::cout << "정책 업데이트 명령 전송 성공! (PID: " << myPid << ")\n";
    }
    else {
        std::cout << "명령 전송 실패. 에러 코드: " << GetLastError() << "\n";
    }

    CloseHandle(hDevice);
    system("pause"); // 실행 직후 콘솔 창이 바로 닫히는 것을 방지
    return 0;
}