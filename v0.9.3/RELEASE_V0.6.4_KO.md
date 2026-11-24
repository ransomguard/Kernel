# RansomGuard knel v0.6.4 — 이벤트 수신 진단 보강

## 릴리스 목적

격리된 Windows 11 VM에서 미니필터 파일 이벤트가 메인 커널 드라이버의
이벤트 큐를 거쳐 사용자 모드 테스트 프로그램에 도달하는지 확인하기 위한
**진단 전용 업데이트**입니다.

지난 v0.6.3 VM 검증에서 두 드라이버는 실행 중이었고 미니필터는
\Callback\ArwFileEvent 경로로 이벤트 알림을 생성했으나, 사용자 모드에
`FILE_WRITE`/`FILE_RENAME` 이벤트가 실제로 도착했는지는 분명하지
않았습니다. 기존 클라이언트는 규칙에 일치한 프로세스 이벤트만 주로
보여주어 타입 식별이 어려웠습니다.

## v0.6.3 → v0.6.4 변경 파일

- `Kernel_test/Anti_Ransom_TestClient.cpp`
  - 모든 성공적인 `IOCTL_RG_GET_EVENT` 호출의 이벤트 타입(1~5), 구조체
    페이로드 크기, 반환 바이트 수, 시퀀스 번호를 출력.
  - `FILE_WRITE` 및 `FILE_RENAME`의 PID, 플래그, 경로와 확장자를 출력.
  - 규칙에 일치하지 않는 프로세스 이벤트도 수신 여부를 출력.
  - 공용 ABI Magic/Version/PayloadSize, 이벤트 타입별 크기, UTF-16 경로 길이를
    검증한 후 출력.
  - 출력 코드 페이지를 UTF-8로 설정하고 수신 루프의 문자/와이드 콘솔
    출력 혼용을 제거.
- `README.md`: 현재 릴리스 정보 및 변경 범위 추가.
- `README_DIAGNOSTIC_KO.md`: Visual Studio x64 빌드와 두 PowerShell 창
  기반의 AUDIT 파일 쓰기/이름 변경 시험 순서 추가.
- `SHA256SUMS.txt`: 이번 소스 트리 기준으로 재생성.

## 변경하지 않은 구성 요소

- `Anti_Ransom_Driver/`, `Anti_Ransom_FsFilter/` 하위 코드와 INF
- `Shared/Common.h` 및 커널 ↔ 사용자 모드 ABI
- `RansomGuard.sln`, `RansomGuard.props`, 드라이버 서명/설치 설정
- Track A/B 자동 판단·차단 로직과 방화벽/복구/`store` 저장소

v0.6.4는 **소스 릴리스 번호**입니다. 커널 드라이버 자체의 버전이
0.6.4로 빌드되었음을 의미하지 않습니다. 기존 v0.6.3 드라이버 설치
상태에서 진단용 클라이언트만 새로 빌드해 확인합니다.

## 검증 상태

- v0.6.3 `Shared/Common.h` 원본과 동일한 구조체/IOCTL ABI 유지.
- 변경 파일만 포함한 새 소스 릴리스 구성.
- **Windows MSVC/WDK 빌드 및 VM 최종 동작 확인은 아직 수행하지 않음.**
  따라서 `type=4`/`type=5` 수신 성공 여부는 새 클라이언트 실행 로그로
  확인해야 합니다.
- 이 패키지에는 컴파일된 `.exe`, `.sys`, 서명 인증서나 키가 없습니다.

## 다음 단계

1. Visual Studio 2022에서 `RansomGuard.sln` 또는
   `Kernel_test/Anti_Ransom_TestClient.vcxproj`를 열고
   **Debug | x64**로 테스트 클라이언트 빌드.
2. Windows 11 격리 VM의 `C:\RG_Test`에 생성된 EXE만 복사하고
   관리자 PowerShell A에서 `& 'C:\RG_Test\Anti_Ransom_TestClient_Diag.exe' 50 --policy audit` 실행.
3. 관리자 PowerShell B에서 `README_DIAGNOSTIC_KO.md`의 4개 파일
   쓰기·이름 변경 테스트를 수행하고 창 A에 표시된 모든 `[RECV]` 행 확보.

관측 결과가 프로세스 이벤트(타입 1~3)뿐이면, 파일 이벤트를 아직 입증한
것이 아닙니다. 무출력 또는 ABI 경고도 증거로 남겨 커널 이벤트 전달
경로를 추가 진단합니다.
