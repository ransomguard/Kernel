# v0.6.2 Windows 첫 빌드 경고 수정

Visual Studio 2022 17.14, WDK 10.0.26100.6584, Debug | x64 환경에서
v0.6.1 빌드 화면에 보인 경고 14개와 오류 9개(C2220)를 대상으로 수정한 버전입니다.

## 변경 내용

1. `Anti_Ransom_Driver/Anti_Ransom_Driver.vcxproj`:
   `_KERNEL_MODE` 사용자 정의를 `ARW_KERNEL_BUILD`로 변경했습니다.
2. `Anti_Ransom_FsFilter/Anti_Ransom_FsFilter.vcxproj`:
   동일하게 변경하고 `ARW_MINIFILTER` 정의는 유지했습니다.
3. `Shared/Common.h`:
   커널 헤더 및 커널 간 콜백 이름의 조건부 컴파일을
   `ARW_KERNEL_BUILD` 기준으로 변경했습니다.
4. `Shared/Common.h`:
   `RG_DEVICE_TYPE`을 `0x8123U`로 선언했습니다.
   `CTL_CODE`의 최상위 비트로 인해 발생하던 테스트 클라이언트의
   `int` -> `DWORD` 부호 변환 경고(C4245)를 방지합니다.

## 변경하지 않은 사항

- IOCTL 기능 번호, 접근 권한, 장치 타입, 버퍼 구조체 및 통신 규약의 값
- 커널/복구 엔진 간 IPC 계약 및 별도 `store` 저장소
- `/WX`(경고를 오류로 처리) 설정: 실제 경고를 고쳤으며 비활성화하지 않았습니다.

## 검증

- 정적 확인: 두 드라이버 프로젝트에 `ARW_KERNEL_BUILD`가 정의되고,
  사용자 모드 테스트 클라이언트에는 정의되지 않는지 확인
- 정적 확인: 7개 IOCTL 번호가 이전 버전과 동일한지 확인
- Windows/WDK 컴파일 및 실제 드라이버 구동 검증은 아직 수행하지 못했습니다.

### Windows에서 다음 단계

1. 기존 솔루션을 닫고 **이 ZIP의** `knel/RansomGuard.sln`을 엽니다.
2. `Debug | x64` 선택 후 `Ctrl+Shift+B`로 빌드합니다.
3. 실패하면 **오류 목록** 및 **출력 > 빌드**의 최초 오류를 공유해 주세요.
4. 개인 PC에서 드라이버를 설치하거나 실행하지 마세요. 빌드 확인 뒤 VM에서 진행합니다.
