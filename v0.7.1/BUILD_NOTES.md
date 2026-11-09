# Windows 커널 빌드 기준선

> **v0.6.3 갱신 (2026-11-02):** 아래의 최초 통합 당시 기록 중 "미검증" 항목은 역사적 기록이다. 사용자 제공 Windows 11 VM 검증 화면에서 v0.6.2의 Debug x64 빌드 3개 성공(0 오류/0 경고), 제어 드라이버 설치·재시작·언로드·IPC 상태/이벤트 1건 수신이 확인됐다. v0.6.3의 **미니필터는 아직 Windows에서 재빌드·재서명·설치·로드하지 않았다**. 자세한 절차와 한계는 `RELEASE_V0.6.3_KO.md`를 참고한다.

이 솔루션은 제공된 `v0.5.0_event-queue-generalization` 소스를 기준으로 누락된 프로젝트 구성을 복원한 **첫 통합 단계**다. 작성 환경은 Linux이며 MSVC/WDK 컴파일, InfVerif/Inf2Cat, 서명 검증, Windows 드라이버 로드 및 Driver Verifier 실행은 아직 하지 않았다. 아래 명령은 Windows에서 수행할 빌드 절차이며, 이미 통과한 결과를 뜻하지 않는다.

## 프로젝트 구성

| 프로젝트 | 종류 | 컴파일 대상 | 주요 설정 |
| --- | --- | --- | --- |
| `Anti_Ransom_Driver` | 비 PnP KMDF 제어 드라이버 | `Communication.c`, `Driver.c`, `Eventqueue.c`, `ProcessMonitor.c`, `ResponseEngine.c`, `SelfProtect.c` | `WindowsKernelModeDriver10.0`, KMDF 1.31, `wdmsec.lib` |
| `Anti_Ransom_FsFilter` | WDM 파일 시스템 미니필터 | `FsFilter.c`, `EntropyDetect.c` | `WindowsKernelModeDriver10.0`, `FltMgr.lib`, `ARW_MINIFILTER` 정의 |
| `Anti_Ransom_TestClient` | 콘솔 테스트 클라이언트 | `Anti_Ransom_TestClient.cpp` 한 파일 | VS 2022 `v143`, C++17 |

솔루션은 `RansomGuard.sln`이며 `Debug|x64`, `Release|x64`만 제공한다. 이전 `Kernel_test.cpp`는 보존하되 컴파일하지 않아 `main` 중복을 피했다. 테스트 클라이언트는 `Shared/Common.h`를 직접 포함한다. 미완성 VSS COM 훅 프로젝트는 이 솔루션에 포함하지 않았다.

공통 출력 경로는 `out\x64\<Configuration>\<ProjectName>\`, 중간 산출물 경로는 `obj\x64\<Configuration>\<ProjectName>\`다. 드라이버 빌드에는 `.sys`, `.inf`, `.cat` 패키지 구성이 포함되지만 실제 생성 성공 여부는 Windows 빌드 로그로 확인해야 한다.

## 도구 버전 선택

이 기준선은 **Visual Studio 2022 + MSVC v143 + 빌드 번호 26100의 SDK/WDK**를 사용한다. 프로젝트의 기본 `WindowsTargetPlatformVersion`은 `10.0.26100.0`이며 MSBuild 속성으로 바꿀 수 있다.

2026-10-29에 확인한 Microsoft 공식 안내는 VS 2022에 WDK `26100.6584`를 연결하고, 최신 기본 WDK `28000.2526`에는 VS 2026을 연결한다. 따라서 VS 2022에서 무조건 “최신 WDK”를 설치하는 방식으로 혼용하지 않는다. [지원 WDK 버전](https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads), [WDK 설치 및 kit versioning](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).

SDK와 WDK의 **빌드 번호**는 맞아야 한다. QFE 번호는 기능 요구에 따라 다를 수 있다. 예를 들어 설치된 제품 버전이 `10.0.26100.6584`여도 `Include` 경로와 프로젝트 대상 버전은 `10.0.26100.0`으로 보일 수 있다. 폴더 이름의 `.0`을 보고 설치된 패치 버전이 0이라고 판단하지 않는다.

VS Installer에서 다음 항목을 확인한다.

- “C++를 사용한 데스크톱 개발”과 MSVC v143 x64/x86 빌드 도구.
- 선택한 빌드 번호의 Windows SDK와 WDK.
- Windows Driver Kit Visual Studio 통합 구성 요소/확장. 드라이버 프로젝트를 열 수 없거나 `WindowsKernelModeDriver10.0`을 찾지 못하면 이 항목을 확인한다.
- 선택한 도구 설정이 요구하는 x64 Spectre 완화 라이브러리. 해당 라이브러리 누락 오류를 보안 완화 옵션 해제로 덮지 않는다.

설치된 Visual Studio/WDK/Python 버전과 Windows OS 빌드 번호는 서로 다른 값이다. 커널 빌드에는 Python이 필요하지 않으며, Python은 사용자 모드 복구/JEV 엔진 환경에서 별도로 확인한다. 커널 소스의 `ExAllocatePool2` 사용 때문에 Windows 10 2004보다 오래된 OS는 이 기준선의 대상이 아니다. 실제 첫 실행 대상은 사용자가 확인한 **Windows 11 x64 VM**으로 한정하고 해당 빌드를 검증 기록에 남긴다. 이 문서는 Windows 10 전체 버전의 런타임 호환성을 검증했다는 뜻이 아니다.

## 호스트와 격리 VMware VM의 역할

편집·빌드는 Windows 개발 호스트에서 해도 되고 충분한 자원이 있는 Windows VM 안에서 해도 된다. 드라이버 로드, 프로세스 종료, 네트워크 격리 및 복구 검증은 별도의 Windows 11 테스트 VM에서 한다. Linux에서는 프로젝트 XML과 파일 참조를 검사할 수 있지만 WDK 빌드를 대신할 수 없다.

빌드만으로 드라이버 서비스가 설치·시작되거나 부팅 옵션, Secure Boot, 메모리 무결성, 방화벽 정책이 바뀌지 않는다. 이 디렉터리에는 그러한 변경을 자동으로 수행하는 설치/실행 스크립트가 없다. 테스트 VM의 서명 및 드라이버 실행 정책은 VM 환경이 확인된 뒤 별도로 준비한다.

## 빌드 명령

VS 2022의 **x64 Native Tools Command Prompt** 또는 대응하는 개발자 PowerShell에서 `kernel` 디렉터리로 이동한다. 일반 셸에 `msbuild`가 없으면 개발자 셸을 먼저 사용한다.

```powershell
msbuild .\RansomGuard.sln /m /t:Build /p:Configuration=Debug /p:Platform=x64
```

Release도 별도로 빌드한다.

```powershell
msbuild .\RansomGuard.sln /m /t:Build /p:Configuration=Release /p:Platform=x64
```

선택한 SDK/WDK 조합을 명시하는 예시는 다음과 같다. 아래 값은 이 기준선의 기본값을 명시한 것이다. 다른 값으로 바꾸기 전에 VS 버전과 SDK/WDK 조합이 지원되는지 확인한다.

```powershell
msbuild .\RansomGuard.sln /m /t:Build /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.26100.0
```

WDK가 아직 준비되지 않았다면 사용자 모드 테스트 클라이언트만 빌드할 수 있다. 이 빌드 성공은 커널 빌드 성공을 의미하지 않는다.

```powershell
msbuild .\Kernel_test\Anti_Ransom_TestClient.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.26100.0
```

`RansomGuard.props`는 UTF-8 소스, 경고 수준 4, 경고를 오류로 처리하는 구성을 둔다. Windows에서 첫 빌드 중 발견한 컴파일/링크 오류는 도구 버전과 전체 빌드 로그를 함께 기록한다. 이 문서의 정적 검사 결과만으로 경고 없는 컴파일을 가정하지 않는다. [WDK 빌드 절차](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/building-a-driver).

## 서명과 INF

두 드라이버 프로젝트는 `TestSign`과 SHA-256 서명 구성을 가진다. 인증서와 개인 키는 패키지에 넣지 않았다. VS가 선택한 로컬 테스트 인증서를 확인하거나 Driver Signing 속성에서 프로젝트용 로컬 인증서를 준비해야 한다. 테스트 서명은 배포용 Microsoft 서명 및 VM의 신뢰/코드 무결성 정책을 대신하지 않는다. 빌드가 서명 단계에서 실패하면 그 오류를 확인하며 호스트의 보호 설정을 자동으로 변경하지 않는다. [개발 중 드라이버 서명](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/signing-a-driver-during-development-and-testing).

`Anti_Ransom_Driver.inf`는 비 PnP 제어 드라이버의 선택적 primitive 패키지 메타데이터다. 이 드라이버는 가짜 하드웨어 ID로 PnP 장치를 만드는 구조가 아니다. Windows 10 이상 비 PnP KMDF에는 프레임워크 공동 설치 관리자가 필요하지 않으며 SCM 서비스 생성 방식도 사용할 수 있다. 실제 설치 절차는 테스트 VM에서 선택·검증한다. [비 PnP 드라이버 설치](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/installing-a-non-pnp-driver).

`Anti_Ransom_FsFilter.inf`는 파일 시스템 드라이버 서비스 타입 2, 수동 시작, `FltMgr` 의존성, Driver Store 경로를 사용한다. Windows 11 24H2 이상은 `Parameters\Instances`, 이전 OS 분기는 서비스 루트의 `Instances`에 인스턴스를 기술한다. v0.6.2의 `385100`은 **실제로 Microsoft MiniSpy에 배정된 고도**이므로 사용하지 않는다. v0.6.3의 `385090`은 현재 공식 할당 목록에 없음을 확인한 **격리 VM 전용 임시값**으로, Microsoft로부터 이 프로젝트에 할당받은 값이 아니다. 배포하려면 정식 할당이 필요하며, VM에서도 로드 전에 기존 필터와 충돌하는지 확인해야 한다. [할당 목록](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes), [고도 할당 정책](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers), [미니필터 INF](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver).

두 INF는 수동 시작이며 `DefaultUninstall` 구문이나 보안 설정을 바꾸는 공동 설치 관리자가 없다. 설치한 패키지의 제거는 선택한 설치 방식과 Windows 패키지 관리 절차를 따른다. 기존 문서의 수동 레지스트리 설정과 새 INF 설치를 중복 적용하지 않는다.

## 이번 단계의 IPC 변경

이벤트 구조체 크기 및 IOCTL 값은 유지했다. 엔진과 클라이언트는 같은 `Shared/Common.h` 계약으로 빌드해야 한다.

첫 VM 기본 정책은 `FastPathMode=AUDIT(1)`이다. 코드 초기값과 새 INF 설치값이 관측 모드이며, INF의 `NOCLOBBER` 플래그는 기존 레지스트리 정책을 보존한다. **이미 설치된 서비스의 `Parameters\FastPathMode=2`는 재빌드만으로 바뀌지 않는다.** 로드 뒤 상태 IOCTL로 실제 값을 확인한다. Python `observe`는 정책을 변경하지 않는다. C++ 테스트 클라이언트의 정책 전송 기본값도 AUDIT이며 `--policy block`을 명시하면 생성 차단 모드를 선택한다. 커널의 선택 가능한 생성 거부 코드와 수동 종료 IOCTL은 그대로 남아 있으므로 관측 CLI가 있다고 해서 커널 전체가 응답 기능 없는 드라이버가 되는 것은 아니다.

1. 엔진 등록은 **장치를 연 프로세스 객체와 해당 파일 객체**에 묶인다. KMDF 큐 콜백이 다른 스레드 문맥에서 실행될 수 있으므로 현재 실행 스레드의 PID를 호출자 권한으로 쓰지 않는다. 요청 IRP의 요청자와 최초 open 프로세스를 비교한다.
2. 등록, 등록 해제, 권한 확인 및 명령 디스패치는 같은 대기 잠금으로 직렬화한다. `GET_EVENT`를 수동 큐로 넘긴 뒤에는 그 요청이 대기하는 동안 잠금을 유지하지 않는다. 명시적 등록 해제는 수동 큐에 남은 읽기 요청을 취소한다.
3. 엔진은 등록에 사용한 **같은 장치 핸들**로 이벤트 수신 및 명령을 수행한다. 두 번째 `CreateFile`로 연 핸들이나 다른 프로세스에 복제한 핸들은 등록된 엔진 권한을 얻지 못한다. 같은 프로세스 안에서 동일 파일 객체를 가리키는 핸들 복제는 이 계약을 유지한다.
4. 종료 명령은 `ExpectedCreateTime != 0`이어야 한다. PID와 프로세스 생성 시간을 함께 확인하며, 응답 버퍼가 유효한지 먼저 확인한 뒤 종료를 요청한다. 대상 식별 또는 응답 공간 검증 실패 시 종료 부작용을 만들지 않는다.
5. `DeviceIoControl` 성공은 명령 전송/처리 성공이다. 실제 종료 요청 결과는 `ARW_TERMINATE_RESPONSE.ResultStatus`로 확인하고, 이후 프로세스 종료를 별도로 확인한다. 테스트 클라이언트는 대상 핸들을 유지한 상태에서 `GetProcessTimes`로 생성 시간을 얻고, 수락된 명령 뒤 최대 5초 동안 종료를 확인한다. 반환 코드 3은 종료 미확인이다.

장치 ACL은 SYSTEM/Administrators 경계다. 서비스 서명/설치 경로의 신뢰까지 인증하는 기능을 새로 구현한 것은 아니며, 다른 관리자 프로세스의 선점 등록을 막는 운영용 서비스 신원 정책은 후속 과제다. 등록 해제로 이미 전달된 이벤트까지 회수하지는 않는다. [KMDF 요청 처리 문맥](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/request-handlers), [요청자 PID](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nf-wdfrequest-wdfrequestgetrequestorprocessid).

## Windows 검증 전 남은 확인

아래는 아직 수행하지 않은 검증 항목이다.

- VS 2022 + 확인된 SDK/WDK에서 x64 Debug/Release 빌드, 생성 INF 검증, 카탈로그 생성 및 실제 서명 검증.
- Windows 11 VM에서 설치·로드·언로드, 장치 ACL, 파일 객체 정리와 엔진 비정상 종료, 여러 스레드의 IOCTL 동시 요청 및 취소.
- 미등록 요청 거부, 다른 open 핸들 거부, 두 엔진 동시 등록 중 하나만 성공, 종료 요청의 0/오래된 생성 시간 거부, 작은 응답 버퍼에서 종료가 발생하지 않음.
- 대기 중인 `GET_EVENT`가 있는 상태에서 정상 명령이 진행됨, 엔진 등록 해제 시 대기 읽기 취소, 재등록 이후 이전 세션의 요청과 혼동하지 않음.
- 희생용 테스트 프로세스로 종료 결과와 실제 종료 확인을 구분. 시스템 프로세스나 실제 사용자 작업을 시험 대상으로 쓰지 않는다.
- 이벤트 유실 카운터와 관측 한계를 함께 기록. 파일 미니필터의 현재 write/rename 이벤트는 작업 전 관측이며 실제 파일 쓰기 완료/차단을 증명하지 않는다.

이 프로젝트 구성 자체에는 네트워크 격리, JEV 판정, VSS 복구 실행을 자동으로 연결하는 드라이버 설치 동작이 없다. 사용자 모드 통합 엔진 및 전체 통합 문서와 함께 검증해야 한다.
