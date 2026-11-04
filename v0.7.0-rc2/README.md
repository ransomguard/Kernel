# RansomGuard Kernel — v0.7.0-rc2 (VM 커널 기능 검증 마일스톤)

**상태: 릴리스 후보(RC2), 격리 Windows 11 VM 연구용.** 이 소스는 v0.6.6 HOTFIX1과 후속 TestClient 진단 보완을 기준으로 한다. **2026-11-05 v0.7.0-rc2 자체의 Debug/x64 3개 프로젝트 빌드, 테스트 서명, Windows 11 VM 설치·수동 기능 검증을 통과했다.** 파일 WRITE/RENAME 이벤트 type=4/5, 프로세스 Fast Path AUDIT/BLOCK, IPC 종료 요청, 엔진 프로세스 자기보호 및 종료가 확인되었다. 사용자 모드 IOCTL ABI는 변경하지 않았다. 자세한 증거와 제한은 [RC2 VM 검증 기록](VM_LAB_V0.7.0_RC2_KO.md)에 정리했다.

**2026-11-05 RC2 수정:** Visual Studio WDK에서 한국 시간 자정 직후 두 드라이버가 `Inf2Cat error 22.9.7: DriverVer set to a date in the future`로 실패하는 문제를 확인했다. `Anti_Ransom_Driver.vcxproj`와 `Anti_Ransom_FsFilter.vcxproj`에 `Inf2CatUseLocalTime=true`(`/uselocaltime`)를 설정하고, `StampInf`가 INF `DriverVer`의 버전 값을 시간 기반 번호로 덮어쓰지 않도록 `TimeStamp=0.7.0.0`을 명시했다. **C/C++ 드라이버 로직은 수정하지 않았다.** 새 구성으로 재빌드 및 테스트 서명 완료, VM에서 `DriverVer=11/05/2026,0.7.0.0`과 새 DriverStore 패키지를 확인했다.

이번 후보에서 런타임 드라이버 로직은 v0.6.6 기준 그대로이며, 두 INF의 `DriverVer`만 `0.7.0.0`으로 올리고 `SelfProtect.h`의 실제 서비스 레지스트리 경로 설명을 바로잡았다. 신규 빌드·서명 없이는 기존 `.sys/.cat`를 v0.7.0이라고 간주할 수 없다. 자세한 결과·미완료 사항·릴리스 전 확인 목록은 [RELEASE_V0.7.0_KO.md](RELEASE_V0.7.0_KO.md)에 기록한다.

**이것은 전체 안티랜섬웨어 완성 릴리스가 아니다.** 미니필터는 관측 전용이며 Track A 자동 복구, Track B/JEV, 프로세스 단위 네트워크 차단, 오탐 제어 및 장시간 안정성 검증이 남아 있다. `vssadmin delete shadows`라는 **문자열을 echo하는 무해한 명령도 차단되는** Fast Path 오탐이 확인되었으므로 실사용 시스템에 적용하지 말 것. 미니필터 고도 `385090`, `ObRegisterCallbacks` 고도 `320000`은 실험용 임시 값으로 취급할 것.

## 이전 v0.6.6 파일 이벤트 콜백 연결·ACK 검증 기록

사용자의 `knel` 저장소에 넣을 Windows 커널 소스다. 이 폴더에는 복구/JEV Python 코드를 넣지 않았다. 복구·VSS 생성·예약 작업·JEV·사용자 모드 분류와 로그는 별도 `store` 압축파일에 있다.

**2026-11-04 v0.6.6 HOTFIX1 (같은 릴리스 경로 유지):** VM에서 첫 v0.6.6 빌드의 메인 드라이버는 RUNNING, 미니필터 `.sys` 존재 검사 `True`였으나 `ExCreateCallback(Create=FALSE)`가 `STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)`로 실패했다. 메인 드라이버가 콜백 객체를 `OBJ_PERMANENT` 없이 생성하여 이름이 사라지는 것이 원인이다. **메인 `Anti_Ransom_Driver/Eventqueue.c`에서 영구 명명, 이름으로 다시 열어 확인, 언로드 때 `ZwMakeTemporaryObject` 정리를 추가했고 연결 실패 시 메인도 기동 실패 처리했다.** 메인 INF 소스만 `0.6.6.1`로 올려 새 패키지를 구분한다. WDK로 생성된 실제 INF의 `DriverVer`는 빌드 시각 값으로 다시 스탬프될 수 있다. 미니필터 소스/INF(`0.6.6.0`)와 사용자 모드 IPC는 수정하지 않았다. **2026-11-04 VMware Windows 11 VM에서 HOTFIX1을 빌드·서명·로드하고 파일 쓰기 `type=4`, 이름 변경 `type=5`가 TestClient로 전달되는 것까지 확인했다.** 두 드라이버의 정상 언로드도 확인됐다. [실제 검증 기록과 큐 포화 분석](QUEUE_STARTUP_VALIDATION_KO.md)을 참고한다.

**같은 v0.6.6의 후속 진단 보완:** `Kernel_test/Anti_Ransom_TestClient.cpp`에서 이벤트 수신 전·후의 `EventsDropped` 증가량을 비교하도록 출력만 보강했다. 실제 VM 측정에서 최초 `EventsGenerated=1405`, `EventsDropped=381`, `QueueDepth=1024`, 이후 `EventsGenerated=1844`, `EventsDropped=381`이었다. **이미 누적된 381건과 수신 중 새 손실 0건을 구분**해야 한다. 이 TestClient 출력 보완은 새 Windows 빌드가 필요하지만, **검증된 두 커널 드라이버 `.sys`를 교체할 필요는 없다.** 새로운 정책은 메인 → TestClient 등록 → 미니필터 순서로 시작해 초기 큐 포화를 최소화하는 것이다.

**최초 v0.6.6 변경(유지):** v0.6.5 Windows 11 VM 실제 검사에서 미니필터가 `ExNotifyCallback`을 **1,083회 호출**했지만 메인 드라이버의 `sink-enter`는 **0회**였다. 미니필터가 새 콜백 객체를 만들지 않고 이미 등록된 메인 드라이버의 이름 있는 객체를 **열도록(Create=FALSE)** 변경했다. 필터 활성화 전 큐에 남지 않는 동기식 연결 검증(probe)을 수행하고, 실제 파일 이벤트에도 16바이트 커널 내부 수신 확인(receipt)을 붙여 큐 등록 성공/거절/수신 부재를 구분한다. 수신자가 없으면 필터 로드를 실패 처리하므로 이전처럼 조용히 이벤트가 유실되지 않는다. 최초 `DriverVer`는 두 프로젝트 모두 `0.6.6.0`이었다. **HOTFIX1의 메인만 `0.6.6.1`로 변경됐다.** 아직 커널 간 실제 파일 이벤트 전달 복구 성공을 주장하지 않는다. [VM_LAB_V0.6.6_KO.md](VM_LAB_V0.6.6_KO.md), [RELEASE_V0.6.6_KO.md](RELEASE_V0.6.6_KO.md) 참조.

**v0.6.5 변경(검증 완료 범위):** `Anti_Ransom_FsFilter/FsFilter.c`와 `Anti_Ransom_Driver/Eventqueue.c`에 단계별 진단을 추가했다. VM에서 두 드라이버 빌드·서명·로드 및 파일 감지 동작은 검증됐지만, 커널 간 파일 이벤트 콜백 수신이 0건으로 확인되었다. 자세한 기존 검사 기록은 [VM_LAB_V0.6.5_KO.md](VM_LAB_V0.6.5_KO.md), [RELEASE_V0.6.5_KO.md](RELEASE_V0.6.5_KO.md)를 참조한다.

**v0.6.4 변경(유지):** `Kernel_test/Anti_Ransom_TestClient.cpp`를 진단용으로 보강했다. 모든 수신 이벤트의 타입·바이트 수·시퀀스 번호를 출력하고, 파일 쓰기/이름 변경 이벤트의 경로/확장자도 확인할 수 있다. 기존 사용법은 [README_DIAGNOSTIC_KO.md](README_DIAGNOSTIC_KO.md)에 있다.

**커널/IPC 호환성:** v0.6.6은 `Shared/Common.h`에 **커널 드라이버끼리만 쓰는 ACK 구조체**를 추가했다. 유저 모드 IOCTL 번호, `ARW_FILE_EVENT`/`ARW_PROCESS_EVENT` 크기, 파일 이벤트 타입, 파이프 이름은 바꾸지 않았다. INF 고도는 격리 VM 임시값 `385090` 그대로다. **메인 드라이버를 먼저 로드한 다음 미니필터를 로드해야 한다.** 미니필터는 여전히 **관측 전용**이고 파일 차단이나 복구를 수행하지 않는다.

**v0.6.3 변경 이력:** 미니필터의 INF 고도 `385100`이 Microsoft MiniSpy에 이미 할당된 것을 확인하여 격리 VM 실험에 한정한 임시 값 `385090`으로 교체했다. 이 값도 정식 할당 고도는 아니다. INF가 변경된 드라이버는 **Windows WDK 카탈로그 재생성·재서명**이 필요하며 이 소스 패키지에는 실행·서명된 바이너리가 없다. 메인 KMDF 및 IPC 프로토콜은 v0.6.2와 동일하다. 기존 VM 검증 순서는 [RELEASE_V0.6.3_KO.md](RELEASE_V0.6.3_KO.md)를 참고한다.

기존 v0.6.1의 기능 수정은 주로 `store`에 있었고, v0.6.2는 Windows 빌드 호환성, v0.6.3은 미니필터 설치 메타데이터, v0.6.4는 테스트 클라이언트 진단, v0.6.5는 파일 이벤트 단계별 진단을 보강했다. v0.6.6은 커널 간 ACK 연결 검증을 추가한 수정안이다. 커널에 스냅샷 생성기를 새로 넣은 것은 아니다.

| 경로 | 역할 / 현재 범위 |
| --- | --- |
| `RansomGuard.sln`, `RansomGuard.props` | Visual Studio/WDK 빌드 구성. HOTFIX1 Debug x64 3/3 빌드·테스트 서명 및 격리 Windows 11 VM 실행 검증 성공; 새 TestClient 진단 출력은 재빌드 필요 |
| `Anti_Ransom_Driver/ProcessMonitor.c` | 프로세스 생성·종료 이벤트, fast path 규칙. 새 설치 기본은 AUDIT; BLOCK 모드는 프로세스 생성 거부 |
| `Anti_Ransom_Driver/ResponseEngine.c` | PID와 예상 생성 시간을 검증한 종료 요청 |
| `Anti_Ransom_Driver/Communication.c` | 엔진 등록·권한 확인·IOCTL, 이벤트 전달 |
| `Anti_Ransom_Driver/Eventqueue.c` | 이벤트 큐와 `FILE_DIAG sink-*` 계측, 커널 간 연결 probe 및 큐 Push 결과 ACK |
| `Anti_Ransom_Driver/SelfProtect.c` | 등록 엔진에 대한 핸들 접근 권한 제한. 모든 관리자/커널 공격을 막는 완전한 보호는 아님 |
| `Anti_Ransom_FsFilter/FsFilter.c` | write/rename 시도 관측, 기존 콜백 객체 열기·probe 확인·이벤트별 ACK 검사; 차단하지 않음 |
| `Anti_Ransom_FsFilter/EntropyDetect.c` | 샘플의 엔트로피 계산. 엔트로피만으로 직접 kill하는 경로 없음 |
| `Shared/Common.h` | 기존 공통 이벤트/IOCTL ABI 불변; 커널 내부 `ARW_FILE_BRIDGE_RECEIPT` 추가. 파일 이벤트에 프로세스 생성 시간은 아직 없음 |
| `Kernel_test` | 수동 수신·상태 조회·종료 명령 클라이언트; 수신한 모든 이벤트의 종류·크기·시퀀스 및 파일 경로 출력(v0.6.4), 실제 프로세스 종료 확인 코드 포함 |

## 남은 구현

1. 의심 **프로세스 instance**별 실제 WFP 통신 차단·해제와 기존 연결/IPv6/UDP 검증.
2. Track B 판정 대기 중 파일 쓰기 억제와 복구 중 재손상 방지.
3. 파일 이벤트의 프로세스 생성 시간, 볼륨/파일 식별자, rename 전후 경로, 최종 결과와 누락 대응.
4. 확인된 악성 증거의 실제 Track A 자동 종료→종료 확인→복구 연동 및 후손 프로세스 대응.
5. Windows 11 VM 기본 기능 검증은 완료. 장시간 부하·충돌·지연·재연결·복구 통합 테스트는 추가 필요. 미니필터 언로드 후 SCM `WIN32_EXIT_CODE=31` 잔존 및 Windows 11 Bypass I/O 미지원 경고는 [RC2 VM 검증 기록](VM_LAB_V0.7.0_RC2_KO.md) 참고.

자세한 빌드 절차는 `BUILD_NOTES.md`, 두 저장소 전체 상태는 `IMPLEMENTATION_STATUS_KO.md`다. 원본의 고엔트로피 누적 후 직접 종료 방식은 이번 설계에서 고엔트로피→Track B로 이어진다. 고엔트로피만으로 악성 확정하지 않으며, 확실한 악성 증거가 있는 Track A의 최종 목표는 즉시 실제 종료다.
