# RansomGuard knel — v0.6.5 파일 이벤트 파이프라인 진단

사용자의 `knel` 저장소에 넣을 Windows 커널 소스다. 이 폴더에는 복구/JEV Python 코드를 넣지 않았다. 복구·VSS 생성·예약 작업·JEV·사용자 모드 분류와 로그는 별도 `store` 압축파일에 있다.

**v0.6.5 변경:** `Anti_Ransom_FsFilter/FsFilter.c`와 `Anti_Ransom_Driver/Eventqueue.c`에 전송 단계별 횟수 제한 진단 카운터를 추가했다. C:에 미니필터가 붙어 있고 파일 I/O가 실제 성공했는데도 유저모드에서 `type=4/5`가 보이지 않은 원인을 `DebugView`로 나눠 확인하기 위한 릴리스다. 두 INF의 `DriverVer`도 0.6.5.0으로 올렸다. **새 버전 드라이버 2개를 모두 빌드/서명/VM에 설치해야 계측 결과가 의미 있다.** 자세한 절차는 [VM_LAB_V0.6.5_KO.md](VM_LAB_V0.6.5_KO.md) 및 [RELEASE_V0.6.5_KO.md](RELEASE_V0.6.5_KO.md) 참조.

**v0.6.4 변경(유지):** `Kernel_test/Anti_Ransom_TestClient.cpp`를 진단용으로 보강했다. 모든 수신 이벤트의 타입·바이트 수·시퀀스 번호를 출력하고, 파일 쓰기/이름 변경 이벤트의 경로/확장자도 확인할 수 있다. 기존 사용법은 [README_DIAGNOSTIC_KO.md](README_DIAGNOSTIC_KO.md)에 있다.

**커널/IPC 호환성:** v0.6.5의 실질적 변화는 커널/미니필터 로깅이다. INF 고도(격리 VM용 임시 `385090`), 공용 `Shared/Common.h`, IOCTL 번호 및 메시지 구조체는 그대로 유지한다. 미니필터는 여전히 **관측 전용**이며 파일 차단/종단 간 전달 성공을 주장하지 않는다. 실제 Windows 11 빌드·서명·로드·진단 검증은 사용자 VM에서 수행해야 한다.

**v0.6.3 변경 이력:** 미니필터의 INF 고도 `385100`이 Microsoft MiniSpy에 이미 할당된 것을 확인하여 격리 VM 실험에 한정한 임시 값 `385090`으로 교체했다. 이 값도 정식 할당 고도는 아니다. INF가 변경된 드라이버는 **Windows WDK 카탈로그 재생성·재서명**이 필요하며 이 소스 패키지에는 실행·서명된 바이너리가 없다. 메인 KMDF 및 IPC 프로토콜은 v0.6.2와 동일하다. 기존 VM 검증 순서는 [RELEASE_V0.6.3_KO.md](RELEASE_V0.6.3_KO.md)를 참고한다.

기존 v0.6.1의 기능 수정은 주로 `store`에 있었고, v0.6.2는 Windows 빌드 호환성 문제를 수정했다. v0.6.3은 미니필터 설치 메타데이터 수정 릴리스이고, 이번 v0.6.4는 테스트 클라이언트 진단 보강 릴리스다. 커널에 스냅샷 생성기를 새로 넣은 것은 아니다.

| 경로 | 역할 / 현재 범위 |
| --- | --- |
| `RansomGuard.sln`, `RansomGuard.props` | Visual Studio/WDK 빌드 구성. v0.6.5 Windows 빌드는 아직 미검증 |
| `Anti_Ransom_Driver/ProcessMonitor.c` | 프로세스 생성·종료 이벤트, fast path 규칙. 새 설치 기본은 AUDIT; BLOCK 모드는 프로세스 생성 거부 |
| `Anti_Ransom_Driver/ResponseEngine.c` | PID와 예상 생성 시간을 검증한 종료 요청 |
| `Anti_Ransom_Driver/Communication.c` | 엔진 등록·권한 확인·IOCTL, 이벤트 전달 |
| `Anti_Ransom_Driver/Eventqueue.c` | 제한된 이벤트 큐와 `FILE_DIAG sink-*` 계측. callback 진입/검증/적재 단계 분리 |
| `Anti_Ransom_Driver/SelfProtect.c` | 등록 엔진에 대한 핸들 접근 권한 제한. 모든 관리자/커널 공격을 막는 완전한 보호는 아님 |
| `Anti_Ransom_FsFilter/FsFilter.c` | write/rename 시도 관측과 고엔트로피 플래그. `diag-pre*`, `diag-notify-*` 계측; 차단은 하지 않음 |
| `Anti_Ransom_FsFilter/EntropyDetect.c` | 샘플의 엔트로피 계산. 엔트로피만으로 직접 kill하는 경로 없음 |
| `Shared/Common.h` | 공통 이벤트/IOCTL ABI. 파일 이벤트에는 프로세스 생성 시간이 아직 없음 |
| `Kernel_test` | 수동 수신·상태 조회·종료 명령 클라이언트; 수신한 모든 이벤트의 종류·크기·시퀀스 및 파일 경로 출력(v0.6.4), 실제 프로세스 종료 확인 코드 포함 |

## 남은 구현

1. 의심 **프로세스 instance**별 실제 WFP 통신 차단·해제와 기존 연결/IPv6/UDP 검증.
2. Track B 판정 대기 중 파일 쓰기 억제와 복구 중 재손상 방지.
3. 파일 이벤트의 프로세스 생성 시간, 볼륨/파일 식별자, rename 전후 경로, 최종 결과와 누락 대응.
4. 확인된 악성 증거의 실제 Track A 자동 종료→종료 확인→복구 연동 및 후손 프로세스 대응.
5. Windows 11 VM에서 빌드·서명·로드·충돌·지연·기능 검증.

자세한 빌드 절차는 `BUILD_NOTES.md`, 두 저장소 전체 상태는 `IMPLEMENTATION_STATUS_KO.md`다. 원본의 고엔트로피 누적 후 직접 종료 방식은 이번 설계에서 고엔트로피→Track B로 이어진다. 고엔트로피만으로 악성 확정하지 않으며, 확실한 악성 증거가 있는 Track A의 최종 목표는 즉시 실제 종료다.
