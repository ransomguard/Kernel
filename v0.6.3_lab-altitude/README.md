# RansomGuard knel — v0.6.3 격리 VM 미니필터 고도 수정

사용자의 `knel` 저장소에 넣을 Windows 커널 소스다. 이 폴더에는 복구/JEV Python 코드를 넣지 않았다. 복구·VSS 생성·예약 작업·JEV·사용자 모드 분류와 로그는 별도 `store` 압축파일에 있다.

**v0.6.3 변경:** 미니필터의 INF 고도 `385100`이 Microsoft MiniSpy에 이미 할당된 것을 확인하여 격리 VM 실험에 한정한 임시 값 `385090`으로 교체했다. 이 값도 정식 할당 고도는 아니다. INF가 변경되어 **Windows 호스트에서 WDK 카탈로그 재생성·재서명이 필요**하며, 이 ZIP에는 실행·서명된 바이너리가 없다. 메인 KMDF 및 IPC 프로토콜은 v0.6.2와 동일하다. 새 VM 검증 순서는 [RELEASE_V0.6.3_KO.md](RELEASE_V0.6.3_KO.md)를 참고한다.

기존 v0.6.1의 기능 수정은 주로 `store`에 있었고, v0.6.2는 Windows 빌드 호환성 문제를 수정했다. 현재 v0.6.3은 미니필터 설치 메타데이터 수정 릴리스이며 커널에 스냅샷 생성기를 새로 넣은 것은 아니다.

| 경로 | 역할 / 현재 범위 |
| --- | --- |
| `RansomGuard.sln`, `RansomGuard.props` | Visual Studio/WDK 빌드 구성. Windows 빌드는 아직 미검증 |
| `Anti_Ransom_Driver/ProcessMonitor.c` | 프로세스 생성·종료 이벤트, fast path 규칙. 새 설치 기본은 AUDIT; BLOCK 모드는 프로세스 생성 거부 |
| `Anti_Ransom_Driver/ResponseEngine.c` | PID와 예상 생성 시간을 검증한 종료 요청 |
| `Anti_Ransom_Driver/Communication.c` | 엔진 등록·권한 확인·IOCTL, 이벤트 전달 |
| `Anti_Ransom_Driver/Eventqueue.c` | 제한된 이벤트 큐; 유실 가능성을 상태와 함께 확인해야 함 |
| `Anti_Ransom_Driver/SelfProtect.c` | 등록 엔진에 대한 핸들 접근 권한 제한. 모든 관리자/커널 공격을 막는 완전한 보호는 아님 |
| `Anti_Ransom_FsFilter/FsFilter.c` | 일부 write/rename 시도 관측과 고엔트로피 플래그 전달. 현재 파일 쓰기 차단은 하지 않음 |
| `Anti_Ransom_FsFilter/EntropyDetect.c` | 샘플의 엔트로피 계산. 엔트로피만으로 직접 kill하는 경로 없음 |
| `Shared/Common.h` | 공통 이벤트/IOCTL ABI. 파일 이벤트에는 프로세스 생성 시간이 아직 없음 |
| `Kernel_test` | 수동 수신·상태 조회·종료 명령 클라이언트; 실제 프로세스 종료 확인 코드 포함 |

## 남은 구현

1. 의심 **프로세스 instance**별 실제 WFP 통신 차단·해제와 기존 연결/IPv6/UDP 검증.
2. Track B 판정 대기 중 파일 쓰기 억제와 복구 중 재손상 방지.
3. 파일 이벤트의 프로세스 생성 시간, 볼륨/파일 식별자, rename 전후 경로, 최종 결과와 누락 대응.
4. 확인된 악성 증거의 실제 Track A 자동 종료→종료 확인→복구 연동 및 후손 프로세스 대응.
5. Windows 11 VM에서 빌드·서명·로드·충돌·지연·기능 검증.

자세한 빌드 절차는 `BUILD_NOTES.md`, 두 저장소 전체 상태는 `IMPLEMENTATION_STATUS_KO.md`다. 원본의 고엔트로피 누적 후 직접 종료 방식은 이번 설계에서 고엔트로피→Track B로 이어진다. 고엔트로피만으로 악성 확정하지 않으며, 확실한 악성 증거가 있는 Track A의 최종 목표는 즉시 실제 종료다.
