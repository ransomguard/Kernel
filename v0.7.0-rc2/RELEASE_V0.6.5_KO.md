# RansomGuard Kernel v0.6.5 — 파일 이벤트 단계별 진단

릴리스 날짜: 2026-11-04 (KST)

## 확인된 문제

Windows 11 격리 VMware VM에서 사용자가 제공한 실측 결과:

- `Anti_Ransom_Driver` 및 `Anti_Ransom_FsFilter` 모두 `RUNNING`.
- `fltmc instances -f Anti_Ransom_FsFilter`: C: 인스턴스 연결, 고도 385090.
- v0.6.4 테스트 클라이언트가 프로세스 생성/종료 이벤트 50건을 수신.
- 클라이언트가 추가 이벤트를 기다리는 동안 `.NET WriteAllBytes`로 8192바이트를 쓰고 `Rename-Item`으로 파일 이름을 변경했으며 파일이 실제 생성됨.
- 이 시점까지 클라이언트에 `type=4 (FILE_WRITE)` / `type=5 (FILE_RENAME)` 출력이 없었음.

따라서 **프로세스 이벤트 IPC는 통과**, **파일 이벤트의 종단 간 전달은 미통과**다. 원인은 아직 특정되지 않았으며 파일 pre-op 관측, 커널 콜백 객체, 메인 드라이버 싱크/큐 중 하나일 수 있다.

## 코드 변경

| 파일 | 변경 |
| --- | --- |
| `Anti_Ransom_FsFilter/FsFilter.c` | write pre-op 진입, rename 대상 요청, 이벤트 준비, `ExNotifyCallback` 호출을 구분하여 단계별 계수. 1, 2, 4, 8... 번째에만 로그를 남겨 출력량 제한. 언로드 때 전체 요약. |
| `Anti_Ransom_Driver/Eventqueue.c` | 싱크 콜백 진입/검증 통과/거부/큐 적재 성공·실패를 구분하여 단계별 계수. 1, 2, 4, 8... 번째에만 로그를 남기고 언로드 시 요약. |
| `Anti_Ransom_Driver/Driver.c` | 제어 드라이버가 정말 v0.6.5 바이너리인지 식별하는 로드 로그. |
| `Anti_Ransom_Driver/*.inf`, `Anti_Ransom_FsFilter/*.inf` | `DriverVer` 날짜/버전 갱신: 2026-11-04, 0.6.5.0. 빌드 출력은 WDK의 INF stamping 때문에 표시값이 달라질 수 있음. |
| `README.md`, `VM_LAB_V0.6.5_KO.md`, 이 문서 | 실험 결과/안전한 새 버전 배포/로그별 판별법. |

## 변경하지 않은 범위

- `Shared/Common.h` 공용 ABI, IOCTL 코드, 이벤트 구조체 크기 및 버전 상수.
- 커널의 차단/종료 정책, `ProcessMonitor`, 파일 이벤트 큐의 전달 정책.
- v0.6.4에서 개선한 테스트 클라이언트 로직.
- 복구/JEV/store, 방화벽 매니저, 대시보드.
- 임시 고도 `385090`. 이 값은 정식 배정 고도가 아니며 격리 VM 실험 전용이다.

**진단 로깅은 고장 지점을 식별하는 도구이지 버그가 이미 수정됐다는 뜻이 아니다.** 미니필터는 여전히 관측 전용이며 쓰기를 차단하지 않는다.

## 검증 상태

- 소스 기준 추가 인터페이스/구조체 변경 없음, Debug x64 Visual Studio/WDK 프로젝트 구성 유지.
- 제공 압축파일은 **소스만 포함**하며 `.sys`, `.cat` 및 테스트 인증서/개인키를 포함하지 않는다.
- 이 실행 환경은 Windows MSVC/WDK를 제공하지 않으므로 **v0.6.5 실제 빌드/서명/로드는 미수행**. Windows 10 호스트에서 VS 2022 + WDK 26100으로 재빌드해야 한다.
- 테스트 이전 VMware 스냅샷 생성 필수. 호스트 운영체제에 커널 드라이버를 설치하지 않는다.

실행 안내: [VM_LAB_V0.6.5_KO.md](VM_LAB_V0.6.5_KO.md).
