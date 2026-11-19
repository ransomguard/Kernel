# RansomGuard Kernel v0.8.0 — 2026-11-16

## 이번 변경의 목적과 결과

v0.7.1에서 원본 v0.5.0의 프로세스 생성 콜백·자기보호 코드는 남아 있었지만,
기본 Fast Path가 AUDIT(1)이었고 테스트 클라이언트도 실행 때마다 AUDIT으로
덮어썼다. 게다가 `echo vssadmin delete shadows` 같은 무해한 명령도 문자열
포함만으로 오탐했다. 고엔트로피 51회 직접 종료는 이전 버전에서 제거돼
Track B로 이동했으나 **그것만으로 전체 Track B 자동 대응이 완성되지는 않았다**.

v0.8.0은 우선 **명백한 위험 명령의 프로세스 생성 사전 차단**과
**기존 Python v0.3.1 ABI v1 호환성**을 회복하는 소스 업데이트다.

### 실제 수정 파일

- `Anti_Ransom_Driver/FastPathPolicy.c/.h` **신규**: 풀 할당 없는 독립 C 규칙 엔진. 실제 `PS_CREATE_NOTIFY_INFO.ImageFileName`의 실행 파일 이름을 확인하고, 인자를 토큰 단위로 파싱한다. 단순 부분 문자열이 아니라 실행 파일+동작 조합으로 판단. 입력 길이 상한 4,096 UTF-16 코드 단위.
- `Anti_Ransom_Driver/ProcessMonitor.c`: 이벤트 메모리 할당보다 **먼저** 규칙을 계산하여 할당 실패가 차단 실패로 이어지지 않도록 변경. `CreationStatus=STATUS_ACCESS_DENIED`를 유지하며 `EVENT_TYPE_PROCESS_BLOCKED(3)` 및 규칙 ID를 기록. 부모 이름만으로 허용하던 우회 제거.
- `Anti_Ransom_Driver/Driver.c`·INF: 새 설치 Fast Path 기본 BLOCK(2). 예전 VM의 `Parameters/FastPathMode=1`은 **NOCLOBBER**로 보존되니 실제 동작 상태를 꼭 확인한다.
- `Kernel_test/Anti_Ransom_TestClient.cpp`: 명시적 `--policy` 없이는 현재 Fast Path를 건드리지 않는다. `--selfprotect off`만 전달할 때 현재 Fast Path를 조회해 유지한다.
- 두 드라이버 INF/WDK 프로젝트: `0.8.0.0` 릴리스 표기 및 새 C 모듈 포함.
- `tests/fastpath_policy_smoke.c`: 실제 커널과 같은 C 판별 함수를 대상으로 29개 정상·악성·오탐 회귀 사례 검사.

### 위험 명령 규칙

| Rule ID | 실제 실행 파일 | 인자 조건 | BLOCK 모드 동작 |
|---|---|---|---|
| 1001 | `vssadmin.exe` | `delete shadows` | 생성 거부 |
| 1002 | `vssadmin.exe` | `resize shadowstorage` | 생성 거부 |
| 1003 | `wmic.exe` | `shadowcopy … delete` | 생성 거부 |
| 1004 | `wbadmin.exe` | `delete catalog/systemstatebackup/backup` | 생성 거부 |
| 1005 | `bcdedit.exe` | `/set … recoveryenabled no` | 생성 거부 |
| 1006 | `bcdedit.exe` | `/set … bootstatuspolicy ignoreallfailures` | 생성 거부 |
| 1007 | `wevtutil.exe` | `cl` | 생성 거부 |
| 1008 | `cipher.exe` | `/w` 또는 `/w:<path>` | 생성 거부 |
| 1009 | `powershell.exe`/`pwsh.exe` | `win32_shadowcopy` 및 `delete` 텍스트 | **감사만**, 생성 거부 안 함 |

`/?` 등 도움말 토큰은 차단 대상에서 제외한다. 실제 Windows 인자 파서의
모든 문법을 구현한 것은 아니므로 복잡한 인용·경유 실행·우회 변형은 아직
현장 검증이 필요하다. 정상 유지보수의 VSS/로그/백업 정리도 BLOCK될 수 있다.
**일반 PC에 설치하거나 운영 중인 백업 서버에서 시험하지 말 것.**

## 구현하지 않은 것 / 절대로 혼동하지 말 것

- 미니필터의 파일 WRITE/RENAME은 **관측만** 하며 쓰기 차단·격리를 하지 않는다.
- Shannon entropy >=7.5는 **Track B 의심 신호**일 뿐, 커널이 51회 후 자동 종료하지 않는다.
- Fast Path 차단은 해당 자식 프로세스 생성을 막는다. 랜섬웨어라고 의심되는 부모 PID를 자동으로 kill하거나 VSS 복구를 호출하는 것은 아니다.
- `Shared/Common.h` ABI v1 이벤트 타입 1–5, 구조체 1616/2232B, IOCTL 번호를 **유지**했다. v0.3.1은 그대로 수신 가능하다. 파일 이벤트에 PID 생성시간이 없는 한계도 그대로다.
- 실제 WFP 방화벽은 별도 **PC 전체 outbound+JEV 허용** 데몬 담당. 커널 단독 WFP, per-PID WFP는 구현하지 않았다.
- `ObRegisterCallbacks` 자기보호는 opt-in이다. 활성화 시 개발자 디버거까지 막힐 수 있다.
- 직접 COM VSS 삭제, 복사·이름 변경한 실행 파일, 명령줄 난독화, 커널 이벤트 유실은 추가 보완 대상이다.

## 수행한 검증

- Linux `cc`로 **실제 FastPathPolicy.c**를 `-std=c11 -Wall -Wextra -Werror -pedantic` 빌드 후 29개 사례 통과.
- 커널 Python 회귀 테스트 **5/5 통과**(Fast Path 연결, ABI 크기·상수, 큐 FIFO 시퀀스).
- 별도 v0.3.1 소스의 Python 테스트 **189/189 통과**, 포함된 wheel과 소스 모듈 바이트 일치.
- **Windows WDK 빌드/서명/VM 커널 로드/실제 차단은 아직 미검증**. 이 ZIP에 `.sys`, `.cat`, `.exe`를 포함하지 않는다.

## 격리 VM 재검증: 실제 삭제를 시도하지 않는 안전한 절차

1. VMware 현재 상태를 스냅샷으로 저장한다. 기존 로드 드라이버/파일은 보존하고, 별도 폴더에 v0.8.0 소스를 압축 해제한다.
2. Windows 호스트 Visual Studio + WDK에서 `RansomGuard.sln`을 열고 **Debug | x64**로 `Anti_Ransom_Driver`, `Anti_Ransom_FsFilter`, `Anti_Ransom_TestClient` **세 프로젝트**를 새로 빌드·테스트 서명한다. `DriverVer`가 `0.8.0.0`인지 확인한다. DLL/EXE만 복사하지 말고 새 서명된 메인·미니필터 패키지를 VM에 설치한다.
3. DebugView `Capture Kernel` 활성화, **메인 드라이버 먼저 로드 → 미니필터 로드**. `fltmc filters`, `fltmc instances -f Anti_Ransom_FsFilter`와 드라이버 상태를 확인한다.
4. v0.8.0 TestClient로 현재 `FastPathMode`를 조회한다. 이전 VM 레지스트리 값 때문에 `1`일 수 있다. 격리 VM 스냅샷 복원 경로가 확보된 경우에만 `Anti_Ransom_TestClient.exe 0 --policy block`을 별도 1회 실행하여 `2`로 바꾸고 종료한다. **관측용 Python과 TestClient는 동시에 엔진 등록할 수 없다**.
5. 무해한 정상 명령 `wevtutil el`이 실행되는지 확인한다. 차단 검증 시에는 실제 로그가 없는 고유 이름만 사용: `wevtutil cl RansomGuard_NONEXISTENT_LAB_080_20261116`. 성공적인 사전 차단이라면 프로세스 생성 자체가 거부되고 드라이버 `ProcessesBlocked`가 증가한다. 만약 차단이 작동하지 않아도 해당 이름의 채널은 존재하지 않아 삭제 대상이 없다.
6. **`vssadmin delete shadows`, `wbadmin delete`, 실존 이벤트 로그의 `wevtutil cl`을 테스트로 실행하지 않는다.** 차단에 실패하면 복구 수단/로그가 실제 삭제된다.
7. Python `ransomguard observe --config ... --db ... --limit 20`으로 이벤트 1–5, `process_creation_blocked`의 RuleId, 파일 이벤트의 고엔트로피 플래그를 확인한다. 첫 단계에서는 `--live-track-b`를 켜지 않는다. 이후 통합 시험은 별도 VM 스냅샷, 방화벽 데몬, JEV 토큰, 복구 매니페스트와 함께 진행한다.

## 핵심 위험

v0.8.0은 운영 배포용이 아니다. 특히 **기존 VM 레지스트리 FastPathMode=1인 경우 새 .sys를 설치해도 차단은 켜지지 않는다.** 재부팅/드라이버 재로드 시 다시 적용되는 정책도 확인할 것. kernel-to-JEV-to-firewall-to-recovery 전체 자동화와 사용자 UI는 **여전히 통합 검증 전**이다.
