# RansomGuard Kernel v0.7.0-rc2 — Windows 11 격리 VM 실제 검증

- 검증일: 2026-11-05 (KST)
- 호스트: Windows 10 + Visual Studio/WDK
- 게스트: VMware Workstation의 Windows 11 격리 테스트 VM
- 소스 스냅샷: `v0.7.0-rc2` (`Inf2CatUseLocalTime=true`, INF `DriverVer=11/05/2026,0.7.0.0`)
- 근거: 사용자가 공유한 관리자 PowerShell, TestClient, Event Log 화면의 수동 관측
- 범위: **VM 내 기능 스모크 테스트**. 장시간 스트레스, 정식 제품 배포 검증이 아님.

## 1. 빌드, 서명, 배포

1. Debug/x64 Visual Studio/WDK 솔루션 3개 프로젝트 빌드 성공.
2. 메인/미니필터 `.sys` 및 `.cat`에 대해 `Get-AuthenticodeSignature` 결과 `Valid` 확인.
3. 두 INF에서 `DriverVer=11/05/2026,0.7.0.0` 확인.
4. `pnputil.exe /add-driver ... /install` 성공: 메인 `oem18.inf`, 미니필터 `oem19.inf`로 게시.
5. `sc.exe qc`에서 각 드라이버의 `BINARY_PATH_NAME`이 신규 DriverStore FileRepository를 가리킴.
6. 이 GitHub 소스 폴더/ZIP에는 로컬 VM에서 만든 시험 서명 `.sys`, `.cat`, `.cer` 또는 실행 바이너리를 포함하지 않음.

## 2. 런타임 기능 결과

| 기능 | 수동 관측 | 결과 |
| --- | --- | --- |
| 메인 커널 드라이버 | `sc.exe start` 후 `RUNNING`, 오류 코드 `0` | PASS |
| 미니필터 | `fltmc.exe load`, `RUNNING`, 고도 `385090`으로 C: 등 볼륨 인스턴스 부착 | PASS |
| 프로세스 이벤트 | TestClient에서 `PROCESS_CREATE(type=1)`, `PROCESS_TERMINATE(type=2)` 수신 | PASS |
| 파일 WRITE | TestClient에서 `FILE_WRITE(type=4)` 및 NT 장치 경로 출력 | PASS |
| 파일 RENAME | `event_test\rc2_test.txt` 이름 변경 시 `FILE_RENAME(type=5)` 수신, `rc2_renamed.txt` 존재 `True` | PASS |
| Fast Path AUDIT | `cmd.exe /d /c "echo vssadmin delete shadows"` 문자열 모의 명령에서 `RULE HIT 1001`, 생성 허용 | PASS |
| Fast Path BLOCK | 위 문자열 모의 명령 거부, `PROCESS_BLOCKED(type=3)`, `matchedRule=1001` | PASS |
| BLOCK 정상 대조군 | `echo RG_SAFE` 정상 출력 | PASS |
| IPC PID 종료 | 일반 `cmd.exe` PID `3196`에 대한 `--terminate` 결과 `ResultStatus=0x00000000`, 실제 종료 확인 | PASS |
| 큐 관측 | 한 상태 조회에서 `EventsGenerated=554`, `EventsDropped=0`, `EventsDelivered=538`, `QueueDepth=13`, `EventsFlushed=3` | 관측값 기록 |

주의: `echo vssadmin delete shadows`는 실제 볼륨 섀도 복사본을 삭제하지 않는 **무해한 문자열 출력**이다. 이 명령이 BLOCK 모드에서 거부된 점은 기능 검증과 동시에 **실사용 시 오탐 위험**을 보여준다.

## 3. 자기보호 검증 및 원복

1. 미니필터와 메인 드라이버를 중지한 뒤 `EnableSelfProtect=1` 설정, 메인 재시작.
2. `Anti_Ransom_TestClient.exe 300 --policy audit --selfprotect keep` 실행 결과 `SelfProtectEnabled=1`, `EngineProcessId=6480`, `FastPathMode=1` 확인.
3. 별도 관리자 PowerShell에서 `Stop-Process -Id 6480 -Force` 실행 → **액세스 거부**, 이후 PID `6480` 생존.
4. 같은 관리자 PowerShell에서 대조군 `cmd.exe` PID `9812` 생성 → `Stop-Process -Id 9812 -Force` 성공, 이후 프로세스 조회 결과 없음.
5. TestClient 정상 종료 후 PID `6480` 조회 결과 없음. `sc.exe stop Anti_Ransom_Driver` → `STOPPED`, `WIN32_EXIT_CODE=0`, `SERVICE_EXIT_CODE=0`.
6. 레지스트리 `EnableSelfProtect=0x0` 원복 확인. **이후 메인 드라이버를 다시 시작하여 OFF 상태를 재확인하는 테스트는 수행하지 않았다.**

자기보호의 검증 범위는 다른 관리자 프로세스의 `Stop-Process -Force` 종료 시도와 일반 프로세스에 대한 선택성이다. 모든 프로세스 조작 경로·커널 모드 공격에 대한 방어를 보증하지 않는다.

## 4. 미니필터 종료와 남은 경고

- `fltmc.exe unload Anti_Ransom_FsFilter` 이후 필터가 목록에서 사라지고 서비스가 `STOPPED`가 됨.
- Windows System 로그의 FilterManager **Event ID 1, 02:08:48**은 `Anti_Ransom_FsFilter`의 성공적 언로드를 명시.
- 그러나 `sc.exe query Anti_Ransom_FsFilter`는 `WIN32_EXIT_CODE=31 (0x1f)`을 표시. 이 값의 원인은 확인되지 않았으며 단순히 무시하거나 완전 무오류 종료라고 단정하지 않음.
- 로드 시 **Event ID 6, 01:47:01**은 필터 등록 성공 기록.
- 같은 시각 **Event ID 11**은 Windows 11 Bypass I/O 미지원 경고와 `Supported features: 0x4` 기록. Bypass I/O 기능 비트는 `0x8`이며, 이 경고와 종료 코드 31 사이의 인과관계는 입증되지 않음.
- Bypass I/O 비트를 실제 지원 또는 적절한 veto 처리 검토 없이 INF에 무작정 설정하지 말 것.

## 5. 판정과 다음 과제

**판정: RC2의 빌드·설치·핵심 기능 VM 스모크 테스트 PASS.** 정식 `v0.7.0` 완료 판정과 구분한다.

남은 과제: (1) Fast Path 명령 문자열 오탐 개선, (2) 파일 WRITE/RENAME 관측 이후 탐지·차단 정책과 원본 복구 통합, (3) Track A 자동 대응 및 Track B/JEV 확률판정, (4) 의심 PID 단위 네트워크 격리와 해제, (5) 미니필터 코드 31 및 Bypass I/O 호환성 분석, (6) 이벤트 고부하·장시간·재연결·파일 결과 정확성 검증, (7) 정식 서명 및 고도 할당.

이 문서는 테스트 캡처를 옮겨 적은 검증 메모이며 실제 캡처 파일, `.sys/.cat` 시험 서명 바이너리 또는 Windows VM 이미지는 포함하지 않는다.
