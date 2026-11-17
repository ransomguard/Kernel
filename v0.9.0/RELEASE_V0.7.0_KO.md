# RansomGuard Kernel v0.7.0-rc2 — 격리 VM 커널 기능 검증 마일스톤

- 작성일: 2026-11-05 (KST)
- 기준 소스: `v0.6.6_file-event-bridge-ack` HOTFIX1 및 TestClient 진단 보완
- 상태: **릴리스 후보(RC2), Debug/x64 빌드·테스트 서명·격리 Windows 11 VM 수동 기능 검증 통과**
- 대상: `knel` 커널 소스 저장소. `store`, 방화벽, JEV API, UI 저장소는 포함하지 않음.

## 1. v0.6.6 대비 실제 변경

**RC1 빌드 오류 및 RC2 수정:** Windows 10 개발 호스트의 Visual Studio/WDK에서 2026-11-05 00:49 (KST) 최초 빌드 시 StampInf가 두 출력 INF의 날짜를 `11/05/2026`으로 찍었고, UTC 기반 기본 Inf2Cat이 이를 미래 날짜로 판단했다(`22.9.7`). 이후 사용자가 Visual Studio 두 프로젝트의 `Inf2Cat > General > Use Local Time`을 `예(/uselocaltime)`로 설정하여 빌드·카탈로그·서명을 복구했다. RC2 소스에는 이 해결책을 `Inf2CatUseLocalTime=true`로 영구 반영했다. StampInf의 버전 번호 자동 재스탬프(`0.53.42.xxx`) 문제도 두 프로젝트의 `Inf` 메타데이터에서 `TimeStamp=0.7.0.0`으로 고정했다. **이후 RC2 소스로 Debug/x64 3개 프로젝트 빌드 및 테스트 서명에 성공했고, Windows 11 VMware VM에서 실제 설치·로드·기능 검증을 진행했다.**

| 경로 | 변경 내용 | 영향 |
| --- | --- | --- |
| `Anti_Ransom_Driver/Anti_Ransom_Driver.inf` | `DriverVer=11/05/2026,0.7.0.0` | 새 WDK 패키지/카탈로그 생성·테스트 서명 필수 |
| `Anti_Ransom_FsFilter/Anti_Ransom_FsFilter.inf` | `DriverVer=11/05/2026,0.7.0.0` | 새 WDK 패키지/카탈로그 생성·테스트 서명 필수 |
| `Anti_Ransom_Driver/Anti_Ransom_Driver.vcxproj`, `Anti_Ransom_FsFilter/Anti_Ransom_FsFilter.vcxproj` | `Inf2CatUseLocalTime=true`; StampInf `SpecifyDriverVerDirectiveVersion=true`, `TimeStamp=0.7.0.0` | 날짜 검사 오류 방지, INF 버전 고정 (RC2에서 추가) |
| `Anti_Ransom_Driver/SelfProtect.h` | 킬 스위치 설명의 잘못된 `RansomGuard` 서비스명을 실제 `Anti_Ransom_Driver`로 정정 | 주석만 수정, 동작 불변 |
| `README.md`, 본 문서 | 2026-11-05 Windows 11 VM 수동 검증 범위·주의·미완료 항목 기록 | 문서 |

**기능 코드는 v0.6.6에서 변경하지 않았다.** 기존 소스 진단 메시지의 `v0.6.6` 표기는 해당 브리지/핫픽스 구현에서 비롯된 이력 표시다. 공유 `ARW_DRIVER_VERSION=0x00010000`은 별도의 **IPC 호환성 버전**이므로 릴리스 번호에 맞춰 바꾸지 않았다. 이벤트 형식·IOCTL 번호·파이프 이름은 이번 후보에서 변경하지 않았다.

## 2. Windows 11 VMware VM 수동 검증 기록

아래는 **2026-11-05(KST) v0.7.0-rc2 새 빌드**를 사용자가 VMware Windows 11 VM의 PowerShell/TestClient 화면에서 직접 확인한 결과다. 원본 화면의 핵심 값을 [VM_LAB_V0.7.0_RC2_KO.md](VM_LAB_V0.7.0_RC2_KO.md)에 기록했다. 이전 v0.6.6 실험의 로그와 구분한다.

| 검사 | VM 관측 증거 | 판정 |
| --- | --- | --- |
| Visual Studio Debug x64 빌드·테스트 서명 | 3/3 빌드 성공, 두 `.sys`/`.cat` Authenticode `Valid`, INF 버전 `0.7.0.0` | PASS (RC2) |
| 새 패키지 설치 | `pnputil /add-driver ... /install` 성공, 메인 `oem18.inf`, 미니필터 `oem19.inf`; `sc qc` DriverStore 새 경로 확인 | PASS (RC2) |
| 메인/미니필터 로드 및 연결 | 두 서비스 `RUNNING`, `fltmc instances -f Anti_Ransom_FsFilter` 고도 `385090`, 파일 시스템 인스턴스 확인 | PASS (RC2) |
| 파일 이벤트 IPC | `type=4 FILE_WRITE`, `type=5 FILE_RENAME`; `event_test\rc2_test.txt` 이름 변경 후 `Test-Path ...\rc2_renamed.txt`가 `True` | PASS (RC2) |
| 프로세스 생성·종료 이벤트 | `type=1 PROCESS_CREATE`, `type=2 PROCESS_TERMINATE` | PASS (RC2) |
| Fast Path AUDIT | `echo vssadmin delete shadows` 모의 명령에서 `RULE HIT 1001`, 프로세스 생성 허용 | PASS (관측) |
| Fast Path BLOCK | 동일 무해한 문자열 모의 명령에 액세스 거부, `type=3 PROCESS_BLOCKED`, `matchedRule=1001` | PASS (차단), 오탐 주의 |
| 정상 Fast Path 대조군 | `cmd.exe /d /c "echo RG_SAFE"` 정상 출력 | PASS |
| PID 종료 요청 IPC | TestClient `--terminate`로 일반 `cmd.exe` PID `3196` 종료; `ResultStatus=0x00000000`와 종료 확인 | PASS |
| 자기보호 활성화 | 레지스트리 `EnableSelfProtect=1`로 메인 재시작 후 `SelfProtectEnabled=1`, 엔진 PID `6480` 등록 | PASS |
| 외부 강제 종료 차단 | 별도 관리자 PowerShell의 `Stop-Process -Id 6480 -Force`가 액세스 거부; PID `6480` 생존 | PASS |
| 비보호 프로세스 대조군 | 일반 `cmd.exe` PID `9812`는 `Stop-Process` 성공, 이후 조회 결과 없음 | PASS |
| 자기보호 정상 종료·설정 원복 | 엔진 PID `6480` 종료 확인, 메인 `STOPPED` 및 종료 코드 `0`; `EnableSelfProtect=0x0` | PASS |
| 미니필터 언로드 | `fltmc unload` 이후 필터 목록에서 제거, FilterManager Event ID `1`(02:08:48) 성공 기록; `sc query`는 `STOPPED`지만 `WIN32_EXIT_CODE=31` | 기능 PASS / 상태 코드 조사 필요 |

**TestClient `0` 수신 모드의 수신 건수 0은 이벤트 채널 고장이 아니다.** 이벤트 수신을 요청하지 않는 상태 조회로, 파일 이벤트 전송은 앞선 별도 시험에서 검증됐다. RC2 상태 스냅샷에서 `EventsDropped=0`을 확인했으나 이는 장시간 부하·무손실 보증이 아니다.

## 3. 미완료·제약 사항 (v0.7.0 정식 릴리스 판단 시 명시)

1. **오탐:** `echo vssadmin delete shadows`처럼 위험 명령 문자열을 단순 출력하는 무해한 `cmd.exe`도 룰 1001에 의해 차단됐다. 현 Fast Path는 토큰/명령구조/실제 행위를 충분히 구별하지 못한다. 배포용 차단 정책으로 간주할 수 없다.
2. **자기보호 검증 범위:** 외부 프로세스 종료 거부와 일반 프로세스 영향 없음은 확인했지만, 스레드 핸들 권한 박탈·복제 핸들·디버그·업데이트·오류 복구 전체는 별도 검증 필요. 커널 모드 적대자를 막는 완전한 보호 기능이라고 주장하지 않는다.
3. **파일 시스템 보호:** 미니필터는 WRITE/RENAME **관측 전용**이다. 파일 쓰기 차단, 원본 복원, 악성/정상 판별은 이 커널 패키지만으로 수행되지 않는다.
4. **Track A/B 통합:** 룰 기반 즉시 생성 거부는 검증했으나 실제 악성 프로세스 자동 종료→종료 확인→복구 연결, JEV 확률 판정, 의심 PID 단위 WFP 네트워크 격리·해제는 **미완료/미검증**이다.
5. **큐·파일 이벤트 메타데이터:** 고부하/장시간·재연결·누락 대응, 프로세스 인스턴스 식별, rename 전체 경로 및 파일 I/O 최종 결과 보완 필요. RC2 수신 상태의 `EventsDropped=0`과 별개로, v0.6.6 과거 시험에는 초기 큐 포화 손실 381건이 존재했다.
6. **미니필터 종료 상태·호환성:** RC2에서 FilterManager Event ID `1`은 실제 언로드 성공을 기록했으나 SCM `WIN32_EXIT_CODE=31 (0x1f)` 원인은 불명이다. 로드 때 FilterManager Event ID `11`에서 Bypass I/O 미지원(`Supported features: 0x4`) 경고가 발생했다. 둘의 인과관계는 확인되지 않았다. `0x8` 기능 비트를 동작 구현·검토 없이 임의 설정하지 말 것.
7. **배포 제약:** 미니필터 고도 `385090` 및 객체 콜백 고도 `320000`은 격리 VM 연구용 임시값이다. 상용/일반 사용자 Windows 배포를 위한 고유 고도 할당·서명·호환성 검증 전까지 외부 시스템에 설치하지 않는다.

## 4. v0.7.0-rc2 최종 빌드·검증 체크리스트

- [x] Windows 10 개발 호스트 VS + WDK에서 **Debug/x64** 3개 프로젝트 재빌드; 빌드 성공 확인.
- [x] 새 `.sys`, `.inf`, `.cat` 한 세트 생성 및 테스트 서명. 새 패키지의 서명 `Valid` 확인.
- [x] 테스트 서명과 실험용 레지스트리를 격리 VMware Windows 11 VM에서 적용.
- [x] VMware Windows 11 VM에서 DriverStore 새 패키지/실제 `ImagePath` 확인. 메인 먼저, 미니필터 다음으로 로드.
- [x] 파일 type=4/5 전송·Fast Path AUDIT/BLOCK·TestClient IPC 종료 요청을 **RC2 빌드로 재검증**.
- [x] 자기보호 기본 OFF 확인, `EnableSelfProtect=1` 시험·선택적 보호 검증, 엔진 정상 종료 및 레지스트리 `0` 원복. **원복 후 재시작 상태 재확인은 별도 항목.**
- [x] 미니필터 정상 언로드를 FilterManager Event ID `1`로 확인.
- [ ] 미니필터 `WIN32_EXIT_CODE=31` 원인과 Bypass I/O Event ID `11` 검토.
- [ ] 장시간 부하·복구 통합·원복 후 재시작 검증.
- [ ] LICENSE·출처·배포 권한 확인. 소스 ZIP에는 실제 테스트 서명 바이너리 `.sys/.cat`를 포함하지 않음.

## 5. 운영 순서와 킬 스위치

- 기본 로드: `sc.exe start Anti_Ransom_Driver`; 이후 `fltmc.exe load Anti_Ransom_FsFilter`.
- 기본 종료: TestClient/엔진 종료 → `fltmc.exe unload Anti_Ransom_FsFilter` → `sc.exe stop Anti_Ransom_Driver`.
- 자기보호 활성화(격리 VM에서만): `HKLM\SYSTEM\CurrentControlSet\Services\Anti_Ransom_Driver\Parameters\EnableSelfProtect`를 `REG_DWORD 1`로 설정 후 드라이버 재시작.
- 자기보호 비활성화: 같은 DWORD를 `0`으로 변경하고 엔진을 정상 종료한 뒤 드라이버를 재시작. **레지스트리 변경만으로 실행 중 콜백이 즉시 해제되지는 않는다.**
- 변경 이후 문제 발생 시 시스템의 보호 기능을 우회하려 하지 말고 사전 준비한 VMware 스냅샷으로 복구.

## 6. GitHub 릴리스 제목·커밋 예시

- 제안 제목: `v0.7.0-rc2 — Kernel VM validation milestone (Inf2Cat local-time fix)`
- 제안 커밋: `release(kernel): add v0.7.0-rc2 WDK build fix and VM validation`
- 실제 `v0.7.0` 정식 태그는 **새 패키지 빌드·서명·재검증을 통과하고 남은 알려진 제한을 릴리스 노트에 명시한 후** 생성할 것.

이 자료는 VM 수동 테스트 화면과 RC2 소스 검토를 바탕으로 한 **증거 수준의 릴리스 후보 기록**이다. RC2 새 빌드가 실제 실행되었음을 확인했으나 자동화된 재현성 테스트, 정식 서명, 전체 Track A/B·JEV·복구 통합 시험을 대체하지 않는다.
