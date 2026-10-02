# RansomGuard v0.4.1 — Backslash Recovery (소스 백슬래시 손상 복구)

여러 소스 파일에서 백슬래시가 소실된 손상을 복구하고, 손상으로 조용히
무효화됐던 핵심 안전장치가 실제로 동작함을 VM에서 재검증한 버전입니다.

**변경일:** 2026-09-28
**이전 버전:** `v0.4.0_unload-protection`

---

## 배경 — 조용한 손상

소스 파일들에서 백슬래시가 전부 소실되는 손상이 발견됐습니다
(`L"\windows\system32\lsass.exe"` → `L"windowssystem32lsass.exe"`,
`"...\n"` → `"...n"`, `L'\0'` → `L'0'`). 이 손상은 컴파일 오류를 내지 않고
런타임 동작만 깨뜨려, 빌드는 정상이지만 핵심 기능이 무효화된 상태로
오래 방치될 수 있는 종류입니다.

### 손상으로 무효화됐던 치명 항목 3가지

| 위치 | 손상 | 실제 영향 |
|---|---|---|
| CriticalProcess.h 보호 목록 | 경로 백슬래시 소실 | 임계 프로세스 보호 목록이 어떤 NT 경로에도 매칭되지 않아 무효화. lsass/csrss 종료 시 시스템 다운 위험 |
| Driver.c / FsFilter.c 레지스트리 경로 | `\Parameters` → `Parameters` | 레지스트리 키 조립 실패로 정책(FastPathMode/SelfProtect/UnloadProtection)이 항상 기본값. 킬 스위치 무력화 |
| ProcessMonitor.c / CriticalProcess.h 종단 | `L'\0'` → `L'0'` | NUL 종단 소실로 경계 밖 읽기(OOB) 가능 |

---

## 복구 방식 — 손상만 국소 복구, 작업은 보존

git 추적 파일은 HEAD와 비교해 손상분(백슬래시만 제거된 쌍)과 의도된
작업분을 분류하고, 손상분만 복구했습니다. 통째 되돌리기는 하지 않았습니다.

- 손상 복구: 백슬래시, `\n`, `L'\0'` 종단 복원
- 보존: 이벤트 집계(EventsDelivered/Flushed), ResponseEngine.c의
  CriticalProcess.h 이관 리팩터, ARW_FILE_EVENT 구조체 등 의도된 작업
- 미추적 파일은 손상 시그니처 기반으로 판별해 복구

복구 후 `git diff HEAD`에는 의도된 작업 변경만 남는 것을 확인했습니다.

---

## 검증 결과 (VM)

VMware Win11 (26100), testsigning on.

| 검증 | 확인 내용 | 결과 |
|---|---|---|
| 임계 프로세스 보호 | lsass 종료 요청 → DebugView `Refused: PID ... is a protected system process` | 화이트리스트 매칭으로 거부 (fail-closed 아님) |
| 레지스트리 킬 스위치 | EnableSelfProtect=1 설정 후 재시작 → `Policy loaded: ... SelfProtect=1` | 레지스트리를 실제로 읽어 정책 반영 |
| 언로드 회귀 | `DriverUnload: cleanup complete` + 통계 정상 | 회귀 없음 |

> 핵심은 "코드만 복구된 것이 아니라 실제 동작까지 살아났는지"입니다.
> 보호 목록이 화이트리스트 매칭(`protected system process`)으로 거부하고,
> 킬 스위치가 레지스트리 값을 실제로 읽는 것을 로그로 확인했습니다.

---

## 함께 반영된 것

- 세 `Common.h` 사본(Shared / Kernel_test / VssAttackSim) 바이트 단위 동기화.
  Kernel_test 사본의 구버전(56B) ABI 불일치 해소.
- `ARW_FILE_EVENT` 구조체 추가 (파일 조작 이벤트 전달용, 2232B).
- 루트의 1세대 `Common.h`를 아카이브로 이동(이름 충돌 방지).

---

## 알려진 한계 / 참고

- 백업 리포의 소스도 동일한 백슬래시 손상이 있어 복구 출처로 쓸 수 없었습니다.
  미추적 파일은 손상 시그니처 패턴으로 판별했습니다.
- 커널 .sys 빌드는 WDK 버전 정합이 맞는 환경(VS 2022 + 해당 WDK)에서 수행합니다.

---

## 다음 단계

- [ ] 미니필터 파일 조작 감지 콜백 (IRP_MJ_WRITE 로그 전송, IRP_MJ_SET_INFORMATION 확장자 변경)
- [ ] 시스템 경로 1차 필터링
- [ ] Track B (파일 조작 로그 → 유저 모드 분석) 연동