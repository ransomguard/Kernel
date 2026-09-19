# RansomGuard v0.1.1 — ResponseEngine Fix

Windows 커널 레벨 안티랜섬웨어 시스템.
`ResponseEngine.c` 의 로그 호출 누락을 복구하고 정적 분석 경고를 제거한 버전입니다.

**변경일:** 2026-09-19
**이전 버전:** `v0.1.0_kernel-verified`

---

## 이번 버전의 변경

| 파일 | 행 | 변경 | 성격 |
|---|---|---|---|
| `ResponseEngine.c` | 108 | 누락된 `ARW_LOG` 호출 복구 | 버그 수정 |
| `ResponseEngine.c` | 118 | 할당 크기를 `chars * sizeof(WCHAR)` 로 변경 | 경고 제거 |
| 빌드 설정 | — | Inf2Cat 비활성화 | 빌드 오류 해결 |
| 빌드 설정 | — | TestClient 중간 디렉터리 분리 | MSB8028 해결 |

### 108행 — `ARW_LOG` 누락

```c
// 변경 전 — 함수명이 없어 콤마 연산자로 해석됨. 컴파일은 통과하나 로그 미출력.
        ("SeLocateProcessImageName failed (0x%08X) - treating as protected.\n",
            status);

// 변경 후
        ARW_LOG("SeLocateProcessImageName failed (0x%08X) - treating as protected.\n",
            status);
```

임계 프로세스 판정이 실패했을 때 이를 알리는 유일한 경로였습니다.
전체 솔루션을 정규식(`^\s+\(`)으로 전수 검색한 결과, 동일 패턴의 누락은 이 한 곳뿐입니다.

### 118행 — C6385 / C6386

```c
// 변경 전 — 분석기가 chars 와 할당 크기의 관계를 추론하지 못해 오탐 발생
lower = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, imageName->Length, ARW_POOL_TAG);

// 변경 후 — 값은 동일하나 SAL 추적이 가능해짐
lower = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, chars * sizeof(WCHAR), ARW_POOL_TAG);
```

`chars = imageName->Length / sizeof(WCHAR)` 이므로 실제 오버런은 없었습니다. 오탐 제거 목적입니다.

---

## 구성

| 컴포넌트 | 역할 | 상태 |
|---|---|---|
| `Anti_Ransom_Driver` | KMDF 커널 드라이버 — 탐지 / 자기보호 / 즉시 대응 | 검증 완료 |
| `Anti_Ransom_TestClient` | 유저 모드 검증 클라이언트 | 검증 완료 |
| `VssComHook` | `vssvc.exe` COM 후킹 DLL | 미착수 |
| Python 상관분석 엔진 | 가중치 기반 점수화 | 미착수 |

```
Anti_Ransom_Driver/
├── Driver.c / Driver.h
├── Communication.c
├── ProcessMonitor.c
├── ResponseEngine.c        ← 이번 버전 수정
├── SelfProtect.c / SelfProtect.h
├── EventQueue.c / EventQueue.h
└── Common.h                ← 유저/커널 공유 프로토콜 계약

Anti_Ransom_TestClient/
└── Anti_Ransom_TestClient.cpp
```

---

## 빌드 요구사항

- Visual Studio + WDK, Windows SDK 10.0.26100.0, x64
- KMDF (`PlatformToolset = WindowsKernelModeDriver10.0`)
- Driver Signing → Sign Mode: **Test Sign**
- 링커 추가 옵션: **`/INTEGRITYCHECK`** (필수)
- Inf2Cat → Run Inf2Cat: **No**

> `/INTEGRITYCHECK` 누락 시 `PsSetCreateProcessNotifyRoutineEx` 가
> `STATUS_ACCESS_DENIED` 를 반환하여 `DriverEntry` 가 실패하고,
> `sc start` 가 **오류 5**로 거부됩니다. 서명 문제로 오인하기 쉬우므로 주의.

---

## 테스트 환경 구성

**VM 설정 (전원 종료 상태에서)**
- Secure Boot **해제**
- 메모리 무결성(HVCI) **해제**
- 중첩 가상화(VT-x/EPT) **해제** — 켜져 있으면 커널 디버깅 중 `NMI_HARDWARE_FAILURE` 발생

**부팅 구성**
```
bcdedit /set testsigning on
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST> port:50000 key:<KEY>
```

**테스트 인증서를 VM에 설치** (빌드 머신과 VM이 다른 경우 필수)
```powershell
$sig = Get-AuthenticodeSignature Anti_Ransom_Driver.sys
[IO.File]::WriteAllBytes("WDKTestCert.cer", $sig.SignerCertificate.RawData)
certutil -addstore -f root WDKTestCert.cer
certutil -addstore -f TrustedPublisher WDKTestCert.cer
```

---

## 드라이버 로드

```
sc create ARWDrv type= kernel start= demand binPath= "C:\test\Anti_Ransom_Driver.sys"
sc start ARWDrv
sc query ARWDrv
```

**재등록 시**
```
sc stop ARWDrv
sc delete ARWDrv
sc create ARWDrv type= kernel start= demand binPath= "C:\test\Anti_Ransom_Driver.sys"
sc start ARWDrv
```

**WinDbg 로그 활성화**
```
ed nt!Kd_DEFAULT_Mask 0xFFFFFFFF
g
```
`Kd_IHVDRIVER_Mask` 만으로는 `ARW_LOG` 출력이 보이지 않습니다. 이 설정은 재부팅 시 초기화됩니다.

---

## 프로토콜

| 항목 | 값 |
|---|---|
| 디바이스 | `\Device\RansomGuard` / `\\.\RansomGuard` |
| Magic | `0x41525747` (`ARWG`) |
| Version | `0x00010000` |
| 이벤트 구조체 | `ARW_PROCESS_EVENT` (1616 bytes) |
| 큐 | 노드 1632B, 최대 깊이 1024 |
| 패스트패스 규칙 | 9개 |

**IOCTL**

| IOCTL | 코드 | 입력 | 출력 |
|---|---|---|---|
| `REGISTER_ENGINE` | 0x800 | `ARW_REGISTER_REQUEST` (8B) | — |
| `UNREGISTER_ENGINE` | 0x801 | — | — |
| `TERMINATE_PROCESS` | 0x802 | `ARW_TERMINATE_REQUEST` | `ARW_TERMINATE_RESPONSE` |
| `UPDATE_POLICY` | 0x803 | `ARW_POLICY_REQUEST` (20B) | — |
| `GET_STATUS` | 0x804 | — | `ARW_STATUS_RESPONSE` |
| `GET_EVENT` | 0x805 | — | `ARW_PROCESS_EVENT` (1616B) |

**호출 순서:** `REGISTER_ENGINE` 이 관문입니다.
나머지 IOCTL은 `ArwpIsCallerRegisteredEngine()` 검사를 통과해야 하며,
미등록 상태에서 호출하면 `STATUS_ACCESS_DENIED`(오류 5)가 반환됩니다.

**`GET_EVENT`** 는 manual 큐로 이관되어 이벤트 발생까지 **블로킹**됩니다.
큐에 적체분이 있으면 즉시 반환되며, `ArwEventQueuePush` → `ArwEventQueueDrain` 경로로 대기 요청이 완료됩니다.

**동작 특성**
- `FastPathMode`: 0=OFF, 1=AUDIT, 2=BLOCK
- `EnableSelfProtect` 는 런타임 **끄기만** 허용 (켜기는 커널이 거부)
- 엔진 프로세스가 핸들을 닫으면 `ArwEvtFileCleanup` 이 자동 등록 해제
- `CommandLineLength` 는 **바이트** 단위 (NUL 제외)

---

## 회귀 테스트 결과

| 항목 | 결과 |
|---|---|
| 드라이버 로드 | `STATE: 4 RUNNING` |
| 디바이스 오픈 | 성공 |
| IOCTL 왕복 | REGISTER / UPDATE_POLICY / GET_STATUS 성공 |
| 패스트패스 차단 | `vssadmin delete shadows /all` → 액세스 거부 |
| 실시간 이벤트 수신 | `RULE 1001 HIT` 블로킹 대기 중 즉시 수신 |
| 커맨드라인 수집 | `len=60 bytes (30 chars)` — 길이·내용 정확 |

**수신 예시**
```
*** [seq=6] RULE 1001 HIT  PID=9724 PPID=6312 ***
     len=60 bytes (30 chars)
     cmd: vssadmin  delete shadows /all|END
```

---

## v0.1.0 검증 결과 (유효)

| 차수 | 항목 | 결과 |
|---|---|---|
| 1 | 드라이버 로드 / 언로드 | 통과 |
| 2 | 디바이스 오픈 | 통과 |
| 3 | IOCTL 왕복 | 통과 |
| 4 | 이벤트 파이프라인 | 큐 감소 10 + 신규 0 = 수신 10 (오차 0), seq 연속 |
| 5 | 패스트패스 차단 | rules 1001 / 1004 / 1005 발화 |

---

## 트러블슈팅 기록

| 증상 | 원인 | 조치 |
|---|---|---|
| `sc start` 오류 5 | WDKTestCert 가 VM 에 미설치 | `certutil -addstore` (root + TrustedPublisher) |
| `sc start` 오류 5 (지속) | `/INTEGRITYCHECK` 누락 | 링커 추가 옵션 지정 후 재빌드 |
| `CreateFileW` 오류 2 | 심볼릭 링크명 불일치 | `\\.\RansomGuard` 로 수정 |
| IOCTL 오류 5 | 등록 관문 미통과 | `REGISTER_ENGINE` 선행 호출 |
| IOCTL 오류 122 | 입력 버퍼 4B (커널은 20B 요구) | `ARW_POLICY_REQUEST` 전체 전송 |
| WinDbg `NMI_HARDWARE_FAILURE` | VMware 중첩 가상화 | VT-x/EPT 가상화 해제 |
| `Inf2Cat signability test failed` | `sc create` 방식에 불필요한 `.cat` 생성 시도 | Inf2Cat → Run Inf2Cat: No |
| `MSB8028` | 두 프로젝트가 중간 디렉터리 공유 | `$(Platform)\$(Configuration)\$(ProjectName)\` 로 분리 |

---

## 알려진 이슈

1. **`EventsGenerated` 와 `QueueDepth` 불일치**
   `ArwpUnregisterEngine` 의 flush 동작 확인 필요.
   엔진 종료 시 큐를 비우면 누적값과 현재값의 차이가 설명됨.

2. **`EventsDelivered` 카운터 부재**
   `ARW_STATUS_RESPONSE` 에 전달 완료 건수 필드가 없어,
   파이프라인 정합성 검증을 유저 모드 계산(수신 전후 `QueueDepth` 비교)에 의존 중.
   추가 시 `Generated = Delivered + Dropped + Depth` 항등식으로 검증 가능.

---

## 다음 단계

- [ ] `ArwpUnregisterEngine` flush 동작 조사
- [ ] `EventsDelivered` 카운터 추가 (`Common.h` 구조체 변경 → 유저·커널 양쪽 재빌드)
- [ ] Python 상관분석 엔진 연동 (프로토콜 상수는 `Common.h` 기준)
- [ ] `VssComHook` COM 후킹 (`/MT` 정적 런타임 필수)
- [ ] `SelfProtect` 활성화 검증 (최종 — 활성화 시 디버깅·언로드 차단됨)