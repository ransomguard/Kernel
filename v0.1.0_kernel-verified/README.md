# RansomGuard v0.1.0 — Kernel Driver Verified

Windows 커널 레벨 안티랜섬웨어 시스템.
이 버전에서 KMDF 드라이버의 end-to-end 동작이 검증되었습니다.

**검증일:** 2026-09-19
**커널 소스 변경:** 없음 (빌드 설정 및 테스트 클라이언트만 변경)

---

## 이 버전의 범위

| 검증됨 | 미착수 |
|---|---|
| 드라이버 로드 / 언로드 | Python 상관분석 엔진 |
| 유저-커널 IOCTL 통신 | VssComHook COM 후킹 |
| 이벤트 큐 파이프라인 | SelfProtect 활성화 |
| 패스트패스 차단 | IP 차단 / 대시보드 |

---

## 포함 파일

```
Anti_Ransom_Driver/
├── Driver.c / Driver.h
├── Communication.c
├── ProcessMonitor.c
├── ResponseEngine.c
├── SelfProtect.c / SelfProtect.h
├── EventQueue.c / EventQueue.h
└── Common.h              ← 유저/커널 공유 프로토콜 계약

Anti_Ransom_TestClient/
└── Kernel_test.cpp       ← 검증용 유저 모드 클라이언트
```

---

## 빌드 요구사항

- Visual Studio + WDK, Windows SDK 10.0.26100.0, x64
- KMDF (`PlatformToolset = WindowsKernelModeDriver10.0`)
- Driver Signing → Sign Mode: **Test Sign**
- 링커 추가 옵션: **`/INTEGRITYCHECK`** (필수)

> `/INTEGRITYCHECK` 누락 시 `PsSetCreateProcessNotifyRoutineEx` 가
> `STATUS_ACCESS_DENIED` 를 반환하여 `DriverEntry` 가 실패하고,
> `sc start` 가 **오류 5**로 거부됩니다. 서명 문제로 오인하기 쉬우므로 주의.

---

## 테스트 환경 구성

**VM 설정 (전원 종료 상태에서)**
- Secure Boot **해제**
- 메모리 무결성(HVCI) **해제**

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

**WinDbg 로그 활성화**
```
ed nt!Kd_DEFAULT_Mask 0xFFFFFFFF
g
```
`Kd_IHVDRIVER_Mask` 만으로는 `ARW_LOG` 출력이 보이지 않습니다.

**재등록 시**
```
sc stop ARWDrv
sc delete ARWDrv
sc create ARWDrv type= kernel start= demand binPath= "C:\test\Anti_Ransom_Driver.sys"
sc start ARWDrv
```

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

**GET_EVENT** 는 manual 큐로 이관되어 이벤트 발생까지 **블로킹**됩니다.
큐에 적체분이 있으면 즉시 반환됩니다.

**동작 특성**
- `FastPathMode`: 0=OFF, 1=AUDIT, 2=BLOCK
- `EnableSelfProtect` 는 런타임 **끄기만** 허용 (켜기는 커널이 거부)
- 엔진 프로세스가 핸들을 닫으면 `ArwEvtFileCleanup` 이 자동 등록 해제

---

## 검증 결과

| 항목 | 결과 |
|---|---|
| 드라이버 로드 | `STATE: 4 RUNNING` |
| 디바이스 오픈 | 성공 |
| IOCTL 왕복 | REGISTER / UPDATE_POLICY / GET_STATUS 성공 |
| 이벤트 수신 | 10건, 큐 감소 10 + 신규 0 = 10 (오차 0) |
| FIFO 순서 | seq 332–341 연속 |
| 패스트패스 차단 | rules 1001 / 1004 / 1005 발화 |

**커널 로그**
```
[RansomGuard] DriverEntry: initialization started (version 0x00010000).
[RansomGuard] Policy loaded: FastPathMode=2, SelfProtect=0, ProcMon=1
[RansomGuard] Event queue initialized (node=1632 bytes, max depth=1024)
[RansomGuard] Communication module initialized (\DosDevices\RansomGuard).
[RansomGuard] Process monitor initialized (9 fast-path rules).
[RansomGuard] SelfProtect disabled by policy (kill switch).
[RansomGuard] Driver loaded successfully.

[RansomGuard] BLOCKED PID 1372 by rule 1001 (parent 9968)
[RansomGuard] BLOCKED PID 5128 by rule 1004 (parent 9968)
[RansomGuard] BLOCKED PID 8652 by rule 1005 (parent 9968)
```

---

## 트러블슈팅 기록

| 증상 | 원인 | 조치 |
|---|---|---|
| `sc start` 오류 5 | WDKTestCert 가 VM 에 미설치 | `certutil -addstore` (root + TrustedPublisher) |
| `sc start` 오류 5 (지속) | `/INTEGRITYCHECK` 누락 | 링커 추가 옵션 지정 후 재빌드 |
| `CreateFileW` 오류 2 | 심볼릭 링크명 불일치 | `\\.\RansomGuard` 로 수정 |
| IOCTL 오류 5 | 등록 관문 미통과 | `REGISTER_ENGINE` 선행 호출 |
| IOCTL 오류 122 | 입력 버퍼 4B (커널은 20B 요구) | `ARW_POLICY_REQUEST` 전체 전송 |
| WinDbg NMI_HARDWARE_FAILURE | VMware 중첩 가상화 | VT-x/EPT 가상화 해제 |

---

## 알려진 이슈

1. **C6385 / C6386** — `ResponseEngine.c` 125·130행 버퍼 오버런 경고.
   `UNICODE_STRING.Length`(바이트)와 문자 수 혼동 추정.
   임계 프로세스 화이트리스트 로직이므로 **우선 수정 대상**.
2. **`SelfProtect.c` 로그 호출 누락** — `ArwInitializeSelfProtect` 의
   실패 경로에서 `ARW_LOG` 함수명이 빠져 콤마 연산자로 해석됨.
   컴파일은 되나 로그가 출력되지 않음.
3. **`EventsGenerated` 와 `QueueDepth` 불일치** —
   `ArwpUnregisterEngine` 의 flush 동작 확인 필요.
4. **`EventsDelivered` 카운터 부재** — 파이프라인 정합성 검증을
   유저 모드 계산에 의존 중.

---

## 다음 단계

- [ ] 실시간 차단 이벤트 수신 확인 (큐 소진 후 대기 상태에서 `vssadmin` 실행)
- [ ] `ResponseEngine.c` 버퍼 오버런 수정
- [ ] `SelfProtect.c` 로그 호출 복구
- [ ] `EventsDelivered` 카운터 추가
- [ ] Python 상관분석 엔진 연동 (프로토콜 상수는 `Common.h` 기준)
- [ ] `VssComHook` COM 후킹 (`/MT` 필수)
- [ ] `SelfProtect` 활성화 검증 (최종)