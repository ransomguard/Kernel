\# RansomGuard v0.1.2 — Event Accounting



Windows 커널 레벨 안티랜섬웨어 시스템.

이벤트 파이프라인의 정합성을 검증할 수 있도록 통계 카운터를 보강한 버전입니다.



\*\*변경일:\*\* 2026-09-19

\*\*이전 버전:\*\* `v0.1.1\_responseengine-fix`



\---



\## 이번 버전의 변경



| 파일 | 변경 | 목적 |

|---|---|---|

| `Common.h` | `ARW\_STATUS\_RESPONSE` 에 `EventsDelivered`, `EventsFlushed` 추가 (56 → 72B) | 항등식 검증 |

| `Driver.c` / `Driver.h` | 전역 카운터 2개 정의·선언 | — |

| `EventQueue.c` | `ArwEventQueueDrain` 전달 성공 시 `EventsDelivered` 증가 | — |

| `EventQueue.c` | `ArwEventQueueFlush` 노드 폐기 시 `EventsFlushed` 증가 | — |

| `Communication.c` | `ArwpHandleGetStatus` 응답에 두 필드 반영 | — |

| TestClient | 통계 출력 + 항등식 검산 | — |

| 빌드 설정 | TestClient 폴더의 중복 `Common.h` 제거 | 프로토콜 계약 단일화 |



\### 항등식



```

EventsGenerated = EventsDelivered + EventsDropped + EventsFlushed + QueueDepth

```



이 한 줄로 이벤트 누수 여부를 판정할 수 있습니다.

모든 이벤트는 \*\*전달 / 폐기(포화) / flush(엔진 해제) / 잔여\*\* 중 하나의 상태로 추적됩니다.



\### 중복 Common.h 제거



TestClient 폴더에 구버전 `Common.h` 복사본이 있어, 따옴표 include 우선순위에 따라

컴파일러가 이 파일을 참조하고 있었습니다(IntelliSense는 정상 경로를 참조하여 오류가 엇갈림).

유저·커널이 동일한 프로토콜 계약을 공유해야 하므로 복사본을 삭제하고 `Shared/Common.h` 로 일원화했습니다.



\---



\## 구성



| 컴포넌트 | 역할 | 상태 |

|---|---|---|

| `Anti\_Ransom\_Driver` | KMDF 커널 드라이버 — 탐지 / 자기보호 / 즉시 대응 | 검증 완료 |

| `Anti\_Ransom\_TestClient` | 유저 모드 검증 클라이언트 | 검증 완료 |

| `VssComHook` | `vssvc.exe` COM 후킹 DLL | 미착수 |

| Python 상관분석 엔진 | 가중치 기반 점수화 | 미착수 |



```

Anti\_Ransom\_Driver/

├── Driver.c / Driver.h          ← 전역 카운터 추가

├── Communication.c              ← 응답 필드 반영

├── ProcessMonitor.c

├── ResponseEngine.c

├── SelfProtect.c / SelfProtect.h

└── EventQueue.c / EventQueue.h  ← 카운터 증가 지점



Shared/

└── Common.h                     ← 유저/커널 공유 프로토콜 계약 (단일본)



Anti\_Ransom\_TestClient/

└── Anti\_Ransom\_TestClient.cpp

```



\---



\## 빌드 요구사항



\- Visual Studio + WDK, Windows SDK 10.0.26100.0, x64

\- KMDF (`PlatformToolset = WindowsKernelModeDriver10.0`)

\- Driver Signing → Sign Mode: \*\*Test Sign\*\*

\- 링커 추가 옵션: \*\*`/INTEGRITYCHECK`\*\* (필수)

\- Inf2Cat → Run Inf2Cat: \*\*No\*\*

\- 중간 디렉터리는 프로젝트별로 분리: `$(Platform)\\$(Configuration)\\$(ProjectName)\\`



> `/INTEGRITYCHECK` 누락 시 `PsSetCreateProcessNotifyRoutineEx` 가

> `STATUS\_ACCESS\_DENIED` 를 반환하여 `DriverEntry` 가 실패하고,

> `sc start` 가 \*\*오류 5\*\*로 거부됩니다.



> `Common.h` 변경 시 \*\*유저·커널 양쪽 모두 재빌드\*\*해야 합니다.

> 한쪽만 갱신하면 구조체 크기 불일치로 IOCTL이 \*\*오류 122\*\*를 반환합니다.



\---



\## 테스트 환경 구성



\*\*VM 설정 (전원 종료 상태에서)\*\*

\- Secure Boot \*\*해제\*\*

\- 메모리 무결성(HVCI) \*\*해제\*\*

\- 중첩 가상화(VT-x/EPT) \*\*해제\*\* — 커널 디버깅 중 `NMI\_HARDWARE\_FAILURE` 방지



\*\*부팅 구성\*\*

```

bcdedit /set testsigning on

bcdedit /debug on

bcdedit /dbgsettings net hostip:<HOST> port:50000 key:<KEY>

```



\*\*테스트 인증서를 VM에 설치\*\*

```powershell

$sig = Get-AuthenticodeSignature Anti\_Ransom\_Driver.sys

\[IO.File]::WriteAllBytes("WDKTestCert.cer", $sig.SignerCertificate.RawData)

certutil -addstore -f root WDKTestCert.cer

certutil -addstore -f TrustedPublisher WDKTestCert.cer

```



\---



\## 드라이버 로드



```

sc create ARWDrv type= kernel start= demand binPath= "C:\\test\\Anti\_Ransom\_Driver.sys"

sc start ARWDrv

sc query ARWDrv

```



\*\*재등록 시\*\*

```

sc stop ARWDrv

sc delete ARWDrv

sc create ARWDrv type= kernel start= demand binPath= "C:\\test\\Anti\_Ransom\_Driver.sys"

sc start ARWDrv

```



\*\*WinDbg 로그 활성화\*\* (재부팅 시 초기화됨)

```

ed nt!Kd\_DEFAULT\_Mask 0xFFFFFFFF

g

```



\---



\## 프로토콜



| 항목 | 값 |

|---|---|

| 디바이스 | `\\Device\\RansomGuard` / `\\\\.\\RansomGuard` |

| Magic | `0x41525747` (`ARWG`) |

| Version | `0x00010000` |

| 이벤트 구조체 | `ARW\_PROCESS\_EVENT` (1616 bytes) |

| 상태 구조체 | `ARW\_STATUS\_RESPONSE` (\*\*72 bytes\*\*, v0.1.2 에서 변경) |

| 큐 | 노드 1632B, 최대 깊이 1024 |

| 패스트패스 규칙 | 9개 |



\*\*IOCTL\*\*



| IOCTL | 코드 | 입력 | 출력 |

|---|---|---|---|

| `REGISTER\_ENGINE` | 0x800 | `ARW\_REGISTER\_REQUEST` (8B) | — |

| `UNREGISTER\_ENGINE` | 0x801 | — | — |

| `TERMINATE\_PROCESS` | 0x802 | `ARW\_TERMINATE\_REQUEST` | `ARW\_TERMINATE\_RESPONSE` |

| `UPDATE\_POLICY` | 0x803 | `ARW\_POLICY\_REQUEST` (20B) | — |

| `GET\_STATUS` | 0x804 | — | `ARW\_STATUS\_RESPONSE` (72B) |

| `GET\_EVENT` | 0x805 | — | `ARW\_PROCESS\_EVENT` (1616B) |



\*\*호출 순서:\*\* `REGISTER\_ENGINE` 이 관문입니다.

나머지 IOCTL은 `ArwpIsCallerRegisteredEngine()` 검사를 통과해야 하며,

미등록 상태에서 호출하면 `STATUS\_ACCESS\_DENIED`(오류 5)가 반환됩니다.



\*\*`GET\_EVENT`\*\* 는 manual 큐로 이관되어 이벤트 발생까지 \*\*블로킹\*\*됩니다.

적체분이 있으면 즉시 반환되며, `ArwEventQueuePush` → `ArwEventQueueDrain` 경로로 대기 요청이 완료됩니다.



\*\*동작 특성\*\*

\- `FastPathMode`: 0=OFF, 1=AUDIT, 2=BLOCK

\- `EnableSelfProtect` 는 런타임 \*\*끄기만\*\* 허용 (켜기는 커널이 거부)

\- 엔진이 핸들을 닫으면 `ArwEvtFileCleanup` → `ArwpUnregisterEngine` → \*\*큐 flush\*\*

\- `CommandLineLength` 는 \*\*바이트\*\* 단위 (NUL 제외)

\- 통계 카운터는 드라이버 언로드 시 초기화됨



\---



\## 검증 결과



| 항목 | 결과 |

|---|---|

| 드라이버 로드 | `STATE: 4 RUNNING` |

| 새 구조체(72B) 통신 | 정상 |

| 패스트패스 차단 | `vssadmin delete shadows /all` → 액세스 거부 |

| 실시간 이벤트 수신 | `RULE 1001 HIT` 블로킹 대기 중 즉시 수신 |

| \*\*항등식\*\* | \*\*19 = 13 + 0 + 1 + 5 (일치)\*\* |



\*\*실측값\*\*

```

수신 전:  Generated 19,  Delivered 10,  Dropped 0,  Flushed 1,  Depth 8

수신 후:  Generated 19,  Delivered 13,  Dropped 0,  Flushed 1,  Depth 5

&#x20;         → 10+0+1+8 = 19,  13+0+1+5 = 19

```



`EventsFlushed = 1` 은 이전 세션 종료 시 엔진 해제로 큐가 비워졌음을 의미합니다.



\---



\## 트러블슈팅 기록



| 증상 | 원인 | 조치 |

|---|---|---|

| `sc start` 오류 5 | WDKTestCert 미설치 | `certutil -addstore` (root + TrustedPublisher) |

| `sc start` 오류 5 (지속) | `/INTEGRITYCHECK` 누락 | 링커 추가 옵션 지정 |

| `CreateFileW` 오류 2 | 심볼릭 링크명 불일치 | `\\\\.\\RansomGuard` 사용 |

| IOCTL 오류 5 | 등록 관문 미통과 | `REGISTER\_ENGINE` 선행 호출 |

| IOCTL 오류 122 | 구조체 크기 불일치 | 유저·커널 양쪽 재빌드 |

| `C2039` 는 나는데 IntelliSense 는 정상 | `Common.h` 중복본 | TestClient 폴더의 복사본 삭제 |

| WinDbg `NMI\_HARDWARE\_FAILURE` | VMware 중첩 가상화 | VT-x/EPT 해제 |

| `Inf2Cat signability test failed` | 불필요한 `.cat` 생성 | Run Inf2Cat: No |

| `MSB8028` | 중간 디렉터리 공유 | `$(ProjectName)` 추가로 분리 |



\---



\## 알려진 이슈



없음. v0.1.1 의 미결 항목(`EventsDelivered` 부재, flush 동작 미확인)이 모두 해소되었습니다.



\---



\## 다음 단계



\- \[ ] Python 상관분석 엔진 연동 (프로토콜 상수는 `Shared/Common.h` 기준, 구조체 확정됨)

\- \[ ] `VssComHook` COM 후킹 (`/MT` 정적 런타임 필수)

\- \[ ] `SelfProtect` 활성화 검증 (최종 — 활성화 시 디버깅·언로드 차단됨)

