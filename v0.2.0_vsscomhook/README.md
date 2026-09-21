\# RansomGuard v0.2.0 — VssComHook (COM 후킹 방어)



Windows 커널 레벨 안티랜섬웨어 시스템.

커널 프로세스 감시로는 잡히지 않는 \*\*VSS COM 직접 호출\*\*을,

유저 모드 IAT 후킹으로 차단하는 계층을 추가한 버전입니다.



\*\*변경일:\*\* 2026-09-21

\*\*이전 버전:\*\* `v0.1.2\_event-accounting`



\---



\## 이번 버전의 핵심 — 다층 방어 실증



랜섬웨어의 VSS(섀도 복사본) 삭제는 두 경로가 있으며, 각각 다른 계층에서 차단됩니다.



| 공격 경로 | 방어 계층 | 결과 |

|---|---|---|

| `vssadmin delete shadows` (프로세스 실행) | 커널 패스트패스 (rule 1001) | ✅ 차단 |

| `IVssBackupComponents` COM 직접 호출 | \*\*VssComHook (유저 모드 IAT 후킹)\*\* | ✅ 차단 |



\*\*COM 직접 호출은 프로세스를 생성하지 않아 커널 감시를 우회\*\*합니다.

이 사각지대를 VssComHook이 메웁니다 — defense-in-depth 의 실물 구현입니다.



\---



\## 우회 및 차단 실측



\### 공격 시뮬레이터로 커널 우회 확인 (VssComHook 없을 때)



`VssAttackSim.exe` 가 `vssadmin.exe` 를 거치지 않고 COM API 로 직접 삭제:



| 관찰 | 결과 |

|---|---|

| WinDbg 커널 로그 | 무반응 — 커널이 \*\*전혀 감지 못 함\*\* |

| 섀도 복사본 | 실제로 삭제됨 |



→ 프로세스 기반 탐지의 사각지대가 실측으로 확인됨.



\### VssComHook 적용 후 차단



| 관찰 | 결과 |

|---|---|

| `CreateVssBackupComponents` | `hr=0x80070005` (E\_ACCESSDENIED) |

| 이후 단계 (Query/DeleteSnapshots) | 도달 못 함 |

| 섀도 복사본 5개 | 그대로 유지 (삭제 0) |



→ 같은 COM 공격이 유저 모드 후킹으로 차단됨.



\---



\## 컴포넌트 구성



| 컴포넌트 | 역할 | 상태 |

|---|---|---|

| `Anti\_Ransom\_Driver` | KMDF 커널 드라이버 — 탐지 / 즉시 대응 | 검증 완료 (v0.1.2) |

| `Anti\_Ransom\_TestClient` | 유저 모드 검증 클라이언트 | 검증 완료 |

| `VssComHook` | VSS COM 후킹 DLL | \*\*차단 검증 완료 (이번)\*\* |

| `VssAttackSim` | 공격 시뮬레이터 (검증 도구) | \*\*이번 추가\*\* |

| Python 상관분석 엔진 | 가중치 점수화 | 미착수 |



```

Anti\_Ransom\_Driver/       (v0.1.2 그대로, 변경 없음)

├── Driver.c/.h, Communication.c, ProcessMonitor.c

├── ResponseEngine.c, SelfProtect.c/.h, EventQueue.c/.h



Shared/

└── Common.h              유저·커널 공유 계약 (IOCTL\_RG\_REPORT\_VSS\_ATTEMPT 포함)



Anti\_Ransom\_TestClient/

└── Anti\_Ransom\_TestClient.cpp



VssComHook/               ← 이번 핵심

└── VssComHook.cpp        IAT 후킹 + 차단



VssAttackSim/             ← 이번 추가 (검증 전용)

└── VssAttackSim.cpp      VSS COM 직접 호출 시뮬레이터

```



\---



\## VssComHook 동작



\### 후킹 방식 — 호출자 IAT 후킹



```

VssAttackSim 이 CreateVssBackupComponents() 호출

&#x20; → vsbackup.h 의 inline 래퍼가

&#x20;   vssapi.dll!CreateVssBackupComponentsInternal 을 IAT 경유로 호출

&#x20; → VssComHook 이 메인 exe(GetModuleHandle(NULL))의 IAT 에서

&#x20;   해당 슬롯을 HookedCreateVssInternal 로 교체

&#x20; → 우리 함수가 대신 실행됨

```



\- 후킹 대상: `vssapi.dll!CreateVssBackupComponentsInternal`

&#x20; (`CreateVssBackupComponents` 는 이를 부르는 inline 래퍼)

\- 설치: PE import 테이블 순회 → IAT 슬롯 `VirtualProtect` 후 주소 교체 → 원본 백업

\- 해제: `DLL\_PROCESS\_DETACH` 에서 원상 복구



\### 현재 차단 방식 (3-1)



`HookedCreateVssInternal` 이 원본을 호출하지 않고 `E\_ACCESSDENIED` 반환

→ VSS 객체 생성 자체를 봉쇄.



\*\*한계:\*\* 이 방식은 VSS 전체를 막으므로 정상 백업 SW 도 차단됨(오탐).

정밀 차단(`DeleteSnapshots` 만 차단)은 vtable 후킹으로 확장 예정 (3-2, 미착수).



\### 진단 장치



IAT 에서 대상 함수를 못 찾으면, `vssapi.dll` 로부터 임포트되는

모든 함수 이름을 `C:\\test\\vsshook.log` 에 덤프해 실제 이름을 확인.



\---



\## 빌드 요구사항



\*\*공통\*\*

\- Visual Studio 2022, 플랫폼 도구 집합 \*\*v143\*\*, x64



\*\*Anti\_Ransom\_Driver\*\* (변경 없음)

\- WDK, Windows SDK 10.0.26100.0, KMDF

\- 링커 `/INTEGRITYCHECK` 필수, Test Sign, Inf2Cat: No



\*\*VssComHook / VssAttackSim\*\*

\- 구성 형식: DLL / 콘솔 exe

\- \*\*런타임 `/MT`(또는 `/MTd`) 필수\*\* — 대상 프로세스에 Debug DLL 이 없을 수 있음

\- x64 (대상 프로세스가 64비트이므로 32비트 DLL 은 주입 불가)

\- VssAttackSim 링크: `vssapi.lib`, `ole32.lib`, `oleaut32.lib`

&#x20; (VssAttackSim.cpp 에 `#pragma comment` 로 포함)



> Debug 런타임(`/MDd`)으로 빌드하면 VM 에서 `MSVCP140D.dll 없음` 으로 로드 실패.



\---



\## 테스트 환경



VMware Win11 (26100)

\- Secure Boot 해제, HVCI 해제, 중첩 가상화(VT-x/EPT) 해제

\- testsigning on, 커널 net 디버깅

\- \*\*`wmic` 은 최신 Win11 에서 제거됨\*\* → 섀도 생성은 아래로:

```powershell

&#x20; Enable-ComputerRestore -Drive "C:\\"

&#x20; (Get-WmiObject -List Win32\_ShadowCopy).Create("C:\\", "ClientAccessible")

&#x20; vssadmin list shadows

```



\---



\## 검증 절차 (VssComHook)



\*\*사전:\*\* `del C:\\test\\vsshook.log` (로그 초기화)



```

1\. VssComHook.dll (/MT, x64) → C:\\test\\ 복사

2\. 섀도 복사본 존재 확인 (vssadmin list shadows)

3\. VssAttackSim.exe delete-all      (관리자 권한)

4\. type C:\\test\\vsshook.log         (후킹 로그 확인)

5\. vssadmin list shadows            (삭제 안 됐는지 확인)

```



\*\*검증 성공 로그:\*\*

```

\[VssComHook] DLL\_PROCESS\_ATTACH - loaded into target.

\[VssComHook] IAT hook installed.

\[VssComHook] \*\*\* INTERCEPTED - BLOCKING (E\_ACCESSDENIED) \*\*\*

```



\*\*콘솔:\*\*

```

\[FAIL] CreateVssBackupComponents  (hr=0x80070005)

```



\---



\## 로그 방식



`OutputDebugStringW` + DebugView 는 이 VM 환경에서 캡처되지 않아,

`C:\\test\\vsshook.log` 파일 로그로 대체. 후킹 설치·가로채기·차단이 모두 파일에 기록됨.



\---



\## 트러블슈팅 기록 (이번 버전)



| 증상 | 원인 | 조치 |

|---|---|---|

| DLL 로드 시 `MSVCP140D.dll 없음` | Debug 동적 런타임(`/MDd`) | `/MTd` 정적 런타임 |

| `wmic` 명령 없음 | 최신 Win11 에서 제거됨 | `Win32\_ShadowCopy.Create` 사용 |

| `Checkpoint-Computer` ServiceDisabled | 시스템 보호 꺼짐 | `Enable-ComputerRestore` |

| 플랫폼 도구 집합 `v145` 없음 | 프로젝트 설정 오류 | `v143` 으로 변경 |

| DebugView 무반응 | 세션/캡처 문제 (미해결) | 파일 로그로 대체 |



\---



\## 검증 요약



| 항목 | 결과 |

|---|---|

| 공격 시뮬레이터 COM 직접 호출 | 동작 |

| 커널 우회 확인 | WinDbg 무반응 + 삭제 성공 |

| DLL 주입 (LoadLibrary) | 성공 |

| IAT 후킹 설치 | `IAT hook installed` |

| COM 생성 가로채기 | `INTERCEPTED` |

| VSS 삭제 차단 | E\_ACCESSDENIED, 섀도 5개 유지 |



\---



\## 알려진 이슈 / 한계



1\. \*\*차단 방식이 광범위\*\* — `CreateVss` 자체를 막아 정상 백업 SW 도 차단됨.

&#x20;  `DeleteSnapshots` 만 막는 vtable 후킹(3-2)으로 정밀화 필요.

2\. \*\*주입이 수동\*\* — `VssAttackSim` 이 스스로 `LoadLibrary`.

&#x20;  실전에서는 외부 인젝터 또는 커널 연동(의심 프로세스 자동 주입)이 필요.

3\. \*\*커널 연동 미구현\*\* — `IOCTL\_RG\_REPORT\_VSS\_ATTEMPT`(0x806) 는 Common.h 에

&#x20;  정의만 존재. 커널 switch 핸들러 및 VssComHook 의 보고 로직 미착수.



\---



\## 다음 단계



\- \[ ] 3-2: `DeleteSnapshots` vtable 후킹 (정밀 차단, 오탐 감소)

\- \[ ] 외부 인젝터 또는 커널 연동 주입

\- \[ ] `IOCTL\_RG\_REPORT\_VSS\_ATTEMPT` 커널 핸들러 + VssComHook 보고 로직

\- \[ ] Python 상관분석 엔진 연동

\- \[ ] `SelfProtect` 활성화 검증 (최종)

