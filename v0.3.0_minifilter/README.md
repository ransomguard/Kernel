# RansomGuard v0.3.0 — Minifilter (파일 암호화 탐지 계층)



Windows 커널 레벨 안티랜섬웨어 시스템.

커널 프로세스 감시로는 잡히지 않는 **파일 대량 암호화 행위**를,

파일시스템 미니필터로 실시간 탐지·대응하는 계층을 추가한 버전입니다.



**변경일:** 2026-09-22

**이전 버전:** `v0.2.0_vsscomhook`



---



## 이번 버전의 핵심 — 파일 암호화 탐지 계층 추가



방어 대상 4개(디렉터리 대량 탐색 / 파일 대량 암호화 / VSS 삭제 / MBR 변조) 중,

그동안 미구현이던 **"파일 대량 암호화"** 를 담당하는 계층을 신설했습니다.



기존 v0.2.0까지는 랜섬웨어의 **선행 행위**(VSS 삭제 등 복구 수단 제거)만 차단했습니다.

프로세스 생성 콜백(`PsSetCreateProcessNotifyRoutineEx`)과 USN Journal은

**이미 완료된 변경만 기록**하므로, 진행 중인 파일 암호화를 실시간으로 포착하지 못하는

구조적 사각지대가 있었습니다. 미니필터는 파일 I/O 경로(pre-write)에 직접 개입해

이 사각지대를 메웁니다.



| 공격 경로 | 방어 계층 | 결과 |

|---|---|---|

| `vssadmin delete shadows` (프로세스 실행) | 커널 패스트패스 (rule 1001) | ✅ 차단 |

| `IVssBackupComponents` COM 직접 호출 | VssComHook (유저 모드 IAT 후킹) | ✅ 차단 |

| **파일 대량 암호화 (고엔트로피 쓰기)** | **미니필터 (Anti_Ransom_FsFilter)** | ✅ **탐지·프로세스 정리 (이번)** |



---



## 아키텍처 원칙 — 완전 분리



미니필터는 기존 `Anti_Ransom_Driver`와 **별개의 .sys로 분리**되어 있습니다.



- **격리:** 미니필터가 크래시하거나 로드에 실패해도, 검증된 기존 기능

&#x20; (프로세스 감시 / VSS fast-path / IOCTL 통신)에 영향이 번지지 않습니다.

- **자기완결:** 미니필터는 감지→대응(프로세스 정리)을 자체적으로 수행하며,

&#x20; 두 드라이버 간 커널 통신은 두지 않았습니다.

- **안전장치 공유:** 시스템 임계 프로세스 화이트리스트만 `Shared/CriticalProcess.h`로

&#x20; 추출해 양쪽 드라이버가 공유합니다(아래 참조).



> altitude와 디바이스 이름이 겹치지 않으므로, 미니필터와 기존 드라이버는

> **동시에 로드**할 수 있습니다. 데모 완성형은 둘 다 로드된 상태입니다.



---



## 컴포넌트 구성



| 컴포넌트 | 역할 | 로드 방식 | 상태 |

|---|---|---|---|

| `Anti_Ransom_Driver` | KMDF 커널 드라이버 — 프로세스 감시 / VSS fast-path / IOCTL | `sc start` | 검증 완료 (v0.2.0) |

| `Anti_Ransom_FsFilter` | 파일시스템 미니필터 — 암호화 탐지 / 프로세스 정리 | `fltmc load` | **검증 완료 (이번)** |

| `Anti_Ransom_TestClient` | 유저 모드 검증 클라이언트 (엔진 역할) | 실행 | 검증 완료 |

| `VssComHook` | VSS COM 후킹 DLL | DLL 주입 | 검증 완료 (v0.2.0) |

| Python 상관분석 엔진 | 가중치 점수화 | — | 미착수 |



```

Anti_Ransom_Driver/        (v0.2.0, ResponseEngine.c만 리팩터링)

├── Driver.c/.h, Communication.c, ProcessMonitor.c

├── ResponseEngine.c, SelfProtect.c/.h, EventQueue.c/.h



Anti_Ransom_FsFilter/      ← 이번 핵심 (독립 미니필터)

├── FsFilter.c             본체: DriverEntry, FltRegisterFilter, pre-write 콜백, 프로세스 정리

├── EntropyDetect.c/.h     판정: 엔트로피 계산 + PID별 쓰기 카운트 + 임계 판정

└── Anti_Ransom_FsFilter.inf   Class=ActivityMonitor, Altitude=385100



Shared/

├── Common.h               유저·커널 공유 계약 (기존)

└── CriticalProcess.h      임계 프로세스 화이트리스트 (신규, 양쪽 드라이버 공유)

```



---



## 미니필터 동작



### 탐지 방식



1. `FsFilter.c`의 pre-write 콜백(`IRP_MJ_WRITE`)이 파일 쓰기를 **관찰**합니다.

2. `EntropyDetect.c`가 쓰기 버퍼의 **고엔트로피 여부**(암호문 수준)를 판정하고,

&#x20;  **프로세스(PID)별로 고엔트로피 쓰기 횟수를 누적**합니다.

3. 특정 프로세스가 임계값을 초과하면, 대량 암호화 행위로 간주해 그 프로세스를 정리합니다.



### 대응 방식 — 프로세스 정리 (I/O 거부 아님)



pre-write 콜백에서 쓰기 I/O 자체를 거부하지 않습니다.

정상 프로그램이 오판될 경우 그 앱의 동작이 막혀 데모가 불안정해지기 때문입니다.

관찰·카운트만 미니필터가 담당하고, 실제 대응은 프로세스 정리 경로

(`ObOpenObjectByPointer` → `ZwTerminateProcess`)로 처리합니다.



### 임계 프로세스 보호 (공유 안전장치)



미니필터가 프로세스를 정리하므로, csrss/lsass 등 시스템 임계 프로세스를

정리하면 `CRITICAL_PROCESS_DIED`로 시스템이 다운됩니다.

이를 막기 위해 기존 `ResponseEngine.c`에서 검증된 화이트리스트

(목록 + 경로 접미사 비교 + fail-closed 원칙)를 `Shared/CriticalProcess.h`로

**static inline 함수로 추출**해 양쪽 드라이버가 공유합니다.

프로세스 정리 직전 이 헤더로 보호 대상 여부를 검사하며, 이미지 경로를

얻지 못하면 보호 대상으로 간주(fail-closed)합니다.



<!-- TODO: 실제 임계 상수 값 확인 후 반영 (EntropyDetect.h)

&#x20;    - 임계 쓰기 횟수 (기본값)

&#x20;    - 엔트로피 임계값 (bit/byte 기준) -->



---



## 빌드 요구사항



**Anti_Ransom_FsFilter (미니필터)**

- 플랫폼 도구 집합: **`WindowsKernelModeDriver10.0`** (WDM Empty, KMDF 아님)

- Windows SDK 10.0.26100.0, x64

- 링커 입력: **`fltMgr.lib`** 필수

- 링커 옵션: `/INTEGRITYCHECK` 필수

- C/C++: `/utf-8`

- Driver Signing: **Test Sign**, Inf2Cat: **No**



> **주의 — KMDF 아님:** 미니필터는 필터 매니저 모델이므로 KMDF가 아닌 WDM으로

> 구성해야 합니다. KMDF 템플릿으로 만들면 링커에 `/ENTRY:"FxDriverEntry"`와

> `WdfDriverEntry.lib`가 잡혀, `DriverEntry`가 `WdfDriverCreate`를 호출하지 않는

> 미니필터 구조와 어긋나 로드에 실패합니다.



> **빌드 도구:** VS 2026(18) 환경에서는 26100 WDK에 해당 빌드 태스크가 없어

> 빌드가 실패합니다. **VS 2022(17.14) MSBuild**로 빌드합니다.



---



## 설치 / 로드 (요약)



상세 절차는 **`SETUP_MINIFILTER.md`** 참조. 핵심만:



```

# 전제: testsigning on + 재부팅, 테스트 인증서 신뢰 등록(certutil)



# 서비스 등록 (INF 카탈로그 미서명 환경 우회 — sc 직접 등록)

copy Anti_Ransom_FsFilter.sys %SystemRoot%System32drivers

sc create Anti_Ransom_FsFilter type= filesys binPath= %SystemRoot%System32driversAnti_Ransom_FsFilter.sys



# altitude / 인스턴스 레지스트리 (ParametersInstances 아래)

#   DefaultInstance / Altitude=385100 / Flags=0



# 로드 및 확인

fltmc load Anti_Ransom_FsFilter

fltmc filters          # Anti_Ransom_FsFilter / Altitude 385100 확인

```



> Debug 구성은 `Inf2Cat=No`라 `.cat`이 없습니다. 이 때문에 `InfDefaultInstall`

> (SetupAPI 경로)은 "디지털 서명 정보 없음"으로 거부되므로, 위와 같이

> `sc create` + 레지스트리로 직접 등록해 우회합니다. `.sys` 자체는

> `/INTEGRITYCHECK` 임베디드 테스트 서명이 있어 testsigning 환경에서 로드됩니다.



---



## 검증 결과 (VM)



VMware Win11 (26100), testsigning on.



| 시나리오 | 관찰 | 결과 |

|---|---|---|

| 미니필터 로드 | `fltmc filters`에 `Anti_Ransom_FsFilter` / Altitude 385100 표시 | ✅ |

| **고엔트로피 대량 쓰기** (암호학적 난수 60개 파일) | 임계 초과 시점에 해당 프로세스가 강제 종료됨 (끝까지 도달 못 함) | ✅ **탐지·정리** |

| **저엔트로피 대량 쓰기** (0으로 채운 60개 파일, 대조군) | 종료되지 않고 정상 완료 | ✅ **오판 없음** |

| 기존 드라이버 동시 로드 | `sc start Anti_Ransom_Driver` 후 테스트 클라이언트 연결·엔진 등록·정책 갱신 정상 | ✅ **회귀 없음** |



> 고엔트로피(암호화)는 정리하고 저엔트로피(정상 파일)는 통과시키는 두 장면이,

> "복구 수단이 아니라 암호화 행위 자체를 탐지하되 정상 작업은 방해하지 않는다"는

> 이번 계층의 설계 목표를 실증합니다.



---



## 알려진 한계



1. **데모 수준 탐지** — 단순 임계값 기반이며, 정교한 오탐 튜닝·성능 최적화는

&#x20;  범위에서 제외했습니다. 정상 암호화/압축 프로그램(7-Zip, VeraCrypt 등)과의

&#x20;  구분은 엔트로피·카운트 휴리스틱 수준에 머뭅니다.

2. **차단이 아닌 사후 정리** — pre-write에서 I/O를 거부하지 않으므로, 임계 도달

&#x20;  전까지의 쓰기는 디스크에 반영됩니다. 실시간 차단이 아니라 "임계 초과 시 정리"입니다.

3. **INF 카탈로그 미서명** — Debug 구성이라 정식 카탈로그 서명이 없어, 표준 INF

&#x20;  설치 경로 대신 `sc` 직접 등록으로 우회합니다. 정식 배포 시 카탈로그 서명 필요.

4. **Python 상관분석 엔진 미연동** — 미니필터는 자기완결로 동작하며, 상관분석

&#x20;  계층과의 연동은 미착수입니다.



---



## 다음 단계



- [ ] 임계 상수 튜닝 및 정상 프로그램 오탐률 측정 (발표용 정량 지표)

- [ ] 디렉터리 대량 탐색 / MBR 변조 탐지 (방어 대상 4개 중 나머지)

- [ ] Python 상관분석 엔진 연동

- [ ] `SelfProtect` 활성화 검증 (최종)

- [ ] Release 빌드 + 카탈로그 서명

