# RansomGuard Kernel v0.6.6 — 파일 이벤트 콜백 브리지 연결·ACK

## HOTFIX1 — 2026-11-04 (v0.6.6 업데이트, v0.6.7 아님)

첫 v0.6.6 빌드는 Windows 10 호스트 VS 2022/WDK 26100에서 **3/3 성공**, VM에서 두 드라이버·카탈로그 서명 모두 `Valid`, 새 DriverStore 경로까지 확인되었다. VM의 실제 실행 결과는 다음과 같다.

| VM 관측 | 결과 |
| --- | --- |
| 메인 제어 드라이버 | v0.6.6 `RUNNING`, `receiver registered` 출력 |
| 미니필터 이미지 경로 | 레지스트리 `ImagePath`를 확장한 `Test-Path` → `True` |
| 미니필터 로드 | `fltmc load`: `0x80070002`, DriverEntry의 `ExCreateCallback(Create=FALSE)`가 `STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)` 반환 |
| 정리 | 메인 `sc.exe stop` 성공, `STOPPED` |

**원인:** 메인 드라이버가 `ExCreateCallback(Create=TRUE)`를 호출하면서 `OBJ_PERMANENT`를 생략했다. API가 객체 포인터를 반환하더라도 *임시 객체의 핸들 수가 0이 되면 이름이 사라질 수 있어* 다른 드라이버가 `Create=FALSE`로 그 이름을 열 수 없었다. 이는 v0.6.5의 `ExNotifyCallback 1,083회 / sink-enter 0회`도 설명한다. Microsoft의 [ExCreateCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-excreatecallback) 문서는 `OBJ_PERMANENT`를 권장한다.

이번 HOTFIX1에서는 **기존 `v0.6.6_file-event-bridge-ack` 폴더와 ZIP 이름을 유지**한다. 새 릴리스 폴더는 만들지 않는다.

- `Anti_Ransom_Driver/Eventqueue.c`: 이름이 이미 존재하면 타 구성요소의 객체를 소유하지 않도록 거절; `OBJ_PERMANENT | OBJ_CASE_INSENSITIVE`로 생성; `ObOpenObjectByPointer(OBJ_KERNEL_HANDLE, DELETE)` 핸들을 보유하여 언로드/등록 실패 시 `ZwMakeTemporaryObject` → `ZwClose` → `ObDereferenceObject`로 정리; 메인 내부에서도 `ExCreateCallback(Create=FALSE)`로 이름 재열기 확인.
- `Anti_Ransom_Driver/Driver.c`: `v0.6.6 HOTFIX1` 시작 로그 추가, 파일 수신기 초기화에 실패하면 **정상 작동으로 오인하지 않고 드라이버 기동을 중단**.
- `Anti_Ransom_Driver/Anti_Ransom_Driver.inf`: **`DriverVer=11/04/2026,0.6.6.1`**. 수정본이 같은 날짜·같은 `0.6.6.0` 패키지로 처리되지 않도록 패치 빌드를 구분한다.
- `Anti_Ransom_FsFilter` 소스/INF `0.6.6.0`와 `Kernel_test`는 **변경 없음**. 이미 서명·설치된 v0.6.6 미니필터와 기존 TestClient를 그대로 사용한다. 두 커널 사이 공유 receipt/IOCTL ABI도 불변.
- 성공 조건: 메인 `HOTFIX1 named-callback lifetime fix active`, `HOTFIX named callback open-by-name verified`, 미니필터 `probe ACK verified`, 그 뒤 실제 파일 이벤트 type=4/5 수신.

**검증 상태:** 첫 v0.6.6 빌드는 성공/VM 로드 실패가 확인됐다. **HOTFIX1 소스는 WDK 재빌드 및 실 VM 검증 전**이므로 복구 성공을 주장하지 않는다. 반드시 [VM_LAB_V0.6.6_KO.md](VM_LAB_V0.6.6_KO.md)의 HOTFIX1 절차를 먼저 따른다.

## 릴리스 상태

- 기준: `v0.6.5_file-pipeline-diagnostics`
- 성격: **커널 간 파일 이벤트 전달 경로 수정 및 실패 검출 강화**, 관측 전용
- Windows 11 VM 실제 빌드·서명·실행: **첫 v0.6.6은 빌드·서명 성공, 로드 실패 원인 확인; HOTFIX1은 미검증**. Windows 10 개발 호스트의 VS 2022/WDK 26100에서 수정본을 빌드하고 격리 VM에서 확인해야 한다.
- 소스 ZIP에는 **빌드·서명된 `.sys/.cat/.cer` 파일이 없다.** GitHub ZIP을 그대로 VM에서 설치하지 않는다.
- 다른 저장소의 복구·JEV·대시보드·방화벽 코드는 변경하지 않았다.

## v0.6.5 실기 검증에서 확정된 현상 (2026-11-04)

VMware Windows 11 가상 머신에서 v0.6.5 두 드라이버의 빌드·테스트 서명·실제 DriverStore 교체·로드를 확인했다. `fltmc instances`에 C:가 연결되었고 8,192바이트 파일 쓰기·이름 변경 테스트도 성공했다.

| 미니필터 / 메인 드라이버 | 관측치 |
| --- | ---: |
| 미니필터 `preWrite` | 20,438 |
| 미니필터 `preRename` | 37 |
| 미니필터 `notifications` (`ExNotifyCallback` 호출 수) | **1,083** |
| 메인 `sink-enter` | **0** |
| 메인 `sink-accepted` / `sink-queued` | **0 / 0** |
| 메인 프로세스 이벤트 `generated` | 148 |

프로세스 생성·종료 IPC와 미니필터 감지 자체는 작동했다. 하지만 **파일 이벤트는 미니필터의 알림 호출과 메인 드라이버 콜백 진입 사이**에서 끊겼다. 정확한 근본 원인은 여전히 VM 검증이 필요하며, 콜백 이름은 양쪽 소스에서 이미 동일했다. `ExNotifyCallback`의 반환형은 `VOID`이므로 단순 호출 횟수는 수신 성공을 보장하지 않는다.

## v0.6.6 변경

| 파일 | 변경 및 이유 |
| --- | --- |
| `Anti_Ransom_FsFilter/FsFilter.c` | `ExCreateCallback`의 `Create=TRUE`를 **`FALSE`**로 바꾸어 메인 드라이버가 만든 기존 `\\Callback\\ArwFileEvent` 객체만 연다. 수신자가 없는 상태에서 미니필터가 별도 객체를 만들지 않는다. |
| `Anti_Ransom_FsFilter/FsFilter.c` | FltMgr 등록 **이전**에 `Argument1=NULL` 진단 probe를 보내고 동기 ACK를 요구한다. ACK 없거나 오류면 `STATUS_DEVICE_NOT_READY`로 로드를 중단하므로, 예전처럼 RUNNING인데 콜백 미연결인 상태를 조기에 탐지할 수 있다. |
| `Anti_Ransom_FsFilter/FsFilter.c` | 실제 write/rename 알림마다 **16바이트 stack receipt**를 `Argument2`로 전달한다. `ExNotifyCallback` 호출 시도, ACK 성공, ACK 누락, 큐 거부를 별도 카운터로 집계한다. |
| `Anti_Ransom_Driver/Eventqueue.c` | `Argument1=NULL` probe에는 ACK만 반환하며 이벤트 큐에는 넣지 않는다. 실제 파일 이벤트는 기존 검증과 큐 Push 후 그 NTSTATUS를 ACK에 기록한다. v0.6.5 송신자의 `Argument2=NULL`도 계속 수신한다. |
| `Shared/Common.h` | **커널 전용** `ARW_FILE_BRIDGE_RECEIPT`(16B), 매직/버전 추가. 사용자 모드 IPC 구조체와 IOCTL 번호는 변경하지 않는다. |
| `Anti_Ransom_Driver/Driver.c` | `v0.6.6 FILE_BRIDGE` 시작 로그로 로드된 이미지 식별. |
| `Anti_Ransom_Driver/*.inf`, `Anti_Ransom_FsFilter/*.inf` | 첫 빌드는 둘 다 `0.6.6.0`; HOTFIX1은 **메인만 `0.6.6.1`**, 미니필터는 `0.6.6.0` 유지. INF stamping은 빌드 산출물의 표시 날짜를 변경할 수 있다. |
| `VM_LAB_V0.6.6_KO.md` | 기존 VM에서 패키지를 교체하고 probe·실제 파일 이벤트를 검증하는 단계별 절차. |

### 커널 콜백 계약

1. 메인 제어 드라이버가 먼저 로드되어 `ExCreateCallback(Create=TRUE)`로 객체를 만들고 `ExRegisterCallback`으로 수신자를 등록한다.
2. 미니필터는 `ExCreateCallback(Create=FALSE)`로 **이름이 같은 기존 객체**를 열어야 한다.
3. 미니필터가 `ExNotifyCallback(object, NULL, &receipt)`를 호출하면 메인 콜백이 probe에 ACK를 기록한다. 큐에 이벤트는 들어가지 않는다.
4. 실제 파일 이벤트는 `ExNotifyCallback(object, event, &receipt)`로 보내며, 메인 콜백이 큐 등록 성공/실패 NTSTATUS와 ACK를 기록한다.
5. 미니필터는 호출이 돌아온 뒤 `receipt.Acknowledged` 및 `receipt.QueueStatus`를 확인한다. **ACK는 큐 적재 확인이며 분석 엔진 처리/악성 판정/복구 성공 확인이 아니다.**

`receipt`는 미니필터의 호출 스택에 있고 동기 호출 중에만 빌려 쓴다. 수신자는 포인터를 보관하지 않는다. 이벤트 버퍼 수명과 기존 nonpaged 큐 복사 방식은 유지한다. 통계 로그는 1, 2, 4, 8, ... 번째 발생 시에만 출력한다.

## 호환성·주의 사항

- 기존 사용자 모드 `ARW_EVENT_HEADER`, `ARW_PROCESS_EVENT`(1616B), `ARW_FILE_EVENT`(2232B), `ARW_MAX_EVENT_SIZE`, 이벤트 종류 1~5, IOCTL/정책 바이트 구조는 불변이다.
- **로드 순서가 필수:** `Anti_Ransom_Driver` → `Anti_Ransom_FsFilter`. 미니필터를 먼저 시작하면 기존 수신 콜백 객체가 없어 로드 실패가 정상이다.
- **언로드 순서:** `Anti_Ransom_FsFilter` → `Anti_Ransom_Driver`. 자기보호가 켜져 언로드가 거부되면 우회하지 않는다.
- v0.6.6 미니필터와 오래된 메인 v0.6.5를 혼용하면 probe ACK를 지원하지 않아 로드가 실패한다. **HOTFIX1 메인 `0.6.6.1`과 기존 v0.6.6 미니필터 `0.6.6.0`은 커널 콜백 계약이 동일해 의도적으로 함께 사용한다.**
- 격리 VM 전용 임시 altitude `385090`은 Microsoft 정식 할당값이 아니므로 배포에 사용하면 안 된다.
- `--policy audit`로만 검사한다. 파일 선차단·자동 kill·엔진 복구·JEV 통신·방화벽 전체 통합은 이 릴리스의 범위 밖이다.
- 신뢰할 수 있는 루트/게시자에 테스트 인증서를 등록하는 작업은 **스냅샷이 있는 VM 안에서만** 한다. 호스트 Windows 테스트 서명 설정·인증서 저장소는 변경하지 않는다.

## 검증 성공 조건 / 실패 분기

| DebugView 메시지 | 의미 |
| --- | --- |
| 메인 `v0.6.6 FILE_BRIDGE receiver registered` | 메인 콜백 수신자 등록됨. 아직 미니필터 전달 확인은 아님. |
| 미니필터 `v0.6.6 FILE_BRIDGE probe ACK verified` | 미니필터 → 메인 콜백 **동기 호출** 성공. |
| 미니필터 `probe FAILED` 또는 객체 `cannot open` | 콜백 연결/로드 순서 문제. 필터가 정상 활성화되지 않으므로 즉시 중단. |
| `sink-enter`, `sink-queued`, `bridge-acked-write/rename` | 파일 이벤트가 메인 수신·큐 적재됐음. |
| 클라이언트 `type=4 (FILE_WRITE)` 및 `type=5 (FILE_RENAME)` | **커널 → 유저 모드 파일 이벤트 전달** 확인. |
| `bridge-missing-ack` / `bridge-rejected-ack` | 메인 수신/검증/큐 적재 실패. 드라이버 원인 추가 조사 필요. |

실제 VM에서 성공을 확인하기 전에는 **"v0.6.6 파일 이벤트 IPC 복구 완료"라고 판정하지 않는다.**
