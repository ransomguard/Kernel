# RansomGuard v0.6.6 — 파일 이벤트 큐 시작 순서·손실 재검증

작성: 2026-11-04. **격리된 Windows 11 VMware VM의 감사(AUDIT) 시험 전용.**

## 1. 실제 VM 검증 결과

2026-11-04 HOTFIX1을 WDK/VS 2022 Debug x64로 3개 프로젝트 모두 빌드·테스트 서명했다. VM에서 새 메인 드라이버 패키지 `oem17.inf`를 설치한 뒤 다음을 확인했다.

| 항목 | 실기 결과 |
| --- | --- |
| 메인 `Anti_Ransom_Driver` | `RUNNING`, `HOTFIX1`, `named callback open-by-name verified` |
| 미니필터 `Anti_Ransom_FsFilter` | `RUNNING`, C: 볼륨 연결, `probe ACK verified` |
| 파일 쓰기 | TestClient `type=4 (FILE_WRITE)` 수신 |
| 이름 변경 | TestClient `type=5 (FILE_RENAME)` 수신. `RG_Test\live_215603006.txt`, `rename_220100921_1.txt`~`_5.txt` 확인 |
| 종료 | **TestClient 종료 후** 미니필터 `STOPPED`, 메인 `STOPPED`; `All in-flight callbacks drained`, `DriverUnload: cleanup complete` |

**검증 범위:** 미니필터 → 커널 콜백 ACK → 이벤트 큐 → 사용자 모드 TestClient까지. 랜섬웨어 자동 차단, Track A/B 전체, 네트워크 격리, JEV 판정, VSS 복구는 이번 검증 대상이 아니다.

## 2. `EventsDropped=381`의 해석

| 관측 시점 | EventsGenerated | EventsDropped | QueueDepth |
| --- | ---: | ---: | ---: |
| TestClient 최초 상태 조회 | 1,405 | 381 | 1,024 |
| 마지막 `DriverUnload` 집계 | 1,844 | 381 | 종료 시 해제 |

`1405 - 381 = 1024`는 `Shared/Common.h`의 `ARW_EVENT_QUEUE_MAX_DEPTH=1024`와 정확히 일치한다. 소스 `Eventqueue.c`는 **큐가 가득 차면 가장 오래된 노드를 제거하고 신규 이벤트를 받는 FIFO**이다. 최초 TestClient 등록 전 미니필터가 여러 분 동안 활성화되어 있었으므로 **수신기 미등록 중 포화에 의한 손실**과 일치한다.

이후 생성 이벤트가 439건 늘었는데 손실 누적값은 381로 그대로였다. 즉, **그 관측 구간에서 추가 손실은 발견되지 않았다.** 다만 수신기 연결 중 고부하·장시간 시험에서도 항상 손실이 0이라고 일반화할 수는 없다. 무제한으로 이벤트를 메모리에 보관할 수 없으므로 큐 용량만 늘려서는 미등록 기간의 손실을 근본적으로 제거하지 못한다.

## 3. 다음 VM 재검증 — 수신기 먼저 연결

1. 기존 VM 스냅샷에서 시작하고 **네트워크 격리 유지**. 두 서비스가 `STOPPED`인지 확인한다. 기존 DriverStore 패키지를 재설치하지 않는다.
2. DebugView를 관리자 권한으로 실행하고 커널 캡처를 켠다.
3. 관리자 PowerShell **창 A**에서 메인 드라이버만 시작한다.

   ```powershell
   sc.exe start Anti_Ransom_Driver
   sc.exe query Anti_Ransom_Driver
   ```

4. 관리자 PowerShell **창 B**에서 TestClient를 **미니필터보다 먼저** 실행하여 엔진 등록을 완료한다. 감사 모드만 쓴다.

   ```powershell
   & 'C:\RG_Test\Anti_Ransom_TestClient.exe' 300 --policy audit
   ```

   `엔진 등록 성공!`, `[커널 상태]` 및 `EventsDropped` 시작값을 기록한다. **이번 수정의 `수신 중 추가 손실` 표시를 보려면 TestClient를 새로 빌드하여 VM에서 실행해야 한다.** 기존 `.exe`는 이 추가 출력이 없지만 파일 이벤트 수신 기능은 동일하다.

5. 창 A에서 **이제** 미니필터를 로드한다.

   ```powershell
   fltmc.exe load Anti_Ransom_FsFilter
   sc.exe query Anti_Ransom_FsFilter
   fltmc.exe instances -f Anti_Ransom_FsFilter
   ```

   두 드라이버 `RUNNING`, C: 연결, DebugView `probe ACK verified`를 확인한다.

6. 창 A에서 안전한 시험 파일을 5개 생성해 이름을 변경한다.

   ```powershell
   $id = Get-Date -Format 'HHmmssfff'
   1..5 | ForEach-Object {
       $index = $_
       $file = "C:\RG_Test\queue_${id}_${index}.txt"
       [System.IO.File]::WriteAllBytes($file, [byte[]]::new(8192))
       Rename-Item -LiteralPath $file -NewName "queue_${id}_${index}.renamed"
   }
   ```

   TestClient가 최대 300건에 도달하면 `[수신 후 상태]`의 `수신 중 추가 손실`을 확인한다. `type=4`/`type=5` 이벤트가 모두 도달했는지도 기록한다. Windows의 일반 백그라운드 이벤트 때문에 300건에 먼저 도달했다면 최대 수신 건수를 늘려 재시도할 수 있으나, **항상 엔진 등록 후 파일 테스트를 실행**한다.

7. 테스트 종료 시 **TestClient가 먼저 종료됐는지** 확인한다. `system("pause")`가 표시되면 아무 키나 눌러 종료한다. 300건을 기다리지 않고 중단할 경우 창 B에서 `Ctrl+C`를 누른다.

   ```powershell
   Get-Process Anti_Ransom_TestClient -ErrorAction SilentlyContinue
   ```

   출력이 없어야 한다. 그다음 창 A에서 **미니필터 → 메인** 순서로 언로드한다.

   ```powershell
   fltmc.exe unload Anti_Ransom_FsFilter
   sc.exe stop Anti_Ransom_Driver
   sc.exe query Anti_Ransom_Driver
   ```

   둘 다 `STOPPED`가 확인되면 성공. TestClient가 여전히 드라이버 디바이스를 열고 있으면 `STOP_PENDING`에 머무를 수 있으므로 **반드시 클라이언트 종료 확인 후** 진행한다. 정상 종료가 지연되면 강제 삭제·드라이버 재설치를 하지 않고 DebugView 언로드 로그를 남긴다.

## 4. 판정과 다음 작업

- **1차 목표:** TestClient 시작값과 최종값의 `EventsDropped` 차이 `0`, `type=4/5` 수신, `STOPPED` 종료.
- **추가 손실 발생 시:** 발생 시각·큐 깊이·`generated/delivered/dropped/flushed`의 시작·끝 값을 기록하고, 대기 요청 처리율·이벤트 폭주·사용자 모드 소비 지연을 분리해서 조사한다. 수치가 없는데 큐를 임의로 8192 이상으로 키우지 않는다.
- `EventsDropped`는 누적값이므로 **시작 전에 이미 있던 381건만으로 이번 수신 구간이 실패했다고 판단하지 않는다.**
- 이번 변경은 **`Kernel_test/Anti_Ransom_TestClient.cpp`의 상태 출력과 문서만 수정**했다. 두 `.sys`의 코드, INF, 미니필터 고도, IOCTL/ABI는 변경하지 않았다.
