# v0.6.5 받았을 때부터 VMware 진단까지 — 단계별 안내

> **실험 전용:** Windows 10 개발 호스트에는 Visual Studio 2022/WDK로 **빌드만** 한다. 서명한 커널 드라이버의 설치와 로드는 **스냅샷이 있는 격리 Windows 11 VM**에서만 수행한다. 이 릴리스는 진단 코드이며 실제 파일 차단을 구현하지 않는다.

## 1. 호스트에서 ZIP 압축 해제·빌드

1. `RansomGuard-knel-v0.6.5-file-pipeline-diagnostics.zip`을 별도 폴더에 압축 해제. v0.6.4 소스와 덮어쓰거나 병합하지 말 것.
2. `v0.6.5_file-pipeline-diagnostics\RansomGuard.sln`을 **Visual Studio 2022**에서 열기.
3. 상단 `Debug | x64` 확인 → **빌드 > 솔루션 다시 빌드**. 이전에 성공했던 VS 2022 Community 17.14.44 + WDK 26100, Spectre 라이브러리 환경을 그대로 사용.
4. 출력에 `0개 실패`, 오류 목록 `0 오류` 확인. 실패하거나 서명 오류가 있으면 여기서 중단한다. **v0.6.4 기존 `.sys`/`.cat`을 새 INF와 섞지 않는다.**
5. `out\x64\Debug` 아래에서 아래 파일을 찾는다. Windows 파일 탐색기에서 직접 검색해도 된다.

   - `Anti_Ransom_Driver.sys`, `Anti_Ransom_Driver.inf`, `Anti_Ransom_Driver.cat`
   - `Anti_Ransom_FsFilter.sys`, `Anti_Ransom_FsFilter.inf`, `Anti_Ransom_FsFilter.cat`
   - `Anti_Ransom_TestClient.exe` (기존 v0.6.4 클라이언트가 있다면 새로 VM에 복사할 필요 없음)

   빌드된 세 파일(`.sys/.inf/.cat`)은 **각 프로젝트별 같은 패키지 폴더**에 있어야 한다. 서로 다른 빌드 산출물을 섞으면 서명 검증이 깨질 수 있다. 빌드 시 WDK의 `StampInf` 때문에 원본 INF와 빌드된 INF의 `DriverVer` 표시가 다를 수 있다. 실제 설치에는 **빌드된 패키지 INF** 사용.

6. 호스트 PowerShell에서 각각 서명 상태를 확인한다. 아래 `경로`는 실제 빌드된 전체 경로로 바꿔야 한다.

```powershell
Get-AuthenticodeSignature '경로\Anti_Ransom_Driver.sys' |
    Format-List Status,SignerCertificate
Get-AuthenticodeSignature '경로\Anti_Ransom_FsFilter.sys' |
    Format-List Status,SignerCertificate
Get-AuthenticodeSignature '경로\Anti_Ransom_Driver.cat' | Format-List Status
Get-AuthenticodeSignature '경로\Anti_Ransom_FsFilter.cat' | Format-List Status
```

`Valid`가 아니면 설치 전에 해결한다. 새 테스트 서명자가 기존 VM에서 신뢰되지 않으면 **공개 인증서(.cer)만** VM으로 전달해 지문을 확인하고, 필요할 때에만 격리 VM의 신뢰 저장소에 등록한다. 개인키(`.pfx`)는 전달하지 않는다. 테스트 서명 모드 및 Secure Boot는 **호스트에서 변경하지 않는다**.

## 2. VMware에 복사 (기존 드라이버 삭제 금지)

1. **VMware 스냅샷**을 먼저 만든다(예: `before-v065-file-diag`). 300건 수신 중이던 이전 테스트 클라이언트는 `Ctrl+C`로 닫는다.
2. 호스트의 빌드된 두 패키지를 기존 `Ransom0_Transfer` 공유 폴더를 통해 **VM 내부** 다음 경로로 복사한다.

```text
C:\RG_Test\v065\Driver\Anti_Ransom_Driver.sys
C:\RG_Test\v065\Driver\Anti_Ransom_Driver.inf
C:\RG_Test\v065\Driver\Anti_Ransom_Driver.cat
C:\RG_Test\v065\FsFilter\Anti_Ransom_FsFilter.sys
C:\RG_Test\v065\FsFilter\Anti_Ransom_FsFilter.inf
C:\RG_Test\v065\FsFilter\Anti_Ransom_FsFilter.cat
```

3. 복사가 끝나면 VM의 공유 폴더/네트워크를 다시 분리해 실험 격리를 유지한다. 이전 드라이버의 `DriverStore` 파일을 직접 덮어쓰거나 `sc delete`, `pnputil /delete-driver /force` 등을 사용하지 않는다.

## 3. VM에서 기존 이미지 상태 기록 후 교체

**관리자 PowerShell**을 열고 아래 조회 명령을 먼저 실행한다. 기존 `BINARY_PATH_NAME`과 `START_TYPE`을 사진으로 남긴다.

```powershell
sc.exe qc Anti_Ransom_Driver
sc.exe qc Anti_Ransom_FsFilter
sc.exe query Anti_Ransom_Driver
sc.exe query Anti_Ransom_FsFilter
fltmc.exe instances -f Anti_Ransom_FsFilter
```

`EnableUnloadProtection=1`처럼 자발적 언로드 보호가 켜진 상태라면 **여기서 멈추고 문의**. 우회하거나 강제 삭제하지 않는다. 현재 격리 테스트 VM은 이전에 정상 언로드가 가능했으며, 새 패키지의 첫 실험에서는 자기보호를 켜지 않는다.

기존 사용 중인 테스트 클라이언트를 종료한 뒤, 두 드라이버를 안전하게 내려 놓는다.

```powershell
fltmc.exe unload Anti_Ransom_FsFilter
sc.exe stop Anti_Ransom_Driver
```

둘 중 하나라도 정상적으로 내려가지 않으면 **반복하거나 강제 중단하지 말고 출력 화면을 보내 달라.** 성공한 경우에만 아래 새 패키지를 등록한다.

```powershell
pnputil.exe /add-driver "C:\RG_Test\v065\Driver\Anti_Ransom_Driver.inf" /install
pnputil.exe /add-driver "C:\RG_Test\v065\FsFilter\Anti_Ransom_FsFilter.inf" /install
```

Primitive INF는 환경에 따라 드라이버 저장소에 **추가만 되고 실행 중 서비스의 이미지 경로 갱신이 완료되지 않을 수 있다**. `추가 성공` 메시지만으로 v0.6.5 적용 성공이라고 판단하지 않는다. 아래를 다시 확인한다.

```powershell
sc.exe qc Anti_Ransom_Driver
sc.exe qc Anti_Ransom_FsFilter
```

`BINARY_PATH_NAME`이 여전히 처음 기록한 v0.6.3 DriverStore 경로라면 여기서 중단하고 설치 결과/서비스 경로 화면을 공유한다. 기존 `.sys` 수동 교체, 임의 서비스 재생성, 서명 건너뛰기는 하지 않는다. 새로운 패키지 경로로 정상 갱신된 후에는 **VM만** 재부팅해 새 이미지를 확실히 로드한다.

## 4. 새 v0.6.5 드라이버 로드·DebugView

1. 재부팅한 VM에서 **DebugView 관리자 실행**, 메뉴 **Capture > Capture Kernel** 체크. **Enable Verbose Kernel Output**도 체크. 로그를 지우고(메뉴 `Edit > Clear Display`), 커널 로그 수집을 유지한다.
2. 별도 관리자 PowerShell에서 **메인 드라이버를 먼저**, 그다음 미니필터를 로드한다.

```powershell
sc.exe start Anti_Ransom_Driver
fltmc.exe load Anti_Ransom_FsFilter
sc.exe query Anti_Ransom_Driver
sc.exe query Anti_Ransom_FsFilter
fltmc.exe instances -f Anti_Ransom_FsFilter
```

3. 둘 다 `RUNNING`이고 C:가 인스턴스 목록에 있어야 한다. DebugView에서 아래 **버전 표시 3개**를 찾는다.

```text
[RansomGuard] v0.6.5 FILE_DIAG control driver image loaded.
[RansomGuard] v0.6.5 FILE_DIAG sink instrumentation active.
[Anti_Ransom_FsFilter] v0.6.5 FILE_DIAG enabled: stage counters log at powers of two.
```

위 문자열이 없다면 **v0.6.5 바이너리를 제대로 로드했는지 미확인** 상태다. 파일 테스트로 넘어가기 전에 서비스 이미지 경로/DebugView 캡처 설정을 다시 확인한다. `sc query RUNNING`만으로 버전을 확인할 수는 없다.

## 5. 이벤트 수신 테스트 (관리자 PowerShell 창 2개)

**창 A — 먼저 실행, 창을 닫지 않기:**

```powershell
& "C:\RG_Test\Anti_Ransom_TestClient.exe" 300 --policy audit
```

`드라이버 연결 성공`, `엔진 등록 성공`, `[이벤트 수신] 최대 300건`을 확인한다. 프로그램이 멈춘 듯해도 정상 대기일 수 있다.

**창 B — A가 켜져 있을 때 실행:**

```powershell
$id = Get-Date -Format 'HHmmssfff'
$file = "C:\RG_Test\live_$id.txt"
[System.IO.File]::WriteAllBytes($file, [byte[]]::new(8192))
Rename-Item -LiteralPath $file -NewName "live_$id.renamed"
Get-Item "C:\RG_Test\live_$id.renamed" |
    Select-Object Name, Length, LastWriteTime
```

`Length=8192`가 표시되면 테스트 파일 작업은 성공이다. 이어서 **창 A의 `type=4/5`**와 **DebugView의 `FILE_DIAG`** 로그를 함께 확인한다. 진단이 끝나면 클라이언트는 `Ctrl+C`로 종료 가능하다.

## 6. DebugView 로그 판별 표

| 해당 로그가 어디까지 보이는가 | 의미 / 다음 조사 지점 |
| --- | --- |
| `diag-prewrite-enter`조차 없음 | v0.6.5 미니필터가 해당 파일 I/O를 보지 못했거나 새 바이너리/커널 로그 캡처가 안 된 상태 |
| `diag-prewrite-enter`는 있으나 `diag-prewrite-prepared` 없음 | 미니필터의 unsupported/PID/할당/속도 제한 등 사전 분기 조사 |
| `diag-prerename-enter`는 있으나 `diag-prerename-prepared` 없음 | rename 사전 분기/할당 조사 |
| `diag-notify-write`/`diag-notify-rename` 있음, 메인 드라이버 `sink-enter` 없음 | 양 드라이버의 `\\Callback\\ArwFileEvent` 객체 연결/등록 실패 가능성 (송신은 수신 확인이 아님) |
| `sink-enter` 있음, `sink-accepted` 없음 | 송신 이벤트 타입/작업/길이 검증에서 거부. `sink-*` 이유/상태 확인 |
| `sink-accepted` 있음, `sink-queued` 없음 | 메인 이벤트 큐 push 실패. `sink-queue-failed` 상태 확인 |
| `sink-queued` 있음, 클라이언트 `type=4/5` 없음 | 큐→대기 IOCTL/엔진 등록/수신 순서 조사 |
| `sink-queued` 있고 클라이언트 `type=4/5`도 있음 | 해당 테스트에서 파일 IPC 종단 간 전달 확인 |

로그는 호출마다 찍히지 않는다. 각 단계에서 **1, 2, 4, 8, 16...번째 발생 시만** 출력되므로 로그의 숫자가 정확한 총 발생 수는 아닐 수 있다. 필터/메인 드라이버를 정상 언로드하면 최종 요약도 나온다. 출력이 아예 없다면 DebugView를 먼저 실행했는지와 실제 로드된 이미지의 버전을 반드시 확인한다.

## 7. 결과 공유

실험 후 다음 세 가지 화면을 보내면 충분하다.

1. `sc.exe qc`로 갱신된 두 `BINARY_PATH_NAME`과 `fltmc`의 C: 연결 상태.
2. DebugView에서 `v0.6.5 FILE_DIAG` 및 `diag-*` / `sink-*` 로그.
3. 테스트 클라이언트에서 `type=4/5`가 보였는지, 없다면 마지막 `[RECV]` 화면.

`--policy block`, `--terminate`는 이 진단에서 사용하지 않는다. 실사용 PC/호스트 드라이버 설치 금지. 고도 385090은 임시 실험용으로 정식 배정값이 아니다.
