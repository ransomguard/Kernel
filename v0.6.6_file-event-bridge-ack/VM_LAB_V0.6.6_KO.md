# RansomGuard v0.6.6 설치·검증 — 기존 v0.6.5 VMware 환경 기준

## 먼저: 2026-11-04 HOTFIX1 적용 (v0.6.6의 최신 수정본)

**이 절차가 현재 VM의 실제 상태에 맞는다. 아래 기존 초기 설치 가이드를 그대로 반복하지 않는다.** 첫 v0.6.6은 빌드/서명 성공 후 메인은 RUNNING이었지만 미니필터 로드에서 `0x80070002`; DebugView에서 `cannot open existing callback \\Callback\\ArwFileEvent (0xC0000034)`가 확인됐다. 미니필터 `.sys`는 실제 존재(`Test-Path=True`)했다. 그 뒤 메인을 정상 중지했다.

원인은 메인 드라이버의 임시 callback 객체 이름이 사라지는 버그이다. HOTFIX1은 메인에 `OBJ_PERMANENT`를 추가하고 `ZwMakeTemporaryObject`로 안전한 언로드 정리를 한다. **미니필터 코드는 바꾸지 않았다.** 메인 `DriverVer`만 **`0.6.6.1`**, 기존 미니필터 `DriverVer`는 `0.6.6.0`이다. v0.6.7로 올리는 것이 아니라 같은 v0.6.6 소스를 갱신한 것이다.

### A. 호스트에서 최신 소스 내려받기 및 메인만 다시 빌드

1. GitHub `releases/RansomGuard-knel-v0.6.6-file-event-bridge-ack.zip`을 **다시 다운로드**한다. 이름이 이전 ZIP과 같으므로 다운로드 날짜를 확인하고 기존 압축을 혼용하지 않는다. 별도 새 폴더에 압축을 **완전히 추출**한다.
2. `v0.6.6_file-event-bridge-ack\RansomGuard.sln`을 Visual Studio에서 열어 `Debug | x64`로 선택한다.
3. `Anti_Ransom_Driver` 프로젝트 우클릭 → **다시 빌드**. 전체 솔루션을 다시 빌드해도 되지만 이미 VM에 있는 v0.6.6 미니필터를 교체할 필요는 없다. 성공 1개, 실패 0개 및 새 패키지 `Successfully signed`를 확인한다.
4. 새 빌드의 `out\x64\Debug\Anti_Ransom_Driver\Anti_Ransom_Driver\`에서 `Anti_Ransom_Driver.sys`, `Anti_Ransom_Driver.inf`, `anti_ransom_driver.cat`을 함께 가져온다. 한 단계 바깥의 `Anti_Ransom_Driver.cer`도 서명 확인용으로 복사할 수 있다. `.pfx` 개인 키는 전송하지 않는다.
5. 새 로그 마커는 `v0.6.6 HOTFIX1 named-callback lifetime fix active.`다. **이 마커가 보이지 않으면 이전 v0.6.6 파일이 실행된 것**이다.

### B. VM에서 새 메인 패키지만 staging/서명/설치

1. VM 네트워크 격리 유지. 기존 스냅샷 보존 및 **새 스냅샷**(예: `before-v066-hotfix1`)을 만들고 진행한다. 마지막 화면에서 메인 드라이버는 정상 `STOPPED`, 미니필터는 로드 실패 상태다.
2. 새 파일 세 개를 **`C:\RG_Test\v066_fix1\Driver\`** 로컬 VM 경로에 복사한다. 이전 `C:\RG_Test\Anti_Ransom_Driver`를 덮어쓰지 않는다. 기존 `C:\RG_Test\Anti_Ransom_FsFilter`는 그대로 보존한다.
3. 관리자 PowerShell에서:

```powershell
Get-ChildItem 'C:\RG_Test\v066_fix1\Driver' -File |
    Where-Object { $_.Extension -in '.sys','.cat' } |
    ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName } |
    Select-Object @{N='File';E={Split-Path $_.Path -Leaf}},Status |
    Format-Table -AutoSize
```

새 `.sys`와 `.cat` **두 개가 모두 `Valid`**인지 확인한다. 서명자가 기존 신뢰된 인증서와 다르면 VM 내부에서 새 `.cer`의 서명자 지문을 확인한 후 등록해야 한다. 호스트 테스트 서명 설정은 바꾸지 않는다.

4. `sc.exe query Anti_Ransom_Driver`가 `STOPPED`인지 확인한다. 그다음:

```powershell
sc.exe qc Anti_Ransom_Driver
pnputil.exe /add-driver "C:\RG_Test\v066_fix1\Driver\Anti_Ransom_Driver.inf" /install
sc.exe qc Anti_Ransom_Driver
```

새 `oemXX.inf`로 추가되고 `BINARY_PATH_NAME`이 **이전 v0.6.6 메인 DriverStore 경로에서 바뀌었는지** 비교한다. 패키지가 추가되었지만 이미지 경로가 같으면 여기서 멈추고 출력 화면을 보낸다. 기존 DriverStore 수동 교체·강제 삭제 금지. 미니필터 `pnputil` 설치는 반복하지 않는다.

5. 경로 변경 확인 후 **VM만 재부팅**한다.

### C. 로드/연결 재검증

DebugView를 관리자 권한으로 먼저 실행하고 `Capture Kernel`, `Enable Verbose Kernel Output`을 켠 다음 관리자 PowerShell에서:

```powershell
sc.exe start Anti_Ransom_Driver
sc.exe query Anti_Ransom_Driver
```

`RUNNING`이어야 하고 DebugView에서 아래 두 가지를 **모두** 확인한다.

```text
[RansomGuard] v0.6.6 HOTFIX1 named-callback lifetime fix active.
[RansomGuard] v0.6.6 HOTFIX named callback open-by-name verified on \Callback\ArwFileEvent.
```

이어서:

```powershell
fltmc.exe load Anti_Ransom_FsFilter
sc.exe query Anti_Ransom_FsFilter
fltmc.exe instances -f Anti_Ransom_FsFilter
```

DebugView에서 **메인 `bridge-probe-ack count=1` 및 필터 `probe ACK verified`**를 확인한다. 두 서비스 `RUNNING`, C: 필터 연결을 확인한 후에만 아래 5절의 **기존 TestClient `--policy audit` 쓰기/이름 변경 실험**을 진행한다.

여기서도 실패하면 재시도·강제 삭제하지 않고 **DebugView 실패 직후 로그/`sc qc`/PowerShell 오류 화면**을 보내준다. 완료 후엔 `fltmc unload Anti_Ransom_FsFilter` → `sc.exe stop Anti_Ransom_Driver` 순서로 정상 중지한다.

---

## 아래는 첫 v0.6.6 초기 설치 기록용 안내

> **실험 VM 전용.** 2026-11-04 v0.6.5에서 확인한 `FsFilter ExNotifyCallback 1,083회 / Driver sink-enter 0회`를 다시 검사하기 위한 **미검증 수정 버전**이다. 호스트 Windows 10에서는 빌드만, 드라이버 설치·테스트 인증서 등록·실행은 스냅샷 있는 격리 Windows 11 VM에서만 한다. 두 드라이버 모두 반드시 v0.6.6으로 교체해야 한다.

## 0. 시작 상태 확인

- 이전 테스트 이후 `Anti_Ransom_FsFilter`와 `Anti_Ransom_Driver`는 정상 중지됨. 마지막 VM 사진에서 Driver `STOPPED`, 필터 unload 성공이 확인됐다.
- VMware에서 현재 VM의 **추가 스냅샷** 생성 (예: `before-v066-bridge`) 후 다음으로 진행한다.
- VM 네트워크 격리 유지. `v0.6.5`의 기존 DriverStore 파일을 수동 덮어쓰거나 강제 삭제하지 않는다.

## 1. 개발 호스트에서 소스 압축 해제·빌드

1. GitHub의 `releases/RansomGuard-knel-v0.6.6-file-event-bridge-ack.zip` 다운로드·압축 해제. ZIP 뷰어 안에서 빌드하지 말고 새 폴더로 **완전히 추출**한다.
2. `v0.6.6_file-event-bridge-ack\RansomGuard.sln`을 **Visual Studio 2022**에서 연다.
3. `Debug | x64` → **빌드 > 솔루션 다시 빌드**. WDK 26100, Spectre 라이브러리 등 이전 v0.6.5에서 성공한 도구 구성 그대로 사용.
4. 출력에서 **3개 성공, 0개 실패**와 서명·Inf2Cat 완료를 확인. 오류가 하나라도 있으면 중단하고 출력 로그를 보내준다.
5. **같은 빌드 산출물 3종** `.sys/.inf/.cat`을 하나의 패키지로 복사해야 한다. 이전 v0.6.5에서 `.cat`이 한 단계 더 깊은 폴더에 있었으므로 다음 경로를 먼저 확인한다.

```text
v0.6.6_file-event-bridge-ack\out\x64\Debug\Anti_Ransom_Driver\Anti_Ransom_Driver\
    anti_ransom_driver.cat
    Anti_Ransom_Driver.inf
    Anti_Ransom_Driver.sys

v0.6.6_file-event-bridge-ack\out\x64\Debug\Anti_Ransom_FsFilter\Anti_Ransom_FsFilter\
    anti_ransom_fsfilter.cat
    Anti_Ransom_FsFilter.inf
    Anti_Ransom_FsFilter.sys
```

6. 필요하면 각 프로젝트의 **한 단계 바깥** `out\x64\Debug\Anti_Ransom_Driver` 및 `...\Anti_Ransom_FsFilter`에서 생성된 공개 인증서 `.cer`도 복사한다. `.cer`은 `.cat`의 대체물이 아니다. 개인 키(`.pfx`)를 VM에 복사하지 않는다.
7. GitHub의 ZIP에는 `.sys/.cat/.cer`가 없다. 세 빌드 파일을 호스트에서 직접 **새 이름의** VMware 공유 폴더 staging으로 옮겨라.

## 2. VM 내부 staging (기존 v0.6.5 파일과 분리)

VM에 아래처럼 새 폴더 2개를 만들고 각 패키지를 복사한다. 이 버전용 staging은 기존 `C:\RG_Test\Anti_Ransom_Driver` 등 **v0.6.5 staging을 덮어쓰지 않는다.**

```text
C:\RG_Test\v066\Driver\anti_ransom_driver.cat
C:\RG_Test\v066\Driver\Anti_Ransom_Driver.inf
C:\RG_Test\v066\Driver\Anti_Ransom_Driver.sys

C:\RG_Test\v066\FsFilter\anti_ransom_fsfilter.cat
C:\RG_Test\v066\FsFilter\Anti_Ransom_FsFilter.inf
C:\RG_Test\v066\FsFilter\Anti_Ransom_FsFilter.sys
```

빌드 시 생성한 `.cer`도 각각 Driver/FsFilter에 넣으면 인증서 점검이 편하다. 공유 폴더에서 VM 내부 로컬 드라이브로 복사한 뒤 공유 폴더를 끊어 VM 격리를 유지한다.

**관리자 PowerShell**에서 패키지 파일 목록과 서명 확인:

```powershell
Get-ChildItem 'C:\RG_Test\v066\Driver','C:\RG_Test\v066\FsFilter' -File |
    Where-Object { $_.Extension -in '.cat','.sys' } |
    ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName } |
    Select-Object @{N='File';E={Split-Path $_.Path -Leaf}},Status |
    Format-Table -AutoSize
```

네 항목이 모두 `Valid`이어야 한다. VM에서 이미 등록한 v0.6.5 서명 인증서와 v0.6.6 서명자가 **같다면 재등록할 필요가 없다**. `UnknownError`가 나면 `.cer`과 `.cat` 서명자의 지문이 동일한지 검증한 뒤에만 해당 테스트 인증서를 VM에 등록해야 한다. 오류를 무시하고 설치하지 않는다.

## 3. 기존 이미지 기록 후 패키지 교체

관리자 PowerShell에서 다음 조회 결과를 **스크린샷으로 기록**한다.

```powershell
sc.exe qc Anti_Ransom_Driver
sc.exe qc Anti_Ransom_FsFilter
sc.exe query Anti_Ransom_Driver
sc.exe query Anti_Ransom_FsFilter
fltmc.exe filters
```

두 서비스가 `STOPPED`인지, 필터 목록에 `Anti_Ransom_FsFilter`가 없는지 확인한다. 이미 중지 상태라면 `stop`이나 `unload`를 반복하지 않는다. 아직 RUNNING이면 클라이언트를 먼저 종료하고, 자기보호 해제·강제 삭제 없이 **필터부터** 정상 중지한다.

다음 두 명령어를 각각 실행:

```powershell
pnputil.exe /add-driver "C:\RG_Test\v066\Driver\Anti_Ransom_Driver.inf" /install
pnputil.exe /add-driver "C:\RG_Test\v066\FsFilter\Anti_Ransom_FsFilter.inf" /install
```

등록 후 반드시 다음을 확인한다.

```powershell
sc.exe qc Anti_Ransom_Driver
sc.exe qc Anti_Ransom_FsFilter
```

**`BINARY_PATH_NAME`이 과거 v0.6.5 DriverStore 경로에서 새로운 경로로 바뀌었는지 비교**해야 한다. `pnputil`이 단순히 패키지 추가만 성공했더라도 서비스가 가리키는 이미지가 옛것이면 새 버전으로 볼 수 없다. 경로가 그대로면 중단하고 `pnputil`/`sc qc` 출력 두 화면을 보낸다. DriverStore 파일 수동 교체·기존 패키지 강제 삭제 금지.

새 경로로 교체된 것을 확인했을 때만 **VM만 재부팅**한다.

## 4. DebugView → 메인 드라이버 → 미니필터 순서로 실행

1. 관리자 권한의 DebugView를 먼저 실행. `Capture > Capture Kernel`, `Enable Verbose Kernel Output` 체크. 로그 캡처 창을 열어 둔다.
2. 새 관리자 PowerShell에서 **메인 드라이버를 먼저** 시작한다.

```powershell
sc.exe start Anti_Ransom_Driver
```

3. DebugView에서 아래 메시지들이 나오는지 확인한다.

```text
[RansomGuard] v0.6.6 FILE_BRIDGE control driver image loaded.
[RansomGuard] v0.6.6 FILE_BRIDGE receiver registered; probe ACK supported.
[RansomGuard] v0.6.6 FILE_DIAG sink instrumentation active.
```

4. 이어서 미니필터를 시작한다.

```powershell
fltmc.exe load Anti_Ransom_FsFilter
```

5. DebugView에 **반드시 다음 두 로그가 모두** 보여야 한다.

```text
[RansomGuard] v0.6.6 FILE_DIAG bridge-probe-ack count=1 type=0 status=0x00000000
[Anti_Ransom_FsFilter] v0.6.6 FILE_BRIDGE probe ACK verified on \Callback\ArwFileEvent.
```

`probe FAILED` 또는 `cannot open existing callback`이면 필터는 **의도적으로 로드를 거부**한다. 명령을 반복하거나 임의로 자기보호·서명 설정을 우회하지 말고 DebugView와 `sc qc`를 캡처한다.

6. 정상 ACK 확인 후 상태 확인:

```powershell
sc.exe query Anti_Ransom_Driver
sc.exe query Anti_Ransom_FsFilter
fltmc.exe instances -f Anti_Ransom_FsFilter
```

두 드라이버 `RUNNING`, 미니필터가 `C:`에 연결된 것을 확인한다. **이때만** 다음 파일 테스트로 넘어간다.

## 5. 파일 쓰기·이름 변경 이벤트 테스트

관리자 PowerShell **창 A**에서 기존 v0.6.4/v0.6.5 TestClient를 계속 사용해도 된다(유저 모드 이벤트 ABI 변경 없음).

```powershell
& 'C:\RG_Test\Anti_Ransom_TestClient.exe' 300 --policy audit
```

`드라이버 연결 성공`, `엔진 등록 성공`, `[이벤트 수신] 최대 300건` 확인. 이 상태를 유지한 채 관리자 PowerShell **창 B**에서:

```powershell
$id = Get-Date -Format 'HHmmssfff'
$file = "C:\RG_Test\live_$id.txt"
[System.IO.File]::WriteAllBytes($file, [byte[]]::new(8192))
Rename-Item -LiteralPath $file -NewName "live_$id.renamed"
Get-Item "C:\RG_Test\live_$id.renamed" |
    Select-Object Name,Length,LastWriteTime
```

`Length=8192`를 확인한다. 그 다음 아래 기록을 모두 확인:

- DebugView 미니필터: `diag-notify-write`, `diag-notify-rename`, `bridge-acked-write`, `bridge-acked-rename`.
- DebugView 메인: `sink-enter`, `sink-accepted`, `sink-queued` (type 4/5).
- TestClient: `type=4 (FILE_WRITE)` 및 `type=5 (FILE_RENAME)`, `payloadBytes=2232`.

어떤 로그도 보이지 않는다면 정확한 지점에서 멈추고 두 화면을 공유한다. 통계는 **1·2·4·8·16... 발생 시에만** 출력된다. 기존 프로세스 이벤트가 계속 보이더라도 300건 수신 제한에 도달하면 테스트 클라이언트는 종료될 수 있으므로 재실행하되 파일 작업은 **창 A가 대기 중일 때** 수행한다.

## 6. 종료 및 결과 전달

결과를 확인했으면 TestClient를 `Ctrl+C`로 정상 종료하고 DebugView를 계속 켜둔 채 다음 순서로 종료한다.

```powershell
fltmc.exe unload Anti_Ransom_FsFilter
sc.exe stop Anti_Ransom_Driver
```

`v0.6.6 FILE_DIAG summary`에서 `notifiedWrite/rename`, `ackedWrite/rename`, `missingAck`, `rejectedAck`, `entered`, `queued`, `probeAcked`를 비교한다. 오류가 있으면 반복/강제 중지하지 않는다.

**보내줄 화면:** (1) 새 DriverStore 경로/양 서비스 `RUNNING`, (2) probe ACK 및 파일 이벤트 진단 로그, (3) TestClient `type=4/5` 여부. 특히 ACK만 있고 `type=4/5`가 없다면 **큐 → TestClient IOCTL** 구간의 추가 확인이 필요하다.

## 7. 안전한 범위

- 이 버전은 파일 이벤트 **관측/IPC 테스트**만 다룬다. 차단, 종료, 격리, 복구는 실행하지 않는다.
- `--policy block`, `--terminate`, 미승인 샘플 실행은 하지 않는다.
- `385090`은 실습 VM 임시 고도이며 실제 제품 배포용 고도가 아니다.
- 절대로 메인 OS/개발 호스트에 테스트 서명 드라이버를 설치하지 않는다.
