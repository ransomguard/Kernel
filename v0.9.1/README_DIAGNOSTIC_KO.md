# RansomGuard v0.6.4 진단용 테스트 클라이언트

## 목적

기존 `Anti_Ransom_TestClient.exe`에서는 정상적인 프로세스 이벤트가 수신되어도
규칙에 일치하지 않으면 상세 출력이 생략되어, `EventsDelivered` 증가만으로
파일 이벤트인지 구별하기 어려웠습니다. 파일 이벤트 상세 출력도 `wprintf`와
`std::cout`을 혼용했습니다.

v0.6.4는 **사용자 모드 테스트 클라이언트만** 변경했습니다. 커널 드라이버,
미니필터, IPC IOCTL 번호, 공용 구조체, 방화벽 데몬은 변경하지 않았습니다.

## 변경 내용

- 모든 `IOCTL_RG_GET_EVENT` 성공마다 `type`, `PayloadSize`, 실제 반환 크기,
  `SequenceNumber`를 ASCII 레이블로 출력합니다.
- 이벤트 타입: 프로세스 생성=1, 종료=2, 차단=3, 파일 쓰기=4, 이름 변경=5.
- 파일 이벤트는 PID, 플래그, 원본 경로, 변경 후 확장자를 출력합니다.
- 규칙에 일치하지 않는 프로세스 이벤트도 PID·PPID·규칙 번호를 출력합니다.
- 공용 ABI(`Shared/Common.h`)의 Magic, Version, PayloadSize 및 이벤트 타입별
  크기(프로세스 1616바이트, 파일 2232바이트)를 검사하고 불일치하면 경고만
  표시합니다. 잘못된 버퍼를 이벤트 구조체로 해석하지 않습니다.
- 파일 경로/명령줄은 길이 검증 후 UTF-16에서 UTF-8로 변환합니다.
- 출력 코드 페이지를 UTF-8로 맞춰 콘솔 한글 깨짐을 줄입니다.

## 빌드: Windows PC의 Visual Studio 2022

1. ZIP을 임의의 작업 폴더에 압축 해제합니다. `Kernel_test`, `Shared`,
   `RansomGuard.props`의 상대 폴더 배치를 유지하세요.
2. Visual Studio 2022에서 `Kernel_test/Anti_Ransom_TestClient.vcxproj`를 엽니다.
3. 상단 빌드 설정에서 **Debug | x64**를 선택하고 **빌드 → 솔루션 빌드**를 누릅니다.
   MSVC v143 및 Windows SDK가 필요합니다. SDK 버전 불일치 메시지가 나오면
   Visual Studio의 프로젝트 대상 변경(Retarget) 기능으로 설치된 SDK를 선택하세요.
4. 빌드 결과는 통상 `out/x64/Debug/Anti_Ransom_TestClient/Anti_Ransom_TestClient.exe`
   입니다. 다른 출력 경로가 표시되면 Visual Studio의 빌드 출력 경로를 따르세요.
5. **이 새 EXE만** 격리 VM으로 옮깁니다. 구버전(2026-09-20 데스크톱 EXE)과
   혼동하지 않도록 VM에서 `C:\RG_Test\Anti_Ransom_TestClient_Diag.exe`로
   이름을 바꿔 놓아도 됩니다. 기존 드라이버 설치/서명은 변경할 필요 없습니다.

## VM에서 안전한 진단 순서

VM에서 **관리자 PowerShell 창을 두 개** 엽니다. 먼저 두 드라이버가 모두
`RUNNING`인지 확인하세요. **창 A(이벤트 수신용)** 에서 아래 명령을 실행한 뒤
창을 그대로 열어 둡니다. 테스트 클라이언트가 커널에 엔진으로 등록된 상태에서
파일을 변경해야 이벤트 전달 경로를 명확히 검증할 수 있습니다.

```powershell
$diag = 'C:\RG_Test\Anti_Ransom_TestClient_Diag.exe'
sc.exe query Anti_Ransom_Driver
sc.exe query Anti_Ransom_FsFilter
& $diag 50 --policy audit
```

**창 B(파일 작업용)** 에서 아래 명령으로 `C:\RG_Test` 안의 테스트 파일에만
쓰기/이름 변경 이벤트를 만듭니다. 이후 창 A의 `[RECV ...]` 출력을 확인합니다.

```powershell
$tag = Get-Date -Format 'HHmmss'
1..4 | ForEach-Object {
    $path = "C:\RG_Test\diag_${tag}_$($_).txt"
    Set-Content -LiteralPath $path -Value "RansomGuard diagnostic $($_)"
    Rename-Item -LiteralPath $path -NewName "diag_${tag}_$($_).renamed"
}
```

예상하는 진단 출력의 예시는 아래와 같습니다.

```text
[RECV 1] type=4 (FILE_WRITE) payloadBytes=2232 returnedBytes=2232 seq=...
       FILE operation=WRITE pid=... flags=...
       path=...RG_Test...

[RECV 2] type=5 (FILE_RENAME) payloadBytes=2232 returnedBytes=2232 seq=...
       FILE operation=RENAME pid=... flags=...
       path=...RG_Test...
       newExtension=renamed
```

주의:

- `type=1,2,3`만 나오면 **프로세스 이벤트가 전달됐다는 뜻**입니다. 이것만으로
  파일 이벤트 연동이 확인된 것은 아닙니다.
- `type=4,5`가 나오면 파일 이벤트의 사용자 모드 수신이 확인됩니다. 경로가
  `RG_Test`와 일치하면 제어된 테스트와의 연관성까지 확인할 수 있습니다.
- 수신 건수가 부족하면 `IOCTL_RG_GET_EVENT`가 대기할 수 있습니다.
  **10~15초 동안 새로운 이벤트가 없으면 Ctrl+C로 종료**하고 결과를 기록하세요.
- `--policy block`, `--terminate` 옵션은 이 진단에서 사용하지 마세요.
- 공유 폴더는 파일 전달 시에만 임시 사용하고, 커널 테스트 전에는 다시
  비활성화하여 격리를 유지하세요.

## 범위 제한

이 패키지에는 **Windows 빌드된 EXE가 포함되어 있지 않습니다**. 제공된 것은
v0.6.3 공용 ABI와 호환되는 v0.6.4 진단용 C++ 소스 및 Visual Studio 프로젝트입니다.
일반 이벤트 출력은 테스트 도구의 관측성을 높일 뿐 커널의 실제 이벤트 수집
문제를 자동으로 고치지는 않습니다.
