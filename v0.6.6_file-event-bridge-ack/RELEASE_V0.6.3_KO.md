# RansomGuard Kernel v0.6.3 — 격리 VM용 미니필터 고도 수정

릴리스 날짜: 2026-11-02

## 결과 및 범위

- v0.6.2의 `Anti_Ransom_FsFilter.inf`에서 사용했던 `385100`은 Microsoft가 **MiniSpy Top**에 할당한 고도입니다. v0.6.3에서는 이를 격리 VM 실험용 임시 고도 `385090`으로 수정했습니다.
- 새 고도 `385090`은 2026-11-02 확인한 Microsoft [공식 할당 목록](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes)에 없지만 **Microsoft가 이 프로젝트에 정식 배정한 고도는 아닙니다**. 제품 배포에는 [정식 고도 신청](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)이 필요합니다. 실제 VM에서 현재 로드된 필터와 중복되는지도 확인해야 합니다.
- `Anti_Ransom_FsFilter.inf`의 `DriverVer`를 `11/02/2026,0.6.3.0`으로 변경했습니다.
- `Anti_Ransom_Driver` KMDF 코드·서비스·IOCTL 및 `Shared/Common.h`, `Anti_Ransom_TestClient` 코드는 v0.6.2와 같습니다. IPC의 `ARW_DRIVER_VERSION`은 호환성을 위해 그대로 두었습니다.
- `store` 복구/JEV 저장소는 이 릴리스에서 수정하지 않았습니다.
- **이 파일은 소스 릴리스이며 `.sys`/`.cat` 바이너리를 포함하지 않습니다.** 이 Linux 환경에서 MSVC/WDK 서명·Windows 로드 검증은 수행할 수 없었습니다.

## 이미 확보된 v0.6.2 사용자 VM 검증 (이전 버전 바이너리)

사용자가 2026-11-02 제공한 스크린샷에서:

1. VS 2022 + WDK 26100, Debug x64로 3개 프로젝트 빌드 성공, 오류 0, 경고 0.
2. `Anti_Ransom_Driver.sys` 및 `.cat` 서명 `Valid`, VM에서 `Anti_Ransom_Driver` INF 등록 성공.
3. `sc.exe start Anti_Ransom_Driver` 결과 `RUNNING`, 종료 코드 0. `sc.exe stop` 결과 `STOPPED`, 종료 코드 0, 이후 재시작 성공.
4. `Anti_Ransom_TestClient.exe 0 --policy audit`: 장치 연결/엔진 등록/상태 조회 성공. `FastPathMode=1`, `SelfProtectEnabled=0`.
5. `Anti_Ransom_TestClient.exe 1 --policy audit`: 이벤트 1건 수신, `QueueDepth 17 -> 16`, `EventsGenerated 17 -> 17`, 유실 0.
6. 기존 VM의 다른 서비스 `ARWDrv`는 `STOPPED` 상태였고 별도로 변경하지 않았습니다.
7. **v0.6.3 미니필터의 실제 빌드/서명/설치/파일 이벤트 수신은 아직 검증되지 않았습니다.**

## Windows 10 개발 호스트에서 빌드

1. `RansomGuard-knel-v0.6.3-lab-altitude.zip` 파일의 `knel` 디렉터리를 호스트에서 압축 해제합니다. 기존 v0.6.2 작업 디렉터리와 섞지 않습니다.
2. 호스트의 **Visual Studio 2022**로 `knel\RansomGuard.sln`을 엽니다.
3. `Debug | x64`를 선택하고 솔루션을 빌드합니다. 문제없이 진행되면 `.sys`, `.inf`, `.cat` 생성 및 서명 완료 메시지를 확인합니다.
4. 새로 생성된 **같은 빌드의 미니필터 패키지**를 사용합니다. 일반적으로 다음 폴더에 있습니다.

   `knel\out\x64\Debug\Anti_Ransom_FsFilter\Anti_Ransom_FsFilter\`

   - `Anti_Ransom_FsFilter.sys`
   - `Anti_Ransom_FsFilter.inf`
   - `Anti_Ransom_FsFilter.cat` (탐색기에는 소문자로 표시될 수 있음)

5. 빌드된 `Anti_Ransom_FsFilter.inf` 내용에서 `InstanceAltitude = "385090"` 또는 해당 인스턴스 `Altitude` 값을 확인합니다. VS의 `StampInf` 작업으로 날짜/버전이 변경될 수 있으므로 **원본 INF가 아닌 빌드 패키지의 INF**를 검사합니다.
6. 서명된 바이너리와 카탈로그를 동일한 폴더에서 VM으로 복사합니다. 호스트에서 커널을 설치·실행하지 않습니다.

## 격리 VM 검증 — 단계별로 수행

1. 스냅샷 유지, VM 네트워크/공유 폴더 연결 해제. 옛 `ARWDrv`를 시작하거나 제거하지 않습니다.
2. 새 `Anti_Ransom_FsFilter.sys`와 `Anti_Ransom_FsFilter.cat`에 `Get-AuthenticodeSignature`를 각각 사용하여 `Valid`인지 확인합니다. 기존 WDK 테스트 인증서와 서명자가 다르면 인증서 지문을 대조하고 VM에만 신뢰를 설정합니다.
3. `fltmc filters`로 **385090**을 사용하는 실행 중인 필터가 없는지 확인합니다. 겹친다면 로드하지 않고 중단합니다. 공식 고도 배정이 없는 상태이므로 이 절차는 격리 실험 목적에만 적용합니다.
4. 패키지의 `Anti_Ransom_FsFilter.inf`를 우클릭 → 설치합니다. 이 단계에서는 자동 실행을 기대하지 않습니다. 새 인스턴스의 레지스트리 고도와 서비스 상태를 확인합니다.
5. 별도 안내를 받아 `fltmc load Anti_Ransom_FsFilter` 후 `fltmc filters`/`fltmc instances`로 로드를 확인합니다. 예상 밖 오류나 블루스크린이 나면 반복 시도하지 않고 스냅샷에서 복구합니다.
6. 파일 쓰기·이름 변경 이벤트를 안전한 더미 파일로 관측하고 IPC 경로를 확인합니다. 이 미니필터는 파일 쓰기 자체를 차단하지 않으며, 복구/JEV의 실제 연동을 검증한 것으로 간주하지 않습니다.

## 릴리스 사용 시 주의사항

- v0.6.2의 기존 서명된 `.sys`/`.cat`을 섞거나 원본 INF만 바꿔 재사용하지 마세요. INF는 카탈로그의 검증 대상이므로 수정 후 **Inf2Cat/SignTool 재생성 및 재서명**이 필요합니다.
- `SelfProtect` / `EnableUnloadProtection`은 첫 미니필터 로딩 테스트에서 활성화하지 않습니다.
- 정식 MS 할당 없이 임시 고도 `385090`을 외부 PC나 실사용 PC에 배포하지 않습니다.
- 스냅샷을 확보한 **Windows 11 격리 VM에서만** 검증합니다.
