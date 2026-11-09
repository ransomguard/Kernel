# Kernel v0.7.1 — QueueFix 소스 릴리스 및 검증 경계

작성: 2026-11-09 (KST) · 저장소: `ransomguard/Kernel` · 대상: 격리 Windows 11 VM

## 변경 사항

- 기존 `v0.7.0-rc2`의 전체 커널/미니필터/테스트 클라이언트 소스를 보존하고 QueueFix를 반영했다.
- `Anti_Ransom_Driver/Eventqueue.c`: FIFO 삽입 락 내부에서 `SequenceNumber`를 부여하여 이벤트 순서와 번호 부여 순서가 역전될 가능성을 제거했다.
- `Anti_Ransom_Driver/Eventqueue.h`, `Shared/Common.h`: 시퀀스 계약에 대한 주석·설명을 갱신했다.
- 두 INF의 `DriverVer=11/09/2026,0.7.1.0`; 두 `.vcxproj`의 StampInf `TimeStamp=0.7.1.0`. `Inf2CatUseLocalTime`은 유지한다.
- 사용자 모드 IOCTL, 커널 이벤트 구조체 및 미니필터 메시지 ABI는 변경하지 않았다. 사용자 모드 `restore v0.3.1`은 ABI v1을 계속 사용한다.

## 2026-11-09 실측 확인

- Windows 11 VMware VM: QueueFix 기반 메인 제어 드라이버 및 `Anti_Ransom_FsFilter`가 `RUNNING`; 미니필터 인스턴스 3개가 보고되었다.
- 해당 QueueFix **기존 빌드**의 `.sys` Authenticode 상태 `Valid` 확인, `pnputil`로 새 패키지 설치 및 메인 드라이버 시작 확인. 설치 당시 INF `DriverVer`는 `11/09/2026,0.7.0.0`이었다.
- 사용자 모드 Observer가 실제 커널 WRITE/RENAME 이벤트를 수신하여 SQLite에 기록했다. 실제 커널 이벤트 시퀀스 `2421`에서 고엔트로피 쓰기 기반 Track B 후보가 생성되었다.
- 200개 이벤트 표본에서 시퀀스 역전은 확인되지 않았으나 **시퀀스 갭 1회, 드라이버 드롭 카운터 증가 1회**가 관찰되었다. 이벤트 무손실은 보장되지 않는다.
- Track B 후보를 사용자 모드에서 실제 JEV로 수동 전달해 `jev-1.14.0`의 `score=0.21` 응답을 확인했다. 이는 자동 JEV 호출 검증이 아니며 Kernel 저장소 기능도 아니다.

## 새 버전의 로컬 검사

- 2026-11-09 Linux 소스 검사: `python3 -m unittest discover -s tests` → **3/3 PASS**. 이 결과는 WDK 빌드/실기동을 대체하지 않는다.

## 아직 검증하지 않은 사항

1. **v0.7.1.0 INF/StampInf 재빌드·시험 서명·VM 재설치**: 새 버전 번호를 반영했으므로 기존 `0.7.0.0` 산출물과 섞지 않는다.
2. 장시간/고부하 이벤트 큐 유실률, 여러 소비자·동시 GET_EVENT 상황의 이벤트 순서 보장.
3. 실제 프로세스별 네트워크 격리, Track A/B 자동 종료·복구 통합 흐름.

**배포 형태:** 소스 전용. `.sys`, `.cat`, 테스트 인증서·개인 키는 포함하지 않는다. 실제 WDK 산출물은 VM/호스트에서 다시 빌드·서명해야 한다. 기존 서명 파일과 새 INF를 혼합하지 않는다.
