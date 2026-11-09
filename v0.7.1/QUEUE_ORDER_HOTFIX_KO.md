# RansomGuard 커널 v0.7.0-rc2 — FIFO 시퀀스 순서 교정 패치

## 배경 (2026-11-09 VM 관측)

- Observer가 읽은 200개 커널 이벤트는 모두 PID 3352의 SRU 관련 파일 쓰기였다.
- 그중 95건은 SRUDB.dat, 94건은 SRU.log였다.
- Triage reset: sequence_gap_or_reorder 5회, driver_drop_counter_advanced 1회.
- SQLite 자체 쓰기 이벤트는 이 200건에 없었다. Observer 자기 DB 필터 오류로
  판정할 근거가 아니다.

## 소스에서 확인한 문제와 수정

기존 Eventqueue.c는 ArwEventInitializeHeader가 여러 스레드에서 먼저
SequenceNumber를 발급하고, 이후 ArwEventQueuePush가 spin lock을 얻어
리스트 끝에 넣었다. 스레드의 실행 순서가 바뀌면 숫자는 1,2여도 실제 큐는
2,1이 될 수 있다. 이 현상은 실제 유실이 없어도 Triage가 순서 이상으로
상태를 초기화하는 원인이 될 수 있다.

수정: 헤더 초기화 단계에서는 SequenceNumber=0으로 두고,
실제 QueuePush의 FIFO 삽입 락 내부에서 시퀀스를 한 번만 발급한다.
전송 구조체 레이아웃, IOCTL, 속성 및 미니필터 코드는 변경하지 않는다.

**변경 파일**

- Anti_Ransom_Driver/Eventqueue.c
- Anti_Ransom_Driver/Eventqueue.h (계약 설명 보완)
- Shared/Common.h (주석만 변경)

## 중요한 한계

1. 이는 확정된 **시퀀스 역전 가능성**을 제거하는 소스 수정이다. 실제
   Windows에서 확인된 5회의 초기화가 모두 이 원인이었다고 증명하지는 못했다.
2. 큐 용량 초과, 이벤트 손실, 드라이버 드롭 카운터 증가 1회는 별개다.
   유실을 가리거나 카운터를 초기화하지 않았다.
3. 여러 GET_EVENT 요청이 동시에 존재할 때의 완료 순서 문제는 이 패치의
   보증 대상이 아니다. 현재 Python Reader는 동시 GET_EVENT를 발행하지 않는다.
4. Windows\System32\sru 경로를 탐지에서 제외하지 않았다. 무조건적인
   경로 예외는 악성 파일 쓰기를 숨길 수 있다.
5. 이 ZIP은 **소스 패치**이며, 사용자가 제공한 서명된 .sys 바이너리를
   수정하지 않는다. Windows/WDK 빌드·시험 서명·VM 검증은 아직 수행되지 않았다.

## 적용 및 검증 순서

1. 현재 VM의 스냅샷과 커널 소스 백업을 유지한다.
2. 호스트에서 기존 v0.7.0-rc2 소스 루트에 이 ZIP을 풀고 파일을 덮어쓴다.
   Anti_Ransom_FsFilter는 수정하지 않는다.
3. Visual Studio + WDK에서 Anti_Ransom_Driver 프로젝트를 Debug | x64로
   빌드하고 기존 시험 서명 절차를 통해 새 .sys/.cat을 생성한다.
4. VM에 기존의 검증된 드라이버 설치/교체 절차대로 배포한다. 실행 중인
   드라이버 .sys를 덮어쓰기 하거나 .cat의 기존 서명을 재사용하지 않는다.
5. 독립된 작은 파일 쓰기 테스트에서 이전/이후의 시퀀스 이상 건수,
   EventsDropped 및 QueueDepth를 별개로 비교한다.
6. 동일한 부하에서 SRU 이벤트가 여전히 집중된다면 수집 소비 속도,
   사용자 모드 SQLite 동기 기록, 드라이버 큐의 성능 문제를 별도로 다룬다.

## 이 환경에서 가능한 확인

    python -m unittest discover -s tests -v

이 테스트는 할당 위치와 순서의 **소스 구조만 검증**한다. Windows WDK 컴파일,
서명 검증, 커널 실기동이나 이벤트 누락 감소를 입증하지 않는다.
