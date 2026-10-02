# RansomGuard v0.5.0 — Event Queue Generalization (이벤트 큐 일반화 + 드라이버 간 싱크)

미니필터가 파일 조작 로그를 기존 드라이버로 보낼 수 있도록, 이벤트 큐를
가변 크기 페이로드 수용 구조로 일반화하고 두 드라이버를 잇는 콜백 싱크를
추가한 버전입니다.

**변경일:** 2026-09-28
**이전 버전:** `v0.4.1_backslash-recovery`

---

## 이번 버전의 목적 — Track B 기반 구조

미니필터(별도 .sys)가 수집한 파일 조작 이벤트(ARW_FILE_EVENT)를 기존
드라이버의 이벤트 큐로 전달하기 위한 하부 구조를 마련했습니다. 두 드라이버는
여전히 분리된 상태를 유지하며, 커널 콜백 객체로 단방향 송신만 추가합니다.

| 문제 | 해결 |
|---|---|
| 이벤트 큐가 ARW_PROCESS_EVENT(1616B) 전용으로 고정 | 가변 페이로드(최대 2232B) 수용하도록 일반화 |
| 미니필터(별도 .sys)가 기존 드라이버 큐에 직접 접근 불가 | 커널 콜백 객체(ExCreateCallback) 싱크로 단방향 전달 |

---

## 핵심 변경

**이벤트 큐 일반화 (Eventqueue.c)**
- 큐 노드를 ARW_PROCESS_EVENT 고정에서 ARW_EVENT_ANY union으로 확장.
  프로세스 이벤트(1616B)와 파일 이벤트(2232B)가 같은 FIFO에 섞여 전달됨.
- Push를 PayloadSize 기반으로 일반화, 범위 검증 [32, 2232] 추가.
- Drain이 노드의 Header.PayloadSize만큼만 복사·완료.

**드라이버 간 콜백 싱크**
- 기존 드라이버가 콜백 객체(ExCreateCallback/ExRegisterCallback)를 등록하고,
  수신 루틴이 전달받은 파일 이벤트를 큐에 Push.
- 로드 순서 무관, 하드 의존 없음(미니필터만 로드되고 기존 드라이버가 없으면
  송신은 no-op). 각 컴포넌트의 분리·격리 원칙 유지.

**Common.h (3사본 동기화)**
- ARW_EVENT_ANY union, ARW_MAX_EVENT_SIZE(2232), 관련 C_ASSERT.
- NewExtension은 점 없이 전달하는 규약을 주석으로 명시.

---

## ABI 변경 (호환성 단절, 의도됨)

GET_EVENT의 최소 출력 버퍼가 1616B에서 2232B(ARW_MAX_EVENT_SIZE)로 바뀌었습니다.
구버전 1616B 버퍼로 요청하면 STATUS_BUFFER_TOO_SMALL(Win32 122)을 받습니다.
유저 모드(테스트 클라이언트, 이후 연동할 분석 엔진)는 다음 규약을 따라야 합니다.

- 수신 버퍼 2232B 이상
- Header.EventType으로 프로세스/파일 이벤트 분기
- 유효 길이는 Header.PayloadSize
- 확장자는 점 없이 전달됨 (txt, not .txt)

---

## 검증 결과 (VM) — 기존 기능 회귀 없음

검증된 큐를 건드린 변경이라, 기존 프로세스 이벤트 경로가 깨지지 않았는지를
최우선으로 확인했습니다. VMware Win11 (26100), testsigning on.

| 확인 | 결과 |
|---|---|
| 큐 노드 크기 | DebugView `Event queue initialized (node=2248 bytes, max depth=1024)` |
| 콜백 싱크 등록 | `File event sink registered` |
| 프로세스 이벤트 수신 | 프로세스 생성/종료가 전과 동일하게 수신(측정 중 신규 이벤트 다수 포착) |
| 이벤트 회계 | 검산 (큐 감소 + 신규 발생) = 수신 건수, EventsDropped 0 |
| 상태 조회 | 오류 122 없이 정상 |
| 패스트패스 회귀 | vssadmin delete shadows → RULE 1001 BLOCKED |
| 언로드 | 엔진 종료 후 정상 해제(싱크 → 큐 순), BSOD 없음 |

> 핵심은 "검증된 큐를 일반화했는데 기존 프로세스 감시가 그대로 동작하는가"였고,
> 프로세스 이벤트 수신·회계·패스트패스가 모두 회귀 없이 통과했습니다.

---

## 참고

- 유저 모드와 커널을 동시에 재빌드해야 합니다(ABI 변경).
- 엔진이 GET_EVENT 중 요청을 건 상태로 드라이버를 내리면 언로드가 지연됩니다.
  엔진을 먼저 종료한 뒤 드라이버를 내리는 것이 정상 순서입니다.

---

## 다음 단계

- [ ] 미니필터 Track B 쓰기 경로 (IRP_MJ_WRITE → 콜백 싱크 송신, 핸들당 1회 억제)
- [ ] 확장자 변경 감지 (IRP_MJ_SET_INFORMATION, FileRenameInformation)
- [ ] 시스템 경로 1차 필터링