# 복구·JEV v0.3.1 ZIP 소스 점검 — 2026-11-16

**대상:** 사용자가 첨부한 `v0.3.1.zip` 소스 및 내부 `ransomguard_integration-0.3.1-py3-none-any.whl`.
v0.3.2 이상은 제공되지 않았으므로 실제 VM에 설치한 버전과 동일하다고 단정하지 않는다.

## 확인된 구현

| 요소 | 소스에서 확인한 구현 | 검증 범위 |
|---|---|---|
| 커널 이벤트 수신 | `protocol.py`, `windows_reader.py`, `cli.py`에 ABI v1 이벤트 타입 1~5/2232B 파일 이벤트 및 등록된 엔진 IOCTL 수신 | 정적 계약+오프라인 테스트 |
| Track B 판별 | `triage.py`: 고엔트로피 `FILE_WRITE`는 Track B 후보, 프로세스 생성시간 상관 없으면 `deferred` | 실제 JEV 자동 승인 아님 |
| 자동 대응 | `cli.py`의 `observe --live-track-b`는 별도 승인/정확한 NT 테스트 디렉터리/JEV 자격정보가 있을 때 후보를 `LiveResponseCoordinator`로 연결 | 운영 기본값은 관측 전용 |
| Track A | `live_response.py`에 명시적으로 승인한 Track A의 host outbound 차단→생성시간 일치 종료 요청→종료 확인→복구 | `observe`에서 Track A 자동 실행은 **없음** |
| 방화벽 | `firewall_control.py`에 독립 데몬 IPC와 사고별 보유(hold) 카운트 관리 | 방화벽 ACK만으로 실제 WFP 적용을 증명하지 않음 |
| JEV | `jev.py`의 원격 API 호출 및 점수 검증/0.2~0.8 분류 정책 | 임계값은 보정되지 않은 데모 기준, 실계정 필요 |
| VSS 스냅샷 | `snapshots.py`, `scheduling.py`: 시간당 1회 스냅샷 및 작업 스케줄 정의, 기록·중복 방지 | Windows 실제 예약작업 설치는 별도 |
| 파일 복구 | `recovery.py`: 사고 시점 **이전** 동일 볼륨의 VSS와 승인된 파일 매니페스트, 스테이징/원자적 파일 교체, SHA-256 확인 | 전체 피해 파일 자동 탐색·ACL/ADS/EFS 복원은 없음 |
| UI | `ui_pipe.py`, `ui_bridge.py`의 best-effort 로컬 IPC | UI 수신기 연결/ACK는 별도 검증 |

## 확실하게 남은 통합 문제

1. **관측 ≠ 자동 실행:** 사용자 화면의 `316 kernel_event`는 저장한 커널 이벤트 수다. 그만큼 악성이라고 판단한 것도, 자동 차단한 것도 아니다. `observe`에서 실제 Track B 자동 대응도 별도 opt-in이며 Track A는 명시적 별도 명령 경로다.
   특히 `PROCESS_BLOCKED(3)` 또는 Fast Path 규칙 1009의 감사 이벤트를 `observe`가 별도의 Track A/B 사고로 자동 승격시키는 경로는 없다. v0.8.0 규칙 1009는 감사만 하고 v0.3.1의 `triage.py`는 **파일 고엔트로피가 없는 프로세스 규칙 이벤트**만으로 Track B 후보를 내지 않는다.
2. **파일 hold가 실제로 없음:** `replay`의 `file_hold`/`file_release`는 모의 효과. v0.3.1과 커널 v0.8.0 모두 판정 대기 중 파일 쓰기를 중단시키는 기능이 없다. 피해 확산 방어/복구 경합의 핵심 미해결 항목이다.
3. **프로세스 ID 바인딩:** 파일 이벤트에 생성시각이 없어 생성 이벤트를 관측하지 못하면 Track B를 `deferred`로 기록한다. `terminate_checked`는 실제 생존 세대 확인을 요구하므로 이 안전조건을 임의 완화하면 안 된다.
4. **자동 피해 목록 없음:** 복구는 미리 승인된 정확한 파일 매니페스트에 한정된다. 최근 1시간의 변경 파일을 자동으로 확정하거나 원래 정상 상태를 찾는 엔진은 없다.
5. **WFP/복구 신뢰:** `firewall_policy_acknowledged`가 True여도 `wfp_enforcement_verified`는 False다. 외부 방화벽 데몬의 ACK와 실제 VM 외부 연결 차단을 구별해 현장 시험해야 한다. 복구 단계의 `containment_confirmed=True`는 상위 오케스트레이터의 신뢰에 의존한다.
6. **잔여 위험:** JEV 장애/점수 애매함 시 전역 네트워크 차단이 유지될 수 있다. 복구는 파일별로 원자적 교체이지만 *매니페스트 전체*에 대한 트랜잭션 롤백은 제공되지 않는다.

## 시험 결과와 판단

- Python 189개 단위·통합 모의 테스트 **전부 통과**. 테스트 출력의 `Asynchronous recovery failed (RecoveryError)`는 예외 경로를 재현한 테스트 내 예상 로그이며 최종 `OK`다.
- wheel의 `ransomguard/*.py` 및 `core/*.py`는 ZIP에 포함된 소스와 **바이트 단위 일치**.
- v0.8.0은 ABI v1을 유지하므로 패킷 형식 수정 없이 현재 소스와 연결 가능하다.
- **결론:** v0.3.1에는 설계에 맞는 복구·JEV·상태관리 구성요소가 실재한다. 다만 본 프로젝트의 목표인 *전체 자동 대응 완결성*은 입증되지 않았으며, 특히 파일 격리·Track A 상위 자동화·피해 목록 선택을 다음 통합 단계에서 해결해야 한다. 현재 검사는 **소스/오프라인 테스트**로 한정하며, 실제 Windows VM·JEV API·WFP·VSS 종단 통합 시험을 대신하지 않는다.
