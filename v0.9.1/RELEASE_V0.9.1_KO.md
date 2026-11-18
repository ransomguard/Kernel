# Kernel v0.9.1 — 통합 설치 연결 정보 패치

이번 버전은 v0.9.0의 C/C++ 런타임 코드를 유지합니다. INF/StampInf 소스 버전을 0.9.1.0으로 구분하고 통합 설치본과의 연결 정보 및 검증 범위를 정리했습니다. 새 커널 동작 수정이나 재빌드 성공을 주장하지 않습니다.

설치 파일: https://github.com/ransomguard/installer/releases/tag/v0.6.0-preview.3
복구 소스: https://github.com/ransomguard/restore/tree/main/v0.5.2

preview.3에 들어간 기존 시험 드라이버 SHA256:
- Core: d197544adb765b1826a460b845b1fc2ed08f4505d17471252b5ebd2abd907226
- Filter: 088f92660dfa263b94654cb8f46ab39a523678ceb46a1822354ce84a4d0ae38b

이 기존 바이너리는 이번 0.9.1.0 INF 메타데이터로 다시 만든 패키지가 아닙니다. 새 INF로 배포 패키지를 만들 때는 WDK 재빌드·카탈로그 생성·서명·VM 재검증이 필요합니다. Microsoft 정식 배포 서명 및 정식 altitude는 아직 확보되지 않았습니다.

이번 소스 정적 검사는 ABI/FIFO 순서 및 FastPath 구조를 확인하며 실제 WDK 빌드·커널 실행 시험을 대신하지 않습니다. 새 Windows 11 ISO 설치 환경 검증은 진행 전입니다. 과거 VM 부하 시험의 추가 유실 0 결과를 모든 환경의 유실 0 보증으로 확대하지 않습니다.
