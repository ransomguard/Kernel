> **v0.6.3 참고 문서:** 우선 `../RELEASE_V0.6.3_KO.md`를 따르세요. 아래 자기보호 검증은 추후 선택 사항이며 첫 로딩 테스트에서는 켜지 않습니다. 과거 안내의 385100은 Microsoft에 이미 할당된 값이므로 사용 금지입니다. 복구/네트워크/호스트에는 적용하지 않고 격리 VM에서만 테스트합니다.

# Anti_Ransom_FsFilter — 설치 및 언로드 자기보호 검증 절차

이 문서는 미니필터(`Anti_Ransom_FsFilter`)를 테스트 VM에 올리고, **언로드
자기보호(EnableUnloadProtection)** 기능을 켜고 끄고 확인하는 절차를 정리한다.
로드/등록 전체 절차의 배경 설명은 `README`(v0.3.0)를 참고한다. 모든 명령은
**관리자 권한** 콘솔에서 실행한다.

---

## 0. 전제

- 스냅샷이 확보된 격리 Windows 11 VM. 테스트 서명 정책은 VM에 기존 설정된 것을 확인하고 호스트에서는 수정하지 않습니다.
- v0.6.3 소스를 Windows 10 개발 호스트의 VS 2022 + WDK 26100으로 **다시 빌드**합니다.
- 새 `Anti_Ransom_FsFilter.sys`, `Anti_Ransom_FsFilter.inf`, `Anti_Ransom_FsFilter.cat`가 같은 빌드 패키지 폴더에 있고 서명이 유효한지 확인합니다. **기존 v0.6.2 파일의 `.cat`을 재사용하면 안 됩니다.**
- VMware 공유 폴더에서 VM 내부로 복사한 뒤 공유 폴더와 네트워크를 끊습니다.
- INF의 서명/고도를 확인한 뒤 `Anti_Ransom_FsFilter.inf`를 우클릭해 설치합니다. 임의의 `sc create` 또는 `reg add`로 중복 서비스/인스턴스를 생성하지 않습니다.
- Windows 11 24H2 이상은 `HKLM\SYSTEM\CurrentControlSet\Services\Anti_Ransom_FsFilter\Parameters\Instances`를 확인합니다. v0.6.3의 `385090`은 **격리 VM 실험용 임시값**이지 정식 할당값이 아니므로 실제 제품 배포에 사용할 수 없습니다.
- 현재 VM에서 기존 필터의 고도 충돌을 확인한 다음, 관리자 PowerShell에서 `fltmc load Anti_Ransom_FsFilter`를 사용하고 `fltmc filters`로 로딩을 확인합니다. 첫 시험에서는 `EnableUnloadProtection`을 설정하지 않습니다.

---

## 1. 언로드 자기보호란

관리자가 `fltmc unload Anti_Ransom_FsFilter`로 미니필터를 손쉽게 내리면, 보안
컴포넌트가 무력화된다. 이 기능은 **자발적 언로드 요청을 조건부로 거부**해 그
구멍을 막는다.

| 항목 | 값 |
|---|---|
| 킬 스위치 값 | `HKLM\SYSTEM\CurrentControlSet\Services\Anti_Ransom_FsFilter\Parameters\EnableUnloadProtection` (REG_DWORD) |
| 기본값 | `0` (꺼짐). 값이 없어도 꺼짐으로 동작 |
| 읽는 시점 | 드라이버 로드 시(`DriverEntry`) **1회**. 런타임 변경은 다음 로드까지 반영되지 않음 |
| 켜짐(1) 동작 | 자발적 `fltmc unload` 거부(`STATUS_FLT_DO_NOT_DETACH`) |
| 강제 언로드 | 시스템 종료 등 mandatory 언로드는 **항상 허용**(종료를 방해하지 않음) |
| 성능 | 언로드 시점에서만 동작. 파일 I/O(pre-write) 경로에는 영향 없음 |

> 값을 한 번만 읽으므로, 값을 바꾼 뒤에는 반드시 드라이버를 **재로드**해야
> 새 값이 적용된다.

---

## 2. 보호 켜기 → 언로드 거부 확인

1. 킬 스위치를 켠다.

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Anti_Ransom_FsFilter\Parameters" /v EnableUnloadProtection /t REG_DWORD /d 1 /f
```

2. 새 값을 반영하기 위해 재로드한다. (지금은 아직 보호가 꺼진 상태로 로드돼
   있으므로 unload가 정상 동작한다.)

```
fltmc unload Anti_Ransom_FsFilter
fltmc load   Anti_Ransom_FsFilter
```

3. 로드 로그에서 보호가 켜졌는지 확인한다(DebugView 또는 WinDbg):

```
[Anti_Ransom_FsFilter] Unload self-protect: ON
```

4. **언로드가 거부되는지 확인한다.**

```
fltmc unload Anti_Ransom_FsFilter
```

기대 결과:

- 명령이 **실패**한다(오류 반환, 필터가 내려가지 않음).
- 커널 로그에 거부 메시지가 남는다:

```
[Anti_Ransom_FsFilter] Unload REFUSED by self-protect (EnableUnloadProtection=1). Set the registry value to 0 and reload to detach.
```

- `fltmc filters`에 `Anti_Ransom_FsFilter`가 **여전히 표시**된다.

---

## 3. 킬 스위치로 해제 → 정상 언로드 확인

보호가 켜진 상태에서는 `fltmc unload`가 거부되므로, 개발자가 빠져나오는 경로는
**값을 0으로 바꾼 뒤 재부팅**하는 것이다. (드라이버가 로드 시점에 값을 다시
읽어 꺼진 상태로 올라온다. 서비스는 demand-start라 부팅 직후 자동 로드되지
않는다.)

1. 킬 스위치를 끈다.

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Anti_Ransom_FsFilter\Parameters" /v EnableUnloadProtection /t REG_DWORD /d 0 /f
```

2. 재부팅한다. (시스템 종료 시의 mandatory 언로드는 보호와 무관하게 허용되므로
   깨끗하게 내려간다.)

```
shutdown /r /t 0
```

3. 재부팅 후 다시 로드하고, 보호가 꺼졌는지 확인한다.

```
fltmc load Anti_Ransom_FsFilter
```

로그:

```
[Anti_Ransom_FsFilter] Unload self-protect: OFF
```

4. **언로드가 정상 동작하는지 확인한다.**

```
fltmc unload Anti_Ransom_FsFilter
fltmc filters            # 목록에서 사라짐
```

기대 결과: 언로드 성공, `fltmc filters` 목록에서 제거됨.

---

## 4. 요약 표

| 상태 | EnableUnloadProtection | 로드 로그 | `fltmc unload` 결과 |
|---|---|---|---|
| 기본 | 0(또는 값 없음) | `Unload self-protect: OFF` | 성공(내려감) |
| 보호 켜짐 | 1 | `Unload self-protect: ON` | **거부**(그대로 유지) |
| 킬 스위치 해제 | 1 → 0 후 재부팅·재로드 | `Unload self-protect: OFF` | 성공(내려감) |

> **주의:** 보호를 켜기 전에 VM 스냅샷을 확보할 것. 값을 1로 둔 채 재부팅 방법을
> 잊으면 해당 VM에서 미니필터를 내릴 방법이 재부팅뿐이 되므로, 킬 스위치 해제
> 절차(3절)를 먼저 숙지한 뒤 켤 것.
