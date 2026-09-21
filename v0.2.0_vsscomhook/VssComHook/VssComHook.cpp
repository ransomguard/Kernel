// ===========================================================================
// File: VssComHook.cpp
// Developer: CHOI HWAN
// Stage: 2 - IAT 후킹 설치 (가로채기 확인용, 차단은 3단계)
//
// 목적: VssAttackSim(호출자) 프로세스의 IAT 에서
//       vssapi.dll!CreateVssBackupComponentsInternal 항목을 찾아
//       HookedCreateVssInternal 로 교체한다.
//       → 커널 프로세스 감시로 못 잡는 COM 직접 호출을 API 레벨에서 포착.
//
// [설계] 이 단계는 "가로채기 성공" 확인까지만 한다.
//        HookedCreateVssInternal 은 로그만 남기고 원본을 그대로 호출한다.
//        (차단은 3단계에서 E_ACCESSDENIED 반환으로)
//
// Build : x64, /MTd(Debug) 또는 /MT(Release), Unicode, DLL
// ===========================================================================
#include <windows.h>
#include <unknwn.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <cstdio>
#include <cstring>

// Common.h 는 C/C++ 양쪽을 스스로 처리하므로 extern "C" 로 감싸지 않는다.
#include "Common.h"

// ---------------------------------------------------------------------------
// 파일 로그 (DebugView 대체)
// ---------------------------------------------------------------------------
static void HookLog(const wchar_t* msg)
{
    FILE* f = NULL;
    if (_wfopen_s(&f, L"C:\\test\\vsshook.log", L"a, ccs=UTF-8") == 0 && f) {
        fwprintf(f, L"%s\n", msg);
        fclose(f);
    }
}

// ANSI 문자열(임포트 이름 등)을 로그에 남길 때
static void HookLogA(const char* prefix, const char* ansi)
{
    FILE* f = NULL;
    if (_wfopen_s(&f, L"C:\\test\\vsshook.log", L"a, ccs=UTF-8") == 0 && f) {
        fwprintf(f, L"%hs%hs\n", prefix, ansi);
        fclose(f);
    }
}

// ---------------------------------------------------------------------------
// 후킹 대상 시그니처
//   VSSAPI.DLL 의 실제 export 는 CreateVssBackupComponents 가 아니라
//   CreateVssBackupComponentsInternal 이다.
// ---------------------------------------------------------------------------
typedef HRESULT(WINAPI* PFN_CREATE_VSS_INTERNAL)(IVssBackupComponents** ppBackup);

static PFN_CREATE_VSS_INTERNAL g_OriginalCreateVss = NULL;  // 원본 주소
static PVOID* g_IatEntry = NULL;                            // 패치한 IAT 슬롯

// ---------------------------------------------------------------------------
// 가로챈 VSS COM 생성 함수
//   [2단계] 로그만 남기고 원본 호출 → 정상 동작 유지.
//   [3단계 예정] 커널 보고 후, 차단이면 E_ACCESSDENIED 반환.
// ---------------------------------------------------------------------------
extern "C" HRESULT WINAPI HookedCreateVssInternal(IVssBackupComponents** ppBackup)
{
    HookLog(L"[VssComHook] *** INTERCEPTED - BLOCKING (E_ACCESSDENIED) ***");

    // [3-1] 차단 검증: 원본을 호출하지 않고 거부.
    //       출력 포인터를 NULL 로 정리해 호출자가 오용하지 않게 한다.
    if (ppBackup != NULL) {
        *ppBackup = NULL;
    }
    return E_ACCESSDENIED;
}

// ---------------------------------------------------------------------------
// 진단: 특정 모듈의 IAT 에서 targetDll 로부터 임포트되는 함수 이름을 전부 로그
//   (정확한 이름을 못 찾을 때 실제 이름을 확인하기 위함)
// ---------------------------------------------------------------------------
static void DumpImportsFromDll(HMODULE hModule, const char* targetDll)
{
    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return;

    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);

    for (; imp->Name != 0; imp++) {
        const char* dllName = (const char*)(base + imp->Name);
        if (_stricmp(dllName, targetDll) != 0) continue;

        HookLogA("[VssComHook]   imports from ", dllName);

        IMAGE_THUNK_DATA* origThunk =
            (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk);
        if (imp->OriginalFirstThunk == 0)
            origThunk = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);

        for (; origThunk->u1.AddressOfData != 0; origThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                HookLog(L"[VssComHook]     (by ordinal)");
                continue;
            }
            IMAGE_IMPORT_BY_NAME* nm =
                (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
            HookLogA("[VssComHook]     - ", (const char*)nm->Name);
        }
    }
}

// ---------------------------------------------------------------------------
// IAT 에서 targetDll!targetFunc 슬롯 포인터를 찾는다. (없으면 NULL)
// ---------------------------------------------------------------------------
static PVOID* FindIatEntry(HMODULE hModule,
    const char* targetDll,
    const char* targetFunc)
{
    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return NULL;

    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);

    for (; imp->Name != 0; imp++) {
        const char* dllName = (const char*)(base + imp->Name);
        if (_stricmp(dllName, targetDll) != 0) continue;

        // INT(이름 배열) 로 이름 매칭, IAT(주소 배열) 의 같은 위치를 반환
        IMAGE_THUNK_DATA* origThunk =
            (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA* iatThunk =
            (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);

        if (imp->OriginalFirstThunk == 0) {
            // INT 가 없으면 IAT 로만 이름 매칭이 불가 → 이 경우는 건너뜀
            continue;
        }

        for (; origThunk->u1.AddressOfData != 0; origThunk++, iatThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;

            IMAGE_IMPORT_BY_NAME* nm =
                (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
            if (strcmp((const char*)nm->Name, targetFunc) == 0) {
                return (PVOID*)&iatThunk->u1.Function;
            }
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// IAT 후킹 설치
// ---------------------------------------------------------------------------
static BOOL InstallVssIatHook(void)
{
    // 호출자(메인 exe)의 IAT 를 대상으로 한다.
    HMODULE hMain = GetModuleHandleW(NULL);
    if (hMain == NULL) {
        HookLog(L"[VssComHook] GetModuleHandle(NULL) failed");
        return FALSE;
    }

    const char* kDll = "vssapi.dll";
    const char* kFunc = "CreateVssBackupComponentsInternal";

    PVOID* entry = FindIatEntry(hMain, kDll, kFunc);
    if (entry == NULL) {
        HookLog(L"[VssComHook] IAT entry NOT found. Dumping vssapi imports:");
        DumpImportsFromDll(hMain, kDll);  // 실제 이름 확인용
        return FALSE;
    }

    // 원본 주소 백업
    g_OriginalCreateVss = (PFN_CREATE_VSS_INTERNAL)(*entry);

    // 슬롯 쓰기 가능하게 보호 변경
    DWORD oldProtect = 0;
    if (!VirtualProtect(entry, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
        HookLog(L"[VssComHook] VirtualProtect(RW) failed");
        return FALSE;
    }

    *entry = (PVOID)HookedCreateVssInternal;   // 교체

    DWORD tmp = 0;
    VirtualProtect(entry, sizeof(PVOID), oldProtect, &tmp);  // 원복

    g_IatEntry = entry;
    HookLog(L"[VssComHook] IAT hook installed.");
    return TRUE;
}

// ---------------------------------------------------------------------------
// IAT 후킹 해제 (원상 복구)
// ---------------------------------------------------------------------------
static void UninstallVssIatHook(void)
{
    if (g_IatEntry == NULL || g_OriginalCreateVss == NULL) return;

    DWORD oldProtect = 0;
    if (VirtualProtect(g_IatEntry, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
        *g_IatEntry = (PVOID)g_OriginalCreateVss;
        DWORD tmp = 0;
        VirtualProtect(g_IatEntry, sizeof(PVOID), oldProtect, &tmp);
    }
    g_IatEntry = NULL;
    HookLog(L"[VssComHook] IAT hook removed.");
}

// ---------------------------------------------------------------------------
// DllMain
// ---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        HookLog(L"[VssComHook] DLL_PROCESS_ATTACH - loaded into target.");
        InstallVssIatHook();
        break;

    case DLL_PROCESS_DETACH:
        UninstallVssIatHook();
        HookLog(L"[VssComHook] DLL_PROCESS_DETACH - unloading.");
        break;
    }
    return TRUE;
}