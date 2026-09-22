// ===========================================================================
// File: VssComHook.cpp
// Developer: CHOI HWAN
// ===========================================================================
#include <windows.h>
#include <unknwn.h>    // COM 기본 인터페이스 (IUnknown 등)
#include <vss.h>       // VSS 기본 타입
#include <vswriter.h>  // vsbackup.h 선행 요구 조건
#include <vsbackup.h>  // IVssBackupComponents 인터페이스 정의

// Common.h는 C/C++ 양쪽을 스스로 처리하도록 작성되었으므로 extern "C"로 감싸지 않는다.
#include "Common.h"

//
// [주의] VSSAPI.DLL 의 실제 export 심볼은 CreateVssBackupComponents 가 아니라
//        CreateVssBackupComponentsInternal 이다.
//        vsbackup.h 의 CreateVssBackupComponents 는 이 함수를 부르는 inline 래퍼일 뿐이다.
//        따라서 원본 해석과 IAT 후킹 대상 모두 "...Internal" 을 사용해야 한다.
//
typedef HRESULT(WINAPI* PFN_CREATE_VSS_INTERNAL)(IVssBackupComponents** ppBackup);

// 원본 함수 주소 (IAT 후킹 설치 시 채워진다)
static PFN_CREATE_VSS_INTERNAL g_OriginalCreateVss = NULL;

//
// 가로챈 VSS COM 생성 함수.
// 설계 원칙: "차단"이 아니라 "커널로 보고" 한다.
//  - 무조건 E_ACCESSDENIED 는 정상 백업 SW 까지 죽이므로 지양.
//  - 커널이 상관분석/화이트리스트로 차단 여부를 최종 결정한다.
//
extern "C" HRESULT WINAPI HookedCreateVssInternal(IVssBackupComponents** ppBackup)
{
    OutputDebugStringW(L"[Anti-Ransomware] CreateVssBackupComponentsInternal intercepted");

    // TODO: Common.h 의 IOCTL_RG_REPORT_VSS_ATTEMPT 또는 GET_EVENT로 커널에 보고
    //       (호출 프로세스 PID, ImagePath, 타임스탬프 포함)
    //       커널 응답이 "차단"이면 여기서 E_ACCESSDENIED 반환.

    // 현재는 보고 골격만 있으므로 원본을 그대로 호출해 정상 동작을 유지한다.
    if (g_OriginalCreateVss != NULL) {
        return g_OriginalCreateVss(ppBackup);
    }

    // 원본을 아직 확보 못 한 상태의 안전한 실패값
    UNREFERENCED_PARAMETER(ppBackup);
    return E_UNEXPECTED;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // TODO: 여기서 InstallVssIatHook() 호출 → IAT 패치
        break;

    case DLL_PROCESS_DETACH:
        // TODO: UninstallVssIatHook() → 원상 복구
        break;
    }
    return TRUE;
}