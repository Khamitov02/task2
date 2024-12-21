// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"Process Attach!", L"DllToInject", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        MessageBox(NULL, L"Process Detach!", L"DllToInject", MB_OK);
        break;
    }
    return TRUE;
}
