// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"
#include <iostream>

// Global variables
HHOOK g_mouseHook = NULL;
HMODULE g_hModule = NULL;

// Mouse hook callback function
LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0)
    {
        if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN)
        {
            MSLLHOOKSTRUCT* hookStruct = (MSLLHOOKSTRUCT*)lParam;
            POINT pt = hookStruct->pt;
            HWND hwnd = WindowFromPoint(pt);
            
            if (hwnd)
            {
                WCHAR className[256];
                WCHAR windowText[256];
                
                GetClassName(hwnd, className, sizeof(className)/sizeof(WCHAR));
                GetWindowText(hwnd, windowText, sizeof(windowText)/sizeof(WCHAR));

                // Check if it's a Chrome window
                if (wcsstr(className, L"Chrome_WidgetWin_1") != NULL ||
                    wcsstr(windowText, L"Google Chrome") != NULL)
                {
                    // Block the click
                    MessageBox(NULL, L"Clicking on Chrome is disabled!", L"Blocked", MB_ICONWARNING);
                    return 1; // Return non-zero to block the click
                }
            }
        }
    }
    
    // Call the next hook in the chain
    return CallNextHookEx(g_mouseHook, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            g_hModule = hModule;
            // Install the mouse hook
            g_mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseProc, hModule, 0);
            if (g_mouseHook)
            {
                MessageBox(NULL, L"Mouse hook installed successfully!", L"DllToInject", MB_OK);
            }
            else
            {
                MessageBox(NULL, L"Failed to install mouse hook!", L"DllToInject", MB_OK | MB_ICONERROR);
            }
        }
        break;

    case DLL_PROCESS_DETACH:
        {
            // Remove the hook when the DLL is unloaded
            if (g_mouseHook)
            {
                UnhookWindowsHookEx(g_mouseHook);
                g_mouseHook = NULL;
                MessageBox(NULL, L"Mouse hook removed!", L"DllToInject", MB_OK);
            }
        }
        break;
    }
    return TRUE;
}
