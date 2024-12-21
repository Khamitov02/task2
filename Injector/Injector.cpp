// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "windows.h"

//we'll assume that due to well-known dll kernel32.dll
//and notn strict6 ASLR LoadLibrary address is the same in all processes
//
//TODO:
//  find kernel32.dll module in child process
//  add rva of LoadLibrary

typedef
_Ret_maybenull_
HMODULE
(WINAPI
    FN_LoadLibraryW)(
        _In_ LPCWSTR lpLibFileName
        );

typedef
_Check_return_
_Post_equals_last_error_
DWORD
(WINAPI
    FN_GetLastError)(
        VOID
        );

/*
00007FF678CA1070 40 53                push        rbx
00007FF678CA1072 48 83 EC 20          sub         rsp,20h
00007FF678CA1076 48 8B D9             mov         rbx, rcx
                                                                                PINJECTION_CONTEXT rpInjectionContext = (PINJECTION_CONTEXT)pContext;
                                                                                HMODULE h = rpInjectionContext->rpLoadLibrary(rpInjectionContext->DllName);
00007FF678CA1079 48 81 C1 10 01 00 00 add         rcx, 110h
00007FF678CA1080 FF 93 00 01 00 00    call        qword ptr[rbx + 100h]
                                                                                if (nullptr == h) return 0;
00007FF678CA1086 48 85 C0             test        rax, rax
00007FF678CA1089 75 06                jne         InjectorThread + 21h(07FF678CA1091h)

00007FF678CA108B 48 83 C4 20          add         rsp, 20h
00007FF678CA108F 5B                   pop         rbx
00007FF678CA1090 C3                   ret

00007FF678CA1091 48 8B 83 08 01 00 00 mov         rax, qword ptr[rbx + 108h]
00007FF678CA1098 48 83 C4 20          add         rsp, 20h
00007FF678CA109C 5B                   pop         rbx
                                                                                return rpInjectionContext->rpGetLastError();
00007FF678CA109D 48 FF E0             jmp         rax
*/

BYTE shellcode_data_x64[] = {
    0x40, 0x53,                                 //push        rbx
    0x48, 0x83, 0xEC, 0x20,                     //sub         rsp,20h
    0x48, 0x8B, 0xD9,                           //mov         rbx, rcx
    0x48, 0x81, 0xC1, 0x10, 0x01, 0x00, 0x00,   //add         rcx, 110h
    0xFF, 0x93, 0x00, 0x01, 0x00, 0x00,         //call        qword ptr[rbx + 100h]
    0x48, 0x85, 0xC0,                           //test        rax, rax
    0x74, 0x06,                                 //je          error
    0x48, 0x83, 0xC4, 0x20,                     //add         rsp, 20h
    0x5B,                                       //pop         rbx
    0xC3,                                       //ret
    //error:
    0x48, 0x8B, 0x83, 0x08, 0x01, 0x00, 0x00,   //mov         rax, qword ptr[rbx + 108h]
    0x48, 0x83, 0xC4, 0x20,                     //add         rsp, 20h
    0x5B,                                       //pop         rbx
    0x48, 0xFF, 0xE0                            //jmp         rax
};

typedef struct _INJECTION_CONTEXT {
    BYTE shellcode[0x100];              //0x000
    FN_LoadLibraryW* rpLoadLibrary;     //0x100
    FN_GetLastError* rpGetLastError;    //0x108
    WCHAR DllName[0x100];               //0x110
} INJECTION_CONTEXT, * PINJECTION_CONTEXT;

#if 0 
DWORD InjectorThread(LPVOID pContext)
{
    HMODULE h = LoadLibrary((LPCWSTR)pContext);
    if (nullptr == h) return 0;
    return GetLastError();
}
#else
DWORD InjectorThread(LPVOID pContext)
{
    PINJECTION_CONTEXT rpInjectionContext = (PINJECTION_CONTEXT)pContext;
    HMODULE h = rpInjectionContext->rpLoadLibrary(rpInjectionContext->DllName);
    if (nullptr != h) return 0;
    return rpInjectionContext->rpGetLastError();
}
#endif

int main()
{
    std::cout << "Hello World!\n";
    int res = -1;

//#if 1
    HMODULE h = LoadLibrary(L"DllToInject.dll");    //path is relative cause dll is places in same dir as exe!
    //TODO: need absolute path
    if (nullptr == h) {
        printf("Dll load failed code=%x ! \n", GetLastError());
        goto error1;
    }
    printf("Dll was successfully loaded! \n");
//#else
//    DWORD tid;
//
//    INJECTION_CONTEXT InjectionContext;
//    memset(&InjectionContext, 0, sizeof(InjectionContext));
//    memcpy(InjectionContext.shellcode, shellcode_data_x64, sizeof(shellcode_data_x64));
//    InjectionContext.rpLoadLibrary = LoadLibrary;   //TODO: see comment above, for well-known dll asumme that p===rp
//    InjectionContext.rpGetLastError = GetLastError; //TODO: see comment above, for well-known dll asumme that p===rp
//    PCWSTR dllName = L"aaaDllToInject.dll";
//    size_t dllNameSize = (wcslen(dllName) + 1) * sizeof(WCHAR);
//    memcpy(InjectionContext.DllName, dllName, dllNameSize);
//
//    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
//    //TODO: check
//    PINJECTION_CONTEXT rpInjectionContext = (PINJECTION_CONTEXT)VirtualAllocEx(hProcess, NULL, sizeof(*rpInjectionContext), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//    //TODO: check
//    SIZE_T bytesWritten;
//    WriteProcessMemory(hProcess, rpInjectionContext, &InjectionContext, sizeof(InjectionContext), &bytesWritten);
//    //TODO: check

//#if 0
//    HANDLE h = CreateRemoteThread(hProcess, NULL, 0, InjectorThread, rpInjectionContext, 0, &tid);
//#else
//    HANDLE h = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rpInjectionContext, rpInjectionContext, 0, &tid);
//#endif
//    if (nullptr == h) {
//        printf("Inject thread creation failed code=%x ! \n", GetLastError());
//        goto error1;
//    }
//    WaitForSingleObject(h, INFINITE);
//    DWORD result;
//    if (!GetExitCodeThread(h, &result)) {
//        printf("GetExitCodeThread failed code =%x ! \n", GetLastError());
//        goto error2;
//    }
//
//    if (0 != result) {
//        printf("Inject thread failed with code =%x ! \n", result);
//    }
//    res = 0; //all is ok
//#endif
//
//error2:
//    CloseHandle(h);
error1:
    return res;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
