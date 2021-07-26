#include <Windows.h>
#include <WinUser.h>
#include <stdio.h>
// dllmain.cpp : Defines the entry point for the DLL application.


//This makes the two variables stored in the shared section of the PE which allow them to be shared between processes using this DLL
#pragma data_seg(".shared")
DWORD g_ThreadId = 0;
HHOOK g_hHook = nullptr;
DWORD g_InjectorThreadID = 0;
#pragma data_seg()
#pragma comment(linker, "/section:.shared,RWS")
HINSTANCE hDLL = NULL;


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HINSTANCE hDLL = (HINSTANCE)hModule;
        break;
    }
    return TRUE;
}
//Heavily referenced this https://docs.microsoft.com/en-us/windows/win32/winmsg/using-hooks
//extern C is necessary in order to be able to retrieve result of GetProcAddress
// __declspec(dllexport) informs the compiler that I would like HookFunction to be exported
//This causes it to be exported with funky C++ values however like HookFunction@12, therefore I will utilize a DEF file.

extern "C" __declspec(dllexport) LRESULT CALLBACK HookFunction(int nCode, WPARAM wParam, LPARAM lParam) {
    //MessageBoxW(NULL, L"Hello from inside HookFunction!", NULL, NULL);
    if (nCode >= 0) //do not process message if not for us
    {
        //If the message intended for notepad is WM_CHAR, call PostThreadMessage with the message details back to the injecting process

        MSG* msgStructure = (MSG*)lParam;
        if (msgStructure->message == WM_CHAR)
        {
            //MessageBoxW(NULL, L"Hello from inside HookFunction!", NULL, NULL);
            //We've detected a readable character, please send back to the injecting process
            if (!PostThreadMessageW(g_InjectorThreadID, WM_CHAR, msgStructure->wParam, msgStructure->lParam))
            {
                //https://forums.codeguru.com/showthread.php?478858-GetLastError()-in-a-MessageBox()
                void* lpBuffer;

                FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                    NULL,
                    ::GetLastError(),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
                    (LPTSTR)&lpBuffer,
                    0,
                    NULL);

                MessageBoxW(NULL, (LPCTSTR)lpBuffer, L"LastRrror", MB_OK);
                LocalFree(lpBuffer);
            }
                
        }
        //TODO: PostThreadMessage a WM_QUIT message if notepad dies
        //...
        
    }
    //call CallNextHookEx as needed to allow other hooks to continue to function
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);

}

/*extern "C" __declspec(dllexport) BOOL SetNotificationThread(DWORD ThreadId) {
    //Called from the injector thread in order to make sure the hook function has access to the thread ID to post messages back to
    printf("[!] Running inside of Set Notification Thread\n");
    //MessageBox(NULL, L"Inside of Set Notification Thread", NULL, NULL);
    g_ThreadId = ThreadId;
    //g_hHook = hHook;
    return 0;
}*/

extern "C"  void __declspec(dllexport) StartHook(DWORD ThreadID, DWORD dwInjectorThreadID, HINSTANCE hDLL)
{
    printf("[!] ATTENTION LORD ABOVE I AM STARTING THY HOOK...\n");
    printf("[!] LORD HASETH GLOBAL THREADID: %d\n", ThreadID);
    g_ThreadId = ThreadID;
    g_InjectorThreadID = dwInjectorThreadID;
    g_hHook = SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)HookFunction, hDLL, ThreadID);
    if (g_hHook == NULL) {
        printf("[-] ERROR SetWindowsHookEx: %lu\n", GetLastError());
        exit(0);
    }
    printf("[*] Hook Set!\n");
}

extern "C"  void __declspec(dllexport) StopHook()
{
    printf("[!] Stopping Hook...\n");
    UnhookWindowsHookEx(g_hHook);
}

