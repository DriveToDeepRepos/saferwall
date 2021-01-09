#include "header.h"

DWORD WINAPI
ThreadFunc(void *data)
{
    // Do stuff.  This will be the first function called on the new thread.
    // When this function returns, the thread goes away.  See MSDN for more details.
    return 0;
}


VOID
TestProcessThreadHooks()
{
    BOOL bOK;
    DWORD dwPid = 0;
    STARTUPINFO info = {sizeof(info)};
    PROCESS_INFORMATION processInfo;
    HANDLE hProcess, hThread = 0;

    wprintf(L"[+] Calling CreateProcess\n");
    bOK = CreateProcess(L"C:\\Windows\\notepad.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo);
    if (!bOK)
    {
        PrintError("CreateProcess");
        goto END;
    }

    wprintf(L"[+] Calling CreateThread\n");
    hThread = CreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);
    if (!hThread)
    {
        PrintError("CreateThread");
        goto END;

    }

    wprintf(L"[+] Calling OpenProcess\n");
    dwPid = GetProcessId(processInfo.hProcess);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess)
    {
        PrintError("OpenProcess");
        goto END;
    }

	wprintf(L"[+] Calling TerminateProcess\n");
	TerminateProcess(hProcess, 0);

END:
    if (bOK)
    {
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
    
    if (hThread)
    {
        CloseHandle(hThread);
    }
}