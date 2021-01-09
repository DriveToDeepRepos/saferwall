#include "header.h"

VOID
TestSyncHooks()
{
    UINT delayInMillis = 3;
    LARGE_INTEGER DelayInterval;
    LONGLONG llDelay = delayInMillis * 1LL;
    DelayInterval.QuadPart = llDelay;
    static NTSTATUS(__stdcall * NtDelayExecution)(IN BOOLEAN Alertable, IN PLARGE_INTEGER DelayInterval) = (NTSTATUS(
        __stdcall *)(BOOLEAN, PLARGE_INTEGER))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDelayExecution");

	
    wprintf(L" ========= Testing sync apis ========= \n\n");

    wprintf(L"[+] Calling NtDelayExecution\n");
    NtDelayExecution(FALSE, &DelayInterval);

	wprintf(L"[+] Calling CreateMutex\n");
    SECURITY_ATTRIBUTES MutexAttributes = {0};
    BOOL bInitialOwner = TRUE;
    WCHAR szMutexName[] = L"SfwMutex";
    HANDLE hMutex = CreateMutexW(&MutexAttributes, bInitialOwner, szMutexName);
    if (!hMutex)
    {
        PrintError("CreateMutexA");
	}
	
}