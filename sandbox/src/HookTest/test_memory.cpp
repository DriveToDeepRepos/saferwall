#include "header.h"

#define PAGELIMIT 80 // Number of pages to ask for

BOOL
TestMemoryHooks()
{
    LPVOID lpvBase;
    SYSTEM_INFO si;

    wprintf(L"\n ========= Testing memory opeations ========= \n\n");

    GetSystemInfo(&si);
    wprintf(L"The page size for this system is %u bytes.\n", si.dwPageSize);

    wprintf(L"[+] Calling VirtualAlloc\n");
    lpvBase = VirtualAlloc(NULL, PAGELIMIT * si.dwPageSize, MEM_RESERVE, PAGE_READWRITE);
    if (lpvBase == NULL)
    {
		PrintError("VirtualAlloc");
        return FALSE;
	}

    wprintf(L"[+] Calling VirtualFree\n");
    VirtualFree(lpvBase, 0, MEM_RELEASE);
    return TRUE;
}