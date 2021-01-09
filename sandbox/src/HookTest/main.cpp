// malware-behavior.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "header.h"
#include <tlhelp32.h>

VOID
LoadHookModule()
{
    BOOL bIsWow64 = FALSE;
    WCHAR ModuleName[MAX_PATH] = L"";
    DWORD dwErr;

    IsWow64Process(GetCurrentProcess(), &bIsWow64);
    if (bIsWow64)
    {
        wprintf(L"Running under wow64 \n");
        wcscpy_s(ModuleName, MAX_PATH, L"HookDLL-x86.dll");
    }
    else
    {
        wprintf(L"Running under native x64 \n");
        wcscpy_s(ModuleName, MAX_PATH, L"HookDLL-x64.dll");
    }

    if (!GetModuleHandle(ModuleName))
    {
        wprintf(L"DLL is not loaded \n");
        if (!LoadLibraryW(ModuleName))
        {
            dwErr = PrintError("LoadLibraryW");
            exit(dwErr);
        }
    }

    wprintf(L"%ws was loaded\n", ModuleName);
}

int
main()
{
    LARGE_INTEGER StartingTime, EndingTime;
    LARGE_INTEGER Frequency, ElapsedMicroseconds;

	//
    // Prepare timer.
	//

    QueryPerformanceFrequency(&Frequency);
    QueryPerformanceCounter(&StartingTime);

    // ========================[ TIMER START ========================]

    //
    // Intialise the PRNG.
    //
    srand((UINT)time(NULL));

    //
    // If the driver is not running,
    // Load the DLL manually.
    //

    LoadHookModule();

    //
    // Test our hook handlers.
    //

    if (TEST_REGISTRY_HOOKS)
        TestRegistryHooks();

    if (TEST_WINCRYPT_HOOKS)
        TestWinCryptHooks();

    if (TEST_FILE_HOOKS)
        TestFileHooks();

    if (TEST_LIB_LOAD_HOOKS)
        TestLibLoadHooks();

    if (TEST_NETWORK_HOOKS)
    {
        TestWinhttpHooks();
        TestWinInetHooks();
    }

    if (TEST_MEMORY_HOOKS)
        TestMemoryHooks();

    if (TEST_WINSVC_HOOKS)
        TestWinSvcHooks();

    if (TEST_HEAP_HOOKS)
        TestHeapHooks();

    if (TEST_OLE_HOOKS)
        TestOleHooks();

    if (TEST_PROCESS_THREADS_HOOKS)
        TestProcessThreadHooks();

    if (TEST_SYNC_HOOKS)
        TestSyncHooks();

    // ========================[ TIMER END ========================]

    QueryPerformanceCounter(&EndingTime);
    ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart;

    //
    // We now have the elapsed number of ticks, along with the
    // number of ticks-per-second. We use these values
    // to convert to the number of elapsed microseconds.
    // To guard against loss-of-precision, we convert
    // to microseconds *before* dividing by ticks-per-second.
    //

    ElapsedMicroseconds.QuadPart *= 1000000;
    ElapsedMicroseconds.QuadPart /= Frequency.QuadPart;

    wprintf(L"Done, execution took: %I64d \n", ElapsedMicroseconds.QuadPart);

    return 0;
}