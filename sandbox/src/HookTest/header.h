#pragma once

#include <Windows.h>
#include <stdlib.h>
#include <time.h>

//
// Strings, Path & IO
//

#include <stdio.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

//
// Network
//

#include <wininet.h>
#pragma comment(lib, "Wininet.lib")

// COM
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

//
// WinCrypt
//
#include <Wincrypt.h>

//
// Defines.
//

#define TEST_FILE_HOOKS TRUE
#define TEST_LIB_LOAD_HOOKS TRUE
#define TEST_MEMORY_HOOKS TRUE
#define TEST_NETWORK_HOOKS TRUE
#define TEST_OLE_HOOKS FALSE
#define TEST_PROCESS_THREADS_HOOKS TRUE
#define TEST_REGISTRY_HOOKS TRUE
#define TEST_SYNC_HOOKS TRUE
#define TEST_WINSVC_HOOKS TRUE
#define TEST_WINCRYPT_HOOKS TRUE
#define TEST_HEAP_HOOKS FALSE

//
// Prototypes
//

VOID
GetRandomString(PWCHAR Str, CONST INT Len);
VOID
GetRandomDir(PWSTR szPathOut);
VOID
GetRandomFilePath(PWSTR szPathOut);
DWORD
PrintError(const char *wszProcedureName);
BOOL
TestFileHooks();
VOID
TestLibLoadHooks();
BOOL
TestMemoryHooks();
BOOL
TestWinInetHooks();
BOOL
TestWinhttpHooks();
VOID
TestOleHooks();
VOID
TestRegistryHooks();
VOID
TestWinSvcHooks();
VOID
TestWinCryptHooks();
VOID
TestProcessThreadHooks();
BOOL
TestHeapHooks();
VOID
TestSyncHooks();
