#pragma once

//
// The Native API header
//
#define NTDLL_NO_INLINE_INIT_STRING
#include "ntdll.h"


//
// Network
//

#include <wininet.h>
#pragma comment(lib, "Wininet.lib")

// COM
////#include <comdef.h>
//#include <Wbemidl.h>
//#pragma comment(lib, "wbemuuid.lib")


//
// WinCrypt
//
#include <Wincrypt.h>


//
// For program instrumentation.
//
#include <detours.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#include "util.h"

//
// New
//
#define MAX_API_PARAMS 10
#define MAX_API_NAME_LEN 32

typedef enum _PARAM_ANNOTATION
{
    // The function reads from the buffer. The caller provides the buffer and initializes it.
    PARAM_IN,

    // The function writes to the buffer. If used on the return value or with _deref, the function provides the buffer
    // and initializes it. Otherwise, the caller provides the buffer and the function initializes it.
    PARAM_OUT,

    // The function both reads from and writes to buffer. The caller provides the buffer and initializes it.
    // If used with _deref, the buffer may be reallocated by the function.
    PARAM_IN_OUT,

	PARAM_RESERVED,
} PARAM_ANNOTATION,
    *PPARAM_ANNOTATION;


typedef enum _PARAM_TYPE
{
	PARAM_IMM,
	PARAM_PTR_IMM,
    PARAM_ASCII_STR,
    PARAM_WIDE_STR,
    PARAM_ARR_ASCII_STR,
    PARAM_ARR_WIDE_STR,
	PARAM_PTR_STRUCT,
	PARAM_BYTE_PTR
} TYPE_PARAM;

typedef enum _TYPE_RETURN_VALUE
{
    TypeVoid,
    TypeDword,
} TYPE_RETURN_VALUE;

typedef struct _API_PARAM
{
    TYPE_PARAM Type;
    LPCSTR Name;
    PARAM_ANNOTATION Annotation;
} API_PARAM, *PAPI_PARAM;

typedef struct _API
{
    BOOL ReturnNonVoid;
    LPCSTR Name;
    UCHAR cParams;
    PAPI_PARAM Parameters;
    PVOID TargetFunction;
    PVOID RealTarget;

} API, *PAPI;

typedef struct _MODULE_INFO
{
    LPCSTR *APIList;
    UINT cAPIs;
} MODULE_INFO, *PMODULE_INFO;



//
// Defines.
//

#define TEST_FILE_HOOKS TRUE
#define TEST_LIB_LOAD_HOOKS TRUE
#define TEST_MEMORY_HOOKS FALSE
#define TEST_NETWORK_HOOKS TRUE
#define TEST_OLE_HOOKS FALSE
#define TEST_PROCESS_THREADS_HOOKS FALSE
#define TEST_REGISTRY_HOOKS FALSE
#define TEST_SYNC_HOOKS FALSE
#define TEST_WINSVC_HOOKS FALSE
#define TEST_WINCRYPT_HOOKS FALSE

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
VOID
TestFileHooks();
VOID
TestLibLoadHooks();
VOID
TestMemoryHooks();
VOID
TestNetworkHooks();
VOID
TestOleHooks();
VOID
TestRegistryHooks();
VOID
TestWinSvcHooks();
VOID
TestWinCryptHooks();