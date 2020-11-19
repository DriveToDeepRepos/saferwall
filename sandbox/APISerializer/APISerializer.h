#pragma once

//
// The Native API header
//
#define NTDLL_NO_INLINE_INIT_STRING
#include "ntdll.h"

//
// For program instrumentation.
//
#include <detours.h>

//
// New
//
#define MAX_API_PARAMS 10
#define MAX_API_NAME_LEN 32

typedef enum _PARAM_ANNOTATION
{
    // The function reads from the buffer. The caller provides the buffer and initializes it.
    ParamIn,

    // The function writes to the buffer. If used on the return value or with _deref, the function provides the buffer
    // and initializes it. Otherwise, the caller provides the buffer and the function initializes it.
    ParamOut,

    // The function both reads from and writes to buffer. The caller provides the buffer and initializes it.
    // If used with _deref, the buffer may be reallocated by the function.
    ParamInOut,

	ParamReserved,
} PARAM_ANNOTATION,
    *PPARAM_ANNOTATION;


typedef enum _TYPE_PARAM
{
    TypeImmediate,
    TypePointerToImmediate,
    TypeValuePointerToString,
    TypePointerToStruct
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
    BOOL ReturnVoid;
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

// Delclare a hashmap <DWORD_PTR> -> PVOID / PAPI