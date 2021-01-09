#pragma once


#include "ntdll.h"

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

	// Reserved.
    PARAM_RESERVED,
} PARAM_ANNOTATION;

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
    LPCWSTR Name;
    PARAM_ANNOTATION Annotation;
} API_PARAM, *PAPI_PARAM;

typedef struct _API
{
    BOOL ReturnVoid;
    LPCWSTR Name;
    UCHAR cParams;
    PAPI_PARAM Parameters;
    PVOID TargetFunction;
    PVOID RealTarget;

} API, *PAPI;

typedef struct _MODULE_INFO
{
    LPCWSTR *APIList;
    UINT cAPIs;
} MODULE_INFO, *PMODULE_INFO;


//
// Prototypes.
//
BOOL
SfwSchemaLoadAPIDef();