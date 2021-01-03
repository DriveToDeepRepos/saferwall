#include "stdafx.h"
#include "hashmap.h"

//
// Prototypes
//

BOOL
ProcessAttach();
BOOL
ProcessDetach();
VOID
EnterHookGuard();
VOID
SfwReleaseHookGuard();
BOOL
SfwHookBeginTransation();
BOOL
SfwHookCommitTransaction();
VOID
HookNtAPIs();
BOOL
SfwHookLoadedModules();

//
// Unfortunatelly sprintf-like functions are not exposed
// by ntdll.lib, which we're linking against.  We have to
// load them dynamically.
//

using __vsnwprintf_fn_t = int(__cdecl *)(wchar_t *buffer, size_t count, const wchar_t *format, ...);
using __snwprintf_fn_t = int(__cdecl *)(wchar_t *buffer, size_t count, const wchar_t *format, ...);
using __snprintf_fn_t = int(__cdecl *)(char *buffer, size_t count, const char *format, ...);
using strlen_fn_t = size_t(__cdecl *)(char const *buffer);
using memcmp_fn_t = int *(__cdecl *)(const void *buffer1, const void *buffer2, size_t count);
using pfn_wcsstr = wchar_t *(__cdecl *)(wchar_t *_String, wchar_t const *_SubStr);
using pfn_wcscat = wchar_t *(__cdecl *)(wchar_t *dest, wchar_t const *src);
using pfn_wcsncat = wchar_t *(__cdecl *)(wchar_t *dest, wchar_t const *src, size_t count);
using pfn_wcslen = size_t(__cdecl *)(const wchar_t *str);
using pfn_wcscmp = int(__cdecl *)(const wchar_t *string1, const wchar_t *string2);
using pfn_RtlAllocateHeap = PVOID(__stdcall *)(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ SIZE_T Size);
using pfn_RtlFreeHeap = BOOLEAN(__stdcall *)(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _Frees_ptr_opt_ PVOID BaseAddress);


//
// Structs
//

typedef struct _HOOK_CONTEXT
{
    DWORD_PTR ModuleBase;
    DWORD SizeOfImage;
    struct hashmap_s *hashmap;  // Name => pAPI
    struct hashmap_s *hashmapA; // Target API => pAPI
    struct hashmap_s *hashmapM; // ModuleName => pModuleInfo
} HOOK_CONTEXT, *PHOOK_CONTEXT;