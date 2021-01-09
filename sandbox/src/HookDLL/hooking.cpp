// HookDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

//
// Defines
//

#define DETOUR_END

//
// Globals
//
extern decltype(NtContinue) *TrueNtContinue;

__vsnwprintf_fn_t _vsnwprintf = nullptr;
__snwprintf_fn_t _snwprintf = nullptr;
__snprintf_fn_t _snprintf = nullptr;
strlen_fn_t _strlen = nullptr;
memcmp_fn_t _memcmp = nullptr;
pfn_wcsstr _wcsstr = nullptr;
pfn_wcscat _wcscat = nullptr;
pfn_wcsncat _wcsncat = nullptr;
pfn_wcslen _wcslen = nullptr;
pfn_wcscmp _wcscmp = nullptr;
extern "C" pfn_RtlAllocateHeap TrueRtlAllocateHeap = nullptr;
pfn_RtlFreeHeap TrueRtlFreeHeap = nullptr;

DWORD dwTlsIndex;
BOOL gInsideHook = FALSE;
PHOOK_CONTEXT pgHookContext = nullptr;
CRITICAL_SECTION gHookDllLock;
// ZydisDecoder g_Decoder;

extern "C" {
DWORD __stdcall HookHandler(VOID);

#ifdef _WIN64
DWORD_PTR __stdcall AsmCall_x64(PCONTEXT, PVOID, UCHAR, DWORD_PTR);
VOID __stdcall AsmReturn_x64(DWORD_PTR, DWORD_PTR);
#else
DWORD_PTR __stdcall AsmCall(PVOID, UCHAR, DWORD_PTR *);
VOID __stdcall AsmReturn(DWORD_PTR, DWORD_PTR);
#endif
}

//
// ETW provider GUID and global provider handle.
// GUID:
//   {a4b4ba50-a667-43f5-919b-1e52a6d69bd5}
//

GUID ProviderGuid = {0xa4b4ba50, 0xa667, 0x43f5, {0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5}};

REGHANDLE ProviderHandle;
#define ATTACH(x) DetAttach(&(PVOID &)True##x, Hook##x, #x)
#define DETACH(x) DetDetach(&(PVOID &)True##x, Hook##x, #x)

bool
IsBadPtr(PVOID pPointer)
{
    MEMORY_BASIC_INFORMATION mbi = {0};

    if (VirtualQuery(pPointer, &mbi, sizeof(mbi)))
    {
        DWORD mask =
            (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
             PAGE_EXECUTE_WRITECOPY);

        bool ret = !(mbi.Protect & mask);

        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
            ret = true;

        return ret;
    }

    return true;
}

DWORD
BaseSetLastNTError(IN NTSTATUS Status)
{
    DWORD dwErrCode;
    dwErrCode = RtlNtStatusToDosError(Status);
    RtlSetLastWin32Error(dwErrCode);
    return dwErrCode;
}

LPVOID
WINAPI
SfwTlsGetValue(IN DWORD Index)
{
    PTEB Teb;

    /* Get the TEB and clear the last error */
    Teb = NtCurrentTeb();
    Teb->LastErrorValue = 0;

    /* Check for simple TLS index */
    if (Index < TLS_MINIMUM_AVAILABLE)
    {
        /* Return it */
        return Teb->TlsSlots[Index];
    }

    /* Check for valid index */
    if (Index >= TLS_EXPANSION_SLOTS + TLS_MINIMUM_AVAILABLE)
    {
        /* Fail */
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return NULL;
    }

    /* The expansion slots are allocated on demand, so check for it. */
    Teb->LastErrorValue = 0;
    if (!Teb->TlsExpansionSlots)
        return NULL;

    /* Return the value from the expansion slots */
    return Teb->TlsExpansionSlots[Index - TLS_MINIMUM_AVAILABLE];
}

BOOL WINAPI
SfwTlsSetValue(IN DWORD Index, IN LPVOID Value)
{
    DWORD TlsIndex;
    PTEB Teb = NtCurrentTeb();

    /* Check for simple TLS index */
    if (Index < TLS_MINIMUM_AVAILABLE)
    {
        /* Return it */
        Teb->TlsSlots[Index] = Value;
        return TRUE;
    }

    /* Check if this is an expansion slot */
    TlsIndex = Index - TLS_MINIMUM_AVAILABLE;
    if (TlsIndex >= TLS_EXPANSION_SLOTS)
    {
        /* Fail */
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    /* Do we not have expansion slots? */
    if (!Teb->TlsExpansionSlots)
    {
        /* Get the PEB lock to see if we still need them */
        RtlAcquirePebLock();
        if (!Teb->TlsExpansionSlots)
        {
            /* Allocate them */
            Teb->TlsExpansionSlots =
                (PVOID *)TrueRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, TLS_EXPANSION_SLOTS * sizeof(PVOID));
            if (!Teb->TlsExpansionSlots)
            {
                /* Fail */
                RtlReleasePebLock();
                BaseSetLastNTError(STATUS_NO_MEMORY);
                return FALSE;
            }
        }

        /* Release the lock */
        RtlReleasePebLock();
    }

    /* Write the value */
    Teb->TlsExpansionSlots[TlsIndex] = Value;

    /* Success */
    return TRUE;
}

BOOL WINAPI
SfwTlsFree(IN DWORD Index)
{
    BOOL BitSet;
    PPEB Peb;
    ULONG TlsIndex;
    PVOID TlsBitmap;
    NTSTATUS Status;

    /* Acquire the PEB lock and grab the PEB */
    Peb = NtCurrentPeb();
    RtlAcquirePebLock();

    /* Check if the index is too high */
    if (Index >= TLS_MINIMUM_AVAILABLE)
    {
        /* Check if it can fit in the expansion slots */
        TlsIndex = Index - TLS_MINIMUM_AVAILABLE;
        if (TlsIndex >= TLS_EXPANSION_SLOTS)
        {
            /* It's invalid */
            BaseSetLastNTError(STATUS_INVALID_PARAMETER);
            RtlReleasePebLock();
            return FALSE;
        }
        else
        {
            /* Use the expansion bitmap */
            TlsBitmap = Peb->TlsExpansionBitmap;
            Index = TlsIndex;
        }
    }
    else
    {
        /* Use the normal bitmap */
        TlsBitmap = Peb->TlsBitmap;
    }

    /* Check if the index was set */
    BitSet = RtlAreBitsSet((PRTL_BITMAP)TlsBitmap, Index, 1);
    if (BitSet)
    {
        /* Tell the kernel to free the TLS cells */
        Status = NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &Index, sizeof(DWORD));
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(STATUS_INVALID_PARAMETER);
            RtlReleasePebLock();
            return FALSE;
        }

        /* Clear the bit */
        RtlClearBits((PRTL_BITMAP)TlsBitmap, Index, 1);
    }
    else
    {
        /* Fail */
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        RtlReleasePebLock();
        return FALSE;
    }

    /* Done! */
    RtlReleasePebLock();
    return TRUE;
}

DWORD
WINAPI
SfwTlsAlloc(VOID)
{
    ULONG Index;
    PTEB Teb;
    PPEB Peb;

    /* Get the PEB and TEB, lock the PEB */
    Teb = NtCurrentTeb();
    Peb = Teb->ProcessEnvironmentBlock;
    RtlAcquirePebLock();

    /* Try to get regular TEB slot */
    Index = RtlFindClearBitsAndSet((PRTL_BITMAP)Peb->TlsBitmap, 1, 0);
    if (Index != 0xFFFFFFFF)
    {
        /* Clear the value. */
        Teb->TlsSlots[Index] = 0;
        RtlReleasePebLock();
        return Index;
    }

    /* If it fails, try to find expansion TEB slot. */
    Index = RtlFindClearBitsAndSet((PRTL_BITMAP)Peb->TlsExpansionBitmap, 1, 0);
    if (Index != 0xFFFFFFFF)
    {
        /* Is there no expansion slot yet? */
        if (!Teb->TlsExpansionSlots)
        {
            /* Allocate an array */
            Teb->TlsExpansionSlots =
                (PVOID *)TrueRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, TLS_EXPANSION_SLOTS * sizeof(PVOID));
        }

        /* Did we get an array? */
        if (!Teb->TlsExpansionSlots)
        {
            /* Fail */
            RtlClearBits((PRTL_BITMAP)Peb->TlsExpansionBitmap, Index, 1);
            Index = 0xFFFFFFFF;
            BaseSetLastNTError(STATUS_NO_MEMORY);
        }
        else
        {
            /* Clear the value. */
            Teb->TlsExpansionSlots[Index] = 0;
            Index += TLS_MINIMUM_AVAILABLE;
        }
    }
    else
    {
        /* Fail */
        BaseSetLastNTError(STATUS_NO_MEMORY);
    }

    /* Release the lock and return */
    RtlReleasePebLock();
    return Index;
}

extern "C" __declspec(noinline) BOOL WINAPI SfwIsInsideHook()
/*++

Routine Description:

    This function checks if are already inside a hook handler.
    This helps avoid infinite recursions which happens in hooking
    as some APIs inside the hook handler end up calling functions
    which are detoured as well.

    There are some few issues you have to be concerned about
    if you are injecting a 64bits DLL inside a WoW64 process.
        1.  Implicit TLS (__declspec(thread)) relies heavily on the
            CRT, which is not available to us.
        2.  Explicit TLS APIs (TlsAlloc() / TlsFree(), etc.) are
            implemented entirely in kernel32.dll, whose 64-bit
            version is not loaded into WoW64 processes.

    In our case, we always injects DLL of the same architecture
    as the process. So it should be ok to use TLS. The TLS
    allocation should happen before attaching the hooks as TlsAlloc
    end up calling RtlAllocateHeap() which might be hooked as well.

Return Value:
    TRUE: if we are inside a hook handler.
    FALSE: otherwise.
--*/
{
    if (!SfwTlsGetValue(dwTlsIndex))
    {
        SfwTlsSetValue(dwTlsIndex, (LPVOID)TRUE);
        return FALSE;
    }
    return TRUE;
}

VOID
SfwReleaseHookGuard()
{
    SfwTlsSetValue(dwTlsIndex, (LPVOID)FALSE);
}

VOID
EnterHookGuard()
{
    SfwTlsSetValue(dwTlsIndex, (LPVOID)TRUE);
}

LONG
CheckDetourAttach(LONG err)
{
    switch (err)
    {
    case ERROR_INVALID_BLOCK: /*printf("ERROR_INVALID_BLOCK: The function referenced is too small to be detoured.");*/
        break;
    case ERROR_INVALID_HANDLE: /*printf("ERROR_INVALID_HANDLE: The ppPointer parameter is null or points to a null
                                  pointer.");*/
        break;
    case ERROR_INVALID_OPERATION: /*	printf("ERROR_INVALID_OPERATION: No pending transaction exists."); */
        break;
    case ERROR_NOT_ENOUGH_MEMORY: /*printf("ERROR_NOT_ENOUGH_MEMORY: Not enough memory exists to complete the
                                     operation.");*/
        break;
    case NO_ERROR:
        break;
    default: /*printf("CheckDetourAttach failed with unknown error code.");*/
        break;
    }
    return err;
}

static const char *
DetRealName(const char *psz)
{
    const char *pszBeg = psz;
    // Move to end of name.
    while (*psz)
    {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg && ((psz[-1] >= 'A' && psz[-1] <= 'Z') || (psz[-1] >= 'a' && psz[-1] <= 'z') ||
                            (psz[-1] >= '0' && psz[-1] <= '9')))
    {
        psz--;
    }
    return psz;
}

VOID
DetAttach(PVOID *ppvReal, PVOID pvMine, PCCH psz)
{
    PVOID pvReal = NULL;
    if (ppvReal == NULL)
    {
        ppvReal = &pvReal;
    }

    LONG l = DetourAttach(ppvReal, pvMine);
    if (l != NO_ERROR)
    {
        LogMessage(L"Detour Attach failed: %s: error %d", DetRealName(psz), l);
        // Decode((PBYTE)*ppvReal, 3);
    }
}

VOID
DetDetach(PVOID *ppvReal, PVOID pvMine, PCCH psz)
{
    LONG l = DetourDetach(ppvReal, pvMine);
    if (l != NO_ERROR)
    {
        LogMessage(L"Detour Detach failed: %s: error %d", DetRealName(psz), l);
    }
}

PVOID
GetAPIAddress(LPCSTR FunctionName, PWSTR ModuleName)
{
    NTSTATUS Status;

    ANSI_STRING RoutineName;
    RtlInitAnsiString(&RoutineName, FunctionName);

    UNICODE_STRING ModulePath;
    RtlInitUnicodeString(&ModulePath, ModuleName);

    HANDLE ModuleHandle = NULL;
    Status = LdrGetDllHandle(NULL, 0, &ModulePath, &ModuleHandle);
    if (Status != STATUS_SUCCESS)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"LdrGetDllHandle failed");
        return NULL;
    }

    PVOID Address;
    Status = LdrGetProcedureAddress(ModuleHandle, &RoutineName, 0, &Address);
    if (Status != STATUS_SUCCESS)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"LdrGetProcedureAddress failed");
        return NULL;
    }

    return Address;
}

PVOID
SfwUtilGetProcAddr(HANDLE ModuleHandle, LPCWSTR ProcedureName)
{
    PVOID Address;
    NTSTATUS Status;

    UNICODE_STRING wideProcedureName;
    RtlInitUnicodeString(&wideProcedureName, ProcedureName);

    ANSI_STRING RoutineName = {0};
    RtlUnicodeStringToAnsiString(&RoutineName, &wideProcedureName, TRUE);

    Status = LdrGetProcedureAddress(ModuleHandle, &RoutineName, 0, &Address);
    if (Status != STATUS_SUCCESS)
    {
        return NULL;
    }

    return Address;
}

BOOL
ProcessAttach()
{
    //
    // Register ETW provider.
    //

    EtwEventRegister(&ProviderGuid, NULL, NULL, &ProviderHandle);

    //
    // Allocate a TLS index.
    //

    if ((dwTlsIndex = SfwTlsAlloc()) == TLS_OUT_OF_INDEXES)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"TlsAlloc() failed");
        return FALSE;
    }

    //
    // Resolve APIs not exposed by ntdll.
    //

    _vsnwprintf = (__vsnwprintf_fn_t)GetAPIAddress((PSTR) "_vsnwprintf", (PWSTR)L"ntdll.dll");
    if (_vsnwprintf == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"_vsnwprintf() is NULL");
    }
    _snwprintf = (__snwprintf_fn_t)GetAPIAddress((PSTR) "_snwprintf", (PWSTR)L"ntdll.dll");
    if (_vsnwprintf == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"_snwprintf() is NULL");
    }

    _snprintf = (__snprintf_fn_t)GetAPIAddress((PSTR) "_snprintf", (PWSTR)L"ntdll.dll");
    if (_snprintf == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"_snprintf() is NULL");
    }

    _wcsstr = (pfn_wcsstr)GetAPIAddress((PSTR) "wcsstr", (PWSTR)L"ntdll.dll");
    if (_wcsstr == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"wcsstr() is NULL");
    }

    _memcmp = (memcmp_fn_t)GetAPIAddress((PSTR) "memcmp", (PWSTR)L"ntdll.dll");
    if (_memcmp == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"memcmp() is NULL");
    }

    _wcscmp = (pfn_wcscmp)GetAPIAddress((PSTR) "wcscmp", (PWSTR)L"ntdll.dll");
    if (_wcscmp == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"wcscmp() is NULL");
    }

    _wcscat = (pfn_wcscat)GetAPIAddress((PSTR) "wcscat", (PWSTR)L"ntdll.dll");
    if (_wcscat == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"wcscat() is NULL");
    }

    _wcsncat = (pfn_wcsncat)GetAPIAddress((PSTR) "wcsncat", (PWSTR)L"ntdll.dll");
    if (_wcsncat == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"wcsncat() is NULL");
    }

    _strlen = (strlen_fn_t)GetAPIAddress((PSTR) "strlen", (PWSTR)L"ntdll.dll");
    if (_strlen == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"strlen() is NULL");
    }

    _wcslen = (pfn_wcslen)GetAPIAddress((PSTR) "wcslen", (PWSTR)L"ntdll.dll");
    if (_wcslen == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"wcslen() is NULL");
    }

    TrueRtlAllocateHeap = (pfn_RtlAllocateHeap)GetAPIAddress((PSTR) "RtlAllocateHeap", (PWSTR)L"ntdll.dll");
    if (TrueRtlAllocateHeap == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"RtlAllocateHeap() is NULL");
    }

    TrueRtlFreeHeap = (pfn_RtlFreeHeap)GetAPIAddress((PSTR) "RtlFreeHeap", (PWSTR)L"ntdll.dll");
    if (TrueRtlFreeHeap == NULL)
    {
        EtwEventWriteString(ProviderHandle, 0, 0, L"RtlAllocateHeap() is NULL");
    }

    // Initialize decoder context
    // ZydisDecoderInit(&g_Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    //
    // Initialize Hook Context.
    //

    pgHookContext = (PHOOK_CONTEXT)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOOK_CONTEXT));

    //
    // Load API Definitions schemas.
    //

    SfwSchemaLoadAPIDef();

    //
    // Initializes a critical section objects.
    // Used for capturing stack trace and IsInsideHook.
    //

    InitializeCriticalSection(&gHookDllLock);

    //
    // Hook Loaded Modules's APIs.
    //

    SfwHookLoadedModules();

    return TRUE;
}

BOOL
ProcessDetach()
{
    SfwHookBeginTransation();
    // DETACH(NtContinue);
    SfwHookCommitTransaction();

    SfwTlsFree(dwTlsIndex);
    EtwEventUnregister(ProviderHandle);

    // Cleanup
    // hashmap_destroy(&hashmap);
    // hashmap_destroy(&hashmapA);
    // hashmap_destroy(&hashmapM);

    EtwEventWriteString(ProviderHandle, 0, 0, L"Detached success");

    return STATUS_SUCCESS;
}

BOOL
SfwHookBeginTransation()
{
    LONG Status;

    //
    // Begin a new transaction for attaching detours.
    //

    Status = DetourTransactionBegin();
    if (Status != NO_ERROR)
    {
        LogMessage(L"DetourTransactionBegin() failed with %d", Status);
        return FALSE;
    }

    //
    // Enlist a thread for update in the current transaction.
    //

    Status = DetourUpdateThread(NtCurrentThread());
    if (Status != NO_ERROR)
    {
        LogMessage(L"DetourUpdateThread() failed with %d", Status);
        return FALSE;
    }

    return TRUE;
}

BOOL
SfwHookCommitTransaction()
{
    /*
    Commit the current transaction.
    */

    PVOID *ppbFailedPointer = NULL;

    LONG error = DetourTransactionCommitEx(&ppbFailedPointer);
    if (error != NO_ERROR)
    {
        LogMessage(
            L"Attach transaction failed to commit. Error %d (%p/%p)", error, ppbFailedPointer, *ppbFailedPointer);
        return FALSE;
    }

    return TRUE;
}

VOID
HookNtAPIs()
{
    LogMessage(L"HookNtAPIs Begin");

    SfwHookBeginTransation();

    //
    // Lib Load APIs.
    //

    // ATTACH(NtContinue);

    SfwHookCommitTransaction();

    LogMessage(L"HookNtAPIs End");
}

extern "C" __declspec(noinline) BOOL WINAPI SfwIsCalledFromSystemMemory(DWORD_PTR ReturnAddress)
{
    if (ReturnAddress >= pgHookContext->ModuleBase &&
        ReturnAddress <= pgHookContext->ModuleBase + pgHookContext->SizeOfImage)
    {
        return FALSE;
    }

    //
    // Get the PEB.
    //
#if defined(_WIN64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);

#elif defined(_WIN32)
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    BOOL bFound = FALSE;
    PPEB_LDR_DATA pLdrData = NULL;
    PLIST_ENTRY pEntry, pHeadEntry = NULL;
    PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
    pLdrData = pPeb->Ldr;

    pHeadEntry = &pLdrData->InMemoryOrderModuleList;
    pEntry = pHeadEntry->Flink;

    while (pEntry != pHeadEntry)
    {
        // Retrieve the current LDR_DATA_TABLE_ENTRY
        pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // Exluce the main module code in the search.
        if (_wcscmp(pLdrEntry->FullDllName.Buffer, pPeb->ProcessParameters->ImagePathName.Buffer) == 0)
        {
            pEntry = pEntry->Flink;
            continue;
        }

        // Fill the MODULE_ENTRY with the LDR_DATA_TABLE_ENTRY information
        if (ReturnAddress >= (ULONGLONG)pLdrEntry->DllBase &&
            ReturnAddress <= (ULONGLONG)pLdrEntry->DllBase + pLdrEntry->SizeOfImage)
        {
            bFound = TRUE;
            break;
        }

        // Iterate to the next entry.
        pEntry = pEntry->Flink;
    }

    return bFound;
}

extern "C" __declspec(noinline) PAPI WINAPI GetTargetAPI(DWORD_PTR Target)
{
    PAPI pAPI = NULL;
    pAPI = (PAPI)hashmap_get(pgHookContext->hashmapA, (PVOID)Target, 0);
    return pAPI;
}

extern "C" __declspec(noinline) PWCHAR WINAPI PreHookTraceAPI(PWCHAR szLog, PAPI pAPI, DWORD_PTR *BasePointer)
{
    INT len = 0;
    PWCHAR szBuff = (PWCHAR)TrueRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
    BOOL bFound = TRUE;

    for (int i = 0; i < pAPI->cParams; i++)
    {
        DWORD_PTR Param = *(DWORD_PTR *)(BasePointer + i);
        switch (pAPI->Parameters[i].Annotation)
        {
        case PARAM_IN:
        case PARAM_IN_OUT:
            switch (pAPI->Parameters[i].Type)
            {
            case PARAM_IMM:
                _snwprintf(szBuff, MAX_PATH, L"%s:0x%x, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                break;
            case PARAM_PTR_IMM:
                _snwprintf(szBuff, sizeof(szBuff), L"%s:%lu, ", (PCHAR)pAPI->Parameters[i].Name, *(DWORD_PTR *)Param);
                break;
            case PARAM_ASCII_STR:
                _snwprintf(szBuff, MAX_PATH, L"%s:%s, ", (PCHAR)pAPI->Parameters[i].Name, (PCHAR)Param);
                break;
            case PARAM_WIDE_STR:
                _snwprintf(szBuff, MAX_PATH, L"%s:%ws, ", (PCHAR)pAPI->Parameters[i].Name, (PWCHAR)Param);
                break;
            case PARAM_PTR_STRUCT:
                _snwprintf(szBuff, MAX_PATH, L"%s:%lu, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                break;
            default:
                LogMessage(L"Unknown");
                bFound = FALSE;
                break;
            }

            if (bFound)
            {
                _wcsncat(szLog, szBuff, _wcslen(szBuff));
                RtlZeroMemory(szBuff, _wcslen(szBuff));
            }
        }
    }

    TrueRtlFreeHeap(RtlProcessHeap(), 0, szBuff);
    return szLog;
}

extern "C" __declspec(noinline) PWCHAR WINAPI
    PreHookTraceAPI_x64(PWCHAR szLog, PAPI pAPI, DWORD_PTR *BasePointer, PCONTEXT pContext)
{
    INT len = 0;
    PWCHAR szBuff = (PWCHAR)TrueRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
    BOOL bFound = TRUE;
    DWORD_PTR Param;

    for (int i = 0; i < pAPI->cParams; i++)
    {
#ifdef _WIN64
        switch (i)
        {
        case 0:
            Param = pContext->Rcx;
            break;
        case 1:
            Param = pContext->Rdx;
            break;
        case 2:
            Param = pContext->R8;
            break;
        case 3:
            Param = pContext->R9;
            break;
        }
#else
        Param = *(DWORD_PTR *)(BasePointer + i);
#endif

        switch (pAPI->Parameters[i].Annotation)
        {
        case PARAM_IN:
        case PARAM_IN_OUT:
            switch (pAPI->Parameters[i].Type)
            {
            case PARAM_IMM:
                _snwprintf(szBuff, MAX_PATH, L"%s:0x%x, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                break;
            case PARAM_PTR_IMM:
                _snwprintf(szBuff, sizeof(szBuff), L"%s:%lu, ", (PCHAR)pAPI->Parameters[i].Name, *(DWORD_PTR *)Param);
                break;
            case PARAM_ASCII_STR:
                _snwprintf(szBuff, MAX_PATH, L"%s:%s, ", (PCHAR)pAPI->Parameters[i].Name, (PCHAR)Param);
                break;
            case PARAM_WIDE_STR:
                _snwprintf(szBuff, MAX_PATH, L"%s:%ws, ", (PCHAR)pAPI->Parameters[i].Name, (PWCHAR)Param);
                break;
            case PARAM_PTR_STRUCT:
                _snwprintf(szBuff, MAX_PATH, L"%s:%lu, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                break;
            default:
                LogMessage(L"Unknown");
                bFound = FALSE;
                break;
            }

            if (bFound)
            {
                _wcsncat(szLog, szBuff, _wcslen(szBuff));
                RtlZeroMemory(szBuff, _wcslen(szBuff));
            }
        }
    }

    TrueRtlFreeHeap(RtlProcessHeap(), 0, szBuff);
    return szLog;
}

// Log Return Value and __Out__ Buffers.
EXTERN_C
__declspec(noinline) PWCHAR WINAPI PostHookTraceAPI(PAPI pAPI, DWORD_PTR *BasePointer, PWCHAR szLog, DWORD_PTR RetValue)
{
    INT len = 0;
    PWCHAR szBuff = (PWCHAR)TrueRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
    BOOL bFound = FALSE;

    for (int i = 0; i < pAPI->cParams; i++)
    {
#ifdef _WIN64
        DWORD_PTR Param = *(DWORD_PTR *)(BasePointer + 8 * i);
#else
        DWORD_PTR Param = *(DWORD_PTR *)(BasePointer + i);
#endif

        switch (pAPI->Parameters[i].Annotation)
        {
        case PARAM_OUT:
        case PARAM_IN_OUT:
            switch (pAPI->Parameters[i].Type)
            {
            case PARAM_IMM:
                _snwprintf(szBuff, MAX_PATH, L"out: %s:0x%x, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                bFound = TRUE;
                break;
            case PARAM_PTR_IMM:
                //if (!IsBadReadPtr((intptr_t *)Param, 8))
                //    Param = *(DWORD_PTR *)Param;
                _snwprintf(szBuff, MAX_PATH, L"out: %s:0x%x, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                bFound = TRUE;
                break;
            case PARAM_ASCII_STR:
                _snwprintf(szBuff, MAX_PATH, L"out: %s:%s, ", pAPI->Parameters[i].Name, (PCHAR)Param);
                bFound = TRUE;
                break;
            case PARAM_WIDE_STR:
                _snwprintf(szBuff, MAX_PATH, L"out: %s:%ws, ", (PCHAR)pAPI->Parameters[i].Name, (PWCHAR)Param);
                bFound = TRUE;
                break;
            case PARAM_PTR_STRUCT:
                _snwprintf(szBuff, MAX_PATH, L"out: %s:0x%p, ", (PCHAR)pAPI->Parameters[i].Name, (PVOID)Param);
                bFound = TRUE;
                break;
            default:
                break;
            }

            if (bFound)
            {
                _wcsncat(szLog, szBuff, _wcslen(szBuff));
                RtlZeroMemory(szBuff, MAX_PATH);
            }
        }
    }

    // Log Return Value
    if (pAPI->ReturnVoid)
    {
        _wcscat(szLog, L") => void");
    }
    else
    {
        _snwprintf(szBuff, MAX_PATH, L") => 0x%p", RetValue);
        _wcsncat(szLog, szBuff, _wcslen(szBuff));
    }

    // Cleanup.
    TrueRtlFreeHeap(RtlProcessHeap(), 0, szBuff);

    return szLog;
}

#ifndef _WIN64
EXTERN_C
VOID WINAPI
GenericHookHandler(DWORD_PTR RealTarget, DWORD_PTR ReturnAddress, DWORD_PTR CallerStackFrame)
{
    //
    // Get the target API.
    //

    PAPI pAPI = GetTargetAPI(RealTarget);
    if (!pAPI)
    {
        LogMessage(L"Could not find API!\n");
    }

    // Are we called from inside a our own hook handler.
    if (SfwIsCalledFromSystemMemory(ReturnAddress) || SfwIsInsideHook())
    {
        // Call the Real API.
        DWORD_PTR RetValue = AsmCall(pAPI->RealTarget, pAPI->cParams, &CallerStackFrame);
        AsmReturn(pAPI->cParams, RetValue);
        return;
    }

    // Allocate space to log the API.
    PWCHAR szLog = (PWCHAR)TrueRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 1024);

    // Append the API name.
    _snwprintf(szLog, MAX_PATH, L"%ws(", pAPI->Name);

    // Pre Hooking.
    PreHookTraceAPI(szLog, pAPI, &CallerStackFrame);

    // Finally perform the call.
    DWORD_PTR RetValue = AsmCall(pAPI->RealTarget, pAPI->cParams, &CallerStackFrame);

    // Log Post Hooking.
    PostHookTraceAPI(pAPI, &CallerStackFrame, szLog, RetValue);

    LogMessage(L"%ws\n", szLog);
    TrueRtlFreeHeap(RtlProcessHeap(), 0, szLog);

    // Releasing our hook guard.
    SfwReleaseHookGuard();

    // Set eax to RetValue, and ecx to cParams so we know how to adjust the stack.
    AsmReturn(pAPI->cParams, RetValue);
}

#else
EXTERN_C
VOID WINAPI
GenericHookHandler_x64(DWORD_PTR ReturnAddress, DWORD_PTR CallerStackFrame, PCONTEXT pContext, DWORD_PTR RealTarget)
{
    DWORD_PTR RetValue;

    //
    // Get the target API.
    //
    PAPI pAPI = GetTargetAPI(RealTarget);
    if (!pAPI)
    {
        LogMessage(L"Could not find API!\n");
        return;
    }

    // Are we called from inside a our own hook handler.
    if (SfwIsCalledFromSystemMemory(ReturnAddress) || SfwIsInsideHook())
    {
        // Call the Real API.
        RetValue = AsmCall_x64(pContext, pAPI->RealTarget, pAPI->cParams, CallerStackFrame);
        AsmReturn_x64(RetValue, ReturnAddress);
        return;
    }

    // Allocate space to log the API.
    PWCHAR szLog = (PWCHAR)TrueRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 1024);

    // Append the API name.
    _snwprintf(szLog, MAX_PATH, L"%ws(", pAPI->Name);

    // Pre Hooking.
    PreHookTraceAPI_x64(szLog, pAPI, &CallerStackFrame, pContext);

    // Finally perform the call.
    RetValue = AsmCall_x64(pContext, pAPI->RealTarget, pAPI->cParams, CallerStackFrame);

    // Log Post Hooking.
    PostHookTraceAPI(pAPI, &CallerStackFrame, szLog, RetValue);

    LogMessage(L"%ws\n", szLog);
    TrueRtlFreeHeap(RtlProcessHeap(), 0, szLog);

    // Releasing our hook guard.
    SfwReleaseHookGuard();

    // Set eax to RetValue, and ecx to cParams so we know how to adjust the stack.
    AsmReturn_x64(RetValue, ReturnAddress);
}
#endif

BOOL
SfwHookLoadedModules()
{
    const unsigned initial_size = 256;
    pgHookContext->hashmapA =
        (struct hashmap_s *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct hashmap_s));
    if (0 != hashmap_create(initial_size, pgHookContext->hashmapA))
    {
        LogMessage(L"hashmap_create failed\n");
    }

    //
    // Get the PEB.
    //
#if defined(_WIN64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);

#elif defined(_WIN32)
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA pLdrData = NULL;
    PLIST_ENTRY pEntry, pHeadEntry = NULL;
    PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;

    pLdrData = pPeb->Ldr;
    pHeadEntry = &pLdrData->InMemoryOrderModuleList;
    pEntry = pHeadEntry->Flink;

    //
    // Begin a new transaction for attaching detours.
    //
    SfwHookBeginTransation();

    //
    // Walk through the loaded modules.
    //

    while (pEntry != pHeadEntry)
    {
        pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        //
        // Skip the main executable module.
        //

        if (_wcscmp(pLdrEntry->FullDllName.Buffer, pPeb->ProcessParameters->ImagePathName.Buffer) == 0)
        {
            pgHookContext->ModuleBase = (DWORD_PTR)pLdrEntry->DllBase;
            pgHookContext->SizeOfImage = pLdrEntry->SizeOfImage;
            pEntry = pEntry->Flink;
            continue;
        }

        //
        // Get ModuleInfo from hashmap.
        //

        UNICODE_STRING szModuleName = {0};
        RtlCreateUnicodeString(&szModuleName, pLdrEntry->BaseDllName.Buffer);
        RtlDowncaseUnicodeString(&szModuleName, &pLdrEntry->BaseDllName, FALSE);
        PMODULE_INFO ModuleInfo =
            (PMODULE_INFO)hashmap_get(pgHookContext->hashmapM, szModuleName.Buffer, szModuleName.Length);
        if (NULL == ModuleInfo)
        {
            LogMessage(L"Could not find %s\n", pLdrEntry->BaseDllName.Buffer);
            pEntry = pEntry->Flink;
            continue;
        }

        //
        // Walk over APIs and hook each of them.
        //
        for (UINT j = 0; j < ModuleInfo->cAPIs; j++)
        {
            PDETOUR_TRAMPOLINE pRealTrampoline;
            PVOID Real, pRealTarget, pRealDetour;

            Real = SfwUtilGetProcAddr(pLdrEntry->DllBase, ModuleInfo->APIList[j]);
            if (!Real)
            {
                LogMessage(L"SfwUtilGetProcAddr() failed to find %s", ModuleInfo->APIList[j]);
                continue;
            }

            //
            // Attach a detour to a target function and
            // retrieve additional detail about the ultimate target.
            //

            LONG l = DetourAttachEx(&Real, HookHandler, &pRealTrampoline, &pRealTarget, &pRealDetour);
            if (l != NO_ERROR)
            {
                LogMessage(L"Detour attach failed");
                return FALSE;
            }

            PAPI pAPI = (PAPI)hashmap_get(
                pgHookContext->hashmap, ModuleInfo->APIList[j], _wcslen(ModuleInfo->APIList[j]) * sizeof(WCHAR));
            if (!pAPI)
            {
                LogMessage(L"hashmap_get() failed");
                return FALSE;
            }

            LogMessage(L"%s() Hooked, pRealTarget: 0x%p", ModuleInfo->APIList[j], pRealTarget);
            pAPI->RealTarget = pRealTrampoline;

            if (0 != hashmap_put(pgHookContext->hashmapA, pRealTarget, 0, pAPI))
            {
                LogMessage(L"hashmap_put failed\n");
                return FALSE;
            }

            //
            // Adjust APIs used by the hook handler to point to the "True" version of the API.
            //

            if (_wcscmp(ModuleInfo->APIList[j], L"HeapAlloc") == 0)
            {
                TrueRtlAllocateHeap = (pfn_RtlAllocateHeap)pRealTrampoline;
            }
            else if (_wcscmp(ModuleInfo->APIList[j], L"HeapFree") == 0)
            {
                TrueRtlFreeHeap = (pfn_RtlFreeHeap)pRealTrampoline;
            }
        }

        //
        // Iterate to the next entry.
        //

        pEntry = pEntry->Flink;
    }

    //
    // Commit the current transaction for attaching detours.
    //
    SfwHookCommitTransaction();

    return TRUE;
}
