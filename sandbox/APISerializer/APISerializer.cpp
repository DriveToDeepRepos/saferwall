// APISerializer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


//
// Strings, Path & IO
//

#include <stdio.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")


#include "jsmn.h"
#include "APISerializer.h"
#include "hashmap.h"



typedef struct _HOOK_CONTEXT
{
    DWORD_PTR ModuleBase;
    DWORD SizeOfImage;
} HOOK_CONTEXT, *PHOOK_CONTEXT;

DWORD dwTlsIndex;


HOOK_CONTEXT gHookContext;
struct hashmap_s hashmapA;


extern "C" {
DWORD __stdcall GetBasePointer(VOID);
DWORD __stdcall GetESP(VOID);
DWORD __stdcall HookHandler(VOID);
DWORD __stdcall PushIntoStack(DWORD_PTR);
DWORD_PTR __stdcall AsmCall(PVOID, UCHAR, DWORD_PTR*);
VOID __stdcall AsmPopStack(VOID);
}



char *
ReadMyFile(const char *filename)
{
    char *buffer = NULL;
    int string_size, read_size;
    FILE *handler = fopen(filename, "r");

    if (handler)
    {
        // Seek the last byte of the file
        fseek(handler, 0, SEEK_END);
        // Offset from the first to the last byte, or in other words, filesize
        string_size = ftell(handler);
        // go back to the start of the file
        rewind(handler);

        // Allocate a string that can hold it all
        buffer = (char *)malloc(sizeof(char) * (string_size + 1));

        // Read it all in one operation
        read_size = fread(buffer, sizeof(char), string_size, handler);

        // fread doesn't set it so put a \0 in the last position
        // and buffer is now officially a string
        buffer[string_size] = '\0';

        if (string_size != read_size)
        {
            // Something went wrong, throw away the memory and set
            // the buffer to NULL
            free(buffer);
            buffer = NULL;
        }

        // Always remember to close the file.
        fclose(handler);
    }

    return buffer;
}

static int
jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}

static void
json_print(const char *jstr, jsmntok_t *json)
{
    if (json == NULL)
    {
        printf("Null!\n");
    }
    else
    {
        printf("%.*s\n", json[0].end - json[0].start, jstr + json[0].start);
    }
}

static int
dump(const char *js, jsmntok_t *t, size_t count, int indent)
{
    int i, j, k;
    jsmntok_t *key;
    if (count == 0)
    {
        return 0;
    }
    if (t->type == JSMN_PRIMITIVE)
    {
        printf("%.*s", t->end - t->start, js + t->start);
        return 1;
    }
    else if (t->type == JSMN_STRING)
    {
        printf("'%.*s'", t->end - t->start, js + t->start);
        return 1;
    }
    else if (t->type == JSMN_OBJECT)
    {
        printf("\n");
        j = 0;
        for (i = 0; i < t->size; i++)
        {
            for (k = 0; k < indent; k++)
            {
                printf("  ");
            }
            key = t + 1 + j;
            j += dump(js, key, count - j, indent + 1);
            if (key->size > 0)
            {
                printf(": ");
                j += dump(js, t + 1 + j, count - j, indent + 1);
            }
            printf("\n");
        }
        return j + 1;
    }
    else if (t->type == JSMN_ARRAY)
    {
        j = 0;
        printf("\n");
        for (i = 0; i < t->size; i++)
        {
            for (k = 0; k < indent - 1; k++)
            {
                printf("  ");
            }
            printf("   - ");
            j += dump(js, t + 1 + j, count - j, indent + 1);
            printf("\n");
        }
        return j + 1;
    }
    return 0;
}

extern "C" __declspec(noinline) BOOL WINAPI IsInsideHook()
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
    if (!TlsGetValue(dwTlsIndex))
    {
        TlsSetValue(dwTlsIndex, (LPVOID)TRUE);
        return FALSE;
    }
    return TRUE;
}

VOID
ReleaseHookGuard()
{
    TlsSetValue(dwTlsIndex, (LPVOID)FALSE);
}

VOID
EnterHookGuard()
{
    TlsSetValue(dwTlsIndex, (LPVOID)TRUE);
}


extern "C" __declspec(noinline) BOOL WINAPI IsCalledFromSystemMemory(DWORD_PTR ReturnAddress)
{
    if (ReturnAddress >= gHookContext.ModuleBase && ReturnAddress <= gHookContext.ModuleBase  + gHookContext.SizeOfImage)
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
        if (wcscmp(pLdrEntry->FullDllName.Buffer, pPeb->ProcessParameters->ImagePathName.Buffer) == 0)
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


WCHAR *
MultiByteToWide(CHAR *lpMultiByteStr)
{
    // int Size = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, szSource, strlen(szSource), NULL, 0);
    // WCHAR *wszDest = reinterpret_cast<WCHAR*>(RtlAllocateHeap(RtlProcessHeap(), 0, Size));
    // SecureZeroMemory(wszDest, Size);
    // MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szSource, strlen(szSource), wszDest, Size);

    /* Get the required size */
    size_t iNumChars = strlen(lpMultiByteStr);

    /* Allocate new wide string */
    SIZE_T Size = (1 + iNumChars) * sizeof(WCHAR);

    WCHAR *lpWideCharStr = reinterpret_cast<WCHAR *>(RtlAllocateHeap(RtlProcessHeap(), 0, Size));
    WCHAR *It;
    It = lpWideCharStr;
    if (lpWideCharStr)
    {
        SecureZeroMemory(lpWideCharStr, Size);
        while (iNumChars)
        {
            *lpWideCharStr = *lpMultiByteStr;
            lpWideCharStr++;
            lpMultiByteStr++;
            iNumChars--;
        }
    }
    return It;

    // return wszDest;
}


extern "C" __declspec(noinline) PAPI WINAPI GetTargetAPI(DWORD_PTR RetAddr)
{
    DWORD_PTR Target;
    PAPI pAPI;

    // CALL NEAR
    BYTE *byte1 = (BYTE *)(RetAddr - 6);
    BYTE *byte2 = (BYTE *)(RetAddr - 5);
    if (*byte1 == 0xFF && *byte2 == 0x15)
    {
        Target = **((DWORD_PTR **)(RetAddr - 4));
        pAPI = (PAPI)hashmap_get(&hashmapA, (PVOID)Target, 0);
        return pAPI;
    }

    return NULL;
}


extern "C" __declspec(noinline) PCHAR WINAPI PreHookTraceAPI(PCHAR szLog, PAPI pAPI, DWORD_PTR* BasePointer)
{
    INT len;
    PCHAR szBuff = (PCHAR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);

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
                _snprintf(szBuff, sizeof(szBuff), "%s:%lu, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                break;
            case PARAM_PTR_IMM:
                _snprintf(
                    szBuff,
                    sizeof(szBuff),
                    "%s:%lu, ",
                    (PCHAR)pAPI->Parameters[i].Name,
                    *(DWORD_PTR *)Param);
                break;
            case PARAM_ASCII_STR:
                _snprintf(szBuff, MAX_PATH, "%s:%s, ", (PCHAR)pAPI->Parameters[i].Name, (PCHAR)Param);
                break;
            case PARAM_WIDE_STR:
                _snprintf(szBuff, MAX_PATH, "%s:%ws, ", (PCHAR)pAPI->Parameters[i].Name, (PWCHAR)Param);
				break;
            case PARAM_PTR_STRUCT:
                _snprintf(szBuff, MAX_PATH, "%s:%lu, ", (PCHAR)pAPI->Parameters[i].Name, Param);
                break;
            default:
                printf("Unknown");
                break;
            }

		strncat(szLog, szBuff, strlen(szBuff));
        RtlZeroMemory(szBuff, sizeof(szBuff));
		}
	}

	RtlFreeHeap(RtlProcessHeap(), 0, szBuff);
	return szLog;
}


// Log Return Value and __Out__ Buffers.
extern "C" __declspec(noinline) PCHAR WINAPI
    PostHookTraceAPI(PAPI pAPI, DWORD_PTR* BasePointer , PCHAR szLog, DWORD_PTR ReturnValue)
{
    INT len;
    PCHAR szBuff = (PCHAR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);

    for (int i = 0; i < pAPI->cParams; i++)
    {
        DWORD_PTR Param = *(DWORD_PTR *)(BasePointer + i);
        switch (pAPI->Parameters[i].Annotation)
        {
        case PARAM_OUT:
        case PARAM_IN_OUT:
            switch (pAPI->Parameters[i].Type)
            {
            case PARAM_IMM:
                _snprintf(szBuff, sizeof(szBuff), "out: %s:%lu", (PCHAR)pAPI->Parameters[i].Name, Param);
                break;
            case PARAM_PTR_IMM:
                _snprintf(
                    szBuff,
                    sizeof(szBuff),
                    "out: %s:%lu",
                    (PCHAR)pAPI->Parameters[i].Name,
                    Param);
                break;
            case PARAM_ASCII_STR:
                _snprintf(
                    szBuff,
                    sizeof(szBuff),
                    "out: %s:%s",
                    (PCHAR)pAPI->Parameters[i].Name,
                    Param);
                break;
            case PARAM_WIDE_STR:
                _snprintf(szBuff, MAX_PATH, "out: %s:%ws", (PCHAR)pAPI->Parameters[i].Name, (PWCHAR)Param);
                break;
            case PARAM_PTR_STRUCT:
                _snprintf(szBuff, sizeof(szBuff), "out: %s:0x%p", (PCHAR)pAPI->Parameters[i].Name, (PVOID)Param);
                break;
            default:
                break;
            }

		strncat(szLog, szBuff, strlen(szBuff));
        }

    }


	if (pAPI->ReturnNonVoid )
    {
        _snprintf(szLog, MAX_PATH, ") => 0x%p", ReturnValue);
    }
    else
    {
        strcat(szLog, " => void");
    }

	RtlFreeHeap(RtlProcessHeap(), 0, szBuff);

    return szLog;
}

extern "C" VOID WINAPI
GenericHookHandler(DWORD_PTR ReturnAddress, DWORD_PTR CallerStackFrame)
{
	// Get the target API.
    PAPI pAPI = GetTargetAPI(ReturnAddress);

    // Are we called from inside a our own hook handler.
    if (IsInsideHook() || IsCalledFromSystemMemory(ReturnAddress))
    {
		// Call the Real API.
        AsmCall(pAPI->RealTarget, pAPI->cParams, &CallerStackFrame);
        return;
    }

	// Allocate space to log the API.
    PCHAR szLog = (PCHAR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);

	// Append the API name.
    snprintf(szLog, MAX_PATH, "%s(", pAPI->Name);

    // Pre Hooking.
	PreHookTraceAPI(szLog, pAPI, &CallerStackFrame);

	// Finally perform the call.
    DWORD_PTR RetValue = AsmCall(pAPI->RealTarget, pAPI->cParams, &CallerStackFrame);

	// Log Post Hooking.
    PostHookTraceAPI(pAPI, &CallerStackFrame, szLog, RetValue);

    printf("%s\n", szLog);

	ReleaseHookGuard();
}

PVOID
GetAPIAddress(PSTR FunctionName, PWSTR ModuleName)
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
        printf("LdrGetDllHandle failed");
        return NULL;
    }

    PVOID Address;
    Status = LdrGetProcedureAddress(ModuleHandle, &RoutineName, 0, &Address);
    if (Status != STATUS_SUCCESS)
    {
        printf("LdrGetProcedureAddress failed");
        return NULL;
    }

    return Address;
}

BOOL
HookBegingTransation()
{
    LONG Status;

    //
    // Begin a new transaction for attaching detours.
    //

    Status = DetourTransactionBegin();
    if (Status != NO_ERROR)
    {
        printf("DetourTransactionBegin() failed with %d", Status);
        return FALSE;
    }

    //
    // Enlist a thread for update in the current transaction.
    //

    Status = DetourUpdateThread(NtCurrentThread());
    if (Status != NO_ERROR)
    {
        printf("DetourUpdateThread() failed with %d", Status);
        return FALSE;
    }

    return TRUE;
}

BOOL
HookCommitTransaction()
{
    /*
    Commit the current transaction.
    */

    PVOID *ppbFailedPointer = NULL;

    LONG error = DetourTransactionCommitEx(&ppbFailedPointer);
    if (error != NO_ERROR)
    {
        printf(
           "Attach transaction failed to commit. Error %d (%p/%p)", error, ppbFailedPointer, *ppbFailedPointer);
        return FALSE;
    }

    return TRUE;
}


int
main()
{
    int r;
    jsmn_parser p;
    jsmntok_t t[10000]; 

	 // Allocate a TLS index.
    //

    if ((dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES)
    {
        printf("TlsAlloc() failed");
    }

    // Read a json file
    const char *filename = "C:\\coding\\saferwall-sandbox\\sandbox\\src\\sdk2json\\mini-apis.json";
    char *JSON_STRING = ReadMyFile(filename);

    jsmn_init(&p);
    r = jsmn_parse(&p, JSON_STRING, strlen(JSON_STRING), t, sizeof(t) / sizeof(t[0]));
    if (r < 0)
    {
        printf("Failed to parse JSON: %d\n", r);
        return 1;
    }

	//dump(JSON_STRING, &t[0], p.toknext, 0);

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT)
    {
        printf("object expected\n");
        return 1;
    }
   
	const unsigned initial_size = 256;
    struct hashmap_s hashmap;
    struct hashmap_s hashmapM;

    if (0 != hashmap_create(initial_size, &hashmap))
    {
        printf("hashmap_create failed\n");
    }

    if (0 != hashmap_create(initial_size, &hashmapM))
    {
        printf("hashmap_create failed\n");
    }

    if (0 != hashmap_create(initial_size, &hashmapA))
    {
        printf("hashmap_create failed\n");
    }

    UINT d = 0;
    UINT cModules = t[0].size;

	// Skip the root json object.
    d++;

	// Iterate over DLL modules.
    for (UINT iModule = 0; iModule < cModules; iModule++)
    {
		// Get the module name.
        json_print(JSON_STRING, &t[d]);

        LPCSTR szModuleName = (LPCSTR) RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, t[d].end - t[d].start + 1);
        RtlCopyMemory((PVOID)szModuleName, JSON_STRING + t[d].start, t[d].end - t[d].start);

		UINT cAPIs = t[++d].size;

		// Allocate space for an array of strings.
        LPCSTR *APIList;
        APIList = (LPCSTR *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LPCSTR) * cAPIs);

		// Create a new ModuleInfo.
        PMODULE_INFO pModuleInfo = (PMODULE_INFO)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MODULE_INFO));
        pModuleInfo->APIList = APIList;
        pModuleInfo->cAPIs = cAPIs;

		// Skip API name and its content object.
         d++; 

		// Iterate over all APIs inside modules.
        for (UINT iAPI = 0; iAPI < cAPIs; iAPI++)
        {
			// Create a new Object.
            PAPI pAPI = (PAPI)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(API));

			// Get API name.
            pAPI->Name = (LPCSTR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, t[d].end - t[d].start + 1);
            RtlCopyMemory((PVOID)pAPI->Name, JSON_STRING + t[d].start, t[d].end - t[d].start);

			APIList[iAPI] = pAPI->Name;

			// Skip the API name string and ita content.
            d+=2;

			// Get the return type.
			if (RtlEqualMemory(JSON_STRING + t[++d].start, "true", 4))
            {
                pAPI->ReturnNonVoid = true;
            }

			// Skip size value.
            d++;
			pAPI->cParams = t[++d].size;
            d++;

			// Allocate space for parameters.
            pAPI->Parameters = (PAPI_PARAM)RtlAllocateHeap(
                RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(API_PARAM) * pAPI->cParams);

            // Walk over API Paramteres.
            for (UINT iParams = 0; iParams < pAPI->cParams; iParams++)
            {
				// Iterate over each parameter infos.
                UINT cParamMembers = t[d].size;

				// Skip member object.
                d++;

                for (UINT iParamMember = 0; iParamMember < cParamMembers; iParamMember++)
                {
                    if (RtlEqualMemory(JSON_STRING + t[d].start, "anno", 4))
                    {
                        pAPI->Parameters[iParams].Annotation =
                            (PARAM_ANNOTATION)(*(PCHAR)(JSON_STRING + t[d + 1].start) - '0');
                    }

                    else if (RtlEqualMemory(JSON_STRING + t[d].start, "type", 4))
                    {
                        pAPI->Parameters[iParams].Type =
                            (TYPE_PARAM)(*(PCHAR)(JSON_STRING + t[d+1].start) - '0');
                    }

                    else if (RtlEqualMemory(JSON_STRING + t[d].start, "name", 4))
                    {
                        pAPI->Parameters[iParams].Name =
                            (LPCSTR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, t[d+1].end - t[d+1].start + 1);
						RtlCopyMemory((PVOID)pAPI->Parameters[iParams].Name, JSON_STRING + t[d + 1].start, t[d+1].end - t[d+1].start);
                    }

					d += 2;
				}
			}

			if (0 != hashmap_put(&hashmap, pAPI->Name, strlen(pAPI->Name), pAPI))
            {
                printf("hashmap_put failed\n");
            }
		}

		if (0 != hashmap_put(&hashmapM, szModuleName, strlen(szModuleName), pModuleInfo))
        {
            printf("hashmap_put failed\n");
        }
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
    NTSTATUS Status;

    pLdrData = pPeb->Ldr;
    pHeadEntry = &pLdrData->InMemoryOrderModuleList;

    pEntry = pHeadEntry->Flink;

    while (pEntry != pHeadEntry)
    {
        // Retrieve the current LDR_DATA_TABLE_ENTRY
        pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// Skip the main exe module.
        if (wcscmp(pLdrEntry->FullDllName.Buffer, pPeb->ProcessParameters->ImagePathName.Buffer) == 0)
        {
            gHookContext.ModuleBase = (DWORD_PTR)pLdrEntry->DllBase;
            gHookContext.SizeOfImage = pLdrEntry->SizeOfImage;
            pEntry = pEntry->Flink;
            continue;
        }

		 // Check if this loaded module is a module we want to hook inside.
        UNICODE_STRING BaseDllName = {0};
        RtlCreateUnicodeString(&BaseDllName, pLdrEntry->BaseDllName.Buffer);
        RtlDowncaseUnicodeString(&BaseDllName, &pLdrEntry->BaseDllName, FALSE);

        ULONG BytesInMultiByteString = 0;
        PCHAR szCurrentModule = (PCHAR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, pLdrEntry->BaseDllName.Length / 2 + 1);
        Status = RtlUnicodeToMultiByteN(szCurrentModule, BaseDllName.Length / 2, &BytesInMultiByteString, BaseDllName.Buffer, BaseDllName.Length);
        if (!NT_SUCCESS(Status))
            return -1;

		// Get ModuleInfo from hashmap.
        PMODULE_INFO ModuleInfo =(PMODULE_INFO)hashmap_get(&hashmapM, szCurrentModule, strlen(szCurrentModule));
        if (NULL == ModuleInfo)
        {
            printf("Could not find %s\n", szCurrentModule);
            pEntry = pEntry->Flink;
            continue;
        }

		// Walk through APIs and hook each of them,
		for (int j = 0; j < ModuleInfo->cAPIs; j++)
        {
            PDETOUR_TRAMPOLINE pRealTrampoline;
            PVOID pRealTarget, pRealDetour;

            HookBegingTransation();

            PVOID Real = GetAPIAddress((PSTR)ModuleInfo->APIList[j],  pLdrEntry->BaseDllName.Buffer);
            DWORD RealAPIAddress = (DWORD)Real;
            LONG l = DetourAttachEx(&Real, HookHandler, &pRealTrampoline, &pRealTarget, &pRealDetour);
            if (l != NO_ERROR)
            {
                printf("Detour attach failed");
            }

			printf("Hooking %s\n", ModuleInfo->APIList[j]);
			HookCommitTransaction();


            PAPI pAPI = (PAPI)hashmap_get(&hashmap, ModuleInfo->APIList[j], strlen(ModuleInfo->APIList[j]));
            pAPI->RealTarget = pRealTrampoline;

			printf("%s() Hooked, target: 0x%p\n", ModuleInfo->APIList[j], pRealTarget);
						
			if (0 != hashmap_put(&hashmapA, (PVOID)RealAPIAddress, 0, pAPI))
			{
                printf("hashmap_put failed\n");
            }

        }

        // Iterate to the next entry.
        pEntry = pEntry->Flink;
    }


	TestFileHooks();

    return 0;
}
