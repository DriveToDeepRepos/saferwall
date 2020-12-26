#include "stdafx.h"

extern PHOOK_CONTEXT pgHookContext;
extern strlen_fn_t _strlen;
extern pfn_wcslen _wcslen;

BOOL
SfwSchemaLoadAPIDef()
{
    int r;
    jsmn_parser p;
    jsmntok_t *t;
    DWORD dwJsonLength = 0;

    //
    // Allocate space for json tokens.
    //

    t = (jsmntok_t *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(jsmntok_t) * 10000);

    //
    // Read the file.
    //

    WCHAR filename[] = L"C:\\coding\\saferwall-sandbox\\sandbox\\src\\sdk2json\\mini-apis.json";
    char *JSON_STRING = (CHAR *)SfwUtilReadFile(filename, &dwJsonLength);

    //
    // Parse the json API definiion file.
    //

    jsmn_init(&p);
    r = jsmn_parse(&p, JSON_STRING, dwJsonLength, t, 100000);
    if (r < 0)
    {
        LogMessage(L"jsmn_parse() failed to parse JSON: %d", r);
        return 0;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT)
    {
        LogMessage(L"object expected");
        return 1;
    }

    const unsigned initial_size = 256;

    pgHookContext->hashmap =
        (struct hashmap_s *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct hashmap_s *));
    if (0 != hashmap_create(initial_size, pgHookContext->hashmap))
    {
        LogMessage(L"hashmap_create() failed\n");
    }

    pgHookContext->hashmapM =
        (struct hashmap_s *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct hashmap_s *));
    if (0 != hashmap_create(initial_size, pgHookContext->hashmapM))
    {
        LogMessage(L"hashmap_create failed\n");
    }

    UINT d = 0;
    UINT cModules = t[0].size;

    // Skip the root json object.
    d++;

    // Iterate over DLL modules.
    for (UINT iModule = 0; iModule < cModules; iModule++)
    {
        // Get the module name.
        LPCWSTR szModuleName =
            (LPCWSTR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, (t[d].end - t[d].start + 1) * sizeof(WCHAR));
        RtlMultiByteToUnicodeN(
            (PWCH)szModuleName,
            (t[d].end - t[d].start + 1) * sizeof(WCHAR),
            NULL,
            JSON_STRING + t[d].start,
            t[d].end - t[d].start);

        UINT cAPIs = t[++d].size;

        // Allocate space for an array of strings.
        LPCWSTR *APIList;
        APIList = (LPCWSTR *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LPCWSTR) * cAPIs);

        // Create a new ModuleInfo.
        PMODULE_INFO pModuleInfo =
            (PMODULE_INFO)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MODULE_INFO));
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
            pAPI->Name = (LPCWSTR)RtlAllocateHeap(
                RtlProcessHeap(), HEAP_ZERO_MEMORY, (t[d].end - t[d].start + 1) * sizeof(WCHAR));
            RtlMultiByteToUnicodeN(
                (PWCH)pAPI->Name,
                (t[d].end - t[d].start + 1) * sizeof(WCHAR),
                NULL,
                JSON_STRING + t[d].start,
                t[d].end - t[d].start);

            APIList[iAPI] = pAPI->Name;

            // Skip the API name string and ita content.
            d += 2;

            // Get the return type.
            if (RtlCompareMemory(JSON_STRING + t[++d].start, "true", 4) == 4)
            {
                pAPI->ReturnVoid = true;
            }

            // Skip size value.
            d++;
            pAPI->cParams = t[++d].size;
            d++;

            // Allocate space for parameters.
            pAPI->Parameters =
                (PAPI_PARAM)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(API_PARAM) * pAPI->cParams);

            // Walk over API Paramteres.
            for (UINT iParams = 0; iParams < pAPI->cParams; iParams++)
            {
                // Iterate over each parameter infos.
                UINT cParamMembers = t[d].size;

                // Skip member object.
                d++;

                for (UINT iParamMember = 0; iParamMember < cParamMembers; iParamMember++)
                {
                    if (RtlCompareMemory(JSON_STRING + t[d].start, "anno", 4) == 4)
                    {
                        pAPI->Parameters[iParams].Annotation =
                            (PARAM_ANNOTATION)(*(PCHAR)(JSON_STRING + t[d + 1].start) - '0');
                    }

                    else if (RtlCompareMemory(JSON_STRING + t[d].start, "type", 4) == 4)
                    {
                        pAPI->Parameters[iParams].Type = (TYPE_PARAM)(*(PCHAR)(JSON_STRING + t[d + 1].start) - '0');
                    }

                    else if (RtlCompareMemory(JSON_STRING + t[d].start, "name", 4) == 4)
                    {
                        pAPI->Parameters[iParams].Name = (LPCWSTR)RtlAllocateHeap(
                            RtlProcessHeap(), HEAP_ZERO_MEMORY, (t[d + 1].end - t[d + 1].start + 1) * sizeof(WCHAR));
                        RtlMultiByteToUnicodeN(
                            (PWCH)pAPI->Parameters[iParams].Name,
                            (t[d + 1].end - t[d + 1].start + 1) * sizeof(WCHAR),
                            NULL,
                            JSON_STRING + t[d + 1].start,
                            t[d + 1].end - t[d + 1].start);
                    }

                    d += 2;
                }
            }

            if (0 != hashmap_put(pgHookContext->hashmap, pAPI->Name, _wcslen(pAPI->Name) * sizeof(WCHAR), pAPI))
            {
                LogMessage(L"hashmap_put failed\n");
            }
        }

        if (0 != hashmap_put(pgHookContext->hashmapM, szModuleName, _wcslen(szModuleName) * sizeof(WCHAR), pModuleInfo))
        {
            LogMessage(L"hashmap_put failed\n");
        }
    }

    NtFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&JSON_STRING, (PSIZE_T)&dwJsonLength, MEM_RELEASE);
    return TRUE;
}