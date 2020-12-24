#include "stdafx.h"

extern HOOK_CONTEXT gHookContext;
extern strlen_fn_t _strlen;

BOOL
SfwSchemaLoadAPIDef()
{
    int r;
    jsmn_parser p;
    jsmntok_t t[10000];

    // Read a json file
    WCHAR filename[] = L"C:\\coding\\saferwall-sandbox\\sandbox\\src\\sdk2json\\mini-apis.json";
    char *JSON_STRING = (CHAR*)SfwUtilReadFile(filename);

    jsmn_init(&p);
    r = jsmn_parse(&p, JSON_STRING, _strlen(JSON_STRING), t, sizeof(t) / sizeof(t[0]));
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
    if (0 != hashmap_create(initial_size, &gHookContext.hashmap))
    {
        LogMessage(L"hashmap_create() failed\n");
    }

    if (0 != hashmap_create(initial_size, &gHookContext.hashmapM))
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
        LPCSTR szModuleName = (LPCSTR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, t[d].end - t[d].start + 1);
        RtlCopyMemory((PVOID)szModuleName, JSON_STRING + t[d].start, t[d].end - t[d].start);

        UINT cAPIs = t[++d].size;

        // Allocate space for an array of strings.
        LPCSTR *APIList;
        APIList = (LPCSTR *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LPCSTR) * cAPIs);

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
            pAPI->Name = (LPCSTR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, t[d].end - t[d].start + 1);
            RtlCopyMemory((PVOID)pAPI->Name, JSON_STRING + t[d].start, t[d].end - t[d].start);

            APIList[iAPI] = pAPI->Name;

            // Skip the API name string and ita content.
            d += 2;

            // Get the return type.
            if (RtlCompareMemory(JSON_STRING + t[++d].start, "true", 4))
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
                    if (RtlCompareMemory(JSON_STRING + t[d].start, "anno", 4))
                    {
                        pAPI->Parameters[iParams].Annotation =
                            (PARAM_ANNOTATION)(*(PCHAR)(JSON_STRING + t[d + 1].start) - '0');
                    }

                    else if (RtlCompareMemory(JSON_STRING + t[d].start, "type", 4))
                    {
                        pAPI->Parameters[iParams].Type = (TYPE_PARAM)(*(PCHAR)(JSON_STRING + t[d + 1].start) - '0');
                    }

                    else if (RtlCompareMemory(JSON_STRING + t[d].start, "name", 4))
                    {
                        pAPI->Parameters[iParams].Name = (LPCSTR)RtlAllocateHeap(
                            RtlProcessHeap(), HEAP_ZERO_MEMORY, t[d + 1].end - t[d + 1].start + 1);
                        RtlCopyMemory(
                            (PVOID)pAPI->Parameters[iParams].Name,
                            JSON_STRING + t[d + 1].start,
                            t[d + 1].end - t[d + 1].start);
                    }

                    d += 2;
                }
            }

            if (0 != hashmap_put(&gHookContext.hashmap, pAPI->Name, _strlen(pAPI->Name), pAPI))
            {
                LogMessage(L"hashmap_put failed\n");
            }
        }

        if (0 != hashmap_put(&gHookContext.hashmapM, szModuleName, _strlen(szModuleName), pModuleInfo))
        {
            LogMessage(L"hashmap_put failed\n");
        }
    }

    RtlFreeHeap(RtlProcessHeap(), 0, JSON_STRING);
    return TRUE;
}