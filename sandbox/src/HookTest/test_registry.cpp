#include "APISerializer.h"

#define TOTALBYTES 8192
#define BYTEINCREMENT 4096

VOID
OpenRegistryKey(PWCHAR pSubKey)
{
    DWORD dwRet;
    HKEY hkResult;

    dwRet = RegOpenKey(HKEY_LOCAL_MACHINE, pSubKey, &hkResult);

    if (dwRet != ERROR_SUCCESS)
    {
		PrintError("RegOpenKey");
    }
}

HKEY
CreateRegistryKey(PWCHAR pSubKey)
{
    HKEY hkResult;
    DWORD dwRet, dwDisposition;

    dwRet = RegCreateKeyEx(
        HKEY_CURRENT_USER, pSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);

    if (dwRet != ERROR_SUCCESS)
    {
		PrintError("RegCreateKeyEx");
    }

    return hkResult;
}

VOID
WriteRegistryKey(HKEY hKey, PWCHAR pSubKey, PWCHAR pValueName, PWCHAR strData)
{
    DWORD dwRet;

    dwRet = RegSetValueEx(hKey, pValueName, 0, REG_SZ, (LPBYTE)(strData), ((((DWORD)lstrlen(strData) + 1)) * 2));
    if (ERROR_SUCCESS != dwRet)
    {
		PrintError("RegSetValueEx");
        RegCloseKey(hKey);
    }
}

VOID
ReadRegistryKey(HKEY hKey, PWCHAR pSubKey, PWCHAR pValueName)
{
    PVOID pData, pOldData;
    DWORD dwRet, pcbData = 0;
    DWORD BufferSize = TOTALBYTES;

    pData = malloc(BufferSize);
    if (pData) {
        dwRet = RegQueryValueEx(hKey, pValueName, NULL, NULL, (BYTE *)pData, &pcbData);
        while (dwRet == ERROR_MORE_DATA)
        {
            BufferSize += BYTEINCREMENT;
            pOldData = pData;
            pData = realloc(pOldData, BufferSize);
            if (pData)
            {
                pcbData = BufferSize;
                dwRet = RegQueryValueEx(hKey, pValueName, NULL, NULL, (BYTE *)pData, &pcbData);
			}

        }

        if (dwRet != ERROR_SUCCESS)
        {
            PrintError("RegQueryValueEx");
            RegCloseKey(hKey);
        }
	}
 
}

VOID
TestRegistryHooks()
{
    wprintf(L"\n ========= Testing registry opeations ========= \n\n");

	HKEY hKey;
    WCHAR pSubKey[MAX_PATH] = L"";
    WCHAR szValueName[MAX_PATH] = L"Thinking Binary";
    WCHAR szValueToWrite[MAX_PATH] = L"there are 10 types of people in this world, "
                                     "those who understand binary and those who dont.";
    WCHAR szAuoRunKey[MAX_PATH] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

	wprintf(L"[+] Calling RegOpenKey\n");
    OpenRegistryKey(szAuoRunKey);

    GetRandomString(pSubKey, 8);
    wcscat_s(pSubKey, MAX_PATH, L"_SFW_TEST");

    wprintf(L"[+] Calling RegCreateKeyExW\n");
    hKey = CreateRegistryKey(pSubKey);

    wprintf(L"[+] Calling RegSetValueExW\n");
    WriteRegistryKey(hKey, pSubKey, szValueName, szValueToWrite);

    wprintf(L"[+] Calling RegQueryValueExW\n");
    ReadRegistryKey(hKey, pSubKey, szValueName);

    wprintf(L"[+] Calling RegDeleteValueW\n");
    RegDeleteValue(hKey, szValueName);

    wprintf(L"[+] Calling RegDeleteKeyW\n");
    RegDeleteKeyW(HKEY_CURRENT_USER, pSubKey);

    RegCloseKey(hKey);
}