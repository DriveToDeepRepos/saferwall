#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include "util.h"

#pragma comment(lib, "Wininet.lib")

BOOL
TestWinInetHooks()
{
    wprintf(L"\n ========= Testing network opeations ========= \n\n");

	wprintf(L"[+] Calling InternetOpenW\n");
    HINTERNET hSession = InternetOpenW(
        L"Mozilla/5.0", // User-Agent
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0);
    if (hSession == NULL)
    {
        PrintError("InternetOpen");
        return FALSE;
    }

	wprintf(L"[+] Calling InternetConnectW\n");
    HINTERNET hConnect = InternetConnectW(
        hSession,
        L"www.google.com", // HOST
        0,
        L"",
        L"",
        INTERNET_SERVICE_HTTP,
        0,
        0);
    if (hConnect == NULL)
    {
        PrintError("InternetConnect");
        return FALSE;
    }

	wprintf(L"[+] Calling HttpOpenRequestW\n");
    HINTERNET hHttpFile = HttpOpenRequest(
        hConnect,
        L"GET", // METHOD
        L"/",   // URI
        NULL,
        NULL,
        NULL,
        0,
        0);
    if (hHttpFile == NULL)
    {
        PrintError("HttpOpenRequest");
        return FALSE;
    }

	wprintf(L"[+] Calling HttpSendRequestW\n");
    BOOL Success = HttpSendRequest(hHttpFile, NULL, 0, 0, 0);
    if (Success == FALSE)
    {
        PrintError("HttpSendRequest");
        return FALSE;
    }


	 // This loop handles reading the data.
    do
    {
        // The call to InternetQueryDataAvailable determines the
        // amount of data available to download.
        DWORD dwSize; // size of the data available

        if (!InternetQueryDataAvailable(hHttpFile, &dwSize, 0, 0))
        {
            PrintError("InternetQueryDataAvailable");
            return FALSE;
        }
        else
        {
            CHAR *szBuffer = new CHAR[dwSize + 1];
            DWORD dwRead = 0;
            BOOL Status = InternetReadFile(hHttpFile, szBuffer, dwSize, &dwRead); 
            if (!Status)
            {
                PrintError("InternetReadFile");
                return FALSE;
            }
            else
            {
                szBuffer[dwRead] = '\0';
                break;
			}
        }
    } while (TRUE);


    InternetCloseHandle(hHttpFile);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);

	return TRUE;
}