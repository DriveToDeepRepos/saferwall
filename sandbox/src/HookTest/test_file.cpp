#include "APISerializer.h"

VOID
TestFileHooks()
{
    WCHAR szFilePath[MAX_PATH] = L"";
    WCHAR szDestFilePath[MAX_PATH] = L"";
    HANDLE hFile;
    BOOL bResult;
    WCHAR Buffer[] = L"Life is short.";
    DWORD dwNumberOfBytesWritten = NULL;

    wprintf(L"\n ========= Testing file opeations ========= \n\n");

    wprintf(L"[+] Calling CreateDirectoryW\n");
    GetRandomDir(szFilePath);
    CreateDirectory(szFilePath, NULL);

    wprintf(L"[+] Calling CreateDirectoryExW\n");
    GetRandomDir(szFilePath);
    bResult = CreateDirectoryEx(L"C:\\ProgramData", szFilePath, NULL);
    if (!bResult)
    {
        PrintError("CreateDirectoryExW");
    }

	wprintf(L"[+] Calling CreateFileW\n");
    GetRandomFilePath(szFilePath);
    hFile = CreateFile(szFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
		PrintError("CreateFileW");
    }

    wprintf(L"[+] Calling WriteFile\n");
    bResult = WriteFile(hFile, Buffer, DWORD(wcslen(Buffer) * sizeof(WCHAR)), &dwNumberOfBytesWritten, NULL);
    if (!bResult)
    {
		PrintError("WriteFileW");
    }

    wprintf(L"[+] Calling CloseHandle\n");
    CloseHandle(hFile);

    wprintf(L"[+] Calling MoveFileW\n");
    GetRandomFilePath(szDestFilePath);
    bResult = MoveFile(szFilePath, szDestFilePath);
    if (!bResult)
    {
		PrintError("MoveFile");
    }

    wprintf(L"[+] Calling DeleteFile\n");
    bResult = DeleteFile(szDestFilePath);
    if (!bResult)
    {
		PrintError("DeleteFile");
    }
}