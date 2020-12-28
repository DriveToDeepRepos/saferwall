#include "stdafx.h"

LPCWSTR
FindFileName(LPCWSTR pPath)
{
    LPCWSTR pT = NULL;
    if (!pPath)
    {
        return NULL;
    }

    for (pT = pPath; *pPath; pPath++)
    {
        if ((pPath[0] == '\\' || pPath[0] == ':' || pPath[0] == '/') && pPath[1] && pPath[1] != '\\' && pPath[1] != '/')
            pT = pPath + 1;
    }

    return pT;
}

// This macro assures that INVALID_HANDLE_VALUE (0xFFFFFFFF) returns FALSE
#define IsConsoleHandle(h) (((((ULONG_PTR)h) & 0x10000003) == 0x3) ? TRUE : FALSE)

DWORD
GetNtPathFromHandle(HANDLE Handle, PUNICODE_STRING *ObjectName)
{
    ULONG ObjectInformationLength;
    PVOID ObjectNameInfo = NULL;

    if (Handle == 0 || Handle == INVALID_HANDLE_VALUE)
        return ERROR_INVALID_HANDLE;

    //
    // Get the size of the information needed.
    //
    if (!NT_SUCCESS(
            NtQueryObject(Handle, ObjectNameInformation, ObjectNameInfo, sizeof(ULONG), &ObjectInformationLength)))
    {
        //
        // Reallocate the buffer and try again.
        //
        ObjectNameInfo = RtlAllocateHeap(RtlProcessHeap(), 0, ObjectInformationLength);
        if (!NT_SUCCESS(NtQueryObject(Handle, ObjectNameInformation, ObjectNameInfo, ObjectInformationLength, NULL)))
        {
            RtlFreeHeap(ObjectNameInfo, 0, NULL);
            return 0;
        }
    }

    *ObjectName = (PUNICODE_STRING)ObjectNameInfo;
    return 0;
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

BOOL
SfwUtilGetFileSize(HANDLE hFile, PDWORD_PTR lpFileSize)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    FILE_STANDARD_INFORMATION StandardInfo;

    Status = NtQueryInformationFile(hFile, &IoStatus, &StandardInfo, sizeof(StandardInfo), FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    *lpFileSize = StandardInfo.EndOfFile.LowPart;
    return TRUE;
}

PVOID
SfwUtilReadFile(CONST WCHAR *wszFileName, DWORD *lpNumberOfBytesRead)
{
    NTSTATUS Status;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjectAttributes;

    //
    // Convert DOS path name to NT path name.
    //

    BOOLEAN bOK;
    UNICODE_STRING DosFileName, NtFileName;
    RtlInitUnicodeString(&DosFileName, wszFileName);
    bOK = RtlDosPathNameToNtPathName_U(DosFileName.Buffer, &NtFileName, NULL, NULL);
    if (!bOK)
    {
        return NULL;
    }

    //
    // Init Object.
    //

    InitializeObjectAttributes(&ObjectAttributes, &NtFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    Status = NtCreateFile(
        &FileHandle,
        FILE_GENERIC_READ,
        &ObjectAttributes,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
        NULL,
        0);
    if (!NT_SUCCESS(Status))
    {
        LogMessage(L"NtCreateFile failed 0x%X\n", RtlGetLastWin32Error());
        return NULL;
    }

    //
    // Get File Size.
    //
    DWORD_PTR Length = 0;
    SfwUtilGetFileSize(FileHandle, &Length);

    //
    // Read the file.
    //
    LPVOID lpBuffer = NULL;
    Status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &lpBuffer, 0, &Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        return NULL;
    }

    Status = NtReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, lpBuffer, Length, NULL, NULL);
    if (Status == STATUS_PENDING)
    {
        Status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
        if (NT_SUCCESS(Status))
        {
            Status = IoStatus.Status;
        }
    }
    else if (Status == STATUS_END_OF_FILE)
    {
        *lpNumberOfBytesRead = 0;
    }

    if (NT_SUCCESS(Status))
    {
		*lpNumberOfBytesRead = (DWORD)IoStatus.Information;
    }

	NtClose(FileHandle);
    return lpBuffer;
}