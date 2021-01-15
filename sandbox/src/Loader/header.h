/*++
Copyright (c) Saferwall.  All rights reserved.

Module Name:

    header.h

Environment:

    User mode only

--*/

#pragma once

//
// Utility macro
//

#define ARRAY_LENGTH(array) (sizeof(array) / sizeof(array[0]))

//
// Logging macros
//

#define InfoPrint(str, ...) printf(##str "\n", __VA_ARGS__)

#define ErrorPrint(str, ...) printf("ERROR: %u: "##str "\n", __LINE__, __VA_ARGS__)

//
// Driver and device names.
//

#define DRIVER_NAME L"SaferWall"
#define DRIVER_NAME_WITH_EXT L"SaferWall.sys"

#define NT_DEVICE_NAME L"\\Device\\SaferWall"
#define DOS_DEVICES_LINK_NAME L"\\DosDevices\\SaferWall"
#define WIN32_DEVICE_NAME L"\\\\.\\SaferWall"

//
// Global variables
//

//
// Handle to the driver
//
extern HANDLE g_Driver;

//
// Utility routines to manage a Windows service.
//

BOOL
UtilCreateService(_In_ SC_HANDLE hSCM, _In_ LPWSTR szDriverName, _In_ LPWSTR szDriverPath);

BOOL
UtilStartService(_In_ SC_HANDLE hSCM, _In_ LPWSTR szDriverName);

BOOL
UtilStopService(_In_ SC_HANDLE hSCM, _In_ LPWSTR szDriverName);

BOOL
UtilDeleteService(_In_ SC_HANDLE hSCM, _In_ LPWSTR szDriverName);

BOOL
UtilOpenDevice(_In_ LPWSTR szWin32DeviceName, _Out_ HANDLE *phDevice);

BOOL
UtilGetServiceState(_In_ SC_HANDLE hService, _Out_ DWORD *State);

BOOL
UtilWaitForServiceState(_In_ SC_HANDLE hService, _In_ DWORD State);

//
// Utility routines to load and unload the driver
//

BOOL
UtilLoadDriver(
    _In_ LPWSTR szDriverNameNoExt,
    _In_ LPWSTR szDriverNameWithExt,
    _In_ LPWSTR szWin32DeviceName,
    _Out_ HANDLE *pDriver);

BOOL
UtilUnloadDriver(_In_ HANDLE hDriver, _In_opt_ SC_HANDLE hSCM, _In_ LPWSTR szDriverNameNoExt);
