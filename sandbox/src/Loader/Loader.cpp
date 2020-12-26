// Loader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"


//
// GUID:
//   {a4b4ba50-a667-43f5-919b-1e52a6d69bd5}
//

GUID ProviderGuid = {
  0xa4b4ba50, 0xa667, 0x43f5, { 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5 }
};

//
// GUID:
//   {53d82d11-cede-4dff-8eb4-f06631800128}
//

GUID SessionGuid = {
  0x53d82d11, 0xcede, 0x4dff, { 0x8e, 0xb4, 0xf0, 0x66, 0x31, 0x80, 0x1, 0x28 }
};

TCHAR SessionName[] = TEXT("InjSession");

VOID
WINAPI
TraceEventCallback(
	_In_ PEVENT_RECORD EventRecord
)
{
	if (!EventRecord->UserData)
	{
		return;
	}

	//
	// TODO: Check that EventRecord contains only WCHAR string.
	//

	wprintf(L"[PID:%04X][TID:%04X] %s\n",
		EventRecord->EventHeader.ProcessId,
		EventRecord->EventHeader.ThreadId,
		(PWCHAR)EventRecord->UserData);
}

ULONG
NTAPI
TraceStart(
	VOID
)
{
	//
	// Start new trace session.
	// For an awesome blogpost on ETW API, see:
	// https://caseymuratori.com/blog_0025
	//

	ULONG ErrorCode = 0;
	TRACEHANDLE TraceHandle = 0;
	TRACEHANDLE TraceSessionHandle = INVALID_PROCESSTRACE_HANDLE;
	EVENT_TRACE_LOGFILE TraceLogfile = { 0 };

	BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
	RtlZeroMemory(Buffer, sizeof(Buffer));

	PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
	EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
	EventTraceProperties->Wnode.ClientContext = 1; // Use QueryPerformanceCounter, see MSDN
	EventTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	EventTraceProperties->LogFileMode = PROCESS_TRACE_MODE_REAL_TIME;
	EventTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	ErrorCode = StartTrace(&TraceSessionHandle, SessionName, EventTraceProperties);
	if (ErrorCode != ERROR_SUCCESS)
	{
		goto Exit;
	}

	//
	// Enable tracing of our provider.
	//

	ErrorCode = EnableTrace(TRUE, 0, 0, &ProviderGuid, TraceSessionHandle);
	if (ErrorCode != ERROR_SUCCESS)
	{
		goto Exit;
	}

	TraceLogfile.LoggerName = SessionName;
	TraceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	TraceLogfile.EventRecordCallback = &TraceEventCallback;

	//
	// Open real-time tracing session.
	//

	TraceHandle = OpenTrace(&TraceLogfile);
	if (TraceHandle == INVALID_PROCESSTRACE_HANDLE)
	{
		//
		// Synthetic error code.
		//
		ErrorCode = ERROR_FUNCTION_FAILED;
		goto Exit;
	}

	//
	// Process trace events. This call is blocking.
	//

	ErrorCode = ProcessTrace(&TraceHandle, 1, NULL, NULL);

Exit:
	if (TraceHandle)
	{
		CloseTrace(TraceHandle);
	}

	if (TraceSessionHandle)
	{
		CloseTrace(TraceSessionHandle);
	}

	RtlZeroMemory(Buffer, sizeof(Buffer));
	EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
	StopTrace(0, SessionName, EventTraceProperties);

	if (ErrorCode != ERROR_SUCCESS)
	{
		printf("Error: %08x\n", ErrorCode);
	}

	return ErrorCode;
}

VOID
NTAPI
TraceStop(
	VOID
)
{
	BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
	RtlZeroMemory(Buffer, sizeof(Buffer));

	PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
	EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);

	StopTrace(0, SessionName, EventTraceProperties);
}

//////////////////////////////////////////////////////////////////////////


BOOL
WINAPI
CtrlCHandlerRoutine(
	_In_ DWORD dwCtrlType
)
{
	if (dwCtrlType == CTRL_C_EVENT)
	{
		//
		// Ctrl+C was pressed, stop the trace session.
		//
		printf("Ctrl+C pressed, stopping trace session...\n");

		TraceStop();
	}

	return FALSE;
}

int main(int argc, char* argv[])
{
	//
	// Setup handling of CTRL+C signals.
	//
	SetConsoleCtrlHandler(&CtrlCHandlerRoutine, TRUE);

	//
	// Stop any previous trace session (if exists).
	//

	TraceStop();

	//
	// Parse command-line parameters.
	//

	printf("Starting tracing session...\n");

	ULONG ErrorCode = TraceStart();

	return ErrorCode == ERROR_SUCCESS
		? EXIT_SUCCESS
		: EXIT_FAILURE;
}
