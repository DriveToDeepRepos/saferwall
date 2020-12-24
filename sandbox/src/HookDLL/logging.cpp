#include "stdafx.h"

//
// Globals
//

extern __vsnwprintf_fn_t _vsnwprintf;
extern REGHANDLE ProviderHandle;
extern pfn_wcscat _wcscat;



VOID TraceAPI(PCWSTR Format, ...) {

	WCHAR Buffer[256];

	va_list arglist;
	va_start(arglist, Format);
	_vsnwprintf(Buffer, RTL_NUMBER_OF(Buffer), Format, arglist);
    va_end(arglist);

	_wcscat(Buffer, L"\n");
	EtwEventWriteString(ProviderHandle, 0, 0, Buffer);
}


VOID LogMessage(PCWSTR Format, ...) {
	WCHAR Buffer[256];

	va_list arglist;
	va_start(arglist, Format);
	_vsnwprintf(Buffer, RTL_NUMBER_OF(Buffer), Format, arglist);
    va_end(arglist);

	EtwEventWriteString(ProviderHandle, 0, 0, Buffer);
}