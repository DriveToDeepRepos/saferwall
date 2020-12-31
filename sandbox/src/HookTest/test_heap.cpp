#include "header.h"
#include <intsafe.h>



BOOL
TestHeapHooks()
{
    DWORD NumberOfHeaps;
    DWORD HeapsIndex;
    DWORD HeapsLength;
    HANDLE hDefaultProcessHeap;
    HRESULT Result;
    PHANDLE aHeaps;
    SIZE_T BytesToAllocate;

    //
    // Retrieve the number of active heaps for the current process
    // so we can calculate the buffer size needed for the heap handles.
    //
    NumberOfHeaps = GetProcessHeaps(0, NULL);
    if (NumberOfHeaps == 0)
    {
        PrintError("GetProcessHeaps");
        return FALSE;
    }

    //
    // Calculate the buffer size.
    //
    Result = SIZETMult(NumberOfHeaps, sizeof(*aHeaps), &BytesToAllocate);
    if (Result != S_OK)
    {
        wprintf(L"SIZETMult failed with HR %d.\n", Result);
        return FALSE;
    }

    //
    // Get a handle to the default process heap.
    //
    hDefaultProcessHeap = GetProcessHeap();
    if (hDefaultProcessHeap == NULL)
    {
        PrintError("GetProcessHeaps");
        return FALSE;
    }

    //
    // Allocate the buffer from the default process heap.
    //
    aHeaps = (PHANDLE)HeapAlloc(hDefaultProcessHeap, 0, BytesToAllocate);
    if (aHeaps == NULL)
    {
        wprintf(L"HeapAlloc failed to allocate %Iu bytes.\n", BytesToAllocate);
        return 1;
    }

    //
    // Save the original number of heaps because we are going to compare it
    // to the return value of the next GetProcessHeaps call.
    //
    HeapsLength = NumberOfHeaps;

    //
    // Retrieve handles to the process heaps and print them to stdout.
    // Note that heap functions should be called only on the default heap of the process
    // or on private heaps that your component creates by calling HeapCreate.
    //
    NumberOfHeaps = GetProcessHeaps(HeapsLength, aHeaps);
    if (NumberOfHeaps == 0)
    {
        PrintError("GetProcessHeaps");
        return FALSE;
    }
    else if (NumberOfHeaps > HeapsLength)
    {
        //
        // Compare the latest number of heaps with the original number of heaps.
        // If the latest number is larger than the original number, another
        // component has created a new heap and the buffer is too small.
        //
        wprintf(L"Another component created a heap between calls. " L"Please try again.\n");
        return FALSE;
    }

    wprintf(L"Process has %d heaps.\n", HeapsLength);
    for (HeapsIndex = 0; HeapsIndex < HeapsLength; ++HeapsIndex)
    {
        wprintf(L"Heap %d at address: %#p.\n", HeapsIndex, aHeaps[HeapsIndex]);
    }

    //
    // Release memory allocated from default process heap.
    //
    if (HeapFree(hDefaultProcessHeap, 0, aHeaps) == FALSE)
    {
        wprintf(L"Failed to free allocation from default process heap.\n");
        return FALSE;
    }

    return TRUE;
}