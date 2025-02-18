#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <winternl.h>

// #ifndef _PEB_DEFINED
// typedef struct _PEB {
//     BOOLEAN InheritedAddressSpace;
//     BOOLEAN ReadImageFileExecOptions;
//     BOOLEAN BeingDebugged;
//     BOOLEAN SpareBool;
//     HANDLE Mutant;
//     PVOID ImageBaseAddress;
//     PPEB_LDR_DATA Ldr;
// } PEB, *PPEB;
// #define _PEB_DEFINED
// #endif

typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

DWORD GetSyscallNumber(LPCSTR functionName);

extern NTSTATUS myNtAllocateVirtualMemory(
    HANDLE hProcess,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern NTSTATUS myNtWriteVirtualMemory(
    HANDLE hProcess,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

extern NTSTATUS myNtProtectVirtualMemory(
    HANDLE hProcess,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

extern DWORD wSystemCall;

void SetSystemCall(DWORD value);

#ifdef _M_X64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

bool IsNtDllHooked();

void UnhookNtdll();

// // Function prototypes for Hell's Gate
// NTSTATUS HellGate_NtAllocateVirtualMemory(
//     HANDLE hProcess,
//     PVOID *BaseAddress,
//     ULONG ZeroBits,
//     PSIZE_T RegionSize,
//     ULONG AllocationType,
//     ULONG Protect
// );

#endif // EVASION_H
