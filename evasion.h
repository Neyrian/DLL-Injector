#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>

DWORD GetSyid(LPCSTR functionName);

extern DWORD smID;

void SetSyid(DWORD value);

extern NTSTATUS CustAVM(HANDLE hProcess, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

extern NTSTATUS CustWVM(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

FARPROC ResolveFn(LPCSTR mod, LPCSTR fn);

char* base64Decode(const char* encoded);

#ifdef _M_X64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#endif // EVASION_H
