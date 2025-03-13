#ifndef DETECTOR_H
#define DETECTOR_H

#include <windows.h>
#include <stdbool.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

// Function definition for modules.
typedef HANDLE(WINAPI *pCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD(WINAPI *pGetFileSize_t)(HANDLE, LPDWORD);
typedef BOOL(WINAPI *pReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *pCloseHandle_t)(HANDLE);

// Main function to check all sandbox evasion techniques
bool PerfomChecksEnv();

#endif // DETECTOR_H
