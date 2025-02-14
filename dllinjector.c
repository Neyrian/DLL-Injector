#include <windows.h>
#include <psapi.h> 
#include <stdio.h>

// Function Prototypes
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG
);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, ULONG, PULONG
);

// Function to Get the Remote DLL Handle Properly
HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* dllName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName))) {
                const char* baseName = strrchr(modName, '\\') ? strrchr(modName, '\\') + 1 : modName;
                if (_stricmp(baseName, dllName) == 0) {
                    return hMods[i];  // Return the actual DLL handle
                }
            }
        }
    }
    return NULL;
}

// Function to Inject and Execute the DLL Function
void InjectAndExecute(HANDLE hProcess, HANDLE hThread, const char* dllPath) {
    LPVOID remoteBuffer = NULL;
    SIZE_T bufferSize = strlen(dllPath) + 1;
    HANDLE hRemoteThread;
    NTSTATUS status;

    // Resolve Required Functions
    FARPROC pLoadLibraryA = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    FARPROC pGetProcAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");

    if (!pLoadLibraryA || !pGetProcAddress) {
        printf("[!] Failed to resolve Kernel32 functions.\n");
        return;
    }
    printf("[*] Successfully resolved Kernel32 functions.\n");

    // Resolve NtAllocateVirtualMemory and NtWriteVirtualMemory from ntdll.dll
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (!hNtdll) {
        printf("[!] Failed to get handle to ntdll.dll.\n");
        return;
    }

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory) {
        printf("[!] Failed to resolve NT system calls.\n");
        return;
    }

    // Allocate Memory in Remote Process
    status = NtAllocateVirtualMemory(hProcess, &remoteBuffer, 0, &bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[!] NtAllocateVirtualMemory failed (Error: 0x%lX).\n", status);
        return;
    }
    printf("[*] Allocated memory at remote address: %p\n", remoteBuffer);

    // Write DLL Path to Remote Memory
    status = NtWriteVirtualMemory(hProcess, remoteBuffer, (PVOID)dllPath, (ULONG)bufferSize, NULL);
    if (status != 0) {
        printf("[!] NtWriteVirtualMemory failed (Error: 0x%lX).\n", status);
        return;
    }
    printf("[*] DLL path written successfully.\n");

    // Load DLL in Remote Process
    hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, remoteBuffer, 0, NULL);
    if (!hRemoteThread) {
        printf("[!] CreateRemoteThread failed for LoadLibraryA. Error: %lu\n", GetLastError());
        return;
    }
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
    printf("[*] Successfully loaded DLL into remote process.\n");

    // Verify if DLL is Loaded
    Sleep(500);  // Give time for LoadLibraryA to complete
    HMODULE hRemoteDLL = GetRemoteModuleHandle(hProcess, strrchr(dllPath, '\\') + 1);
    if (!hRemoteDLL) {
        printf("[!] DLL was not found in the remote process after LoadLibraryA.\n");
        return;
    }
    printf("[*] DLL is successfully loaded at: %p\n", hRemoteDLL);
    printf("[*] Successfully executed DLLMain in remote process.\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <DLL Path>\n", argv[0]);
        return -1;
    }

    const char* dllPath = argv[1];

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    const char* targetProcess = "C:\\Windows\\explorer.exe";

    if (!CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] Failed to create explorer.exe. Error: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] Successfully created a suspended explorer.exe process.\n");

    InjectAndExecute(pi.hProcess, pi.hThread, dllPath);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("[*] Explorer.exe process successfully started.\n");

    return 0;
}
