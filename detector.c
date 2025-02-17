#include "detector.h"

// Function to launch calc.exe (for evasion testing)
void LaunchCalc() {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    if (CreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, false, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// EDR Detection: Scan system driver directory for known EDR drivers
bool DetectEDRs() {
    const char* edrDrivers[] = {
        "atrsdfw.sys", "avgtpx86.sys", "avgtpx64.sys", "naswSP.sys", "edrsensor.sys",
        "CarbonBlackK.sys", "parity.sys", "cbk7.sys", "cbstream", "csacentr.sys",
        "csaenh.sys", "csareg.sys", "csascr.sys", "csaav.sys", "csaam.sys", 
        "SentinelMonitor.sys", "mfencfilter.sys", "PSINPROC.SYS", "PSINFILE.SYS",
        "klifks.sys", "klifaa.sys", "Klifsm.sys", "mbamwatchdog.sys"
    };

    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\drivers\\*.sys", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) return false;

    do {
        for (int i = 0; i < sizeof(edrDrivers) / sizeof(edrDrivers[0]); i++) {
            if (StrStrIA(findFileData.cFileName, edrDrivers[i])) {
                printf("[!] Detected EDR: %s\n", edrDrivers[i]);
                LaunchCalc();
                return true;
            }
        }
    } while (FindNextFileA(hFind, &findFileData));

    FindClose(hFind);
    return false;
}

// Sleep Patching Detection: Checks if Sleep(10000) completes normally
bool DetectSleepPatching() {
    LARGE_INTEGER startTime, endTime, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);

    Sleep(10000);  // Expected to take ~10,000 ms

    QueryPerformanceCounter(&endTime);
    double elapsedMs = ((double)(endTime.QuadPart - startTime.QuadPart) / frequency.QuadPart) * 1000.0;

    if (elapsedMs < 9000.0 || elapsedMs > 11000.0) {
        printf("[!] Sleep timing anomaly detected: %f ms\n", elapsedMs);
        LaunchCalc();
        return true;
    }
    return false;
}

// Sandbox Detection: Checks for common VM and sandbox files
bool DetectSandboxFiles() {
    const char* sandboxFiles[] = {
        "C:\\Windows\\System32\\drivers\\Vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vm3dgl.dll",
        "C:\\Windows\\System32\\drivers\\vmdum.dll",
        "C:\\Windows\\System32\\drivers\\vm3dver.dll",
        "C:\\Windows\\System32\\drivers\\vmtray.dll",
        "C:\\Windows\\System32\\drivers\\vmci.sys",
        "C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmx_svga.sys",
        "C:\\Windows\\System32\\drivers\\vmxnet.sys",
        "C:\\Windows\\System32\\VBoxGuest.sys",
        "C:\\Windows\\System32\\VBoxSF.sys",
        "C:\\Windows\\System32\\VBoxVideo.sys",
        "C:\\Windows\\System32\\VBoxService.exe",
        "C:\\Windows\\System32\\VBoxTray.exe",
        "C:\\Windows\\System32\\VBoxControl.exe"
    };

    for (int i = 0; i < sizeof(sandboxFiles) / sizeof(sandboxFiles[0]); i++) {
        if (PathFileExistsA(sandboxFiles[i])) {
            printf("[!] Sandbox file detected: %s\n", sandboxFiles[i]);
            LaunchCalc();
            return true;
        }
    }
    return false;
}

// Filename Hash Detection: Checks if file name matches hash (common in sandboxes)
bool DetectFilenameHash() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);

    DWORD bytesRead;
    ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE hash[16]; // MD5 hash size
    DWORD hashLen = sizeof(hash);

    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CryptHashData(hHash, buffer, fileSize, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    HeapFree(GetProcessHeap(), 0, buffer);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    char hashStr[33];
    for (int i = 0; i < 16; i++)
        sprintf(&hashStr[i * 2], "%02X", hash[i]);

    char* fileName = PathFindFileNameA(exePath);
    fileName[strlen(fileName) - 4] = '\0';  // Remove ".exe"

    if (_stricmp(fileName, hashStr) == 0) {
        printf("[!] File name matches MD5 hash (possible packed execution)\n");
        LaunchCalc();
        return true;
    }
    return false;
}

//Detect SandBox DLLs
bool DetectDLLs() {
    const char* realDLLs[] = {
        "kernel32.dll",
        "networkexplorer.dll",
        "NlsData0000.dll"
    };

    const char* sandboxDLLs[] = {
        "cmdvrt.32.dll",
        "cuckoomon.dll",
        "cmdvrt.64.dll",
        "pstorec.dll",
        "avghookx.dll",
        "avghooka.dll",
        "snxhk.dll",
        "api_log.dll",
        "dir_watch.dll",
        "wpespy.dll"
    };
    
    for (int i = 0; i < sizeof(realDLLs) / sizeof(realDLLs[0]); i++) {
        HMODULE lib_inst = LoadLibraryA(realDLLs[i]);
        if (lib_inst == NULL) {
            LaunchCalc();
            return true;
        }
        FreeLibrary(lib_inst);
    }

    for (int i = 0; i < sizeof(sandboxDLLs) / sizeof(sandboxDLLs[0]); i++) {
        HMODULE lib_inst = GetModuleHandleA(sandboxDLLs[i]);
        if (lib_inst != NULL) {
            LaunchCalc();
            return true;
        }
    }

    return false;
}

bool IsDebuggerPresentPEB() {
    // Get Process Environment Block (PEB)
    #ifdef _WIN64
        PEB* peb = (PEB*)__readgsqword(0x60);
        // NtGlobalFlag is at offset 0xBC in 64-bit PEB
        DWORD NtGlobalFlag = *(DWORD*)((BYTE*)peb + 0xBC); 
    #else // _WIN32
        PEB* peb = (PEB*)__readfsdword(0x30);
        // NtGlobalFlag is at offset 0x68 in 32-bit PEB
        DWORD NtGlobalFlag = *(DWORD*)((BYTE*)peb + 0x68); 
    #endif

    // Check NtGlobalFlag
    return NtGlobalFlag & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);
}

bool IsDebuggerPresentHeap() {
    // Get Process Environment Block (PEB)
    #ifdef _WIN64
        PEB* peb = (PEB*)__readgsqword(0x60);
        PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)peb + 0x30));
        DWORD dwHeapFlagsOffset = 0x70; // 0x14 if Windows version inferior to Vista but who use old computers ? ;)
        DWORD dwHeapForceFlagsOffset = 0x74; // 0x18 if Windows version inferior to Vista but who use old computers ? ;)
    #else // _WIN32
        PEB* peb = (PEB*)__readfsdword(0x30);
        // Assuming no WOW64 processes for simplicity
        PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)peb + 0x18)); 
        DWORD dwHeapFlagsOffset = 0x40; // 0x0C if Windows version inferior to Vista but who use old computers ? ;)
        DWORD dwHeapForceFlagsOffset = 0x44; // 0x10 if Windows version inferior to Vista but who use old computers ? ;)
    #endif // _WIN64

    DWORD dwHeapFlags = *(DWORD*)((PBYTE)pHeapBase + dwHeapFlagsOffset);
    DWORD dwHeapForceFlags = *(DWORD*)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);

    // Check heap flags
    return (dwHeapFlags & ~HEAP_GROWABLE) || (dwHeapForceFlags!= 0);
}

// Main Sandbox Detection Function
bool PerfomChecksEnv() {
    bool detected = false;

    printf("[*] Checking for EDRs...\n");
    detected |= DetectEDRs();

    printf("[*] Checking for sleep patching...\n");
    detected |= DetectSleepPatching();

    printf("[*] Checking for sandbox files...\n");
    detected |= DetectSandboxFiles();

    printf("[*] Checking for filename hash matching...\n");
    detected |= DetectFilenameHash();

    printf("[*] Checking for dll...\n");
    detected |= DetectDLLs();

    printf("[*] Checking for NtGlobalFlag...\n");
    detected |= IsDebuggerPresentPEB();

    printf("[*] Checking for Heap Flags...\n");
    detected |= IsDebuggerPresentHeap();

    if (detected) {
        printf("[!] Env unsafe, terminating execution.\n");
    } else {
        printf("[*] No sandbox detected.\n");
    }

    return detected;
}
