#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdbool.h>
// #include <windows.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define STATUS_NO_MORE_FILES 0x80000006

// typedef struct _PEB_LDR_DATA {
//   BYTE       Reserved1[8];
//   PVOID      Reserved2[3];
//   LIST_ENTRY InMemoryOrderModuleList;
// } PEB_LDR_DATA, *PPEB_LDR_DATA;

// typedef struct _UNICODE_STRING {
//     USHORT Length;
//     USHORT MaximumLength;
//     PWSTR  Buffer;
// } UNICODE_STRING, *PUNICODE_STRING;

// typedef struct _RTL_USER_PROCESS_PARAMETERS {
//   BYTE           Reserved1[16];
//   PVOID          Reserved2[10];
//   UNICODE_STRING ImagePathName;
//   UNICODE_STRING CommandLine;
// } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// typedef VOID (NTAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);   

// typedef struct _PEB {
//   BYTE                          Reserved1[2];
//   BYTE                          BeingDebugged;
//   BYTE                          Reserved2[1];
//   PVOID                         Reserved3[2];
//   PPEB_LDR_DATA                 Ldr;
//   PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
//   PVOID                         Reserved4[3];
//   PVOID                         AtlThunkSListPtr;
//   PVOID                         Reserved5;
//   ULONG                         Reserved6;
//   PVOID                         Reserved7;
//   ULONG                         Reserved8;
//   ULONG                         AtlThunkSListPtr32;
//   PVOID                         Reserved9[45];
//   BYTE                          Reserved10[96];
//   PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
//   BYTE                          Reserved11[128];
//   PVOID                         Reserved12[1];
//   ULONG                         SessionId;
// } PEB, *PPEB;   

// Main function to check all sandbox evasion techniques
bool PerfomChecksEnv();

#endif // DETECTOR_H
