#ifndef DETECTOR_H
#define DETECTOR_H

#include <windows.h>
#include <stdbool.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <time.h>
#include <psapi.h>
#include <wincrypt.h>
#include <shlwapi.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

// Function to launch calc.exe (for testing sandbox evasion)
void LaunchCalc();

// Main function to check all sandbox evasion techniques
bool PerfomChecksEnv();


#endif // DETECTOR_H
