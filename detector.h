#ifndef DETECTOR_H
#define DETECTOR_H

#include <windows.h>
#include <stdbool.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

// Main function to check all sandbox evasion techniques
bool PerfomChecksEnv();

#endif // DETECTOR_H
