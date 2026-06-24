#ifndef DETECTOR_H
#define DETECTOR_H

#include "evasion.h"

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define STATUS_NO_MORE_FILES 0x80000006

// Main function to check all sandbox evasion techniques
bool PerfomChecksEnv(WINAPI_TABLE *);

#endif // DETECTOR_H
