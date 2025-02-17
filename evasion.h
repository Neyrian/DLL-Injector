#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

// Define the system call numbers and function addresses as external variables

bool IsNtDllHooked();

void UnhookNtdll();


#endif // EVASION_H
