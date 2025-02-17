#ifndef DETECTOR_H
#define DETECTOR_H

#include <windows.h>
#include <stdbool.h>

// Function to launch calc.exe (for testing sandbox evasion)
void LaunchCalc();

// EDR Detection
bool DetectEDRs();

// Sleep Patching Detection
bool DetectSleepPatching();

// Sandbox File Detection
bool DetectSandboxFiles();

// Packed Execution Detection (Filename Hash)
bool DetectFilenameHash();

//Detect SandBox DLLs
bool DetectDLLs();

// Main function to check all sandbox evasion techniques
bool CheckSandbox();


#endif // DETECTOR_H
