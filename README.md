# 🚀 Advanced DLL Injector with EDR/AV/Sandbox Evasion

## 🔥 Overview
This project implements a **stealthy DLL injector** for **Windows 10 and 11** with advanced evasion techniques. It includes mechanisms to **bypass EDR, AV, and sandbox detections** while using direct syscalls and obfuscation to reduce detection rates. The injector creates a suspended process, injects a DLL, and executes its entry point in a stealthy manner.

---

## 📌 **Features**

✅ **Stealthy Injection:** Creates a suspended process and injects a DLL without using common Windows API calls.

✅ **EDR/AV/Sandbox Evasion:** Implements multiple checks to detect sandbox environments, VM detection, and EDR hooks.

✅ **Direct Syscalls:** Bypass API hooks in `ntdll.dll`. (hardcoded SSN need to uses Hell's Gate & SysWhispers)

✅ **Avoid calling GetModuleHandle:** Uses `PEB walk` to retrieve functions in modules.

✅ **Obfuscation:** Base64 encoding and decoding of DLL names, function names, and suspicious artifacts.

✅ **Cryptography:** Implements its own cryptography functions, avoiding the usage of wincrypt

✅ **Decoy Execution:** The injector executes a decoy function to mimic legitimate software behavior.

---

## 🚀 **Usage**
### **1️⃣ Compilation**
```info
Requirements:
  - gcc-mingw-w64-x86-64-win32
  - nasm
  - make
```
Use **makefile** or manual compilation below

```bash
nasm -f win64 syscalls.asm -o syscalls.o
x86_64-w64-mingw32-gcc -o injector.exe dllinjector.c detector.h detector.c evasion.c evasion.h syscalls.o -Wno-array-bounds -Wall -lshlwapi -Wl,--section-alignment,4096 -Wl,--gc-sections -Wl,--strip-debug -Wl,--image-base,0x140000000 -O2
x86_64-w64-mingw32-objcopy --rename-section .CRT=.data injector.exe
x86_64-w64-mingw32-strip --strip-debug --strip-unneeded injector.exe
x86_64-w64-mingw32-gcc -shared -o malDLL.dll malDLL.c -Wl,--subsystem,windows -mwindows
```

### **2️⃣ Running the Injector**
```powershell
injector.exe C:\path\to\dll
```
> **Note**: Replace `C:\path\to\dll` with the actual path of your DLL (you can use the dll in this repo for testing)
---

## 🐍 **EDR, AV, and Sandbox Evasion**
### ✅ **EDR Detection (`detector.c`)**
- Scans `C:\Windows\System32\drivers\` for known **EDR & AV drivers** (Carbon Black, CrowdStrike, SentinelOne, etc.).
- If found, decoy is executed instead of the injection.

### ✅ **Anti-Sandbox Techniques**
- **Detects Virtual Machine Artifacts**:
  - Checks for **VMware**, **VirtualBox**, and **Hyper-V files**.
- **Detects Sleep Patching**:
  - Measures the **execution time** of `Sleep(10000)`.
  - If altered, execution is stopped.
- **Detects Filename Hash Matching**:
  - Checks if the **binary filename matches its MD5 hash** (common in packed malware).
- **Detects Sandbox DLLs**:
  - Checks for the presence of sandbox's DLLs.
### ✅ **Anti-Debugger Techniques**
- **Detect if NtGlobalFlag is present in PEB.**
- **Detect debugger flags in HEAP**

---

## 📝 **Project Structure**
```
📂 Project Folder
│── detector.c       # EDR/AV/Sandbox detection
│── detector.h       # Header file for detection functions
│── dllinjector.c    # Main DLL injector
│── evasion.c        # Evasion functions (syscalls, b64decode...) and decoy
│── evasion.h        # Header file for evasion functions and decoy
|── makefile         # easy to compile
|── malDLL.c         # Source DLL that can be used for testing
│── README.md        # This documentation
│── syscalls.asm     # Direct Syscalls Functions
```
---
## Modules Breakdown
### **1️⃣ dllinjector.c - Main DLL Injector**
- Creates a **suspended** process (`SearchProtocolHost.exe` or `explorer.exe`).
- Uses **direct syscalls** to allocate memory and write the DLL path.
- Executes the entry point of the injected DLL stealthily.

### **2️⃣ detector.c & detector.h - EDR/AV/Sandbox Detection**
- Detects **common AV/EDR drivers** in `C:\Windows\System32\drivers`.
- Checks for **sandbox-specific DLLs** like `cuckoomon.dll`, `VBox*.dll`, etc.
- Uses `NtQuerySystemInformation` to determine if the environment is a VM.
- Implements **cursor movement & sleep patching** to evade automated sandboxes.

### **3️⃣ evasion.c & evasion.h - Evasion Functions & Decoy Execution**
- Implements **Base64 encoding & decoding** to hide DLL and function names.
- **Legitimate Decoy Execution**: The injector executes a CPU-intensive function to simulate legitimate software behavior.
- Use PEB walk to retrieve function in modules without API.

### **4️⃣ syscalls.asm - Direct Syscalls for Hell’s Gate & SysWhispers**
- Implements **NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory** using direct syscalls.

---

## **Test**

- [x] Windows 10 (22H2)
- [x] Windows 11 (11 24H2)

---

## ⚠️ **Legal Disclaimer**
> **This tool is for educational and research purposes only.**  
> Do not use it for malicious activities. The author is not responsible for any misuse.

---

## 📬 **Contributing**
Feel free to **submit issues or pull requests** to improve the project.  

---

## 📜 **References**
- 🔗 **MITRE ATT&CK Framework**: [T1202 - Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)  
- 🔗 **AV & EDR Detection**: [Exe_Who GitHub](https://github.com/Nariod/exe_who)

---

🚀 **Happy Hacking!**

