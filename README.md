# 🚀 Advanced DLL Injector with EDR/AV/Sandbox Evasion

## 🔥 Overview
This project implements a **stealthy DLL injector** for **Windows 10 and 11** with advanced evasion techniques. It includes mechanisms to **bypass EDR, AV, and sandbox detections** while using direct syscalls, manual API resolution, PEB walk, and obfuscation to reduce detection rates. The injector creates a suspended process, injects a DLL, and executes its entry point in a stealthy manner.

- 0/69 on [VirusTotal](https://www.virustotal.com/gui/file/21a1b9a16ac78b0b898dac1866b4871b0bd26d6287a731b913711db3c78e555e)
- Not detected on [Hybrid Analysis Sandbox](https://hybrid-analysis.com/sample/21a1b9a16ac78b0b898dac1866b4871b0bd26d6287a731b913711db3c78e555e)

---

## 📌 **Features**

✅ **Stealthy Injection:** Creates a suspended process and injects a DLL without using common Windows API calls.

✅ **EDR/AV/Sandbox Evasion:** Implements multiple checks to detect sandbox environments, VM detection, and EDR hooks.

✅ **Direct Syscalls:** Bypass API hooks in `ntdll.dll`. (hardcoded SSN. Improvement: use Hell's Gate & SysWhispers)

✅ **Avoid calling function from module:** Uses `PEB walk` to retrieve functions in modules without loading them.

✅ **Obfuscation:** NEW: Rather than plain string Base64 encoding, suspicious artifacts are obfuscated after the binary is build. Thanks to [4g3nt47's Obfuscator](https://github.com/4g3nt47/Obfuscator.git).

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
Use **makefile** or compile it your ways (don't forget to use the obfuscator 😊 )

The makefile will:
```
1 - Compile the dependencies
2 - Compile the obfuscator
3 - Compile the dllinjector into injector.exe
4 - Modify the PE section
5 - Run the obfuscator, this will generate obfsinjector.exe
6 - Fix the checksum cause we messed with the PE :)
```

### **2️⃣ Running the Injector**
```powershell
obfsinjector.exe C:\path\to\dll
```
> **Note**: 
> - Use the obfsinjector executable. Otherwise, the build binary (injector.exe) won't work since the strings won't be obfuscated.
> - Replace `C:\path\to\dll` with the actual path of your DLL (you can use the dll in this repo for testing)
> - It's recommanded to disable debugging (set to ```false``` the ```DEBUG``` variable in ```evasion.h```. If you do, the program may appear unresponsive. It's due to various waiting time. Just wait 15 sec 😊 )
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
│── dllinjector.c         # Main DLL injector
│── detector.c            # EDR/AV/Sandbox detection
│── evasion.c             # Evasion functions (syscalls, b64decode...) and decoy
|── malDLL.c              # Source DLL that can be used for testing
│── binary_obfuscator.c   # Contains the obfuscator's functions
│── obfuscator.c          # Main program used to obfuscate the build binary
│── detector.h            # Header file for detection functions
│── evasion.h             # Header file for evasion functions and decoy
│── binary_obfuscator.h   # Contains the obfuscator's definition
│── syscalls.asm          # Direct Syscalls Functions
|── makefile              # easy to compile
│── README.md             # This documentation
```
---
## Modules Breakdown
### **Main DLL Injector: dllinjector.c**
- Creates a **suspended** process (`SearchProtocolHost.exe` or `explorer.exe`).
- Uses **direct syscalls** to allocate memory and write the DLL path.
- Executes the entry point of the injected DLL stealthily.

### **EDR/AV/Sandbox Detection: detector.c & detector.h**
- Detects **common AV/EDR drivers** in `C:\Windows\System32\drivers`.
- Checks for **sandbox-specific DLLs** like `cuckoomon.dll`, `VBox*.dll`, etc.
- Uses `NtQuerySystemInformation` to determine if the environment is a VM.
- Implements **cursor movement & sleep patching** to evade automated sandboxes.

### **Evasion Functions & Decoy Execution: evasion.c & evasion.h**
- Implements **Base64 encoding & decoding** to hide DLL and function names.
- **Legitimate Decoy Execution**: The injector executes a CPU-intensive function to simulate legitimate software behavior.
- Use PEB walk to retrieve function in modules without API.

### **Direct Syscalls: syscalls.asm**
- Implements **NtAllocateVirtualMemory, NtWriteVirtualMemory** using direct syscalls.

### **Obfuscator**
- Not my work, please ref to [Obfuscator](https://github.com/4g3nt47/Obfuscator.git).

> TL;DR: The Obfuscator is compiled and the built binary is passed to the obfuscator. Then each string in the binary that start with a unique string ([OBFS_ENC]) is then encoded one byte at a time by XORing it with a key that is continously adjusted.
---

## **Test**

- [x] Windows 10 (22H2)
- [x] Windows 11 (11 24H2)
- [x] Windows Server 2025 (24H2)

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
- 🔗 **Binary Obfuscation**: [Obfuscator](https://github.com/4g3nt47/Obfuscator.git)
---

🚀 **Happy Hacking!**

