# 🚀 Advanced Payload Injector with EDR/AV/Sandbox Evasion

## 🔥 Overview
This project implements a **stealthy Payload injector** for **Windows 10 and 11** with advanced evasion techniques. It includes mechanisms to **bypass EDR, AV, and sandbox detections** while using direct syscalls, manual API resolution, PEB walk, and obfuscation to reduce detection rates. The injector creates a suspended process, injects an embedded payload (built with msfvenom), and executes it in a stealthy manner. 

> NEW: Rather than loading and executing a DLL already present on disk, the loader now has its own obfuscated payload 👌

> The old dll injector is always disponible on the [dllInjector](https://github.com/Neyrian/DLL-Injector/tree/dllInjector) branch. Tho it's not optimized and has a lot of flaws ^^

I am still working on the stealh:
- Using a simple msfvenom's msgbox payload:
  - 5/69 on [VirusTotal](https://www.virustotal.com/gui/file/53cb4bf5ab8d90710bfd0e7416a17f15c31e862ab8aeb6c3bf50b13f462a75ea?nocache=1)
  - Suspicious on [Hybrid Analysis Sandbox](https://hybrid-analysis.com/sample/53cb4bf5ab8d90710bfd0e7416a17f15c31e862ab8aeb6c3bf50b13f462a75ea)
- Using a simple msfvenom's windows/x64/meterpreter/reverse_tcp payload
  - 4/70 on [VirusTotal](https://www.virustotal.com/gui/file/9f2b5b0ff6aef85fd01223d850a16a588befb045f6ad9e732a85f81770286fd6?nocache=1)
  - no specific threat on [Hybrid Analysis Sandbox](https://hybrid-analysis.com/sample/9f2b5b0ff6aef85fd01223d850a16a588befb045f6ad9e732a85f81770286fd6)

---

## 📌 **Features**

✅ **Stealthy Injection:** Creates a suspended process and injects a payload without using common Windows API calls.

✅ **Embeded payload:** Upon compilation, the payload is dynamically embedded into the binary.

✅ **EDR/AV/Sandbox Evasion:** Implements multiple checks to detect sandbox environments, VM detection, and EDR hooks.

✅ **Direct Syscalls:** Bypass API hooks. (hardcoded SSN. Improvement: use Hell's Gate & SysWhispers)

✅ **Avoid calling function from module:** Uses `PEB walk` to retrieve functions in modules without loading them.

✅ **NEW Obfuscation:** Rather than plain string Base64 encoding, suspicious artifacts are obfuscated after the binary is build. Thanks to [4g3nt47's Obfuscator](https://github.com/4g3nt47/Obfuscator.git).

✅ **NEW Removing dtoa Dependencies (CRT-Free Formatting)** maintain a purely native, dependency-free binary by avoiding the standard C formatting engine: No Floating-Point Math, Native Windows APIs Only.

✅ **NEW Automated OpSec & Heuristics Testing:** includes a custom (AI generated)static-analysis engine (opsec_analyzer.py) designed to evaluate compiled payloads against common Endpoint Detection and Response (EDR) and Antivirus (AV) heuristics. *Just for fun*

✅ **Decoy Execution:** The injector executes a decoy function to mimic legitimate software behavior.

---

## 🚀 **Usage**
### **1️⃣ Compilation**
```info
Requirements:
  - gcc-mingw-w64-x86-64-win32
  - nasm
  - gcc
  - make
  - python3
  - (optional) radare2
```
Use **makefile** or compile it your ways (don't forget to use the obfuscator 😊 )

The makefile will:
```
1 - Compile the dependencies
2 - Compile the obfuscator
3 - Build the payload (you can modify it directly from the makefile)
4 - Run the payloadObfuscator on the generated payload.h
5 - Compile the payloadinjector.c into injector.exe
6 - Modify the PE section
7 - Run the obfuscator, this will generate obfsinjector.exe
8 - Fix the checksum cause we messed with the PE :)
9 - (Optional) run a check script for fun
```

### **2️⃣ Running the Injector**
```powershell
obfsinjector.exe
```
> **Note**: 
> - Use the obfsinjector executable. Otherwise, the build binary (injector.exe) won't work since the strings won't be obfuscated.
> - It's recommanded to disable debugging (set to ```false``` the ```DEBUG``` variable in ```evasion.h```. If you do, the program may appear unresponsive. It's due to various waiting time. Just wait 15 sec 😊 )
---
### **Automated OpSec & Heuristics Testing**
```bash
make tests
```
Just for fun
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
  - Checks for the presence of sandbox's DLLs and checks if some real dll exists
### ✅ **Anti-Debugger Techniques**
- **Detect if NtGlobalFlag is present in PEB.**
- **Detect debugger flags in HEAP**

---

## 📝 **Project Structure**
```
📂 Project Folder
│── payloadinjector.c     # Main Payload injector
│── detector.c            # EDR/AV/Sandbox detection
│── evasion.c             # Evasion functions (syscalls, b64decode...) and decoy
│── detector.h            # Header file for detection functions
│── evasion.h             # Header file for evasion functions and decoy
│── syscalls.asm          # Direct Syscalls Functions
|── makefile              # easy to compile
│── README.md             # This documentation
│── 📂 obfs_obfuscator        # Contains the obfuscators c files
    │── obfuscator.c          # Main program used to obfuscate the build binary
    │── binary_obfuscator.c   # Contains the obfuscator's functions
    │── binary_obfuscator.h   # Contains the obfuscator's definition
    │── payloadObfuscator.c   # Contains the obfuscator's payoad functions
│── 📂 tests                  # Contains the Automated OpSec & Heuristics Testing
    │── opsec_analyzer.py     

```
---
## Modules Breakdown
### **Main Payload Injector: payloadinjector.c**
- Creates a **suspended** process (`SearchProtocolHost.exe`).
- Uses **direct syscalls** to allocate memory, write the payload and executes the payload stealthily.

### **EDR/AV/Sandbox Detection: detector.c & detector.h**
- Detects **common AV/EDR drivers** in `C:\Windows\System32\drivers`.
- Checks for **sandbox-specific DLLs** like `cuckoomon.dll`, `VBox*.dll`, etc.
- Implements **sleep patching** to evade automated sandboxes.

### **Evasion Functions & Decoy Execution: evasion.c & evasion.h**
- Implements **Base64 encoding & decoding** to hide payload and function names.
- **Legitimate Decoy Execution**: The injector executes a CPU-intensive function to simulate legitimate software behavior.
- Use PEB walk to retrieve function in modules without API.

### **Direct Syscalls: syscalls.asm**
- Implements **NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtQueryDirectoryFile** using direct syscalls.

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

