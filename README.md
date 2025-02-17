# 🚀 Advanced DLL Injector with EDR/AV/Sandbox Evasion

## 🔥 Overview
This project is a **stealthy DLL injector** for **Windows**, capable of injecting a specified DLL into a suspended process while **evading EDRs, AVs, and sandbox environments**.  
The project includes **sandbox and security software detection** (`detector.c`), making it harder to analyze in controlled environments.

---

## 📌 **Features**
✅ **Indirect System Calls** (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`)  
✅ **Manually Resolving API Calls** (No `GetProcAddress`)  
✅ **Injection into Suspended Process** (`SearchProtocolHost.exe`)  
✅ **EDR/AV Detection** (Scans `C:\Windows\System32\drivers\`)  
✅ **Sandbox Detection** (Detects VM files, mouse activity, and sleep patching)

---

## 🚀 **Usage**
### **1️⃣ Compilation (On Kali Linux)**
```bash
x86_64-w64-mingw32-gcc -o injector.exe dllinjector.c detector.h detector.c -Wall -lshlwapi
```

### **2️⃣ Running the Injector**
```powershell
injector.exe C:\path\to\dll
```
> **Note**: Replace `C:\path\to\dll` with the actual path of your DLL.

---

## 🐍 **EDR, AV, and Sandbox Evasion**
### ✅ **EDR Detection (`detector.c`)**
- Scans `C:\Windows\System32\drivers\` for known **EDR & AV drivers** (Carbon Black, CrowdStrike, SentinelOne, etc.).
- If found, execution is stopped.

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

---

## 📝 **File Structure**
```
📂 Project Folder
│── injector.c       # Main DLL injector
│── detector.c       # EDR/AV/Sandbox detection
│── detector.h       # Header file for detection functions
│── README.md        # Documentation
```

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
- 🔗 **Pikabot Campaign TM**: [Trend Micro: Pikabot Spam Wave](https://www.trendmicro.com/en_us/research/24/a/a-look-into-pikabot-spam-wave-campaign.html)
- 🔗 **Pikabot Campaign Mitre**: [MITRE ATT&CK: Pikabot Campaign (C0037)](https://attack.mitre.org/campaigns/C0037/)

---

## 🎯 **Next Steps**
✅ Improve evasion against modern EDRs (e.g., **hook unhooking**).  
✅ Implement **direct system calls** to avoid `ntdll.dll` detection.  
✅ Add **extra payload encryption** (e.g., AES) for more stealth.

---

🚀 **Happy Coding!**

