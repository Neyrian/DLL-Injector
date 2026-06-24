# Entirely written using Gemini

import sys
import json
import math
import subprocess
import os

def calculate_entropy(data):
    """Calculates Shannon entropy of a bytearray."""
    if not data:
        return 0.0
    entropy = 0
    # Count frequency of each byte
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def run_rabin2(filepath):
    """Executes rabin2 and retrieves section info as JSON."""
    try:
        # -Sj tells rabin2 to output sections in JSON format
        result = subprocess.run(['rabin2', '-Sj', filepath], 
                                capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        # Handle variations in rabin2 JSON output versions
        return data if isinstance(data, list) else data.get('sections', [])
    except FileNotFoundError:
        print("[!] Error: 'rabin2' command not found. Ensure radare2 is in your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running rabin2 on {filepath}:\n{e.stderr}")
        sys.exit(1)

def get_imports(filepath):
    try:
        # -ij gets the imports in JSON format
        result = subprocess.run(['rabin2', '-ij', filepath], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get('imports', [])
    except Exception:
        return []
    
def get_strings(filepath):
    try:
        # -zj gets data strings in JSON format
        result = subprocess.run(['rabin2', '-zj', filepath], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get('strings', [])
    except Exception:
        return []

def get_binary_info(filepath):
    try:
        # -Ij gets general file info in JSON format
        result = subprocess.run(['rabin2', '-Ij', filepath], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get('info', {})
    except Exception:
        return {}
    
def analyze_binary(filepath):
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    print(f"--- Analyzing: {filepath} ---")
    sections = run_rabin2(filepath)
    
    text_size = 0
    data_size = 0
    has_crt = False

    print("\n{:<10} | {:<8} | {:<8} | {:<8} | {:<10}".format(
        "SECTION", "SIZE", "VSIZE", "PERMS", "ENTROPY"))
    print("-" * 55)

    with open(filepath, 'rb') as f:
        for sec in sections:
            name = sec.get('name', 'UNKNOWN')
            paddr = sec.get('paddr', 0)
            size = sec.get('size', 0)
            vsize = sec.get('vsize', 0)
            perm = sec.get('perm', '----')

            # Extract data from the physical file to calculate entropy
            f.seek(paddr)
            raw_data = f.read(size)
            entropy = calculate_entropy(raw_data)

            # Store metrics for heuristics
            if name == '.text':
                text_size = size
            elif name == '.data':
                data_size = size
            elif name == '.CRT':
                has_crt = True

            # Highlight suspicious entropy in output
            ent_str = f"{entropy:.2f}"
            if entropy >= 6.8:
                ent_str += " (!)"

            print("{:<10} | 0x{:<6x} | 0x{:<6x} | {:<8} | {:<10}".format(
                name, size, vsize, perm, ent_str))

    print("\n" + "="*55)
    print(">>> OPSEC HEURISTICS REPORT")
    print("="*55)

    alerts = 0

    # 1. RWX Permission Check
    for sec in sections:
        perm = sec.get('perm', '')
        if 'r' in perm and 'w' in perm and 'x' in perm:
            print(f"[!] HIGH RISK: Section '{sec.get('name')}' has RWX (-rwx) permissions. This guarantees an EDR flag.")
            alerts += 1

    # 2. Entropy Check
    for sec in sections:
        # Re-calculate just for the alert block
        f = open(filepath, 'rb')
        f.seek(sec.get('paddr', 0))
        ent = calculate_entropy(f.read(sec.get('size', 0)))
        f.close()

        if ent >= 7.0:
            print(f"[!] HIGH RISK: Section '{sec.get('name')}' has massive entropy ({ent:.2f}). Highly indicative of packed/encrypted payloads.")
            alerts += 1
        elif ent >= 6.5 and sec.get('name') not in ['.text']:
            print(f"[-] WARNING: Section '{sec.get('name')}' has unusually high entropy ({ent:.2f}) for a non-code section. (Watch your string obfuscation).")
            alerts += 1

    # 3. Data vs Text Ratio Check
    if text_size > 0:
        ratio = (data_size / text_size) * 100
        if ratio > 50:
            print(f"[-] WARNING: .data section is {ratio:.1f}% the size of .text. Large data sections relative to code often trigger heuristic ML models.")
            alerts += 1

    # 4. .CRT Check
    if not has_crt:
        print("[+] INFO: No .CRT section found. (TLS merge successful or stripped CRT).")

    if alerts == 0:
        print("[+] SUCCESS: Binary passed basic static heuristic checks cleanly!")
    else:
        print(f"\nTotal OpSec Warnings/Alerts: {alerts}")
    
    # 5. VSIZE vs SIZE Check (Uninitialized memory / Packer heuristic)
    for sec in sections:
        size = sec.get('size', 0)
        vsize = sec.get('vsize', 0)
        
        # Only flag if the virtual size is larger than raw size AND larger than a single memory page (0x1000)
        if size > 0 and vsize > (size * 3) and vsize > 0x1000:
            print(f"[!] HIGH RISK: Section '{sec.get('name')}' has a VSIZE (0x{vsize:x}) vastly larger than its SIZE (0x{size:x}). Classic packer/unpacker signature.")
            alerts += 1
    
    # 6. Non-Standard Section Names
    standard_sections = ['.text', '.data', '.rdata', '.pdata', '.xdata', '.bss', '.reloc', '.rsrc', '.idata', '.CRT', '.tls']
    for sec in sections:
        name = sec.get('name', '')
        if name not in standard_sections:
            print(f"[-] WARNING: Non-standard section name detected: '{name}'. This looks highly suspicious to static analysis.")
            alerts += 1
    
    # 7. Suspicious IAT (Too few imports)
    imports = get_imports(filepath)
    if len(imports) < 5:
        print(f"[-] WARNING: Import Address Table (IAT) is abnormally small ({len(imports)} imports). EDRs flag this as suspicious dynamic API resolution.")
        alerts += 1
    
    # 8. Plaintext String Leak Check
    strings = get_strings(filepath)
    leaked_obfs = [s.get('string') for s in strings if "[OBFS_ENC]" in s.get('string', '')]
    if leaked_obfs:
        print(f"[!] CRITICAL RISK: Obfuscation failed! Found {len(leaked_obfs)} plaintext '[OBFS_ENC]' strings in the binary.")
        alerts += 1
    
    # Optional: Check for standard suspicious strings
    bad_strings = ['cmd.exe', 'powershell', 'ntdll.dll']
    for s in strings:
        text = s.get('string', '').lower()
        for bad in bad_strings:
            if bad in text:
                print(f"[-] WARNING: Highly fingerprinted string found in plaintext: '{bad}'")
                alerts += 1
    
    # 9. TimeDateStamp Check
    info = get_binary_info(filepath)
    compiled_time = info.get('compiled', '1970')
    if "1970" in str(compiled_time) or "1992" in str(compiled_time): # 1992 is a classic Delphi malware stamp
        print(f"[-] WARNING: Suspicious compilation timestamp detected ({compiled_time}).")
        alerts += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python opsec_analyzer.py <payload.exe>")
        sys.exit(1)
    
    analyze_binary(sys.argv[1])