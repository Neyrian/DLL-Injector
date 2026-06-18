import pefile
import sys
import os

def update_pe_checksum(file_path):
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    try:
        # Load the executable into the pefile engine
        pe = pefile.PE(file_path)

        # Extract the old checksum from the PE header
        old_checksum = pe.OPTIONAL_HEADER.CheckSum

        # Calculate the actual mathematical CRC of the current file
        new_checksum = pe.generate_checksum()

        if old_checksum == new_checksum:
            print(f"[*] {file_path}: Checksum is already valid (0x{old_checksum:08X}).")
            return

        # Assign the newly calculated checksum to the header
        pe.OPTIONAL_HEADER.CheckSum = new_checksum

        # Write the modified PE structure back to the disk
        pe.write(filename=file_path)
        
        print(f"[+] {file_path}: Checksum updated from 0x{old_checksum:08X} to 0x{new_checksum:08X}")

    except pefile.PEFormatError:
        print(f"[!] {file_path} is not a valid PE file.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    # Ensure a file path was passed as an argument
    if len(sys.argv) != 2:
        print("Usage: python fix_checksum.py <target_executable>")
        sys.exit(1)

    update_pe_checksum(sys.argv[1])