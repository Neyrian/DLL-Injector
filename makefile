# Define the compiler, assembler, and tools
CC = x86_64-w64-mingw32-gcc
ASM = nasm
OBJCOPY = x86_64-w64-mingw32-objcopy
STRIP = x86_64-w64-mingw32-strip

# Define output binaries
TARGET_EXE = injector.exe
TARGET_OBFS_EXE = obfsinjector.exe
PAYLOAD_DLL = msfdll.dll #Change this accordingly to the name of your binary/payload. For testing, I will use msfvenom msgbox payload :)
PAYLOAD_HEADER = payload.h #do not change this please, or modify the code accordingly!
OBFS_KEY = 144
OBFUSCATOR = obfs_src/obfuscator obfs_src/obfuscator.o obfs_src/binary_obfuscator.o obfs_src/binObfuscator obfs_src/binObfuscator.o

# Define source files
ASM_SRC = syscalls.asm
ASM_OBJ = syscalls.o

C_SRCS = dllinjector.c detector.c evasion.c
C_HDRS = detector.h evasion.h
C_OBJS = $(C_SRCS:.c=.o)

# Compilation flags
CFLAGS = -Wall -Wno-array-bounds -O2 
LDFLAGS = -O2 -flto -ffunction-sections -fdata-sections -lshlwapi -Wl,--section-alignment,4096 -Wl,--gc-sections -Wl,--strip-debug -Wl,--image-base,0x140000000

# Default target
all: $(TARGET_EXE) $(PAYLOAD_DLL) $(OBFUSCATOR) $(PAYLOAD_HEADER)

# Assemble syscalls.asm
$(ASM_OBJ): $(ASM_SRC)
	$(ASM) -f win64 $(ASM_SRC) -o $(ASM_OBJ)

# Compile C files
%.o: %.c $(C_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Link the injector executable
$(TARGET_EXE): $(PAYLOAD_HEADER) $(C_OBJS) $(ASM_OBJ)  obfs_src/obfuscator
	$(CC) -o $(TARGET_EXE) $(C_OBJS) $(ASM_OBJ) $(PAYLOAD_HEADER) $(LDFLAGS)
	$(OBJCOPY) --rename-section .CRT=.data $(TARGET_EXE)
	$(STRIP) --strip-debug --strip-unneeded $(TARGET_EXE)
	./obfs_src/obfuscator $(TARGET_EXE) $(TARGET_OBFS_EXE) $(OBFS_KEY)
	@echo "Recalculating PE CheckSum..."
	python3 fix_checksum.py $(TARGET_OBFS_EXE)
# cleaning intermediary files
	rm -f $(ASM_OBJ) $(C_OBJS) $(OBFUSCATOR) $(TARGET_EXE) $(PAYLOAD_DLL)
	
$(PAYLOAD_HEADER): $(PAYLOAD_DLL) obfs_src/binObfuscator
	./obfs_src/binObfuscator $(PAYLOAD_DLL) $(OBFS_KEY)

$(PAYLOAD_DLL):
	msfvenom -p windows/x64/messagebox -o $(PAYLOAD_DLL)

## simple compilation instruction of the obfuscators
obfs_src/obfuscator.o: obfs_src/obfuscator.c
	gcc -Os -c -Wall obfs_src/obfuscator.c -o obfs_src/obfuscator.o

obfs_src/binary_obfuscator.o: obfs_src/binary_obfuscator.c
	gcc -Os -c -Wall obfs_src/binary_obfuscator.c -o obfs_src/binary_obfuscator.o

obfs_src/obfuscator: obfs_src/obfuscator.o obfs_src/binary_obfuscator.o
	gcc -Os -s -Wall obfs_src/obfuscator.o obfs_src/binary_obfuscator.o -o obfs_src/obfuscator

obfs_src/binObfuscator.o: obfs_src/binObfuscator.c
	gcc -Os -c -Wall obfs_src/binObfuscator.c -o obfs_src/binObfuscator.o

obfs_src/binObfuscator: obfs_src/binObfuscator.o
	gcc -Os -s -Wall obfs_src/binObfuscator.o -o obfs_src/binObfuscator

# Clean up generated files
clean:
	rm -f $(ASM_OBJ) $(C_OBJS) $(TARGET_EXE) $(PAYLOAD_DLL) $(OBFUSCATOR) $(TARGET_OBFS_EXE) $(PAYLOAD_HEADER)
