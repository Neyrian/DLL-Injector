# Define the compiler, assembler, and tools
CC = x86_64-w64-mingw32-gcc
ASM = nasm
OBJCOPY = x86_64-w64-mingw32-objcopy
STRIP = x86_64-w64-mingw32-strip

# Define output binaries
TARGET_EXE = injector.exe
TARGET_DLL = malDLL.dll

# Define source files
ASM_SRC = syscalls.asm
ASM_OBJ = syscalls.o

C_SRCS = dllinjector.c detector.c evasion.c
C_HDRS = detector.h evasion.h
C_OBJS = $(C_SRCS:.c=.o)

DLL_SRC = malDLL.c

# Compilation flags
CFLAGS = -Wall -Wno-array-bounds -O2
LDFLAGS = -lshlwapi -Wl,--section-alignment,4096 -Wl,--gc-sections -Wl,--strip-debug -Wl,--image-base,0x140000000
DLL_LDFLAGS = -shared -Wl,--subsystem,windows -mwindows

# Default target
all: $(TARGET_EXE) $(TARGET_DLL)

# Assemble syscalls.asm
$(ASM_OBJ): $(ASM_SRC)
	$(ASM) -f win64 $(ASM_SRC) -o $(ASM_OBJ)

# Compile C files
%.o: %.c $(C_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Link the injector executable
$(TARGET_EXE): $(C_OBJS) $(ASM_OBJ)
	$(CC) -o $(TARGET_EXE) $(C_OBJS) $(ASM_OBJ) $(LDFLAGS)
	$(OBJCOPY) --rename-section .CRT=.data $(TARGET_EXE)
	$(STRIP) --strip-debug --strip-unneeded $(TARGET_EXE)

# Build the malicious DLL
$(TARGET_DLL): $(DLL_SRC)
	$(CC) $(DLL_LDFLAGS) -o $(TARGET_DLL) $(DLL_SRC)

# Clean up generated files
clean:
	rm -f $(ASM_OBJ) $(C_OBJS) $(TARGET_EXE) $(TARGET_DLL)
