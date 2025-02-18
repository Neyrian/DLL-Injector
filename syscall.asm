section .data
    global wSystemCall
    wSystemCall dq 0

section .text
global myNtAllocateVirtualMemory
global myNtWriteVirtualMemory
global myNtProtectVirtualMemory

myNtAllocateVirtualMemory:
    mov r10, rcx
    mov rax, [rel wSystemCall] ; Load the value of wSystemCall into RAX
    syscall
    ret

myNtWriteVirtualMemory:
    mov r10, rcx          ; Move ProcessHandle to R10
    mov rax, [rel wSystemCall] ; Load the value of wSystemCall into RAX
    syscall               ; Execute the system call
    ret                   ; Return to caller

myNtProtectVirtualMemory:
    mov r10, rcx          ; Move ProcessHandle to R10
    mov rax, [rel wSystemCall] ; Load the value of wSystemCall into RAX
    syscall               ; Execute the system call
    ret                   ; Return to caller