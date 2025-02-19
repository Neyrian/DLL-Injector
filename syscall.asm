section .data
    global smID
    smID dq 0

section .text
global CustAVM
global CustWVM

CustAVM:
    mov r10, rcx
    mov rax, [rel smID] ; Load the value of smID into RAX
    syscall
    ret

CustWVM:
    mov r10, rcx          ; Move ProcessHandle to R10
    mov rax, [rel smID] ; Load the value of smID into RAX
    syscall               ; Execute the system call
    ret                   ; Return to caller