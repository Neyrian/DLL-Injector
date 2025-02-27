section .text
global CustAVM
global CustWVM

CustAVM:
    mov r10, rcx
    mov rax, 0x18 ; Load the value of smID into RAX
    db 0x0F, 0x05   ; Encoded `syscall` instruction to prevent hooking
    ret

CustWVM:
    mov r10, rcx          ; Move ProcessHandle to R10
    mov rax, 0x3A ; Load the value of smID into RAX
    db 0x0F, 0x05   ; Encoded `syscall` instruction to prevent hooking
    ret                   ; Return to caller