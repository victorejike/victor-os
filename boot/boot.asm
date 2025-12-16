global start
extern kernel_main

section .text
bits 32
start:
    mov esp, stack_top
    
    ; Clear direction flag
    cld
    
    ; Push multiboot info pointer
    push ebx
    push eax
    
    ; Call kernel main
    call kernel_main
    
    ; Halt if kernel returns
    cli
.hang:
    hlt
    jmp .hang

section .bss
align 4096
stack_bottom:
    resb 16384 ; 16 KB stack
stack_top: