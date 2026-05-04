.intel_syntax noprefix
.text

.globl HookEntry
.extern g_OriginalMmAddress
.extern pCheckDriverCallback  

HookEntry:
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    
    sub rsp, 0x28                     
    mov r10, [rip + pCheckDriverCallback]
    call r10                          
    add rsp, 0x28                    

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq

    sub rsp, 0x38
    test r9d, 0xFFFFFFFC

    mov r10, [rip + g_OriginalMmAddress]
    add r10, 13
    jmp r10