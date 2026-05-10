.intel_syntax noprefix
.text

.global MyKeyboardCallbackHook1
.extern g_OriginalKbdCallback
.extern g_RuntimeKeyboardHook

MyKeyboardCallbackHook1:
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    sub rsp, 0x58

    mov r10, [rip + g_RuntimeKeyboardHook]
    call r10    

    add rsp, 0x58

   
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq

    mov rax, rsp
    mov [rax+0x8], rbx
    mov [rax+0x10], rsi
    mov [rax+0x18], rdi

    mov r10, [rip + g_OriginalKbdCallback] 
    add r10, 15
    jmp r10


