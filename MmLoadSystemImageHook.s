.intel_syntax noprefix
.text

.globl HookEntry
.extern g_OriginalMmAddress

HookEntry:
    pushfq
    push r10

    pop r10
    popfq

    sub rsp, 0x38
    test r9d, 0xFFFFFFFC

    mov r10, [rip + g_OriginalMmAddress]
    add r10, 13
    jmp r10