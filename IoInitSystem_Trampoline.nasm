SECTION .text
extern IoInitSystemHook  ; The function implemented in C

global IoInitSystem_Trampoline

IoInitSystem_Trampoline:
    ; 1. Save all registers so we don't corrupt Windows execution state
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    ; 2. Call the C function (this is where your custom logic runs)
    sub rsp, 0x20          ; Allocate shadow space for x64 calling convention
    call IoInitSystemHook
    add rsp, 0x20

    ; 3. Restore the registers
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq

    ; 4. Execute the original bytes that were overwritten
    ; Note: Usually the first bytes of the target function are replaced by a jump.
    ; Those original instructions must be executed here before returning.

    ; 5. Return to the original function execution flow
    ret