.intel_syntax noprefix
.text

.globl HookEntry
.type HookEntry, @function

HookEntry:
    push rax
    pop rax
    ret 