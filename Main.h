#ifndef __MAIN_H__
#define __MAIN_H__

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Guid/EventGroup.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include "Hook.h"

extern EFI_EXIT_BOOT_SERVICES originalExitBootServices;
extern UINT64 winloadReturnAddress;
extern LIST_ENTRY *g_PsLoadedModuleList;
extern VOID* g_TargetKbdAddr;
extern VOID* g_RuntimeKeyboardHook;
extern char kbd_US[128];


extern VOID HookEntry(void);
VOID EFIAPI MyKeyboardCallbackHook(VOID* arg1, VOID* arg2);
VOID SerialWrite(CHAR8* str);
VOID SerialWriteHex(UINT64 value);

// Pattern & Export
VOID* FindPattern(VOID* base, UINTN size, UINT8* sig, UINTN sigSize);
VOID* EFIAPI FindNtosExportByName(VOID *kernelBase, CHAR8* exportName);

// Hook
VOID InstallPureAsmHook(VOID* target);
extern VOID HookEntry(void);


#endif