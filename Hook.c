#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/EventGroup.h>          // For gEfiEventExitBootServicesGuid

EFI_EVENT gExitBootServicesEvent = NULL;

// ============================================================
// YOUR BOOTKIT HOOK
// ============================================================
VOID EFIAPI OnExitBootServices(IN EFI_EVENT Event, IN VOID *Context)
{
    (void)Event;
    (void)Context;

    Print(L"\n[BOOTKIT] ===========================================\n");
    Print(L"[BOOTKIT] HOOK TRIGGERED SUCCESSFULLY!\n");
    Print(L"[BOOTKIT] My code ran before Windows boot\n");
    Print(L"[BOOTKIT] Windows should continue normally now...\n");
    Print(L"[BOOTKIT] ===========================================\n");

    // === YOUR REAL PAYLOAD GOES HERE ===
}

// ============================================================
// Main Entry Point
// ============================================================
EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
)
{
  EFI_STATUS Status;
  EFI_HANDLE *Handles = NULL;
  UINTN HandleCount = 0;
  UINTN Index;
  EFI_HANDLE BootHandle;
  EFI_DEVICE_PATH_PROTOCOL *BootPath;

  // Register the ExitBootServices event hook
  Status = gBS->CreateEventEx(
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  OnExitBootServices,
                  NULL,
                  &gEfiEventExitBootServicesGuid,
                  &gExitBootServicesEvent
                );

  if (!EFI_ERROR(Status)) {
      Print(L"[BOOTKIT] ExitBootServices hook registered successfully!\n");
  } else {
      Print(L"[BOOTKIT] Warning: Could not register hook: %r\n", Status);
  }

  Print(L"Hello from UEFI!\n");
  Print(L"Searching for Windows 19041...\n");
  gBS->Stall(1500000);

  Status = gBS->LocateHandleBuffer(
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                );

  if (EFI_ERROR(Status) || HandleCount == 0) {
    Print(L"No filesystems found!\n");
    gBS->Stall(2000000);
    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    BootPath = FileDevicePath(Handles[Index], L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    if (BootPath == NULL) continue;

    Status = gBS->LoadImage(FALSE, ImageHandle, BootPath, NULL, 0, &BootHandle);
    FreePool(BootPath);

    if (!EFI_ERROR(Status)) {
      Print(L"Found Windows 19041! Booting...\n");
      gBS->Stall(800000);

      if (Handles != NULL) {
        FreePool(Handles);
      }

      return gBS->StartImage(BootHandle, NULL, NULL);
    }
  }

  if (Handles != NULL) FreePool(Handles);

  Print(L"Windows not found!\n");
  gBS->Stall(3000000);
  return EFI_NOT_FOUND;
}