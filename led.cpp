#include <ntddk.h>
#include <ntddkbd.h>

VOID SetCapsLockLed(BOOLEAN Enable)
{
    UNICODE_STRING deviceName;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, L"\\Device\\KeyboardClass0");

    NTSTATUS status = IoGetDeviceObjectPointer(
        &deviceName,
        FILE_READ_DATA,
        &fileObject,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
        return;

    KEYBOARD_INDICATOR_PARAMETERS params = { 0 };

    params.UnitId = 0;

    if (Enable)
    {
        params.LedFlags = KEYBOARD_CAPS_LOCK_ON;
    }
    else
    {
        params.LedFlags = 0;
    }

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IO_STATUS_BLOCK iosb;

    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_KEYBOARD_SET_INDICATORS,
        deviceObject,
        &params,
        sizeof(params),
        NULL,
        0,
        FALSE,
        &event,
        &iosb
    );

    if (irp)
    {
        status = IoCallDriver(deviceObject, irp);

        if (status == STATUS_PENDING)
        {
            KeWaitForSingleObject(
                &event,
                Executive,
                KernelMode,
                FALSE,
                NULL
            );
        }
    }

    ObDereferenceObject(fileObject);
}