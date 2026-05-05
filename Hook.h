#ifndef __HOOK_H__
#define __HOOK_H__

// אנחנו משתמשים ב-CONTAINING_RECORD של EDK2 אם הוא קיים, אם לא - זה הגרסה שתעבוד:
#undef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (UINT8*)(address) - \
                                                  (UINT64)(&((type *)0)->field)))

#define COM1_PORT 0x3F8

typedef enum {
    MmNonCached = 0,
    MmCached = 1,
    MmWriteCombined = 2,
    MmHardwareCoherentCached = 3,
    MmNonCachedUnorderedWriteCombined = 4,
    MmUSWCCached = 5
} MEMORY_CACHING_TYPE;

typedef VOID* (EFIAPI *MM_MAP_IO_SPACE)(PHYSICAL_ADDRESS PhysicalAddress, UINTN NumberOfBytes, MEMORY_CACHING_TYPE CacheType);
typedef VOID (EFIAPI *MM_UNMAP_IO_SPACE)(VOID* BaseAddress, UINTN NumberOfBytes);

typedef struct _UNICODE_STRING {
    UINT16 Length;
    UINT16 MaximumLength;
    CHAR16* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    VOID* ExceptionTable;
    UINT32 ExceptionTableSize;
    VOID* GpValue;
    VOID* NonPagedDebugInfo;
    VOID* DllBase;
    VOID* EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    UINT32 Flags;
    UINT16 LoadCount;
    UINT16 SignatureLevel : 4;
    UINT16 SignatureType : 3;
    UINT16 Unused : 9;
    VOID* SectionPointer;
    UINT32 CheckSum;
    UINT32 CoverageSectionSize;
    VOID* CoverageSection;
    VOID* LoadedImports;
    VOID* Spare;
    UINT32 SizeOfImageNotRounded;
    UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _LOADER_PARAMETER_BLOCK {
    UINT32 OsMajorVersion;
    UINT32 OsMinorVersion;
    UINT32 Size;
    UINT32 OsLoaderSecurityVersion;
    LIST_ENTRY LoadOrderListHead;
    LIST_ENTRY MemoryDescriptorListHead;
    LIST_ENTRY BootDriverListHead;
    LIST_ENTRY EarlyLaunchListHead;
    LIST_ENTRY CoreDriverListHead;
    LIST_ENTRY CoreExtensionsDriverListHead;
    LIST_ENTRY TpmCoreDriverListHead;
} LOADER_PARAMETER_BLOCK, *PLOADER_PARAMETER_BLOCK;

typedef struct _KEYBOARD_INPUT_DATA {
    UINT16 UnitId;
    UINT16 MakeCode;
    UINT16 Flags;
    UINT16 Reserved;
    UINT32 ExtraInformation;
} KEYBOARD_INPUT_DATA;


#endif