#ifndef TYPE_H
#define TYPES_H

#include <ntifs.h>
#include <wdftypes.h>

//stuff dumped from windbg

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
#pragma warning(pop)
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PVOID                         ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PVOID                         PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PEB32 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _EXHANDLE
{
    union {
        PVOID GenericHandleOverlay;
        ULONGLONG Value;
        struct {
            UCHAR TagBits : 2;
            ULONG Index : 30;
        };
    };

} EXHANDLE, * PEXHANDLE;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
    ULONG AuditMask;
    ULONG MaxRelativeAccessMask;

} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;


typedef struct _HANDLE_TABLE_ENTRY
{
    union {
        LONGLONG VolatileLowValue;
        LONGLONG LowValue;
        PHANDLE_TABLE_ENTRY_INFO InfoTable;
    };
    union {
        LONGLONG HighValue;
        struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
        EXHANDLE LeafHandleValue;
    };
    union {
        LONGLONG RefCountField;
        struct {
            UCHAR Unlocked : 1;
            USHORT RefCnt : 16;
            UCHAR Attributes : 3;
            ULONGLONG ObjectPointerBits : 44;
        };
    };
    struct {
        ULONG GrantedAccessBits : 25;
        UCHAR NoRightsUpgrade : 1;
        UCHAR Spare1 : 6;
    };
    ULONG Spare2;
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE_FREE_LIST
{
    EX_PUSH_LOCK FreeListLock;
    PHANDLE_TABLE_ENTRY FirstFreeHandleEntry;
    PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
    LONG HandleCount;
    ULONG HighWaterMark;
} HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;

typedef struct _HANDLE_TRACE_DB_ENTRY
{
    CLIENT_ID ClientId;
    PVOID Handle;
    ULONG Type;
    PVOID StackTrace[16];

} HANDLE_TRACE_DB_ENTRY, * PHANDLE_TRACE_DB_ENTRY;



typedef struct _HANDLE_TRACE_DEBUG_INFO
{
    LONG RefCount;
    ULONG TableSize;
    ULONG BitMaskFlags;
    FAST_MUTEX CloseCompactionLock;
    ULONG CurrentStackIndex;
    HANDLE_TRACE_DB_ENTRY TraceDb[1];

} HANDLE_TRACE_DEBUG_INFO, * PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;
    LONG ExtraInfoPages;
    ULONGLONG TableCode;
    PEPROCESS QuotaProcess;
    LIST_ENTRY HandleTableList;
    ULONG UniqueProcessId;
    union {
        ULONG Flags;
        struct {
            UCHAR StrictFIFO : 1;
            UCHAR EnableHandleExceptions : 1;
            UCHAR Rundown : 1;
            UCHAR Duplicated : 1;
            UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;
        };
    };
    EX_PUSH_LOCK HandleContentionEvent;
    EX_PUSH_LOCK HandleTableLock;
    union {
        HANDLE_TABLE_FREE_LIST FreeLists[1];
        UCHAR ActualEntry[32];
    };

    struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;

} HANDLE_TABLE, * PHANDLE_TABLE;

typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    );

typedef struct _OBJECT_CREATE_INFORMATION
{
    ULONG Attributes;
    PVOID RootDirectory;
    CHAR ProbeMode;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG SecurityDescriptorCharge;
    PVOID SecurityDescriptor;
    struct _SECURITY_QUALITY_OF_SERVICE* SecurityQos;
    struct _SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

} OBJECT_CREATE_INFORMATION, * POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HEADER
{
    LONGLONG PointerCount;
    union {
        LONGLONG HandleCount;
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;
    union {
        UCHAR TraceFlags;
        struct {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };
    UCHAR InfoMask;
    union {
        UCHAR Flags;
        struct {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };
    ULONG Reserved;
    union {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;



#endif // !TYPE_H
