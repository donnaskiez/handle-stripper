#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define IOCTL_BATCH_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BATCH_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\hmmmmsss");
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING(L"\\??\\hmmmmsss");

typedef struct _CALLBACK_CONTEXT
{
	PKPROCESS process;

} CALLBACK_CONTEXT, *PCALLBACK_CONTEXT;

CALLBACK_CONTEXT callback_context = { 0 };

static const uintptr_t EPROCESS_PLIST_ENTRY_OFFSET = 0x448;
static const uintptr_t EPROCESS_IMAGE_FILE_NAME_OFFSET = 0x5a8;
static const uintptr_t LDR_DATA_TABLE_IN_MEMORY_LINKS_OFFSET = 0x010;
static const uintptr_t EPROCESS_PROCESS_ID_OFFSET = 0x440;

#endif
