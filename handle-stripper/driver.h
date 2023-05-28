#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define IOCTL_BATCH_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BATCH_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RUN_HANDLE_STRIPPER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2003, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_TERMINATE 0x0001

//https://www.sysnative.com/forums/threads/object-headers-handles-and-types.34987/
#define GET_OBJECT_HEADER_FROM_HANDLE(x) ((x << 4) | 0xffff000000000000)


UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\greeeee");
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING(L"\\??\\greeeee");
UNICODE_STRING OBJECT_TYPE_PROCESS = RTL_CONSTANT_STRING(L"Process");

static const uintptr_t EPROCESS_IMAGE_FILE_NAME_OFFSET = 0x5a8;
static const uintptr_t EPROCESS_HANDLE_TABLE_OFFSET = 0x570;
static const uintptr_t OBJECT_HEADER_SIZE = 0x30;
static const uintptr_t EPROCESS_PLIST_ENTRY_OFFSET = 0x448;

CHAR protected_process_name[15] = "notepad.exe";
UNICODE_STRING uprotected_process_name = RTL_CONSTANT_STRING(L"notepad.exe");

#endif
