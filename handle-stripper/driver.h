#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define IOCTL_BATCH_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BATCH_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RUN_HANDLE_STRIPPER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2003, METHOD_BUFFERED, FILE_ANY_ACCESS)

//handle access masks
//https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
#define PROCESS_CREATE_PROCESS 0x0080
#define PROCESS_TERMINATE 0x0001
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_DUP_HANDLE 0x0040
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_SET_INFORMATION 0x0200
#define PROCESS_SET_QUOTA 0x0100
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020

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
