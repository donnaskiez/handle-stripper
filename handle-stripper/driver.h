#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define IOCTL_BATCH_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BATCH_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_TERMINATE 0x0001

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\hmmmmsss");
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING(L"\\??\\hmmmmsss");

static const uintptr_t EPROCESS_IMAGE_FILE_NAME_OFFSET = 0x5a8;

CHAR protected_process_name[15] = "notepad.exe";
UNICODE_STRING uprotected_process_name = RTL_CONSTANT_STRING(L"notepad.exe");

#endif
