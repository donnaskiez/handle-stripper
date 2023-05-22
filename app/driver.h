#ifndef IDRIVER_H
#define IDRIVER_H

#include <windows.h>
#include <iostream>

#define IOCTL_RUN_HANDLE_STRIPPER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2003, METHOD_BUFFERED, FILE_ANY_ACCESS)

BOOL ValidateAccess()
{
	BOOL result = 0;
	HANDLE device;
	BOOL status;

	device = CreateFileW(
		L"\\\\.\\hmmmmsss",
		GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE,
		0,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		0
	);

	if (!device)
	{
		std::cout << "Failed to open handle to device" << std::endl;
		return FALSE;
	}

	status = DeviceIoControl(
		device,
		IOCTL_RUN_HANDLE_STRIPPER,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		(LPOVERLAPPED)NULL
	);

	if (!status)
	{
		std::cout << "Failed to send ioctl to driver" << std::endl;
		return FALSE;
	}

	return result;
}

#endif // !IDRIVER_H
