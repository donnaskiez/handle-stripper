#include "driver.h"

#include "common.h"

//L"\\\\.\\greeeee"
DriverInterface::DriverInterface(LPCWSTR DeviceName)
{
	if (!DeviceName)
	{
		std::cout << "Invalid device name passed as argument" << std::endl;
		return;
	}

	this->device_name = DeviceName;
	this->status = FALSE;

	device_handle = CreateFileW(
		DeviceName,
		GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE,
		0,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
		0
	);

	if (!device_handle)
	{
		std::cout << "Failed to open handle to device" << std::endl;
		return;
	}
}

bool DriverInterface::EnableProcessLoadCallbacks()
{
	status = DeviceIoControl(
		device_handle,
		IOCTL_ENABLE_PROCESS_LOAD_CALLBACKS,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		(LPOVERLAPPED)NULL
	);

	return status;
}

bool DriverInterface::DisableProcessLoadCallbacks()
{
	status = DeviceIoControl(
		device_handle,
		IOCTL_DISABLE_PROCCESS_LOAD_CALLBACKS,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		(LPOVERLAPPED)NULL
	);

	return status;
}

bool DriverInterface::EnableObRegisterCallbacks()
{
	status = DeviceIoControl(
		device_handle,
		IOCTL_ENABLE_OB_HANDLE_CALLBACKS,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		(LPOVERLAPPED)NULL
	);

	return status;
}

bool DriverInterface::DisableObRegisterCallbacks()
{
	status = DeviceIoControl(
		device_handle,
		IOCTL_DISABLE_OB_HANDLE_CALLBACKS,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		(LPOVERLAPPED)NULL
	);

	return status;
}

bool DriverInterface::RunHandleStripperThread()
{
	status = DeviceIoControl(
		device_handle,
		IOCTL_RUN_HANDLE_STRIPPER,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		(LPOVERLAPPED)NULL
	);

	return status;
}

bool DriverInterface::WaitForProcessLoad()
{
	HANDLE event_handle = CreateEvent(NULL, FALSE, FALSE, NULL);

	if (!event_handle)
		return 0;

	OVERLAPPED overlapped = { 0 };
	overlapped.hEvent = event_handle;

	status = DeviceIoControl(
		device_handle,
		IOCTL_INVERTED_PROCESS_START_NOTIFY,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		&overlapped
	);

	if (status)
	{
		WaitForSingleObject(overlapped.hEvent, INFINITE);
	}

	return status;
}
