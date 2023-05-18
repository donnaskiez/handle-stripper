#include "driver.h"

#include "types.h"

PVOID registration_handle = NULL;
PVOID protected_process_creator = NULL;

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	DEBUG_LOG("Unloading driver");
	ObUnRegisterCallbacks(registration_handle);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_LINK);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DEBUG_LOG("Handle to symbolic link %wZ opened", DEVICE_SYMBOLIC_LINK);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DEBUG_LOG("Handle to symbolic link %wZ closed", DEVICE_SYMBOLIC_LINK);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

OB_PREOP_CALLBACK_STATUS ObPreOpCallbackRoutine(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	//Completely strip permissions
	ACCESS_MASK deny_access = SYNCHRONIZE | PROCESS_TERMINATE;
	
	//This mask to be used for lsass/csrss
	ACCESS_MASK downgrade_access = 0;

	//This callback routine is executed in the context of the thread that 
	//is requesting to open said handle

	PEPROCESS process = PsGetCurrentProcess();
	CHAR process_name[15];

	RtlCopyMemory(
		&process_name,
		(PVOID)((uintptr_t)process + EPROCESS_IMAGE_FILE_NAME_OFFSET),
		sizeof(process_name)
	);

	//This gives us the target process for the handle

	PEPROCESS target_process = (PEPROCESS)OperationInformation->Object;
	CHAR target_name[15];

	RtlCopyMemory(
		&target_name,
		(PVOID)((uintptr_t)target_process + EPROCESS_IMAGE_FILE_NAME_OFFSET),
		sizeof(target_name)
	);

	if (!strcmp(protected_process_name, target_name))
	{
		//todo: downgrade handles from lsass and csrss

		if (!strcmp(process_name, "lsass.exe") || !strcmp(process_name, "csrss.exe"))
		{
			//downgrade access
		}
		else if (!strcmp(process_name, protected_process_name))
		{
			DEBUG_LOG("Handle being opened by: %s", process_name);
		}
		else
		{
			if (strcmp(process_name, "explorer.exe"))
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = deny_access;
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = deny_access;
				DEBUG_LOG("handle stripped from: %s", process_name);
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

VOID ObPostOpCallbackRoutine(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION OperationInformation
)
{

}

VOID ImageLoadNotifyRoutine(
	_In_ PUNICODE_STRING ImageName,
	_In_ HANDLE Processid,
	_In_ PIMAGE_INFO ImageInfo
)
{
	UNREFERENCED_PARAMETER(ImageInfo);


}

NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	status = IoCreateDevice(
		DriverObject,
		0,
		&DEVICE_NAME,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DriverObject->DeviceObject
	);

	if (!NT_SUCCESS(status))
		return STATUS_FAILED_DRIVER_ENTRY;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
	DriverObject->DriverUnload = DriverUnload;

	status = IoCreateSymbolicLink(
		&DEVICE_SYMBOLIC_LINK,
		&DEVICE_NAME
	);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(&DriverObject->DeviceObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	OB_OPERATION_REGISTRATION operation_registration = { 0 };

	operation_registration.ObjectType = PsProcessType;
	operation_registration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operation_registration.PreOperation = ObPreOpCallbackRoutine;
	operation_registration.PostOperation = ObPostOpCallbackRoutine;

	OB_CALLBACK_REGISTRATION callback_registration = { 0 };

	callback_registration.Version = OB_FLT_REGISTRATION_VERSION;
	callback_registration.OperationRegistration = &operation_registration;
	callback_registration.OperationRegistrationCount = 1;
	callback_registration.RegistrationContext = NULL;

	status = ObRegisterCallbacks(
		&callback_registration,
		&registration_handle
	);

	status = PsSetLoadImageNotifyRoutineEx(
		
	)

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("Failed to register our callback: %lx", status);
		IoDeleteDevice(&DriverObject->DeviceObject);
		IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_LINK);
		return status;
	}

	DEBUG_LOG("Driver entry complete");

	return status;
}