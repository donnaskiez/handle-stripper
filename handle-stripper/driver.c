#include "driver.h"

#include "types.h"

NTKERNELAPI
BOOLEAN
ExEnumHandleTable(
	__in PHANDLE_TABLE HandleTable,
	__in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	__in PVOID EnumParameter,
	__out_opt PHANDLE Handle
);

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
	_In_ PVOID Object
);

PVOID registration_handle = NULL;
PEPROCESS protected_process_creator = NULL;
PEPROCESS protected_process = NULL;

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

BOOLEAN EnumHandleCallback(
	_In_ PHANDLE_TABLE HandleTable,
	_In_ PHANDLE_TABLE_ENTRY Entry,
	_In_ HANDLE Handle,
	_In_ PVOID Context
)
{
	DEBUG_LOG("Handle Table Entry: %llx", (UINT64)Entry);

	DEBUG_LOG("ObjectPointerBits: %llx", Entry->ObjectPointerBits);

	PVOID object_header = GET_OBJECT_HEADER_FROM_HANDLE(Entry->ObjectPointerBits);

	DEBUG_LOG("Object header: %llx", (UINT64)object_header);

	//Object header is the first 30 bytes of the object
	POBJECT_TYPE object_type = ObGetObjectType((uintptr_t)object_header + OBJECT_HEADER_SIZE);

	DEBUG_LOG("Object type: %wZ", object_type->Name);

	return FALSE;
}

NTSTATUS EnumerateProcessHandles(
	_In_ PEPROCESS Process
)
{
	if (!Process)
	{
		DEBUG_LOG("Process passed in null to enumprochandles");
		return STATUS_INVALID_PARAMETER_1;
	}

	DEBUG_LOG("Beginning to enumerate process handles for proc: %llx", (UINT64)Process);

	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN result;

	//Make sure we are running at an IRQL low enough that allows paging
	PAGED_CODE();

	PHANDLE_TABLE handle_table = *(PHANDLE_TABLE*)((uintptr_t)Process + EPROCESS_HANDLE_TABLE_OFFSET);

	DEBUG_LOG("handle table: %llx", (UINT64)handle_table);

	if (!handle_table)
	{
		DEBUG_ERROR("Handle table pointer is null");
		return;
	}

	result = ExEnumHandleTable(
		handle_table,
		EnumHandleCallback,
		NULL,
		NULL
	);

	DEBUG_LOG("Result: %c", result);

	return status;
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

	PEPROCESS process_creator = PsGetCurrentProcess();
	CHAR process_creator_name[15];

	RtlCopyMemory(
		&process_creator_name,
		(PVOID)((uintptr_t)process_creator + EPROCESS_IMAGE_FILE_NAME_OFFSET),
		sizeof(process_creator_name)
	);

	//This gives us the target process for the handle

	PEPROCESS target_process = (PEPROCESS)OperationInformation->Object;
	CHAR target_name[15];

	RtlCopyMemory(
		&target_name,
		(PVOID)((uintptr_t)target_process + EPROCESS_IMAGE_FILE_NAME_OFFSET),
		sizeof(target_name)
	);

	//Make sure we are only focusing on our protected process
	if (!strcmp(protected_process_name, target_name))
	{
		//todo: downgrade handles from lsass and csrss

		if (!strcmp(process_creator_name, "lsass.exe") || !strcmp(process_creator_name, "csrss.exe"))
		{
			//downgrade access
		}
		else if (target_process == process_creator)
		{
			//Allow handles created by the protected process 

			DEBUG_LOG("Handles created by the protected process are fine for now: %s", process_creator_name);
		}
		else if (process_creator == protected_process_creator)
		{
			//Allow handles created by the protected process' creator i.e explorer, cmd etc.

			DEBUG_LOG("Process creator: %s handles are fine for now...", process_creator_name);
		}
		else
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = deny_access;
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = deny_access;
			DEBUG_LOG("handle stripped from: %s", process_creator_name);
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

VOID ProcessCreateNotifyRoutine(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
)
{
	NTSTATUS status;
	PEPROCESS parent_process;
	PEPROCESS target_process;

	CHAR parent_process_name[15];
	CHAR target_process_name[15];

	status = PsLookupProcessByProcessId(ParentId, &parent_process);

	if (!NT_SUCCESS(status))
		return;

	status = PsLookupProcessByProcessId(ProcessId, &target_process);

	if (!NT_SUCCESS(status))
		return;

	RtlCopyMemory(
		&parent_process_name,
		(PVOID)((uintptr_t)parent_process + EPROCESS_IMAGE_FILE_NAME_OFFSET),
		sizeof(parent_process_name)
	);

	RtlCopyMemory(
		&target_process_name,
		(PVOID)((uintptr_t)target_process + EPROCESS_IMAGE_FILE_NAME_OFFSET),
		sizeof(target_process_name)
	);

	if (!strcmp(target_process_name, protected_process_name))
	{
		DEBUG_LOG("parent process for notepad is: %s", parent_process_name);
		protected_process_creator = parent_process;
		protected_process = target_process;
	}
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	DEBUG_LOG("Unloading driver");
	PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, TRUE);
	ObUnRegisterCallbacks(registration_handle);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_LINK);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS MajorControl(
	PDRIVER_OBJECT DriverObject,
	PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation(Irp);

	switch (stack_location->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_RUN_HANDLE_STRIPPER:
		
		DEBUG_LOG("RunHandleStripper IOCTL Received");

		HANDLE thread_handle;

		status = PsCreateSystemThread(
			&thread_handle,
			PROCESS_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			EnumerateProcessHandles,
			protected_process
		);

		if (!NT_SUCCESS(status))
		{
			DEBUG_LOG("Failed to start handle enumeration thread");
			goto end;
		}

		break;

	default:

		DEBUG_ERROR("Invalid IOCTL code passed");
	}

end: 

	Irp->IoStatus.Status = status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
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
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MajorControl;
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

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("Failed to register our callback: %lx", status);
		IoDeleteDevice(&DriverObject->DeviceObject);
		IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_LINK);
		return status;
	}

	status = PsSetCreateProcessNotifyRoutine(
		ProcessCreateNotifyRoutine,
		FALSE
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_LOG("Failed to create image load notify routine");
		ObUnRegisterCallbacks(registration_handle);
		IoDeleteDevice(&DriverObject->DeviceObject);
		IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_LINK);
		return status;
	}

	DEBUG_LOG("Driver entry complete");

	return status;
}