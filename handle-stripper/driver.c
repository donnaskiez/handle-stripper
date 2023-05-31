#include "driver.h"

#include "types.h"

//For if we unload the driver at the same time while we diable 
//our ObRegisterCallbacks
KMUTEX registration_handle_mutex;
PVOID registration_handle = NULL;

KMUTEX protected_process_mutex;
PEPROCESS protected_process_creator = NULL;
PEPROCESS protected_process = NULL;

KMUTEX process_launch_irp_mutex;
PIRP process_launch_notify_irp = NULL;

//taken from reactos, required to prevent system hang after 
//handle table entry has been processed
VOID NTAPI ExUnlockHandleTableEntry(
	IN PHANDLE_TABLE HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry
)
{
	LONG_PTR OldValue;
	PAGED_CODE();

	/* Sanity check */
	ASSERT((KeGetCurrentThread()->CombinedApcDisable != 0) ||
		(KeGetCurrentIrql() == APC_LEVEL));

	/* Set the lock bit and make sure it wasn't earlier */
	OldValue = InterlockedOr((PLONG)&HandleTableEntry->VolatileLowValue, 1);

	/* Unblock any waiters */
	ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
}

BOOLEAN CheckIfProtectedProcessIsNull()
{
	KeWaitForSingleObject(&protected_process_mutex, Executive, KernelMode, FALSE, NULL);
	BOOLEAN result = protected_process == NULL ? 1 : 0;
	KeReleaseMutex(&protected_process_mutex, FALSE);
	return result;
}

BOOLEAN CheckIfRegistrationHandleIsNull()
{
	KeWaitForSingleObject(&registration_handle_mutex, Executive, KernelMode, FALSE, NULL);
	BOOLEAN result = registration_handle == NULL ? 1 : 0;
	KeReleaseMutex(&registration_handle_mutex, FALSE);
	return result;
}

NTSTATUS HandleInvertedCall(
	_In_ PIRP Irp
)
{
	NTSTATUS status = STATUS_SUCCESS;

	DEBUG_LOG("Handling inverted call");

	if (!CheckIfProtectedProcessIsNull())
	{
		DEBUG_LOG("Process has started, releasing IRP");

		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return status;
	}

	KeWaitForSingleObject(&process_launch_irp_mutex, Executive, KernelMode, FALSE, NULL);
	process_launch_notify_irp = Irp;
	KeReleaseMutex(&process_launch_irp_mutex, 0);
	return status;
}

VOID CompleteInvertedCallIrp(
	_In_ PIRP Irp
)
{
	NTSTATUS status = STATUS_SUCCESS;

	DEBUG_LOG("Completing inverted IRP");

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	process_launch_notify_irp = NULL;
	return status;
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

BOOLEAN EnumHandleCallback(
	_In_ PHANDLE_TABLE HandleTable,
	_In_ PHANDLE_TABLE_ENTRY Entry,
	_In_ HANDLE Handle,
	_In_ PVOID Context
)
{
	PVOID object_header = GET_OBJECT_HEADER_FROM_HANDLE(Entry->ObjectPointerBits);

	//Object header is the first 30 bytes of the object
	PVOID object = (uintptr_t)object_header + OBJECT_HEADER_SIZE;

	POBJECT_TYPE object_type = ObGetObjectType(object);

	if (!RtlCompareUnicodeString(&object_type->Name, &OBJECT_TYPE_PROCESS, TRUE))
	{
		PEPROCESS process = (PEPROCESS)object;

		if (process == protected_process)
		{
			DEBUG_LOG("Handle references our protected process with access mask: %lx", (ACCESS_MASK)Entry->GrantedAccessBits);
			ACCESS_MASK handle_access_mask = (ACCESS_MASK)Entry->GrantedAccessBits;

			if (handle_access_mask & PROCESS_CREATE_PROCESS)
			{
				Entry->GrantedAccessBits &= ~PROCESS_CREATE_PROCESS;
				DEBUG_LOG("Stripped PROCESS_CREATE_PROCESS");
			}
			else if (handle_access_mask & PROCESS_CREATE_THREAD)
			{
				Entry->GrantedAccessBits &= ~PROCESS_CREATE_THREAD;
				DEBUG_LOG("Stripped PROCESS_CREATE_THREAD");
			}
			else if (handle_access_mask & PROCESS_DUP_HANDLE)
			{
				Entry->GrantedAccessBits &= ~PROCESS_DUP_HANDLE;
				DEBUG_LOG("Stripped PROCESS_DUP_HANDLE");
			}
			else if (handle_access_mask & PROCESS_QUERY_INFORMATION)
			{
				Entry->GrantedAccessBits &= ~PROCESS_QUERY_INFORMATION;
				DEBUG_LOG("Stripped PROCESS_QUERY_INFORMATION");
			}
			else if (handle_access_mask & PROCESS_QUERY_LIMITED_INFORMATION)
			{
				Entry->GrantedAccessBits &= ~PROCESS_QUERY_LIMITED_INFORMATION;
				DEBUG_LOG("Stripped PROCESS_QUERY_LIMITED_INFORMATION");
			}
			else if (handle_access_mask & PROCESS_SET_INFORMATION)
			{
				Entry->GrantedAccessBits &= ~PROCESS_SET_INFORMATION;
				DEBUG_LOG("Stripped PROCESS_SET_INFORMATION");
			}
			else if (handle_access_mask & PROCESS_SET_QUOTA)
			{
				Entry->GrantedAccessBits &= ~PROCESS_SET_QUOTA;
				DEBUG_LOG("Stripped PROCESS_SET_QUOTA");
			}
			else if (handle_access_mask & PROCESS_SUSPEND_RESUME)
			{
				Entry->GrantedAccessBits &= ~PROCESS_SUSPEND_RESUME;
				DEBUG_LOG("Stripped PROCESS_SUSPEND_RESUME ");
			}
			else if (handle_access_mask & PROCESS_TERMINATE)
			{
				Entry->GrantedAccessBits &= ~PROCESS_TERMINATE;
				DEBUG_LOG("Stripped PROCESS_TERMINATE");
			}
			else if (handle_access_mask & PROCESS_VM_OPERATION)
			{
				Entry->GrantedAccessBits &= ~PROCESS_VM_OPERATION;
				DEBUG_LOG("Stripped PROCESS_VM_OPERATION");
			}
			else if (handle_access_mask & PROCESS_VM_READ)
			{
				Entry->GrantedAccessBits &= ~PROCESS_VM_READ;
				DEBUG_LOG("Stripped PROCESS_VM_READ");
			}
			else if (handle_access_mask & PROCESS_VM_WRITE)
			{
				Entry->GrantedAccessBits &= ~PROCESS_VM_WRITE;
				DEBUG_LOG("Stripped PROCESS_VM_WRITE");
			}
		}
	}

	ExUnlockHandleTableEntry(HandleTable, Entry);

	return FALSE;
}

NTSTATUS EnumerateProcessHandles(
	_In_ PEPROCESS Process
)
{
	//Make sure we are running at an IRQL low enough that allows paging
	PAGED_CODE();

	if (!Process)
	{
		DEBUG_LOG("Process passed in null to enumprochandles");
		return STATUS_INVALID_PARAMETER_1;
	}

	if (Process == PsInitialSystemProcess)
		return STATUS_SUCCESS;

	DEBUG_LOG("Beginning to enumerate process handles for proc: %llx", (UINT64)Process);

	PHANDLE_TABLE handle_table = *(PHANDLE_TABLE*)((uintptr_t)Process + EPROCESS_HANDLE_TABLE_OFFSET);

	if (!handle_table)
	{
		DEBUG_ERROR("Handle table pointer is null");
		return STATUS_ABANDONED;
	}

#pragma warning(push)
#pragma warning(suppress : 6387)

	BOOLEAN result = ExEnumHandleTable(
		handle_table,
		EnumHandleCallback,
		NULL,
		NULL
	);

#pragma warning(pop)

	return STATUS_SUCCESS;
}

VOID EnumerateProcessList()
{
	PEPROCESS base_process = PsInitialSystemProcess;

	if (!base_process)
	{
		DbgPrint("Failed to get system process struct");
		return STATUS_NOT_FOUND;
	}

	PEPROCESS current_process = base_process;

	do 
	{
		EnumerateProcessHandles(current_process);

		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)current_process + EPROCESS_PLIST_ENTRY_OFFSET);

		current_process = (PEPROCESS)((uintptr_t)list->Flink - EPROCESS_PLIST_ENTRY_OFFSET);

	} while (current_process != base_process || !current_process);
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

		KeWaitForSingleObject(&protected_process_mutex, Executive, KernelMode, FALSE, NULL);
		protected_process = target_process;
		KeReleaseMutex(&protected_process_mutex, 0);

		KeWaitForSingleObject(&process_launch_irp_mutex, Executive, KernelMode, FALSE, NULL);
		process_launch_notify_irp != NULL
			? CompleteInvertedCallIrp(process_launch_notify_irp)
			: DEBUG_ERROR("No process launch IRP queued");
		KeReleaseMutex(&process_launch_irp_mutex, 0);
	}
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	DEBUG_LOG("Unloading driver");

	if (!CheckIfRegistrationHandleIsNull())
		ObUnRegisterCallbacks(registration_handle);

	PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, TRUE);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_LINK);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS EnableObRegisterCallbacks()
{
	DEBUG_LOG("Enabling ObRegisterCallbacks");

	NTSTATUS status;

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
		return status;
	}

	return status;
}

NTSTATUS ToggleLoadProcessNotifyRoutine(
	_In_ BOOLEAN Toggle
)
{
	DEBUG_LOG("Toggling Process load routine. Remove: %d", Toggle);

	NTSTATUS status;

	status = PsSetCreateProcessNotifyRoutine(
		ProcessCreateNotifyRoutine,
		Toggle
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("Failed to register or unregister process create notifyu routien");
		return status;
	}

	return status;
}

VOID ModifyRegistrationHandle(
	_In_ UINT64 NewValue)
{
	KeWaitForSingleObject(&registration_handle_mutex, Executive, KernelMode, FALSE, NULL);
	registration_handle = (PVOID)NewValue;
	KeReleaseMutex(&registration_handle_mutex, FALSE);
}

NTSTATUS MajorControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PIRP Irp
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
			EnumerateProcessList,
			NULL
		);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to start handle enumeration thread");

		break;

	case IOCTL_ENABLE_OB_HANDLE_CALLBACKS:

		status = EnableObRegisterCallbacks();

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to register our obregistercallback");

		break;

	case IOCTL_DISABLE_OB_HANDLE_CALLBACKS:

		DEBUG_LOG("Disabling ObRegisterCallbacks");

		if (!CheckIfRegistrationHandleIsNull())
		{
			ObUnRegisterCallbacks(registration_handle);
			ModifyRegistrationHandle(NULL);
			break;
		}

		DEBUG_ERROR("registration handle already null");
		break;

	case IOCTL_ENABLE_PROCESS_LOAD_CALLBACKS:

		status = ToggleLoadProcessNotifyRoutine(FALSE);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to enable load process notify rioutine");

		break;

	case IOCTL_DISABLE_PROCCESS_LOAD_CALLBACKS:

		status = ToggleLoadProcessNotifyRoutine(TRUE);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to disable our process load notify routine");

		break;

	case IOCTL_INVERTED_PROCESS_START_NOTIFY:

		status = HandleInvertedCall(Irp);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to process inverted call IRP");

		return status;

	default:

		DEBUG_ERROR("Invalid IOCTL code passed");

		break;
	}

end: 

	Irp->IoStatus.Status = status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
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

	KeInitializeMutex(&registration_handle_mutex, 0);
	KeInitializeMutex(&protected_process_mutex, 0);
	KeInitializeMutex(&process_launch_irp_mutex, 0);

	DEBUG_LOG("Driver entry complete");

	return status;
}