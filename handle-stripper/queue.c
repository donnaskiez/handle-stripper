#include "queue.h"

KSPIN_LOCK queue_lock;
PQUEUE list_head;
PIO_CSQ csq;

VOID Enqueue(
	_In_ PQUEUE* Head,
	_In_ PIRP Irp
)
{
	PQUEUE new_entry = ExAllocatePool2( NonPagedPool, sizeof( QUEUE ), QUEUE_TAG );

	if ( !new_entry )
		return;

	new_entry->Irp = Irp;
	new_entry->next = *Head;
	*Head = new_entry;
}

PIRP Dequeue(
	_In_ PQUEUE* Head
)
{
	PQUEUE current = NULL;
	PQUEUE previous = NULL;
	PIRP irp = NULL;

	if ( !( *Head ) )
		return;

	current = *Head;

	while ( current->next )
	{
		previous = current;
		current = current->next;
	}

	irp = current->Irp;
	ExFreePool2( current, QUEUE_TAG, NULL, NULL );

	if ( previous )
		previous->next = NULL;
	else
		*Head = NULL;

	return irp;
}

VOID QueueInsertIrp( _In_ PIO_CSQ Csq, _In_ PIRP Irp )
{
	Enqueue( &list_head, Irp );
}

VOID QueueRemoveIrp( _In_ PIO_CSQ Csq, _In_ PIRP Irp )
{
	Dequeue( &list_head );
}

PIRP QueuePeekNextIrp( _In_ PIO_CSQ Csq, _In_ PIRP Irp, _In_ PVOID PeekContext )
{
	//not implemented
}

VOID QueueAcquireLock( _In_ PIO_CSQ Csq, _In_ PKIRQL Irql )
{
	KeAcquireSpinLock( &queue_lock, Irql );
}

VOID QueueReleaseLock( _In_ PIO_CSQ Csq, _In_ KIRQL Irql )
{
	KeReleaseSpinLock( &queue_lock, Irql );
}

VOID QueueCompleteCancelledIrp( _In_ PIO_CSQ Csq, _In_ PIRP Irp )
{
	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
}

VOID QueueInitialize()
{
	NTSTATUS status;

	list_head = NULL;

	status = IoCsqInitializeEx(
		&csq,
		QueueInsertIrp,
		QueueRemoveIrp,
		QueuePeekNextIrp,
		QueueAcquireLock,
		QueueReleaseLock,
		QueueCompleteCancelledIrp
	);

	if ( !NT_SUCCESS( status ) )
	{
		//DEBUG_ERROR("Failed to initialize cancel safe queue");
		return;
	}

	KeInitializeSpinLock( queue_lock );
}