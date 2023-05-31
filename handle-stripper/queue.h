#ifndef QUEUE_H
#define QUEUE_H

#include <ntddk.h>

#define QUEUE_TAG 'qqqq'

typedef struct _QUEUE
{
	PIRP Irp;
	struct _QUEUE* next;

}QUEUE, *PQUEUE;

VOID Enqueue(
	_In_ PQUEUE* Head, 
	_In_ PIRP Irp
);

PIRP Dequeue(
	_In_ PQUEUE* Head
);

VOID QueueInsertIrp(
	_In_ PIO_CSQ Csq,
	_In_ PIRP Irp
);

VOID QueueRemoveIrp(
	_In_ PIO_CSQ Csq,
	_In_ PIRP Irp
);

PIRP QueuePeekNextIrp(
	_In_ PIO_CSQ Csq,
	_In_ PIRP Irp,
	_In_ PVOID PeekContext
);

VOID QueueAcquireLock(
	_In_ PIO_CSQ Csq,
	_In_ PKIRQL Irql
);

VOID QueueReleaseLock(
	_In_ PIO_CSQ Csq,
	_In_ KIRQL Irql
);

VOID QueueCompleteCancelledIrp(
	_In_ PIO_CSQ Csq,
	_In_ PIRP Irp
);

VOID QueueInitialize();

#endif