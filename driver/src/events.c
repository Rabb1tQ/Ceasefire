#include "../inc/driver.h"

NTSTATUS QueueEvent(_In_ PNETWORK_EVENT event)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&g_EventQueueLock, &oldIrql);

    // Check if queue is full
    UINT32 nextHead = (g_EventQueueHead + 1) % EVENT_QUEUE_SIZE;
    if (nextHead == g_EventQueueTail) {
        // Queue is full, discard oldest event
        KdPrint(("Ceasefire Driver: Event queue full, discarding oldest event\n"));
        g_EventQueueTail = (g_EventQueueTail + 1) % EVENT_QUEUE_SIZE;
    }

    // CRITICAL: Zero the destination first to ensure no garbage in padding bytes
    RtlSecureZeroMemory(&g_EventQueue[g_EventQueueHead], sizeof(NETWORK_EVENT));
    
    // Copy event to queue field by field to avoid padding issues
    g_EventQueue[g_EventQueueHead].Timestamp = event->Timestamp;
    g_EventQueue[g_EventQueueHead].ProcessId = event->ProcessId;
    g_EventQueue[g_EventQueueHead].EventType = event->EventType;
    RtlCopyMemory(g_EventQueue[g_EventQueueHead].ProcessPath, event->ProcessPath, sizeof(event->ProcessPath));
    g_EventQueue[g_EventQueueHead].Protocol = event->Protocol;
    RtlCopyMemory(g_EventQueue[g_EventQueueHead].LocalAddr, event->LocalAddr, sizeof(event->LocalAddr));
    RtlCopyMemory(g_EventQueue[g_EventQueueHead].RemoteAddr, event->RemoteAddr, sizeof(event->RemoteAddr));
    g_EventQueue[g_EventQueueHead].AddressFamily = event->AddressFamily;
    g_EventQueue[g_EventQueueHead].LocalPort = event->LocalPort;
    g_EventQueue[g_EventQueueHead].RemotePort = event->RemotePort;
    g_EventQueue[g_EventQueueHead].Allowed = event->Allowed;
    g_EventQueue[g_EventQueueHead].MatchedRuleId = event->MatchedRuleId;
    g_EventQueue[g_EventQueueHead].BytesSent = event->BytesSent;
    g_EventQueue[g_EventQueueHead].BytesReceived = event->BytesReceived;
    g_EventQueue[g_EventQueueHead].Direction = event->Direction;
    
    g_EventQueueHead = nextHead;

    // 事件消费方采用轮询（IOCTL_GET_EVENTS），无人等待 KEVENT，
    // g_EventAvailableEvent 已删除，不再维护信号。

    KeReleaseSpinLock(&g_EventQueueLock, oldIrql);

    return status;
}

NTSTATUS GetEvent(_Out_ PNETWORK_EVENT event)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&g_EventQueueLock, &oldIrql);

    // Check if queue is empty
    if (g_EventQueueHead == g_EventQueueTail) {
        status = STATUS_NO_MORE_ENTRIES;
    } else {
        // Copy event from queue
        RtlCopyMemory(event, &g_EventQueue[g_EventQueueTail], sizeof(NETWORK_EVENT));
        g_EventQueueTail = (g_EventQueueTail + 1) % EVENT_QUEUE_SIZE;
    }

    KeReleaseSpinLock(&g_EventQueueLock, oldIrql);

    return status;
}

NTSTATUS QueueDnsEvent(_In_ PDNS_EVENT event)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&g_DnsEventQueueLock, &oldIrql);

    // Check if queue is full
    UINT32 nextHead = (g_DnsEventQueueHead + 1) % EVENT_QUEUE_SIZE;
    if (nextHead == g_DnsEventQueueTail) {
        // Queue is full, discard oldest event
        g_DnsEventQueueTail = (g_DnsEventQueueTail + 1) % EVENT_QUEUE_SIZE;
    }

    // Copy event to queue
    RtlCopyMemory(&g_DnsEventQueue[g_DnsEventQueueHead], event, sizeof(DNS_EVENT));
    g_DnsEventQueueHead = nextHead;

    KeReleaseSpinLock(&g_DnsEventQueueLock, oldIrql);

    return status;
}

NTSTATUS GetDnsEvent(_Out_ PDNS_EVENT event)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&g_DnsEventQueueLock, &oldIrql);

    // Check if queue is empty
    if (g_DnsEventQueueHead == g_DnsEventQueueTail) {
        status = STATUS_NO_MORE_ENTRIES;
    } else {
        // Copy event from queue
        RtlCopyMemory(event, &g_DnsEventQueue[g_DnsEventQueueTail], sizeof(DNS_EVENT));
        g_DnsEventQueueTail = (g_DnsEventQueueTail + 1) % EVENT_QUEUE_SIZE;
    }

    KeReleaseSpinLock(&g_DnsEventQueueLock, oldIrql);

    return status;
}
