#include "../inc/driver.h"

// Global variables
PDEVICE_OBJECT g_DeviceObject = NULL;
HANDLE g_WfpEngineHandle = NULL;

// Rule list and spin lock
LIST_ENTRY g_RuleList;
KSPIN_LOCK g_RuleListLock;

// Event queue and synchronization
NETWORK_EVENT g_EventQueue[EVENT_QUEUE_SIZE];
UINT32 g_EventQueueHead = 0;
UINT32 g_EventQueueTail = 0;
KSPIN_LOCK g_EventQueueLock;

// DNS event queue
DNS_EVENT g_DnsEventQueue[EVENT_QUEUE_SIZE];
UINT32 g_DnsEventQueueHead = 0;
UINT32 g_DnsEventQueueTail = 0;
KSPIN_LOCK g_DnsEventQueueLock;

// Default policy (allow all if no rule matches)
BOOLEAN g_DefaultAllow = TRUE;

// 进程退出清理限速表的通知回调（PASSIVE_LEVEL；只碰 throttle.c 自有自旋锁）。
// 用普通版 PsSetCreateProcessNotifyRoutine 即可：我们不拦创建，只在进程退出
// 时清限速条目，避免死 PID 滞留内核、PID 复用后新进程无辜继承限速。
VOID CfProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ParentId);
    if (!Create) {
        ThrottleRemoveByPid(HandleToUlong(ProcessId));
    }
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KdPrint(("Ceasefire Driver: DriverEntry called\n"));

    // Initialize rule list
    InitializeListHead(&g_RuleList);
    KeInitializeSpinLock(&g_RuleListLock);

    // Initialize event queue
    KeInitializeSpinLock(&g_EventQueueLock);

    // Initialize DNS event queue
    KeInitializeSpinLock(&g_DnsEventQueueLock);

    // Initialize stream-layer throttle table (kernel rate limiting)
    ThrottleInit();
    // Initialize kernel pacing engine (inbound download shaping): injection
    // handle + 1ms release timer. Failure degrades to inert shaping.
    PacingInit();
    // Initialize user-visible diagnostics counters (IOCTL_GET_DIAGS)
    CfDiagInit();
    // Initialize five-tuple -> PID table (outbound transport shaping attribution)
    FlowTupleInit();
    // Initialize active-flow registry (clean callout teardown at unload)
    FlowRegistryInit();

    // 进程退出通知：限速条目随进程退出清理。注册失败不阻断加载——通知表满
    // 时降级运行（死 PID 条目留给服务侧清扫/覆盖）好过防火墙整体不工作。
    status = PsSetCreateProcessNotifyRoutine(CfProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Ceasefire Driver: PsSetCreateProcessNotifyRoutine FAILED 0x%X "
            "(throttle entries will NOT be cleaned on process exit)\n", status);
    } else {
        KdPrint(("Ceasefire Driver: process-notify callback registered\n"));
    }

    // Create device object
    status = CreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: Failed to create device object: 0x%X\n", status));
        // DriverEntry 失败时内核不会调 DriverUnload：已注册的进程通知回调
        // 必须在此手动注销，否则驱动镜像被卸载后回调指针悬空（BSOD）。
        // 注入句柄同理（PacingShutdown 会放空队列并等在途注入完成）。
        PsSetCreateProcessNotifyRoutine(CfProcessNotifyCallback, TRUE);
        PacingStopTimer();
        PacingShutdown();
        return status;
    }

    // Register WFP callouts
    status = RegisterCallouts(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: Failed to register WFP callouts: 0x%X\n", status));
        PsSetCreateProcessNotifyRoutine(CfProcessNotifyCallback, TRUE);
        PacingStopTimer();
        PacingShutdown();
        // 对照成功卸载路径：符号链接随设备对象一并拆除
        {
            UNICODE_STRING dosDeviceName;
            RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
            IoDeleteSymbolicLink(&dosDeviceName);
        }
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    KdPrint(("Ceasefire Driver: Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(DriverObject);

    KdPrint(("Ceasefire Driver: DriverUnload called\n"));

    // 最先注销进程退出通知：必须发生在 FlowRemoveAllContexts/清表之前，
    // 防止注销窗口里回调再进来碰正在拆除的状态。
    status = PsSetCreateProcessNotifyRoutine(CfProcessNotifyCallback, TRUE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Ceasefire Driver: process-notify unregister FAILED 0x%X "
            "(callback may fire after unload!)\n", status);
    }

    // 卸载顺序（pacing）：先停 1ms 放行定时器并等在途 DPC 走完，杜绝
    // 拆除窗口里 DPC 再触碰扣留队列；ThrottleClearAll 内部会放空全部扣留
    // 队列（立即注入）；最后 PacingShutdown 销毁注入句柄（等待所有在途
    // 注入的完成回调走完）之后本镜像才可被卸载。
    PacingStopTimer();

    // Unregister WFP callouts
    UnregisterCallouts();

    // Clear all rules and throttle entries (ThrottleClearAll flushes pacing
    // queues as part of clearing)
    ClearRules();
    ThrottleClearAll();

    // Destroy the injection handle (waits for outstanding inject completions)
    PacingShutdown();

    // Delete the DOS symbolic link along with the device object
    {
        UNICODE_STRING dosDeviceName;
        RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
        IoDeleteSymbolicLink(&dosDeviceName);
    }

    // Delete device object
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }

    KdPrint(("Ceasefire Driver: Driver unloaded\n"));
}

NTSTATUS CreateDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING dosDeviceName;
    NTSTATUS status;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);

    // Delete old symbolic link if exists (cleanup from previous load)
    IoDeleteSymbolicLink(&dosDeviceName);

    // Create device object with a restrictive DACL: only SYSTEM and
    // Administrators may open the device and send rule-management IOCTLs.
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_NETWORK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        NULL,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: IoCreateDeviceSecure failed: 0x%X\n", status));
        return status;
    }

    // Create symbolic link
    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: IoCreateSymbolicLink failed: 0x%X\n", status));
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // IOCTLs are METHOD_BUFFERED (per-IOCTL buffering); the device-level
    // DO_BUFFERED_IO flag is not needed. Finish initialization so the device
    // can be opened.
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

NTSTATUS DispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    KdPrint(("Ceasefire Driver: DispatchCreate called\n"));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    KdPrint(("Ceasefire Driver: DispatchClose called\n"));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp;
    ULONG ioControlCode;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG bytesReturned = 0;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    KdPrint(("Ceasefire Driver: DispatchDeviceControl called with IOCTL: 0x%X\n", ioControlCode));

    switch (ioControlCode) {
        case IOCTL_ADD_RULE:
            if (inputBufferLength < sizeof(RULE_INPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = AddRule((PRULE_INPUT)inputBuffer);
            break;

        case IOCTL_REMOVE_RULE:
            if (inputBufferLength < sizeof(RULE_ID_INPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = RemoveRule(((PRULE_ID_INPUT)inputBuffer)->RuleId);
            break;

        case IOCTL_UPDATE_RULE:
            if (inputBufferLength < sizeof(RULE_INPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = UpdateRule((PRULE_INPUT)inputBuffer);
            break;

        case IOCTL_CLEAR_RULES:
            status = ClearRules();
            break;

        case IOCTL_SET_DEFAULT_POLICY:
            if (inputBufferLength < sizeof(UINT32)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            g_DefaultAllow = (*(UINT32*)inputBuffer != 0) ? TRUE : FALSE;
            KdPrint(("Ceasefire Driver: Default policy set to %s\n", g_DefaultAllow ? "ALLOW" : "BLOCK"));
            break;

        case IOCTL_SET_THROTTLE:
            if (inputBufferLength < sizeof(THROTTLE_INPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = ThrottleSetEntry((PTHROTTLE_INPUT)inputBuffer);
            break;

        case IOCTL_CLEAR_THROTTLE:
            // 全表清空（服务停止/显式回收）：与 SET_THROTTLE(0,0,0) 的单条目
            // 删除语义严格分离，避免全局开关切换误清按进程限速条目。
            ThrottleClearAll();
            status = STATUS_SUCCESS;
            break;

        case IOCTL_GET_EVENT:
            if (outputBufferLength < sizeof(NETWORK_EVENT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = GetEvent((PNETWORK_EVENT)outputBuffer);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(NETWORK_EVENT);
            }
            break;

        case IOCTL_GET_DNS_EVENT:
            if (outputBufferLength < sizeof(DNS_EVENT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = GetDnsEvent((PDNS_EVENT)outputBuffer);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(DNS_EVENT);
            }
            break;

        case IOCTL_GET_DIAGS:
            if (outputBufferLength < sizeof(CF_DIAGS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            CfDiagSnapshot((PCF_DIAGS)outputBuffer);
            bytesReturned = sizeof(CF_DIAGS);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
