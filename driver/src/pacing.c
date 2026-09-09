// Kernel pacing（第 19 轮）：入站 TCP 下载限速的执行手段。
//
// 第 17 轮的 drop-to-throttle（BLOCK 触发对端重传退避）已被实测否决：拦截
// 强度超过一半时接收端乱序堆积，本机 tcpip 栈主动 RST 连接（机制性失败，
// 数据表见 WFP实现方案.md）。第 18 轮的"传输层克隆-回退-重建-注入"也被
// VM 实测否决：INBOUND_TRANSPORT 收方向 NBL 只含 TCP 载荷（NB 起点=应用
// 数据、DataOffset=0），IP/TCP 头根本不在 NBL 里，clone+retreat 拿到的是
// 垃圾——该层方案前提不成立。本版（第 19 轮）把执行点整体迁到
// FWPS_LAYER_INBOUND_IPPACKET_V4/V6。该层实测（驱动 43/45 探针，Win10
// 19045）NB 起点 = TCP 头且 DataOffset=0，IP 头在 NB 的 headroom 里（字节数
// = metadata ipHeaderSize）。实现"克隆-扣留-定时注入"：
//   * classify（DISPATCH_LEVEL）令牌不足时：先 NdisRetreatNetBufferDataStart
//     原始 NBL 露出 IP 头（WinDivert 同层同法）、克隆、复原原始 NBL，入队，
//     返回 BLOCK +
//     FWPS_CLASSIFY_OUT_FLAG_ABSORB——包一个不丢，接收端永远看到有序
//     字节流，任意速率（含几 KB/s）都稳。注意必须 retreat 原始 NBL 再克隆：
//     克隆不含 DataOffset 之前的 headroom 内容（驱动 59 实测全零）；
//   * KTIMER + KeSetTimerEx（1ms 周期）驱动 DPC 扫描扣留队列，对每个 PID
//     只看队头（严格 FIFO），ThrottleCheck 通过才出队并注入——令牌在
//     "注入时"消耗（快路径到达时消耗除外），与第 17 轮的关键语义差别；
//   * 注入用 FwpsInjectNetworkReceiveAsync0（NETWORK 类型按族句柄）：克隆
//     带 IP 头、地址/校验和天然正确。曾实测否决的路径：手工 NBL+NDIS 分配器
//     被同步拒绝（0xC0220035）；手工 IP 头 + WFP 分配器 NBL 可注入但被栈
//     丢弃（0xC000021B）；克隆不带 IP 头 + 传输层接收注入完成回调
//     BUFFER_TOO_SMALL（0xC0000023）——矩阵详见句柄声明处注释。
//     文档约束：注入必须带外执行（DPC / 系统线程均可，绝不能在 classify
//     栈内直接注入）；注入的包会被再次指示给本 callout，用
//     FwpsQueryPacketInjectionState0 自识别放行。
//
// 内存上限：每 PID 扣留 512KB、全局 4MB。超限时新包不再扣留、直接 BLOCK
// 丢弃——此时丢弃是对的：队列已代表一个多窗口的积压，说明对端没降速。
// 注入失败（同步返回失败或完成回调 Status 失败）：释放克隆 + 诊断计数，
// 当丢包处理，不重试。

#include "../inc/driver.h"

#define PACING_POOL_TAG 'caPC' // "PCac"

// 队列上限（字节）
#define PACING_PID_HOLD_LIMIT   (512 * 1024ULL)
#define PACING_GLOBAL_HOLD_LIMIT (4 * 1024 * 1024ULL)
#define PACING_MAX_CONTEXTS     64   // 同时被扣留流量的 PID 数上限
#define PACING_DPC_BATCH        32   // 单次 tick 每 DPC 最多注入的包数

// 一个被扣留的包（含再注入所需的全部上下文）
typedef struct _PACED_PACKET {
    LIST_ENTRY Link;
    PNET_BUFFER_LIST Clone;      // 原始 NBL 的克隆，NB 已 retreat 到 IP 头
    BOOLEAN IsV6;                // 注入时的 addressFamily
    UINT32 ProcessId;
    UINT32 PayloadBytes;         // TCP 载荷字节（令牌计费口径）
    IF_INDEX InterfaceIndex;
    IF_INDEX SubInterfaceIndex;
} PACED_PACKET, *PPACED_PACKET;

// 每个 PID 的 FIFO 扣留队列
typedef struct _PACING_CONTEXT {
    BOOLEAN InUse;
    UINT32 ProcessId;
    LIST_ENTRY Queue;            // PACED_PACKET.Link
    UINT32 PacketCount;
    UINT64 QueuedBytes;
} PACING_CONTEXT, *PPACING_CONTEXT;

static PACING_CONTEXT s_Contexts[PACING_MAX_CONTEXTS];

static KSPIN_LOCK s_HoldLock;
static BOOLEAN s_Initialized = FALSE;

// 注入句柄（DriverEntry 创建、DriverUnload 释放）。第 19 轮连环实测：
//   * NETWORK 类型要求按族建句柄，AF_UNSPEC 非法；
//   * 手工 NBL 必须用 FwpsAllocateNetBufferAndNetBufferList0 分配（文档
//     明确"专供 WFP 包注入"）——NDIS 分配器建的 NBL 被注入同步校验拒绝
//     （0xC0220035，驱动 49/50/52 实测）；WFP 分配器 + 传输层接收注入
//     可过同步校验但完成回调报 0xC0000023（驱动 51/53，tcpip 补 IP 头
//     失败，该层克隆/带 headroom 均救不了）；
//   * 最终定式（驱动 60 实测通过）：按族 NETWORK 句柄 + 原始 NBL 克隆
//     （classify 里先 retreat ipHeaderSize 露出原 IP 头再克隆，地址/校验和
//     天然正确）+ FwpsInjectNetworkReceiveAsync0。手工 IP 头路线（驱动
//     54-58，头字节已验证正确）虽过同步校验但被栈丢弃 0xC000021B。
// NULL = pacing 不可用，入站整形惰性（全部放行），与 callout 注册失败降级
// 口径一致。
static HANDLE s_InjHandleV4 = NULL;
static HANDLE s_InjHandleV6 = NULL;

// 释放一个未注入成功/已注入完成的扣留包（克隆 NBL + 包体）
static VOID PacingFreePacket(_In_ PPACED_PACKET packet)
{
    if (packet->Clone != NULL) {
        FwpsFreeCloneNetBufferList0(packet->Clone, 0);
    }
    ExFreePoolWithTag(packet, PACING_POOL_TAG);
}

// 当前全局扣留字节数/包数（s_HoldLock 内维护）
static UINT64 s_GlobalQueuedBytes = 0;
static UINT32 s_GlobalQueuedPackets = 0;

// 第 18 轮 VM 蓝屏（0xD1）取证的常开探针（审查窗口加，零逻辑改动）：
// 热路径按 1/N 采样、冷路径全量，WARNING 级——无调试器时也写入内核打印
// 缓冲区，蓝屏后随内核转储保留。落点格式：[CF-PACING] <事件> <参数>。
static volatile LONG64 s_ProbeHoldSeq = 0;    // hold 成功序号（采样 1/32）
static volatile LONG64 s_ProbeInjectSeq = 0;  // 注入完成序号（采样 1/64）
static volatile LONG64 s_ProbeTickSeq = 0;    // 有产出的 tick 序号（采样 1/256）

// 放行引擎：周期定时器 + DPC
static KTIMER s_PacingTimer;
static KDPC s_PacingDpc;

BOOLEAN PacingEnabled(_In_opt_ BOOLEAN isV6)
{
    HANDLE h = isV6 ? s_InjHandleV6 : s_InjHandleV4;
    return s_Initialized && h != NULL;
}

// 自识别（classify 最先调用，防自己注入的包被自己再扣）：用本驱动的注入
// 句柄查包的注入状态。只有本句柄注入/曾注入的包返回 TRUE；其他驱动的
// 注入（BY_OTHER）不归我们管。
BOOLEAN PacingIsSelfInjected(_In_ PNET_BUFFER_LIST nbl, _In_ BOOLEAN isV6)
{
    FWPS_PACKET_INJECTION_STATE state;
    HANDLE h = isV6 ? s_InjHandleV6 : s_InjHandleV4;

    if (!s_Initialized || h == NULL) {
        return FALSE;
    }
    state = FwpsQueryPacketInjectionState0(h, nbl, NULL);
    return state == FWPS_PACKET_INJECTED_BY_SELF ||
           state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF;
}

NTSTATUS PacingInit(VOID)
{
    LARGE_INTEGER dueTime;

    KeInitializeSpinLock(&s_HoldLock);
    RtlSecureZeroMemory(s_Contexts, sizeof(s_Contexts));
    // 所有队列头立即初始化（Flink/Blink 指向自身）：GetContextLocked 惰性
    // 创建仍会重建，但保证任何路径下 IsListEmpty/RemoveHeadList 语义成立，
    // 避免零内存槽位被清队循环误判为"非空"（曾导致 net stop 时 0xD1）。
    {
        UINT32 i;
        for (i = 0; i < PACING_MAX_CONTEXTS; i++) {
            InitializeListHead(&s_Contexts[i].Queue);
        }
    }

    {
        NTSTATUS status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &s_InjHandleV4);
        if (!NT_SUCCESS(status)) {
            s_InjHandleV4 = NULL;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[CF-PACING] v4 injection handle create failed 0x%08X - v4 download pacing DISABLED\n",
                status);
        }
    }
    {
        NTSTATUS status = FwpsInjectionHandleCreate0(AF_INET6, FWPS_INJECTION_TYPE_NETWORK, &s_InjHandleV6);
        if (!NT_SUCCESS(status)) {
            s_InjHandleV6 = NULL;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[CF-PACING] v6 injection handle create failed 0x%08X - v6 download pacing DISABLED\n",
                status);
        }
    }

    KeInitializeTimerEx(&s_PacingTimer, SynchronizationTimer);
    KeInitializeDpc(&s_PacingDpc, PacingTimerDpc, NULL);
    dueTime.QuadPart = -10000; // 1ms（相对时间，100ns 单位）
    KeSetTimerEx(&s_PacingTimer, dueTime, 1 /* 周期 1ms */, &s_PacingDpc);

    s_Initialized = TRUE;
    KdPrint(("Ceasefire Driver: pacing engine initialized (v4=%p v6=%p)\n", s_InjHandleV4, s_InjHandleV6));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[CF-PACING] init ok v4=%p v6=%p\n", s_InjHandleV4, s_InjHandleV6);
    return STATUS_SUCCESS;
}

// 卸载序：先停定时器并等在途 DPC 走完（PASSIVE_LEVEL，可阻塞），之后队列
// 不会再被 DPC 触碰；剩余扣留由 PacingDrainAll 放空（DriverUnload 在
// UnregisterCallouts 之后、句柄销毁之前调用）。
VOID PacingStopTimer(VOID)
{
    if (!s_Initialized) {
        return;
    }
    KeCancelTimer(&s_PacingTimer);
    KeFlushQueuedDpcs();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[CF-PACING] stop-timer\n");
}

// 前置：PacingStopTimer 已执行。放空全部扣留队列（无视令牌，立即注入），
// 失败按丢包释放。此后 FwpsInjectionHandleDestroy0 会等所有在途注入完成。
VOID PacingDrainAll(VOID)
{
    KIRQL oldIrql;
    PPACED_PACKET batch[PACING_DPC_BATCH];
    UINT32 i, n;
    UINT32 drained = 0;

    if (!s_Initialized) {
        return;
    }

    for (;;) {
        n = 0;
        KeAcquireSpinLock(&s_HoldLock, &oldIrql);
        for (i = 0; i < PACING_MAX_CONTEXTS && n < PACING_DPC_BATCH; i++) {
            if (!s_Contexts[i].InUse) {
                continue; // 从未使用/已清空的槽位：队列语义不保证，必须跳过
            }
            while (n < PACING_DPC_BATCH && !IsListEmpty(&s_Contexts[i].Queue)) {
                PLIST_ENTRY e = RemoveHeadList(&s_Contexts[i].Queue);
                PPACED_PACKET p = CONTAINING_RECORD(e, PACED_PACKET, Link);
                s_Contexts[i].PacketCount--;
                s_Contexts[i].QueuedBytes -= p->PayloadBytes;
                s_GlobalQueuedBytes -= p->PayloadBytes;
                s_GlobalQueuedPackets--;
                if (s_Contexts[i].PacketCount == 0) {
                    s_Contexts[i].InUse = FALSE;
                    s_Contexts[i].ProcessId = 0;
                }
                batch[n++] = p;
            }
        }
        KeReleaseSpinLock(&s_HoldLock, oldIrql);

        if (n == 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            PacingInjectNow(batch[i]);
            drained++;
        }
    }

    if (drained > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] drain-all %u packets\n", drained);
    }
}

// 注入单个包。成功后克隆由完成回调释放；同步失败按丢包处理（不重试）。
VOID PacingInjectNow(_In_ VOID* rawPacket)
{
    PPACED_PACKET packet = (PPACED_PACKET)rawPacket;
    NTSTATUS status;

    // 网络层接收注入（WinDivert 同层验证的定式）：NBL = 完整 IP 数据报
    // （自建 IP 头 + 原样 TCP 段），compartment 用 UNSPECIFIED 让栈自解析。
    status = FwpsInjectNetworkReceiveAsync0(
        packet->IsV6 ? s_InjHandleV6 : s_InjHandleV4,
        NULL,                       // injectionContext（自识别靠句柄匹配即可）
        0,                          // flags
        UNSPECIFIED_COMPARTMENT_ID,
        packet->InterfaceIndex,
        packet->SubInterfaceIndex,
        packet->Clone,
        PacingInjectComplete,
        packet);

    if (!NT_SUCCESS(status)) {
        // 文档：返回非 SUCCESS 时完成回调不会被调用，包须就地释放
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] inject-SYNC-FAIL 0x%08X pid=%u bytes=%u if=%u sub=%u v6=%u\n",
            status, packet->ProcessId, packet->PayloadBytes, packet->InterfaceIndex,
            packet->SubInterfaceIndex, packet->IsV6);
        PacingFreePacket(packet);
        CfDiagPacingInjectFail();
    }
}

// 注入完成回调（IRQL <= DISPATCH_LEVEL）。包所有权在此释放；注入结果
// 以 NBL Status 为准（文档 FWPS_INJECT_COMPLETE0）。
VOID NTAPI PacingInjectComplete(
    _In_ VOID* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
)
{
    PPACED_PACKET packet = (PPACED_PACKET)context;

    UNREFERENCED_PARAMETER(dispatchLevel);

    if (NT_SUCCESS(netBufferList->Status)) {
        CfDiagPacingInjected();
        if (InterlockedIncrement64(&s_ProbeInjectSeq) % 64 == 1) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[CF-PACING] inject-ok #%I64d pid=%u bytes=%u\n",
                s_ProbeInjectSeq, packet->ProcessId, packet->PayloadBytes);
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] inject-COMPLETE-FAIL 0x%08X pid=%u bytes=%u\n",
            netBufferList->Status, packet->ProcessId, packet->PayloadBytes);
        CfDiagPacingInjectFail();
    }

    FwpsFreeCloneNetBufferList0(netBufferList, 0);
    ExFreePoolWithTag(packet, PACING_POOL_TAG);
}

// 放行引擎：1ms 周期 DPC（DISPATCH_LEVEL）。每个 PID 只看队头，严格 FIFO；
// ThrottleCheck 通过才消耗令牌并注入，不通过则该 PID 本轮跳过（令牌按
// 时间持续回填，队头包攒够即走）。
VOID NTAPI PacingTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PPACED_PACKET batch[PACING_DPC_BATCH];
    KIRQL oldIrql;
    UINT32 i, n = 0;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!PacingEnabled(TRUE) && !PacingEnabled(FALSE)) {
        return;
    }

    CfDiagPacingTimerTick();

    // 批量出队后锁外注入（注入耗时不可控，绝不能持自旋锁注入）。
    // ThrottleCheck 在持 s_HoldLock 时调用是安全的：throttle.c 的所有清退
    // 路径都是"先放 throttle 锁再进 s_HoldLock"，不存在反向嵌套。
    KeAcquireSpinLock(&s_HoldLock, &oldIrql);
    for (i = 0; i < PACING_MAX_CONTEXTS && n < PACING_DPC_BATCH; i++) {
        if (!s_Contexts[i].InUse || IsListEmpty(&s_Contexts[i].Queue)) {
            continue;
        }
        // 只取队头（FIFO）；ThrottleCheck 失败（令牌不足）则该 PID 本轮止步
        while (n < PACING_DPC_BATCH && !IsListEmpty(&s_Contexts[i].Queue)) {
            PLIST_ENTRY e = s_Contexts[i].Queue.Flink;
            PPACED_PACKET head = CONTAINING_RECORD(e, PACED_PACKET, Link);
            if (!ThrottleCheck(head->ProcessId, FALSE, head->PayloadBytes)) {
                break;
            }
            (VOID)RemoveHeadList(&s_Contexts[i].Queue);
            s_Contexts[i].PacketCount--;
            s_Contexts[i].QueuedBytes -= head->PayloadBytes;
            s_GlobalQueuedBytes -= head->PayloadBytes;
            s_GlobalQueuedPackets--;
            if (s_Contexts[i].PacketCount == 0) {
                s_Contexts[i].InUse = FALSE;
                s_Contexts[i].ProcessId = 0;
            }
            batch[n++] = head;
        }
    }
    KeReleaseSpinLock(&s_HoldLock, oldIrql);

    if (n > 0 && InterlockedIncrement64(&s_ProbeTickSeq) % 256 == 1) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] tick batch=%u\n", n);
    }

    for (i = 0; i < n; i++) {
        PacingInjectNow(batch[i]);
    }
}

// 查找或创建 PID 上下文（调用方持 s_HoldLock）
static PPACING_CONTEXT PacingGetContextLocked(_In_ UINT32 processId, _Out_ BOOLEAN* created)
{
    UINT32 i;
    PPACING_CONTEXT freeSlot = NULL;

    *created = FALSE;
    for (i = 0; i < PACING_MAX_CONTEXTS; i++) {
        if (s_Contexts[i].InUse && s_Contexts[i].ProcessId == processId) {
            return &s_Contexts[i];
        }
        if (!s_Contexts[i].InUse && freeSlot == NULL) {
            freeSlot = &s_Contexts[i];
        }
    }
    if (freeSlot == NULL) {
        return NULL;
    }
    freeSlot->InUse = TRUE;
    freeSlot->ProcessId = processId;
    InitializeListHead(&freeSlot->Queue);
    freeSlot->PacketCount = 0;
    freeSlot->QueuedBytes = 0;
    *created = TRUE;
    return freeSlot;
}

// 该 PID 的扣留队列是否非空（只拿 s_HoldLock 的快速判断，不创建上下文）。
// 供 INBOUND_IPPACKET 快路径前置检查：队列非空说明同 PID 已有包在攒令牌
// 等待，新到包必须继续入队，保证同 PID 严格 FIFO——否则队头大包等待期间
// 后到小包走快路径先注入，造成同流乱序、接收端重传重复投递，且小包持续
// 偷走令牌让队头近似饥饿。
// 锁序论证：全局约定"先 throttle 锁再 hold 锁"（见 PacingTimerDpc 注释）。
// 本函数只拿 s_HoldLock、不碰 throttle 锁；调用点在 classify 快路径判定处，
// 此刻未持任何锁，不存在反序嵌套。
BOOLEAN PacingPidHasHeld(_In_ UINT32 processId)
{
    KIRQL oldIrql;
    UINT32 i;
    BOOLEAN hasHeld = FALSE;

    if (!s_Initialized) {
        return FALSE;
    }
    KeAcquireSpinLock(&s_HoldLock, &oldIrql);
    for (i = 0; i < PACING_MAX_CONTEXTS; i++) {
        if (s_Contexts[i].InUse && s_Contexts[i].ProcessId == processId &&
            !IsListEmpty(&s_Contexts[i].Queue)) {
            hasHeld = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&s_HoldLock, oldIrql);
    return hasHeld;
}

// classify 扣留入口（DISPATCH_LEVEL，INBOUND_IPPACKET 层）。返回 TRUE =
// 已入队，调用方设置 BLOCK + ABSORB；返回 FALSE = 未入队（超限/分配失败/
// 构造失败），调用方设置普通 BLOCK（此时丢弃）。
// 该层 NB 起点 = TCP 头且 DataOffset=0（驱动 43/45 实测），克隆里没有 IP
// 头；收方向构造 API 在 Win10 又不可用（STATUS_DATA_NOT_ACCEPTED，驱动 46
// 实测）——因此自建完整 IP 数据报：手工 IP 头 + 复制 TCP 段到单个非分页
// 缓冲，自建 MDL/NBL 供网络层接收注入。
BOOLEAN PacingHoldPacket(
    _In_ UINT32 processId,
    _In_ BOOLEAN isV6,
    _In_ PNET_BUFFER_LIST originalNbl,
    _In_ UINT32 payloadBytes,
    _In_ const BYTE (*localAddr)[16],   // CfAddrSet 形态（前 4 字节主机序 / 16 字节网络序）
    _In_ const BYTE (*remoteAddr)[16],
    _In_ COMPARTMENT_ID compartmentId,      // 保留参数：注入用 UNSPECIFIED
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_ UINT32 interfaceIndex,     // classify 固定值 INTERFACE_INDEX
    _In_ UINT32 subInterfaceIndex   // classify 固定值 SUB_INTERFACE_INDEX
    )
{
    PPACED_PACKET packet;
    PPACING_CONTEXT ctx;
    PNET_BUFFER nb;
    ULONG nbLen;
    KIRQL oldIrql;
    BOOLEAN created;

    UNREFERENCED_PARAMETER(compartmentId);
    UNREFERENCED_PARAMETER(localAddr);
    UNREFERENCED_PARAMETER(remoteAddr);

    if (!PacingEnabled(isV6)) {
        return FALSE;
    }

    packet = (PPACED_PACKET)ExAllocatePoolWithTag(NonPagedPool, sizeof(PACED_PACKET), PACING_POOL_TAG);
    if (packet == NULL) {
        CfDiagPacingInjectFail();
        return FALSE;
    }
    RtlSecureZeroMemory(packet, sizeof(PACED_PACKET));

    // 注入路径要求单 NB；链化指示按失败丢弃，绝不放行半处理的数据
    nb = NET_BUFFER_LIST_FIRST_NB(originalNbl);
    if (nb == NULL || NET_BUFFER_NEXT_NB(nb) != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] hold-fail multi-nb pid=%u\n", processId);
        goto fail;
    }
    nbLen = NET_BUFFER_DATA_LENGTH(nb);
    // 上限扣掉最大 IPv4 头 60B：扣留注入后数据报 = ipHeaderSize + nbLen，
    // IPv4 总长 / IPv6 载荷长字段均为 16 位，二者之和不得越过 0xFFF0。
    if (nbLen < 21 || nbLen > (0xFFF0 - 60u)) { // 20B TCP 头 + >=1B 载荷
        goto fail;
    }

    // ---- retreat 原始 NBL 露出 IP 头，克隆后再复原（WinDivert 同层同法）----
    // 该层 NB 起点 = TCP 头，IP 头在 NB DataOffset 之前的 headroom 里，
    // metadata 的 ipHeaderSize 给出字节数。注意：headroom 属于原始 NBL，
    // 必须先 retreat 原始 NBL 再克隆（克隆不保留 DataOffset 前的内容，
    // 驱动 59 实测克隆后 retreat 拿到全零）；网络层接收注入要求 NBL 以
    // IP 头开头——用原始 IP 头（地址/校验和天然正确），不自造。
    {
        NTSTATUS retreatStatus;
        NTSTATUS cloneStatus;
        UINT32 ipHdrSize = 0;
        UINT8 ver;

        if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) != 0) {
            ipHdrSize = inMetaValues->ipHeaderSize;
        }
        // 范围校验（不能只认裸头）：IPv4 带选项时 IHL>5（ipHeaderSize 24-60，
        // 4 字节对齐）；IPv6 带扩展头时 ipHeaderSize = 40 + 扩展链长。
        // retreat/advance 与注入都按实际 ipHdrSize 操作，头形态无关。
        if (isV6 ? (ipHdrSize < 40u)
                 : (ipHdrSize < 20u || ipHdrSize > 60u || (ipHdrSize & 3u) != 0)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[CF-PACING] hold-fail iphdr-size=%u v6=%u pid=%u\n",
                ipHdrSize, isV6, processId);
            goto fail;
        }

        retreatStatus = NdisRetreatNetBufferDataStart(nb, ipHdrSize, 0, NULL);
        if (!NT_SUCCESS(retreatStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[CF-PACING] hold-fail retreat 0x%08X size=%u pid=%u\n",
                retreatStatus, ipHdrSize, processId);
            goto fail;
        }
        // 验证首字节确为 IP 版本；失败则复原原始 NBL 放行失败路径
        {
            UINT8* v = (UINT8*)NdisGetDataBuffer(nb, 1, &ver, 1, 0);
            if (v == NULL || (UINT32)(*v >> 4) != (isV6 ? 6u : 4u)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[CF-PACING] hold-fail ver %u v6=%u pid=%u\n",
                    v == NULL ? 0xFFu : (UINT32)(*v >> 4), isV6, processId);
                NdisAdvanceNetBufferDataStart(nb, ipHdrSize, FALSE, NULL);
                goto fail;
            }
        }

        cloneStatus = FwpsAllocateCloneNetBufferList0(originalNbl, NULL, NULL, 0, &packet->Clone);
        // 无论克隆成败，原始 NBL 先复原（classify 返回后栈继续用它）
        NdisAdvanceNetBufferDataStart(nb, ipHdrSize, FALSE, NULL);
        if (!NT_SUCCESS(cloneStatus) || packet->Clone == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[CF-PACING] hold-fail clone 0x%08X pid=%u\n", cloneStatus, processId);
            goto fail;
        }
    }

    // 路由隔间：注入用 UNSPECIFIED_COMPARTMENT_ID（WinDivert 同款），
    // classify 传来的 compartmentId 不再参与注入。
    packet->InterfaceIndex = interfaceIndex;
    packet->SubInterfaceIndex = subInterfaceIndex;
    packet->IsV6 = isV6;
    packet->ProcessId = processId;
    packet->PayloadBytes = payloadBytes;

    // 入队（含内存上限检查）。超限/表满 → 丢弃，此时丢弃是对的。
    KeAcquireSpinLock(&s_HoldLock, &oldIrql);
    ctx = PacingGetContextLocked(processId, &created);
    if (ctx == NULL ||
        s_GlobalQueuedPackets >= 0x7FFFFFFF ||
        s_GlobalQueuedBytes + payloadBytes > PACING_GLOBAL_HOLD_LIMIT ||
        ctx->QueuedBytes + payloadBytes > PACING_PID_HOLD_LIMIT) {
        KeReleaseSpinLock(&s_HoldLock, oldIrql);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] queue-drop pid=%u bytes=%u ctxNull=%u global=%I64u\n",
            processId, payloadBytes, ctx == NULL ? 1u : 0u, s_GlobalQueuedBytes);
        CfDiagPacingQueueDrop();
        PacingFreePacket(packet);
        return FALSE;
    }
    InsertTailList(&ctx->Queue, &packet->Link);
    ctx->PacketCount++;
    ctx->QueuedBytes += payloadBytes;
    s_GlobalQueuedBytes += payloadBytes;
    s_GlobalQueuedPackets++;
    CfDiagPacingQueueDepth(s_GlobalQueuedBytes); // 记录峰值
    KeReleaseSpinLock(&s_HoldLock, oldIrql);

    CfDiagPacingHeld();
    if (InterlockedIncrement64(&s_ProbeHoldSeq) % 32 == 1) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] hold #%I64d pid=%u bytes=%u globalQ=%I64u/%u\n",
            s_ProbeHoldSeq, processId, payloadBytes,
            s_GlobalQueuedBytes, s_GlobalQueuedPackets);
    }
    return TRUE;

fail:
    PacingFreePacket(packet);
    CfDiagPacingInjectFail();
    return FALSE;
}

// 清退：指定 PID 的扣留队列全部立即注入放行（PASSIVE_LEVEL，来自 IOCTL
// 删除限速 / 进程退出通知路径）。限速关闭后包绝不能被永久扣住。
VOID PacingFlushPid(_In_ UINT32 processId)
{
    PPACED_PACKET batch[PACING_DPC_BATCH];
    KIRQL oldIrql;
    UINT32 i, n;
    UINT32 flushed = 0;

    if (!PacingEnabled(TRUE) && !PacingEnabled(FALSE)) {
        return;
    }

    for (;;) {
        n = 0;
        KeAcquireSpinLock(&s_HoldLock, &oldIrql);
        for (i = 0; i < PACING_MAX_CONTEXTS && n < PACING_DPC_BATCH; i++) {
            if (!s_Contexts[i].InUse || s_Contexts[i].ProcessId != processId) {
                continue;
            }
            while (n < PACING_DPC_BATCH && !IsListEmpty(&s_Contexts[i].Queue)) {
                PLIST_ENTRY e = RemoveHeadList(&s_Contexts[i].Queue);
                PPACED_PACKET p = CONTAINING_RECORD(e, PACED_PACKET, Link);
                s_Contexts[i].PacketCount--;
                s_Contexts[i].QueuedBytes -= p->PayloadBytes;
                s_GlobalQueuedBytes -= p->PayloadBytes;
                s_GlobalQueuedPackets--;
                if (s_Contexts[i].PacketCount == 0) {
                    s_Contexts[i].InUse = FALSE;
                    s_Contexts[i].ProcessId = 0;
                }
                batch[n++] = p;
            }
        }
        KeReleaseSpinLock(&s_HoldLock, oldIrql);

        if (n == 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            PacingInjectNow(batch[i]);
            flushed++;
        }
    }

    if (flushed > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[CF-PACING] flush-pid %u packets pid=%u\n", flushed, processId);
    }
}

// 清退：放空全部队列（IOCTL 清表路径；卸载路径用 PacingDrainAll 同实现）。
VOID PacingFlushAll(VOID)
{
    // 实现与 PacingDrainAll 相同（全部 PID 无令牌放行）
    PacingDrainAll();
}

// 卸载收尾（前置：PacingStopTimer 已执行）：放空剩余队列后销毁注入句柄。
// FwpsInjectionHandleDestroy0 会等所有在途注入的完成回调走完，之后本驱动
// 代码才可被卸载。
VOID PacingShutdown(VOID)
{
    if (!s_Initialized) {
        return;
    }
    PacingDrainAll();
    if (s_InjHandleV4 != NULL) {
        FwpsInjectionHandleDestroy0(s_InjHandleV4);
        s_InjHandleV4 = NULL;
    }
    if (s_InjHandleV6 != NULL) {
        FwpsInjectionHandleDestroy0(s_InjHandleV6);
        s_InjHandleV6 = NULL;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[CF-PACING] shutdown done\n");
}
