// 流层字节计数（驱动内联统计）
//
// 背景：服务端每 5 秒轮询一次 EStats，毫秒级传完的短连接整个生命周期都落在
// 采集启用之前，字节数永远为 0。这里把逐连接计数下沉到 WFP 数据路径：
//   1. TCP 连接在 ALE 授权放行时（ProcessAleAuth）调用 FwpsFlowAssociateContext0
//      关联一个 FLOW_BYTE_CONTEXT，五元组/PID/进程路径在授权时抓取；
//   2. 流层 classify（StreamThrottleCallout）对流数据原子累加收发字节数；
//   3. flow 删除时 FlowDeleteFn 把累计总量随 NETWORK_EVENT
//      （EventType = NETWORK_EVENT_TYPE_TCP_FLOW_CLOSE）入队上报。
//
// 降级约定：本文件任何失败（内存不足、flowHandle 元数据缺失、关联被拒绝等）
// 都只影响该连接的字节统计，由服务端 EStats 路径兜底，绝不阻断连接放行。

#include "../inc/driver.h"

#define FLOW_CTX_TAG 'tlFC' // 'CFlt'，池标记（小端显示）

// Release 构建里 KdPrint 是空操作，诊断用 DbgPrintEx（限流，防刷屏）
static volatile LONG s_DbgLines = 0;
#define FLOW_DBG(fmt, ...) do { \
    if (InterlockedExchangeAdd(&s_DbgLines, 1) < 64) { \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[CF-FLOW] " fmt "\n", __VA_ARGS__); \
    } \
} while (0)

static VOID FlowCtxFree(_In_ PFLOW_BYTE_CONTEXT ctx)
{
    ExFreePoolWithTag(ctx, FLOW_CTX_TAG);
}

static PFLOW_BYTE_CONTEXT FlowCtxAllocate(VOID)
{
    PFLOW_BYTE_CONTEXT ctx = (PFLOW_BYTE_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(FLOW_BYTE_CONTEXT), FLOW_CTX_TAG);
    if (ctx != NULL) {
        RtlSecureZeroMemory(ctx, sizeof(FLOW_BYTE_CONTEXT));
    }
    return ctx;
}

// ---------------------------------------------------------------------------
// 活跃流登记表（注销泄漏根因修复的核心数据结构）
//
// 背景：FwpsCalloutUnregisterById0 对仍挂着 flow context 的活跃流要逐条
// 同步回调 flowDeleteFn 才能完成注销；实测在活跃流较多时该路径不可靠
// （注销不干净 → 注册残留 → 同 GUID 下一实例 0x80320009 静默失效）。
// 引擎按 flowHandle 标识流上下文，而 flowHandle 只在 classify 元数据里
// 出现一次，此前驱动不保留——卸载路径想主动 FwpsFlowRemoveContext0 也
// 无从下手。这里在每次 FwpsFlowAssociateContext0 成功后把
// (flowHandle, layerId, calloutId, ctx) 登记进固定大小表，FlowDeleteFn
// 里摘除；卸载时 FlowRemoveAllContexts 逐条 FwpsFlowRemoveContext0
// 主动撤上下文（该调用会同步回调 flowDeleteFn → 报数 + 释放 + 摘表），
// 把"等引擎兜底"变成"驱动主动清零"，再注销 callout 就不再被活跃流拖住。
//
// 表满时新流不登记（不阻塞关联）：这些流的上下文退回旧的
// "callout 注销时引擎兜底回调"路径，由 wfp.c 的注销重试兜底。
#define MAX_FLOW_REGISTRY 1024

typedef struct _FLOW_REGISTRY_ENTRY {
    UINT64 FlowHandle;
    UINT16 LayerId;
    UINT32 CalloutId;
    UINT_PTR Context; // 0 = 空槽；非 0 即 FLOW_BYTE_CONTEXT 指针
} FLOW_REGISTRY_ENTRY;

static FLOW_REGISTRY_ENTRY s_FlowRegistry[MAX_FLOW_REGISTRY];
static KSPIN_LOCK s_FlowRegistryLock;
static BOOLEAN s_FlowRegistryInitialized = FALSE;

VOID FlowRegistryInit(VOID)
{
    KeInitializeSpinLock(&s_FlowRegistryLock);
    RtlSecureZeroMemory(s_FlowRegistry, sizeof(s_FlowRegistry));
    s_FlowRegistryInitialized = TRUE;
}

static VOID FlowRegistryAdd(
    _In_ UINT64 flowHandle,
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT_PTR context
)
{
    KIRQL oldIrql;
    UINT32 i;

    if (!s_FlowRegistryInitialized || context == 0) {
        return;
    }

    KeAcquireSpinLock(&s_FlowRegistryLock, &oldIrql);
    for (i = 0; i < MAX_FLOW_REGISTRY; i++) {
        if (s_FlowRegistry[i].Context == 0) {
            s_FlowRegistry[i].FlowHandle = flowHandle;
            s_FlowRegistry[i].LayerId = layerId;
            s_FlowRegistry[i].CalloutId = calloutId;
            s_FlowRegistry[i].Context = context;
            break;
        }
    }
    KeReleaseSpinLock(&s_FlowRegistryLock, oldIrql);
    // 表满：不覆盖（覆盖会把仍活跃的旧流变成不可撤销，比不登记更糟）
}

static VOID FlowRegistryRemove(_In_ UINT_PTR context)
{
    KIRQL oldIrql;
    UINT32 i;

    if (!s_FlowRegistryInitialized || context == 0) {
        return;
    }

    KeAcquireSpinLock(&s_FlowRegistryLock, &oldIrql);
    for (i = 0; i < MAX_FLOW_REGISTRY; i++) {
        if (s_FlowRegistry[i].Context == context) {
            s_FlowRegistry[i].Context = 0;
            break;
        }
    }
    KeReleaseSpinLock(&s_FlowRegistryLock, oldIrql);
}

// 卸载路径专用（PASSIVE_LEVEL）：主动撤销所有已登记的 flow context。
// 必须在 FwpsCalloutUnregisterById0 之前调用（顺序：服务侧清 BFE 过滤器
// → 本函数撤上下文 → callout 注销）。FwpsFlowRemoveContext0 同步调用
// flowDeleteFn（报数 + FlowCtxFree + 摘表），因此这里不能持锁调用——
// 先在锁内摘下表项再出锁调用。若调用时流已自然结束（摘表与调用之间被
// FlowDeleteFn 抢先），返回 STATUS_OBJECT_NAME_NOT_FOUND，属正常竞争。
VOID FlowRemoveAllContexts(VOID)
{
    UINT32 i;
    UINT32 removed = 0;
    UINT32 pass;

    if (!s_FlowRegistryInitialized) {
        return;
    }

    // 复扫兜底：主扫期间 stream callout 尚未注销，并发 classify 可能把新
    // 上下文（FlowRegistryAdd）登进已扫过的槽位。一轮扫完后若表里仍有
    // 非零槽位，再撤一轮；最多 3 轮，或直到某一轮无新增为止。
    for (pass = 0; pass < 3; pass++) {
        BOOLEAN found = FALSE;

        for (i = 0; i < MAX_FLOW_REGISTRY; i++) {
            FLOW_REGISTRY_ENTRY entry;
            KIRQL oldIrql;
            NTSTATUS status;

            KeAcquireSpinLock(&s_FlowRegistryLock, &oldIrql);
            entry = s_FlowRegistry[i];
            s_FlowRegistry[i].Context = 0;
            KeReleaseSpinLock(&s_FlowRegistryLock, oldIrql);

            if (entry.Context == 0) {
                continue;
            }
            found = TRUE;

            status = FwpsFlowRemoveContext0(entry.FlowHandle, entry.LayerId, entry.CalloutId);
            if (NT_SUCCESS(status)) {
                removed++;
            } else {
                // 典型：STATUS_OBJECT_NAME_NOT_FOUND = 流刚好先于我们自然结束
                FLOW_DBG("FwpsFlowRemoveContext0(handle=0x%llX layer=%u) = 0x%08X",
                    entry.FlowHandle, entry.LayerId, status);
            }
        }

        if (!found) {
            break;
        }
    }

    if (removed != 0) {
        KdPrint(("Ceasefire Driver: removed %u flow contexts before callout unregister\n", removed));
    }
}

VOID NTAPI FlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
)
{
    // 本回调有四个触发来源：流正常结束（引擎移除 flow context）、驱动卸载
    // （UnregisterCallouts 注销 callout 时引擎对仍挂着上下文的活跃流的兜底
    // 回调）、驱动卸载前的主动撤销（FlowRemoveAllContexts →
    // FwpsFlowRemoveContext0 同步调到这里），以及注销重试窗口内同一路径的
    // 重放。无论哪条路径都只需在这里上报累计字节并释放上下文——绝不能在
    // FlowDeleteFn 里调用 FwpsFlowRemoveContext0（重入/未定义行为）。
    PFLOW_BYTE_CONTEXT ctx = (PFLOW_BYTE_CONTEXT)(UINT_PTR)flowContext;
    NETWORK_EVENT event;
    UINT64 interruptTime = 0;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    CfDiagFlowDelete(layerId == FWPS_LAYER_STREAM_V6);
    FlowRegistryRemove((UINT_PTR)ctx);

    if (ctx == NULL) {
        return;
    }

    // flow 删除回调运行在 DISPATCH_LEVEL；QueueEvent 内部自旋锁可在此 IRQL 使用。
    RtlSecureZeroMemory(&event, sizeof(NETWORK_EVENT));
    event.Timestamp = KeQueryInterruptTimePrecise(&interruptTime);
    event.EventType = NETWORK_EVENT_TYPE_TCP_FLOW_CLOSE;
    event.ProcessId = ctx->ProcessId;
    RtlCopyMemory(event.ProcessPath, ctx->ProcessPath, sizeof(event.ProcessPath));
    event.Protocol = ctx->Protocol;
    RtlCopyMemory(event.LocalAddr, ctx->LocalAddr, sizeof(event.LocalAddr));
    RtlCopyMemory(event.RemoteAddr, ctx->RemoteAddr, sizeof(event.RemoteAddr));
    event.AddressFamily = ctx->AddressFamily;
    event.LocalPort = ctx->LocalPort;
    event.RemotePort = ctx->RemotePort;
    event.Direction = ctx->Direction;
    event.Allowed = TRUE;      // 该连接已被放行过；close 报数仅用于统计
    event.MatchedRuleId = 0;   // 归因已在 ALE 授权事件完成，避免重复计入规则命中
    // 计数器在 flow 结束后不再有写入者；原子读确保与流层最后一次累加的顺序。
    event.BytesSent = InterlockedOr64((volatile LONG64*)&ctx->BytesSent, 0);
    event.BytesReceived = InterlockedOr64((volatile LONG64*)&ctx->BytesReceived, 0);

    QueueEvent(&event);

    FlowCtxFree(ctx);
}

// ---------------------------------------------------------------------------
// 五元组 → PID 关联表（出站传输层整形的归因数据源）
//
// OUTBOUND_TRANSPORT_V4 的 classify 不带进程元数据、也没有本驱动挂的 flow
// context（上下文挂在流层/flow-established 层）。这里用 ALE flow-established
// 抓到的 (五元组, PID) 建立一张固定大小、轮转覆盖的表，出站传输层按主机序
// 五元组查 PID。表项不主动删除：连接关闭后残留项最多让同五元组的新连接
// 继承旧 PID（端口复用窗口很短），轮转覆盖很快抹掉。
#define MAX_TUPLE_ENTRIES 2048

// 双栈五元组表项：V4 地址按 types.h 顶部形态（首 4 字节主机序 u32，其余 0），
// V6 为 16 字节网络序原样。混族五元组不可能相同，无需额外 family 判断即可
// 正确区分（V4 槽的 4..16 字节恒 0，与任何真实 V6 地址前缀冲突概率为 0——
// 除非 V6 地址本身即 v4-mapped 且后 12 字节一致，仍用 Family 字段显式区分）。
typedef struct _TUPLE_PID_ENTRY {
    UINT32 Family;     // CF_ADDR_FAMILY_*（0 = 空槽）
    BYTE LocalAddr[16];
    UINT16 LocalPort;
    BYTE RemoteAddr[16];
    UINT16 RemotePort;
    UINT32 ProcessId;
} TUPLE_PID_ENTRY;

static TUPLE_PID_ENTRY s_TupleTable[MAX_TUPLE_ENTRIES];
static KSPIN_LOCK s_TupleLock;
static UINT32 s_TupleNext = 0;
static BOOLEAN s_TupleInitialized = FALSE;

VOID FlowTupleInit(VOID)
{
    KeInitializeSpinLock(&s_TupleLock);
    RtlSecureZeroMemory(s_TupleTable, sizeof(s_TupleTable));
    s_TupleNext = 0;
    s_TupleInitialized = TRUE;
}

static BOOLEAN TupleEntryMatches(
    _In_ const TUPLE_PID_ENTRY* entry,
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort
)
{
    return entry->ProcessId != 0 &&
        entry->Family == addressFamily &&
        RtlCompareMemory(entry->LocalAddr, *localAddr, 16) == 16 &&
        entry->LocalPort == localPort &&
        RtlCompareMemory(entry->RemoteAddr, *remoteAddr, 16) == 16 &&
        entry->RemotePort == remotePort;
}

VOID FlowTupleRecordPid(
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort,
    _In_ UINT32 processId
)
{
    KIRQL oldIrql;
    UINT32 i, slot;

    if (!s_TupleInitialized || processId == 0 ||
        (addressFamily != CF_ADDR_FAMILY_V4 && addressFamily != CF_ADDR_FAMILY_V6)) {
        return;
    }

    KeAcquireSpinLock(&s_TupleLock, &oldIrql);

    // 已有同五元组项则刷新 PID
    slot = s_TupleNext;
    for (i = 0; i < MAX_TUPLE_ENTRIES; i++) {
        if (TupleEntryMatches(&s_TupleTable[i], addressFamily, localAddr, localPort, remoteAddr, remotePort)) {
            slot = i;
            break;
        }
    }
    if (slot == s_TupleNext) {
        s_TupleNext = (s_TupleNext + 1) % MAX_TUPLE_ENTRIES;
    }

    s_TupleTable[slot].Family = addressFamily;
    RtlCopyMemory(s_TupleTable[slot].LocalAddr, *localAddr, 16);
    s_TupleTable[slot].LocalPort = localPort;
    RtlCopyMemory(s_TupleTable[slot].RemoteAddr, *remoteAddr, 16);
    s_TupleTable[slot].RemotePort = remotePort;
    s_TupleTable[slot].ProcessId = processId;

    KeReleaseSpinLock(&s_TupleLock, oldIrql);
}

UINT32 FlowTupleLookupPid(
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort
)
{
    KIRQL oldIrql;
    UINT32 i;
    UINT32 pid = 0;

    if (!s_TupleInitialized) {
        return 0;
    }

    // 零成本快路径：没有任何限速条目时查表的 PID 没有消费者（唯一调用方
    // 是出站传输层整形），直接返回 0 放行——不取自旋锁、不扫 2048 槽表。
    // 未限速状态下本函数退化为一次原子读，消除高 pps 下的全表扫描开销。
    if (!ThrottleHasActiveEntries()) {
        return 0;
    }

    KeAcquireSpinLock(&s_TupleLock, &oldIrql);
    for (i = 0; i < MAX_TUPLE_ENTRIES; i++) {
        if (TupleEntryMatches(&s_TupleTable[i], addressFamily, localAddr, localPort, remoteAddr, remotePort)) {
            pid = s_TupleTable[i].ProcessId;
            break;
        }
    }
    KeReleaseSpinLock(&s_TupleLock, oldIrql);
    return pid;
}

UINT32 FlowOnTcpConnectionAllowed(
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_opt_ const void* classifyContext,
    _In_ UINT16 fwpsLayerId,
    _In_ UINT32 calloutId,
    _In_ UINT32 processId,
    _In_ UINT32 protocol,
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort,
    _In_ UINT32 direction,
    _In_ const WCHAR* processPath
)
{
    PFLOW_BYTE_CONTEXT ctx;
    UINT64 classifyHandle = 0;
    NTSTATUS status;
    BOOLEAN isV6 = (fwpsLayerId == FWPS_LAYER_STREAM_V6);

    FLOW_DBG("associate attempt: ctx=%p metaFlags=0x%08llX hasFlowHandle=%d pid=%u",
        classifyContext,
        inMetaValues ? inMetaValues->currentMetadataValues : 0,
        inMetaValues && (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) ? 1 : 0,
        processId);
    // FwpsFlowAssociateContext0 needs only the flowHandle metadata; the
    // classify-handle dance (FwpsAcquire/ReleaseClassifyHandle0) is for
    // injection/pending operations and classifyContext is NULL at the
    // flow-established layer anyway.
    if (inMetaValues == NULL ||
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0) {
        CfDiagAssoc(isV6, FALSE);
        return 7; // no flowHandle metadata
    }

    ctx = FlowCtxAllocate();
    if (ctx == NULL) {
        CfDiagAssoc(isV6, FALSE);
        return 2;
    }

    ctx->BytesSent = 0;
    ctx->BytesReceived = 0;
    ctx->ProcessId = processId;
    ctx->Protocol = protocol;
    RtlCopyMemory(ctx->LocalAddr, *localAddr, sizeof(ctx->LocalAddr));
    RtlCopyMemory(ctx->RemoteAddr, *remoteAddr, sizeof(ctx->RemoteAddr));
    ctx->AddressFamily = addressFamily;
    ctx->LocalPort = localPort;
    ctx->RemotePort = remotePort;
    ctx->Direction = direction;
    if (processPath != NULL) {
        // 内核侧不用 CRT wcsncpy_s；手动限长拷贝并保证 NUL 结尾
        ULONG len = 0;
        while (processPath[len] != L'\0' && len < MAX_PATH_LENGTH - 1) {
            len++;
        }
        RtlCopyMemory(ctx->ProcessPath, processPath, len * sizeof(WCHAR));
        ctx->ProcessPath[len] = L'\0';
    }

    status = FwpsFlowAssociateContext0(
        inMetaValues->flowHandle, fwpsLayerId, calloutId, (UINT_PTR)ctx);
    if (!NT_SUCCESS(status)) {
        // 典型场景：ALE 重鉴权（策略变化）时该流已关联过旧上下文。
        // 旧上下文仍挂在流上并由其 FlowDeleteFn 释放/报数，此处释放新分配即可。
        FLOW_DBG("FwpsFlowAssociateContext0 failed (layer=%u callout=%u): 0x%08X",
            fwpsLayerId, calloutId, status);
        FlowCtxFree(ctx);
        CfDiagAssoc(isV6, FALSE);
        return 4;
    }

    FlowRegistryAdd(inMetaValues->flowHandle, fwpsLayerId, calloutId, (UINT_PTR)ctx);
    CfDiagAssoc(isV6, TRUE);

    FLOW_DBG("flow counting enabled PID=%u layer=%u callout=%u",
        processId, fwpsLayerId, calloutId);
    return 0;
}

// 流层惰性关联：ALE flow-established 层拿到的 flowHandle 与流层使用的
// flow id 在本机实测对不上（重复关联同一 (flow,layer,callout) 不返回
// STATUS_OBJECT_NAME_EXISTS，且流层 classify 始终收到 flowContext=0），
// 因此改为在流层 classify 内部、发现 flowContext==0 时用当次元数据里的
// flowHandle 就地关联——flow id 天然一致，删除回调也随之生效。
UINT32 FlowLazyAssociateAtStream(
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_ UINT16 fwpsLayerId,
    _In_ UINT32 processId,
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort,
    _In_ UINT32 direction,
    _In_ UINT32 calloutId
    )
{
    PFLOW_BYTE_CONTEXT ctx;
    BOOLEAN isV6 = (fwpsLayerId == FWPS_LAYER_STREAM_V6);

    if (inMetaValues == NULL ||
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0) {
        CfDiagAssoc(isV6, FALSE);
        return 7;
    }

    ctx = FlowCtxAllocate();
    if (ctx == NULL) {
        CfDiagAssoc(isV6, FALSE);
        return 2;
    }

    ctx->ProcessId = processId;
    ctx->Protocol = PROTOCOL_TCP;
    RtlCopyMemory(ctx->LocalAddr, *localAddr, sizeof(ctx->LocalAddr));
    RtlCopyMemory(ctx->RemoteAddr, *remoteAddr, sizeof(ctx->RemoteAddr));
    ctx->AddressFamily = addressFamily;
    ctx->LocalPort = localPort;
    ctx->RemotePort = remotePort;
    ctx->Direction = direction;
    ctx->ProcessPath[0] = L'\0'; // 流层拿不到进程路径，服务按五元组归因

    // 不在此处登记五元组→PID：惰性关联拿到的 processId 可能为 0（空转），
    // 且 ALE_AUTH_CONNECT / flow-established 两处已覆盖登记（见 wfp.c）。

    if (!NT_SUCCESS(FwpsFlowAssociateContext0(
            inMetaValues->flowHandle, fwpsLayerId, calloutId,
            (UINT_PTR)ctx))) {
        FlowCtxFree(ctx);
        CfDiagAssoc(isV6, FALSE);
        return 4;
    }
    FlowRegistryAdd(inMetaValues->flowHandle, fwpsLayerId, calloutId, (UINT_PTR)ctx);
    CfDiagAssoc(isV6, TRUE);
    return 0;
}

VOID FlowCountStreamBytes(
    _In_ UINT64 flowContext,
    _In_ BOOLEAN outbound,
    _In_ UINT32 byteCount
)
{
    PFLOW_BYTE_CONTEXT ctx = (PFLOW_BYTE_CONTEXT)(UINT_PTR)flowContext;

    if (byteCount == 0 || ctx == NULL) {
        return;
    }

    // classify 运行在 DISPATCH_LEVEL 左右，计数必须走 InterlockedXxx 原子操作。
    if (outbound) {
        InterlockedAdd64((volatile LONG64*)&ctx->BytesSent, (LONG64)byteCount);
    } else {
        InterlockedAdd64((volatile LONG64*)&ctx->BytesReceived, (LONG64)byteCount);
    }
}
