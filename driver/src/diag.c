// 用户态可读的驱动诊断统计（cfctl diags / IOCTL_GET_DIAGS）。
//
// 动机：FwpsCalloutRegister 失败（尤其 0x80320009 FWP_E_ALREADY_EXISTS
// 僵尸注册）此前只走 DbgPrintEx，VM 无内核调试器时完全不可见，导致
// "V4 流层静默失效"只能靠猜。所有计数器均为 Interlocked 原子操作，
// classify 路径（DISPATCH_LEVEL）与注册路径（PASSIVE_LEVEL）共用安全。

#include "../inc/driver.h"

static CF_DIAGS s_Diags;

VOID CfDiagInit(VOID)
{
    RtlSecureZeroMemory(&s_Diags, sizeof(s_Diags));
    s_Diags.Magic = CF_DIAGS_MAGIC;
    s_Diags.Version = CF_DIAGS_VERSION;
    s_Diags.Size = (UINT32)sizeof(CF_DIAGS);
}

// 槽位 >= CF_DIAG_SLOT_IN_TRANSPORT（12/13）的注册/注销状态落在 v4 尾部的
// 独立数组（保持 0..11 历史槽字节布局不变，见 types.h 注释）。
VOID CfDiagRecordRegister(_In_ UINT32 slot, _In_ NTSTATUS status, _In_ UINT32 calloutId)
{
    if (slot >= CF_DIAG_SLOT_IN_TRANSPORT) {
        UINT32 i = slot - CF_DIAG_SLOT_IN_TRANSPORT;
        if (i >= 2) {
            return;
        }
        InterlockedExchange((volatile LONG*)&s_Diags.InTransportRegStatus[i], (LONG)status);
        InterlockedExchange((volatile LONG*)&s_Diags.InTransportCalloutId[i], (LONG)calloutId);
        return;
    }
    InterlockedExchange((volatile LONG*)&s_Diags.RegStatus[slot], (LONG)status);
    InterlockedExchange((volatile LONG*)&s_Diags.CalloutId[slot], (LONG)calloutId);
}

VOID CfDiagRecordUnregister(_In_ UINT32 slot, _In_ NTSTATUS status, _In_ UINT32 retries)
{
    if (slot >= CF_DIAG_SLOT_IN_TRANSPORT) {
        UINT32 i = slot - CF_DIAG_SLOT_IN_TRANSPORT;
        if (i >= 2) {
            return;
        }
        InterlockedExchange((volatile LONG*)&s_Diags.InTransportUnregStatus[i], (LONG)status);
        InterlockedExchange((volatile LONG*)&s_Diags.InTransportUnregRetries[i], (LONG)retries);
        return;
    }
    InterlockedExchange((volatile LONG*)&s_Diags.UnregStatus[slot], (LONG)status);
    InterlockedExchange((volatile LONG*)&s_Diags.UnregRetries[slot], (LONG)retries);
}

static VOID CfDiagBump(_In_ volatile UINT64* counter)
{
    InterlockedIncrement64((volatile LONG64*)counter);
}

VOID CfDiagClassifyStream(_In_ BOOLEAN isV6)
{
    CfDiagBump(&s_Diags.ClassifyStream[isV6 ? 1 : 0]);
}

VOID CfDiagClassifyFlowEst(_In_ BOOLEAN isV6)
{
    CfDiagBump(&s_Diags.ClassifyFlowEst[isV6 ? 1 : 0]);
}

VOID CfDiagAssoc(_In_ BOOLEAN isV6, _In_ BOOLEAN ok)
{
    if (ok) {
        CfDiagBump(&s_Diags.AssocOk[isV6 ? 1 : 0]);
    } else {
        CfDiagBump(&s_Diags.AssocFail[isV6 ? 1 : 0]);
    }
}

VOID CfDiagFlowDelete(_In_ BOOLEAN isV6)
{
    CfDiagBump(&s_Diags.FlowDelete[isV6 ? 1 : 0]);
}

VOID CfDiagStreamBytes(_In_ BOOLEAN isV6, _In_ UINT32 byteCount)
{
    InterlockedAdd64(
        (volatile LONG64*)&s_Diags.StreamBytesCounted[isV6 ? 1 : 0],
        (LONG64)byteCount);
}

// v3：进程退出通知回调删除限速条目的累计次数（throttle.c 调用）
VOID CfDiagBumpThrottleNotifyRemove(VOID)
{
    InterlockedIncrement((volatile LONG*)&s_Diags.ThrottleNotifyRemoves);
}

// v4：入站传输层（下载限速）classify 与终结判定计数（wfp.c 调用）
VOID CfDiagClassifyInTransport(_In_ BOOLEAN isV6)
{
    CfDiagBump(&s_Diags.InTransportClassify[isV6 ? 1 : 0]);
}

VOID CfDiagInTransportVerdict(_In_ BOOLEAN isV6, _In_ BOOLEAN permitted)
{
    if (permitted) {
        CfDiagBump(&s_Diags.InTransportPermit[isV6 ? 1 : 0]);
    } else {
        CfDiagBump(&s_Diags.InTransportBlock[isV6 ? 1 : 0]);
    }
}

// v5：kernel pacing（克隆-扣留-定时注入）计数器（pacing.c 调用）
VOID CfDiagPacingHeld(VOID)
{
    CfDiagBump(&s_Diags.PacingHeld);
}

VOID CfDiagPacingInjected(VOID)
{
    CfDiagBump(&s_Diags.PacingInjected);
}

VOID CfDiagPacingInjectFail(VOID)
{
    CfDiagBump(&s_Diags.PacingInjectFail);
}

VOID CfDiagPacingQueueDrop(VOID)
{
    CfDiagBump(&s_Diags.PacingQueueDrop);
}

// 记录全局扣留队列深度峰值（非累计：只增不减，取历史最大值）
VOID CfDiagPacingQueueDepth(_In_ UINT64 currentBytes)
{
    UINT64 prev = s_Diags.PacingQueueDepthMax;
    while (currentBytes > prev) {
        UINT64 observed = InterlockedCompareExchange64(
            (volatile LONG64*)&s_Diags.PacingQueueDepthMax, (LONG64)currentBytes, (LONG64)prev);
        if (observed == prev) {
            break;
        }
        prev = observed;
    }
}

VOID CfDiagPacingTimerTick(VOID)
{
    CfDiagBump(&s_Diags.PacingTimerTicks);
}

VOID CfDiagSnapshot(_Out_ PCF_DIAGS out)
{
    // 快照读取无锁：字段独立原子更新，撕裂读最坏让两个计数器短暂不一致，
    // 对诊断用途可接受（避免在 IOCTL 路径引入新锁）。
    // v3 尾部的 ThrottleActiveEntries 不是累计计数，无法预增——快照时锁内
    // 现读限速表活跃条目数。
    s_Diags.ThrottleActiveEntries = ThrottleSnapshotActiveCount();
    RtlCopyMemory(out, &s_Diags, sizeof(CF_DIAGS));
}
