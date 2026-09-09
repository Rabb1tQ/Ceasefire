#include "../inc/driver.h"

// Real per-process rate limiting (feature 5).
//
// A token bucket per throttled process (plus one optional global bucket,
// ProcessId == 0) is enforced at FWPM_LAYER_STREAM_V4: when the bucket for
// the stream's direction is empty the indicated TCP segment is blocked, so
// the sender retransmits and backs off -- the configured rate becomes real
// enforced throughput. Buckets are managed from user mode via
// IOCTL_SET_THROTTLE; classification runs at DISPATCH_LEVEL, so everything
// here is non-paged and guarded by a spin lock.

#define MAX_THROTTLE_ENTRIES 256

// 桶容量下限：独立于速率。历史实现桶容量 = 1 秒速率，当速率 < 一个 MSS
//（TCP 常见 1460 字节）时，出站放行与 pacing 出队都要求一次性攒够整段
// 字节数，队头永远等不满 → 队列顶满丢弃、出站全 BLOCK（低速率死锁）。
// 容量取 max(Rate, 1600)（MSS + 余量）后，低速率也能随时间攒出一个 MSS；
// 消费判据（Tokens >= 整段字节）不变，保持 pacing 语义。
#define THROTTLE_MIN_BUCKET_CAPACITY 1600

// 桶容量 = max(Rate, THROTTLE_MIN_BUCKET_CAPACITY)
static UINT64 ThrottleBucketCapacity(_In_ UINT64 rateBps)
{
    return rateBps > THROTTLE_MIN_BUCKET_CAPACITY
        ? rateBps
        : THROTTLE_MIN_BUCKET_CAPACITY;
}

// Bucket capacity equals one second of the configured rate (bounded burst),
// refilled continuously with KeQueryInterruptTime (100ns units).
typedef struct _THROTTLE_ENTRY {
    BOOLEAN InUse;
    UINT32 ProcessId;     // 0 = global entry (applies to every TCP stream)
    UINT64 RateUpBps;     // bytes/sec; 0 = unlimited in that direction
    UINT64 RateDownBps;
    UINT64 TokensUp;      // currently available bytes
    UINT64 TokensDown;
    UINT64 LastRefill;    // KeQueryInterruptTime, 100ns units
} THROTTLE_ENTRY;

static THROTTLE_ENTRY s_Entries[MAX_THROTTLE_ENTRIES];
static KSPIN_LOCK s_Lock;
static BOOLEAN s_Initialized = FALSE;

// 当前 InUse 表项数（近似值，锁内增减维护）。唯一的读者是
// FlowTupleLookupPid 的零成本快路径：计数为 0 时必然无任何限速条目，
// 五元组表查出的 PID 再准确也没有消费者，直接放行即可。竞态方向安全：
// 读到偏小的旧值至多多放行一个段，下一段就会看到新条目。
static volatile LONG s_ActiveCount = 0;

VOID ThrottleInit(VOID)
{
    KeInitializeSpinLock(&s_Lock);
    RtlSecureZeroMemory(s_Entries, sizeof(s_Entries));
    s_Initialized = TRUE;
    KdPrint(("Ceasefire Driver: throttle table initialized (%u slots)\n", MAX_THROTTLE_ENTRIES));
}

VOID ThrottleClearAll(VOID)
{
    KIRQL oldIrql;
    if (!s_Initialized) {
        return;
    }
    KeAcquireSpinLock(&s_Lock, &oldIrql);
    RtlSecureZeroMemory(s_Entries, sizeof(s_Entries));
    // 必须在锁内清零：否则先放锁再清零的窗口里并发的 ThrottleSetEntry
    // 刚加上的条目会被这里的清零掩盖（计数 0 但表里有条目），快路径会
    // 永久放行本该限速的流量。
    InterlockedExchange(&s_ActiveCount, 0);
    KeReleaseSpinLock(&s_Lock, oldIrql);

    // kernel pacing 清退：清表的同时放空全部扣留队列（限速关闭后包绝不
    // 能被永久扣住）。PASSIVE_LEVEL 路径；卸载路径由 PacingStopTimer 先行
    // 停掉放行定时器，注入无竞争。
    PacingFlushAll();
    KdPrint(("Ceasefire Driver: throttle table cleared\n"));
}

static VOID RefillEntry(_Inout_ THROTTLE_ENTRY* entry, _In_ UINT64 now);

// IOCTL_SET_THROTTLE handler (PASSIVE_LEVEL). Setting both rates to 0 removes
// the entry. ProcessId 0 is the global entry and obeys the same rule: (0,0,0)
// removes only the pid-0 entry -- it never clears other entries (the whole
// table is cleared via IOCTL_CLEAR_THROTTLE / ThrottleClearAll).
NTSTATUS ThrottleSetEntry(_In_ PTHROTTLE_INPUT input)
{
    KIRQL oldIrql;
    UINT32 i;
    THROTTLE_ENTRY* slot = NULL;
    BOOLEAN wasActive;


    if (!s_Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&s_Lock, &oldIrql);

    // Exact PID match wins; the global entry lives in its own slot (pid 0).
    for (i = 0; i < MAX_THROTTLE_ENTRIES; i++) {
        if (s_Entries[i].InUse && s_Entries[i].ProcessId == input->ProcessId) {
            slot = &s_Entries[i];
            break;
        }
    }
    if (slot == NULL && (input->RateUpBps != 0 || input->RateDownBps != 0)) {
        for (i = 0; i < MAX_THROTTLE_ENTRIES; i++) {
            if (!s_Entries[i].InUse) {
                slot = &s_Entries[i];
                break;
            }
        }
    }

    if (slot == NULL) {
        KeReleaseSpinLock(&s_Lock, oldIrql);
        if (input->RateUpBps == 0 && input->RateDownBps == 0) {
            // 幂等删除：对不存在的 PID 下发删除视为成功（进程退出通知回调
            // 可能已抢先清掉该条目，服务侧撤回晚到属正常时序，不能报错刷屏）。
            // 只有"要新增但表真满"才走下面的资源不足错误。
            KdPrint(("Ceasefire Driver: throttle remove for absent PID %u (idempotent)\n", input->ProcessId));
            return STATUS_SUCCESS;
        }
        KdPrint(("Ceasefire Driver: throttle table full, cannot add PID %u\n", input->ProcessId));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (input->RateUpBps == 0 && input->RateDownBps == 0) {
        // Removing an existing entry
        wasActive = slot->InUse;
        RtlSecureZeroMemory(slot, sizeof(THROTTLE_ENTRY));
        if (wasActive) {
            InterlockedDecrement(&s_ActiveCount);
        }
        KeReleaseSpinLock(&s_Lock, oldIrql);
        // kernel pacing 清退：限速条目被删除时立即放行该 PID 的全部扣留包
        PacingFlushPid(input->ProcessId);
        KdPrint(("Ceasefire Driver: throttle entry removed for PID %u\n", input->ProcessId));
        return STATUS_SUCCESS;
    }

    wasActive = slot->InUse;
    if (!wasActive) {
        // 从空闲槽新建条目（复用已有条目只更新速率，计数不变）
        slot->InUse = TRUE;
        InterlockedIncrement(&s_ActiveCount);
    }
    {
        UINT64 now = KeQueryInterruptTime();

        if (wasActive) {
            // 更新已有条目：先按旧速率结算流逝时间（RefillEntry 依赖旧
            // Rate 字段，必须在覆盖前调用），保留现有令牌并夹到新容量——
            // 改速率不回满桶重置，避免每次调速率凭空补满突发。
            RefillEntry(slot, now);
        }

        slot->ProcessId = input->ProcessId;
        slot->RateUpBps = input->RateUpBps;
        slot->RateDownBps = input->RateDownBps;

        if (wasActive) {
            UINT64 capUp = ThrottleBucketCapacity(slot->RateUpBps);
            UINT64 capDown = ThrottleBucketCapacity(slot->RateDownBps);
            if (slot->TokensUp > capUp) {
                slot->TokensUp = capUp;
            }
            if (slot->TokensDown > capDown) {
                slot->TokensDown = capDown;
            }
        } else {
            // 新条目：初始满桶 = min(Rate, 容量) = Rate（容量 >= 恒成立），
            // 与旧语义一致——新限速进程首秒不空转。
            slot->TokensUp = input->RateUpBps;
            slot->TokensDown = input->RateDownBps;
        }
        slot->LastRefill = now;
    }

    KeReleaseSpinLock(&s_Lock, oldIrql);

    KdPrint(("Ceasefire Driver: throttle entry set: PID=%u up=%u B/s down=%u B/s\n",
        input->ProcessId, input->RateUpBps, input->RateDownBps));
    return STATUS_SUCCESS;
}

static VOID RefillEntry(_Inout_ THROTTLE_ENTRY* entry, _In_ UINT64 now)
{
    UINT64 elapsed;
    UINT64 addUp = 0, addDown = 0;

    if (now <= entry->LastRefill) {
        return;
    }
    elapsed = now - entry->LastRefill;

    if (entry->RateUpBps > 0) {
        UINT64 capUp = ThrottleBucketCapacity(entry->RateUpBps);
        if (entry->TokensUp < capUp) {
            addUp = (entry->RateUpBps * elapsed) / 10000000ULL; // 100ns -> seconds
            if (addUp > capUp - entry->TokensUp) {
                addUp = capUp - entry->TokensUp; // clamp to burst cap
            }
        }
    }
    if (entry->RateDownBps > 0) {
        UINT64 capDown = ThrottleBucketCapacity(entry->RateDownBps);
        if (entry->TokensDown < capDown) {
            addDown = (entry->RateDownBps * elapsed) / 10000000ULL;
            if (addDown > capDown - entry->TokensDown) {
                addDown = capDown - entry->TokensDown;
            }
        }
    }

    // Skip updating LastRefill when nothing refilled (both directions
    // unlimited or full): keeps fractional accumulation accurate.
    if (addUp == 0 && addDown == 0) {
        return;
    }

    entry->TokensUp += addUp;
    entry->TokensDown += addDown;
    entry->LastRefill = now;
}

// 五元组查表（FlowTupleLookupPid）前的零成本快路径：没有任何限速条目时
// 调用方可直接放行，不取自旋锁、不扫 2048 槽表。InterlockedOr(x, 0) 是
// 无锁原子读，DLC 以下任意 IRQL 可用。
BOOLEAN ThrottleHasActiveEntries(VOID)
{
    return s_Initialized && InterlockedOr(&s_ActiveCount, 0) != 0;
}

// 进程退出通知回调使用：把该 PID 的全部条目清掉（正常至多 1 条，但按可能
// 多条写，循环不提前退出）。回调运行在 PASSIVE_LEVEL，这里只碰本文件自有的
// 自旋锁；取锁前先用无锁快路径过滤，无条目时不付取锁开销。
VOID ThrottleRemoveByPid(_In_ UINT32 pid)
{
    KIRQL oldIrql;
    UINT32 i;
    LONG removed = 0;

    if (!s_Initialized || !ThrottleHasActiveEntries()) {
        return;
    }

    KeAcquireSpinLock(&s_Lock, &oldIrql);
    for (i = 0; i < MAX_THROTTLE_ENTRIES; i++) {
        if (s_Entries[i].InUse && s_Entries[i].ProcessId == pid) {
            RtlSecureZeroMemory(&s_Entries[i], sizeof(THROTTLE_ENTRY));
            removed++;
        }
    }
    if (removed > 0) {
        InterlockedExchangeAdd(&s_ActiveCount, -removed);
    }
    KeReleaseSpinLock(&s_Lock, oldIrql);

    if (removed > 0) {
        // kernel pacing 清退：进程退出时限速条目随表清掉，扣留队列同步放行
        //（死 PID 的扣留包已无消费者，注入是唯一正确去向）。
        PacingFlushPid(pid);
        KdPrint(("Ceasefire Driver: process-exit removed %d throttle entries for PID %u\n", removed, pid));
        CfDiagBumpThrottleNotifyRemove();
    }
}

// diag v3：ThrottleActiveEntries 在快照时刻锁内读取
UINT32 ThrottleSnapshotActiveCount(VOID)
{
    KIRQL oldIrql;
    UINT32 count;

    if (!s_Initialized) {
        return 0;
    }
    KeAcquireSpinLock(&s_Lock, &oldIrql);
    count = (UINT32)InterlockedOr(&s_ActiveCount, 0);
    KeReleaseSpinLock(&s_Lock, oldIrql);
    return count;
}

// Stream-layer classify decision. Returns TRUE when the indicated data is
// permitted, FALSE when the bucket is exhausted (segment should be blocked).
// When neither a per-process nor a global entry exists, always TRUE.
BOOLEAN ThrottleCheck(
    _In_ UINT32 processId,
    _In_ BOOLEAN outbound,
    _In_ UINT32 byteCount
)
{
    KIRQL oldIrql;
    UINT32 i;
    THROTTLE_ENTRY* specific = NULL;
    THROTTLE_ENTRY* globalEntry = NULL;
    THROTTLE_ENTRY* entry;
    UINT64 now;
    BOOLEAN permitted = TRUE;

    if (!s_Initialized) {
        return TRUE;
    }

    KeAcquireSpinLock(&s_Lock, &oldIrql);

    for (i = 0; i < MAX_THROTTLE_ENTRIES; i++) {
        if (!s_Entries[i].InUse) {
            continue;
        }
        if (s_Entries[i].ProcessId == processId) {
            specific = &s_Entries[i];
        } else if (s_Entries[i].ProcessId == 0) {
            globalEntry = &s_Entries[i];
        }
    }

    // A per-process entry overrides the global one.
    entry = specific != NULL ? specific : globalEntry;
    if (entry != NULL) {
        now = KeQueryInterruptTime();
        RefillEntry(entry, now);

        if (outbound && entry->RateUpBps > 0) {
            if (entry->TokensUp >= byteCount) {
                entry->TokensUp -= byteCount;
            } else {
                permitted = FALSE;
            }
        } else if (!outbound && entry->RateDownBps > 0) {
            if (entry->TokensDown >= byteCount) {
                entry->TokensDown -= byteCount;
            } else {
                permitted = FALSE;
            }
        }
    }

    KeReleaseSpinLock(&s_Lock, oldIrql);
    return permitted;
}
