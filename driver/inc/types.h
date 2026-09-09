#pragma once

#include <ntddk.h>
#include "common.h"

// 地址族常量（与 service/src/driver/converter.rs 双栈约定一致）
#define CF_ADDR_FAMILY_V4    4
#define CF_ADDR_FAMILY_V6    6
#define CF_ADDR_FAMILY_NONE  0 // 旧驱动/通配

// 双栈地址的统一内存形态（所有跨层结构共用，务必保持一致）：
//   * family = V4：Byte[0..4] 存放 ALE/传输层固定值里的"主机序 UINT32"
//     按本机字节序原样拷贝（等价于旧结构的 UINT32 LocalAddr 位形态），
//     Byte[4..16] 全 0。V4 不转 v4-mapped、不做字节交换——与旧 32 位
//     语义逐位相同，避免第二套换算规则。
//   * family = V6：Byte[0..16] 为 FWP_BYTE_ARRAY16 的 16 字节网络序
//     原样值（无字节交换问题）。
//   * 比较规则：结构内不允许混族比较；掩码比较按 family 分派。

static __inline VOID CfAddrSetV4(_Out_ BYTE (*addr)[16], _In_ UINT32 v4HostOrder)
{
    RtlCopyMemory(addr, &v4HostOrder, sizeof(UINT32));
    RtlZeroMemory((BYTE*)addr + sizeof(UINT32), 16 - sizeof(UINT32));
}

static __inline VOID CfAddrSetV6(_Out_ BYTE (*addr)[16], _In_ const FWP_BYTE_ARRAY16* value)
{
    RtlCopyMemory(addr, value->byteArray16, 16);
}

static __inline BOOLEAN CfAddrIsZero(_In_ const BYTE* addr)
{
    // pack(1) 结构里地址可能非 8 字节对齐，经 memcpy 读取避免未对齐解引用
    UINT64 lo, hi;
    RtlCopyMemory(&lo, addr, sizeof(UINT64));
    RtlCopyMemory(&hi, addr + sizeof(UINT64), sizeof(UINT64));
    return (lo | hi) == 0;
}

// Firewall rule (kernel representation)
// Direction values (wire values shared with service converter.rs):
// 0=Both/any, 1=Inbound, 2=Outbound
#define RULE_DIRECTION_BOTH    0
#define RULE_DIRECTION_IN      1
#define RULE_DIRECTION_OUT     2

typedef struct _FIREWALL_RULE {
    UINT32 RuleId;
    UINT32 Priority;
    BOOLEAN Enabled;
    BOOLEAN IsAllow;  // TRUE=allow, FALSE=block
    UINT32 Direction; // RULE_DIRECTION_*

    // Match conditions (0 means wildcard)
    UINT32 ProcessId;
    WCHAR ProcessPath[MAX_PATH_LENGTH];
    UINT32 Protocol;  // IPPROTO_TCP, IPPROTO_UDP, 0=any

    // 远端地址条件：RemoteAddr 全 0 = 任意地址（不看 family/掩码）
    BYTE RemoteAddr[16];      // 形态见文件顶部双栈约定
    BYTE RemoteAddrMask[16];  // 与 RemoteAddr 同族同形态
    UINT32 AddressFamily;     // CF_ADDR_FAMILY_*

    UINT16 RemotePort;        // 区间起点（与 RemotePortEnd 组成区间；0/0 = 通配）
    UINT16 LocalPort;
    UINT16 RemotePortEnd;     // 端口区间终点（单端口 = 起点；0 且起点 0 = 通配）
    UINT16 LocalPortEnd;

    LIST_ENTRY ListEntry;
} FIREWALL_RULE, *PFIREWALL_RULE;

// Network event (reported to service layer)
// Must match service/src/driver/converter.rs DriverEvent structure exactly!
#pragma pack(push, 1)  // Pack structure to 1-byte alignment to eliminate padding
// Event types carried in NETWORK_EVENT.EventType (offset 12, formerly zeroed
// padding). Legacy drivers always wrote 0 there, so 0 keeps its old meaning.
#define NETWORK_EVENT_TYPE_CONNECTION     0 // ALE 授权事件（建立/拦截），历史含义
#define NETWORK_EVENT_TYPE_TCP_FLOW_CLOSE 1 // TCP flow 删除时的字节总量上报

typedef struct _NETWORK_EVENT {
    UINT64 Timestamp;           // 8 bytes, offset 0
    UINT32 ProcessId;           // 4 bytes, offset 8
    UINT32 EventType;           // 4 bytes, offset 12 (NETWORK_EVENT_TYPE_*)
    WCHAR ProcessPath[MAX_PATH_LENGTH];  // 520 bytes (260*2), offset 16
    UINT32 Protocol;            // 4 bytes, offset 536
    BYTE LocalAddr[16];         // 16 bytes, offset 540（双栈形态见文件顶部）
    BYTE RemoteAddr[16];        // 16 bytes, offset 556
    UINT16 LocalPort;           // 2 bytes, offset 572
    UINT16 RemotePort;          // 2 bytes, offset 574
    BOOLEAN Allowed;            // 1 byte, offset 576
    BYTE _Padding3;             // 1 byte, offset 577
    UINT32 MatchedRuleId;       // 4 bytes, offset 578
    UINT64 BytesSent;           // 8 bytes, offset 582
    UINT64 BytesReceived;       // 8 bytes, offset 590
    UINT32 AddressFamily;       // 4 bytes, offset 598 (CF_ADDR_FAMILY_*)
    UINT32 Direction;           // 4 bytes, offset 602 (RULE_DIRECTION_*; 0 for legacy events)
} NETWORK_EVENT, *PNETWORK_EVENT;  // Total: 606 bytes
#pragma pack(pop)

// Per-connection byte counters attached to a TCP data flow via
// FwpsFlowAssociateContext0. Allocated at ALE authorization time, accumulated
// atomically at the stream layer, and reported in one NETWORK_EVENT with
// EventType = NETWORK_EVENT_TYPE_TCP_FLOW_CLOSE when the flow is deleted.
typedef struct _FLOW_BYTE_CONTEXT {
    volatile UINT64 BytesSent;           // outbound stream bytes (InterlockedAdd64)
    volatile UINT64 BytesReceived;       // inbound stream bytes
    UINT32 ProcessId;
    UINT32 Protocol;
    BYTE LocalAddr[16];                  // 双栈形态见 types.h 顶部约定
    BYTE RemoteAddr[16];
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT32 AddressFamily;                // CF_ADDR_FAMILY_*
    UINT32 Direction;                    // RULE_DIRECTION_IN / RULE_DIRECTION_OUT
    WCHAR ProcessPath[MAX_PATH_LENGTH];  // captured at authorize time (metadata is gone by flow-delete time)
} FLOW_BYTE_CONTEXT, *PFLOW_BYTE_CONTEXT;

// DNS event (for DNS response capture) - separate event type
typedef struct _DNS_EVENT {
    UINT64 Timestamp;
    UINT32 ProcessId;
    BYTE RemoteAddr[16];  // DNS 服务器地址（双栈形态见 types.h 顶部约定）
    UINT32 AddressFamily; // CF_ADDR_FAMILY_*
    UINT16 DataLength;
    BYTE Data[512];  // DNS packet data (max 512 bytes for UDP)
} DNS_EVENT, *PDNS_EVENT;

// IOCTL input/output structures
typedef struct _RULE_INPUT {
    UINT32 RuleId;
    UINT32 Priority;
    BOOLEAN Enabled;
    BOOLEAN IsAllow;
    UINT32 ProcessId;
    WCHAR ProcessPath[MAX_PATH_LENGTH];
    UINT32 Protocol;
    BYTE RemoteAddr[16];      // 双栈形态见 types.h 顶部约定
    BYTE RemoteAddrMask[16];
    UINT32 AddressFamily;     // CF_ADDR_FAMILY_*
    UINT16 RemotePort;        // 区间起点（与 RemotePortEnd 组成区间；0/0 = 通配）
    UINT16 LocalPort;
    UINT32 Direction;         // RULE_DIRECTION_*  — offset 580
    UINT16 RemotePortEnd;     // 端口区间终点（单端口 = 起点；0 且起点 0 = 通配）— offset 584
    UINT16 LocalPortEnd;      // offset 586
} RULE_INPUT, *PRULE_INPUT;   // Total: 588 bytes（与 service DriverRuleInput 一致）

typedef struct _RULE_ID_INPUT {
    UINT32 RuleId;
} RULE_ID_INPUT, *PRULE_ID_INPUT;

// Per-process stream-layer throttle entry (IOCTL_SET_THROTTLE input).
// Wire layout shared with service DriverThrottleInput (repr(C), 12 bytes).
// ProcessId 0 = the global entry; both rates 0 removes the entry (including
// the pid-0 global entry itself -- it never clears other entries). Clearing
// the whole table is IOCTL_CLEAR_THROTTLE's job.
typedef struct _THROTTLE_INPUT {
    UINT32 ProcessId;
    UINT32 RateUpBps;    // bytes/sec; 0 = no limit in this direction
    UINT32 RateDownBps;
} THROTTLE_INPUT, *PTHROTTLE_INPUT;

// ---------------------------------------------------------------------------
// 驱动诊断统计（IOCTL_GET_DIAGS 输出）。
//
// 背景：V4 流层字节计数完全失效而 V6 正常、BFE 侧 callout/过滤器却完全
// 对称——嫌疑在驱动运行时状态（FwpsCalloutRegister 对 V4 流层实际返回
// FWP_E_ALREADY_EXISTS（僵尸注册）时旧代码只走 DbgPrint，用户态不可见）。
// 本结构把关键运行时状态暴露给服务/cfctl：
//   * RegStatus/CalloutId：12 个 callout 的注册返回码（NTSTATUS，0=成功）
//     与最终 calloutId（0=失败，该层本会话完全静默失效）；
//   * Classify*/Assoc*/FlowDelete/StreamBytes：按层运行计数器，用于区分
//     "classify 根本没被调起"（过滤器/weight 问题）与"被调起但归因/关联
//     失败"（驱动逻辑问题）。
//
// 布局约定：自然对齐（非 pack），与服务侧 DriverDiagsRaw（repr(C)）逐字段
// 一致；RegStatus 数组下标 = CF_DIAG_SLOT_*。
// ---------------------------------------------------------------------------
#define CF_DIAGS_MAGIC   0x30474944 // "DIG0"
// v2：新增 UnregStatus/UnregRetries（见结构体尾部注释）。服务侧按 Version
// 门控：v1 驱动（Size 更小）读出的尾部字段保持为 0。
// v3：尾部再追加 ThrottleActiveEntries/ThrottleNotifyRemoves 两个 UINT32
//（限速表进程退出清理，见结构体尾部注释）。服务侧 Version < 3 时同样把
// v3 尾部显式清零。
// v4：尾部再追加入站传输层（下载限速）classify/verdict 计数器（见结构体
// 尾部注释）。服务侧 Version < 4 时同样把 v4 尾部显式清零。
// v5：尾部再追加 kernel pacing（第 18 轮，克隆-扣留-定时注入）计数器
//（见结构体尾部注释）。服务侧 Version < 5 时同样把 v5 尾部显式清零。
#define CF_DIAGS_VERSION 5

// 槽位布局：0..5 为 V4 六层、6..11 为 V6 六层（历史布局，0..11 的下标与
// 数组前 12 项严格不变——服务侧旧版本按 0..11 解析仍完全正确）；12/13 为
// 新增的入站传输层（下载限速）槽位。为保持 CF_DIAGS 追加式演进（v1→v2→
// v3 都只在尾部追加，老驱动回填短布局时尾部保持零），12/13 不扩历史数组，
// 而是落在 v4 尾部的独立数组 InTransportReg* 里（diag.c 内做映射）。
#define CF_DIAG_SLOT_ALE_CONNECT       0
#define CF_DIAG_SLOT_RECV_ACCEPT       1
#define CF_DIAG_SLOT_DNS               2
#define CF_DIAG_SLOT_STREAM            3
#define CF_DIAG_SLOT_FLOW_ESTABLISHED  4
#define CF_DIAG_SLOT_OUT_TRANSPORT     5
#define CF_DIAG_SLOT_V6_BASE           6 // V6 各层 = 对应 V4 slot + 6
#define CF_DIAG_SLOT_IN_TRANSPORT      12 // 入站传输层（下载限速）；存于 v4 尾部数组
#define CF_DIAG_SLOT_IN_TRANSPORT_V6   13
#define CF_DIAG_SLOT_COUNT             12 // 历史数组仍为 12 槽；12/13 见上

typedef struct _CF_DIAGS {
    UINT32 Magic;                          // CF_DIAGS_MAGIC
    UINT32 Version;                        // CF_DIAGS_VERSION
    UINT32 Size;                           // sizeof(CF_DIAGS)
    UINT32 Reserved;
    UINT32 RegStatus[CF_DIAG_SLOT_COUNT];  // FwpsCalloutRegister NTSTATUS（0=成功；0x80320009=僵尸注册）
    UINT32 CalloutId[CF_DIAG_SLOT_COUNT];  // 最终 calloutId（0=注册失败）
    // 运行计数器：[0]=V4、[1]=V6。classify 计数在对应 Common 入口累加
    volatile UINT64 ClassifyStream[2];     // STREAM_V4/V6 classify 次数
    volatile UINT64 ClassifyFlowEst[2];    // ALE_FLOW_ESTABLISHED classify 次数
    volatile UINT64 AssocOk[2];            // FwpsFlowAssociateContext0 成功（flow-established + 惰性关联）
    volatile UINT64 AssocFail[2];
    volatile UINT64 FlowDelete[2];         // FlowDeleteFn 回调次数（=产出 Close 报数事件数）
    volatile UINT64 StreamBytesCounted[2]; // FlowCountStreamBytes 累计字节
    // v2 追加：卸载路径 FwpsCalloutUnregisterById0 的最终返回码与重试次数
    //（UnregRetries = 失败尝试次数，0 = 一次成功）。UnregStatus != 0 即本次
    // 卸载泄漏了该层注册——下一个同 GUID 实例的 RegStatus 会出现
    // 0x80320009 且该层整会话静默失效，两者对照即可确认因果。
    // 注意：CfDiagInit 在 DriverEntry 清零，因此本字段只在"驱动仍处于
    // 上一次加载的会话"内可读（正常 sc stop 后设备已消失，主要靠
    // UnregisterCalloutByIdChecked 的 DbgPrintEx 留痕；本字段服务于
    // 注销部分失败但驱动未卸载干净的病态会话诊断）。
    UINT32 UnregStatus[CF_DIAG_SLOT_COUNT];  // 最终注销返回码（0=成功）
    UINT32 UnregRetries[CF_DIAG_SLOT_COUNT]; // 注销失败重试次数
    // v3 追加：限速表进程生命周期清理计数。
    // ThrottleActiveEntries：快照时刻限速表 InUse 条目数（锁内读）；
    // ThrottleNotifyRemoves：PsSetCreateProcessNotifyRoutine 回调因进程退出
    // 而删除限速条目的累计次数（InterlockedIncrement 维护，本会话内有效，
    // CfDiagInit 在 DriverEntry 清零）。
    UINT32 ThrottleActiveEntries;            // 快照时刻活跃限速条目数
    UINT32 ThrottleNotifyRemoves;            // 进程退出清理累计次数
    // v4 追加：入站传输层（下载限速 drop-to-throttle）运行计数器，
    // [0]=V4、[1]=V6。Classify 在 InboundIpPacketThrottleCommon 入口累加
    //（第 19 轮起下载限速执行点在 INBOUND_IPPACKET 层）；
    // Permit/Block 在每次终结决策（含无法归因/纯 ACK 放行）时累加，
    // Classify - (Permit + Block) 的差值 = 提前返回（非 TCP/无写权）次数。
    volatile UINT64 InTransportClassify[2];
    volatile UINT64 InTransportPermit[2];
    volatile UINT64 InTransportBlock[2];
    // v4 追加：入站传输层两个 callout（[0]=V4 slot12、[1]=V6 slot13）的
    // 注册/注销状态，语义与上方 RegStatus*/Unreg* 数组相同。独立成组放在
    // 尾部以保持 0..11 历史槽的字节布局逐位不变。
    UINT32 InTransportRegStatus[2];
    UINT32 InTransportCalloutId[2];
    UINT32 InTransportUnregStatus[2];
    UINT32 InTransportUnregRetries[2];
    // v5 追加：kernel pacing（克隆-扣留-定时注入，下载限速的执行手段）。
    // held：进入扣留队列的包数（classify 扣留成功）；injected：注入成功
    // （同步成功且完成回调 Status 成功）；injectFail：注入失败（含克隆/
    // 回退/重建失败、同步失败、完成回调失败——当丢包处理）；queueDrop：
    // 超限丢弃（每 PID 512KB / 全局 4MB 上限）；queueDepthMax：全局扣留
    // 峰值字节数；timerTicks：放行引擎 DPC 触发次数。
    // 恒等式：injected ≈ held - queueDrop - injectFail。
    volatile UINT64 PacingHeld;
    volatile UINT64 PacingInjected;
    volatile UINT64 PacingInjectFail;
    volatile UINT64 PacingQueueDrop;
    volatile UINT64 PacingQueueDepthMax;   // 峰值（非累计）
    volatile UINT64 PacingTimerTicks;
} CF_DIAGS, *PCF_DIAGS;
