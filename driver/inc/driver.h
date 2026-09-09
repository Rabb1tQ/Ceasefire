#pragma once

// Define Windows version before including any headers
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN10
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN10
#endif

#ifndef WINVER
#define WINVER _WIN32_WINNT_WIN10
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include <wdmsec.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmtypes.h>

// WFP field definitions are provided by fwpsk.h
// No need to redefine them here

// FWP action types
#ifndef FWP_ACTION_CALLOUT
#define FWP_ACTION_CALLOUT 0x00000002
#endif

// FWP weight types
#define FWP_UINT8 0
#define FWP_UINT16 1
#define FWP_UINT32 2
#define FWP_UINT64 3

// Stream-direction fixed-value flags (fwpmu.h values; not in fwpsk.h)
#ifndef FWP_CONDITION_FLAG_IS_OUTBOUND
#define FWP_CONDITION_FLAG_IS_OUTBOUND 0x00000001
#endif
#ifndef FWP_CONDITION_FLAG_IS_INBOUND
#define FWP_CONDITION_FLAG_IS_INBOUND 0x00000002
#endif

// FWP_DIRECTION enum (fwptypes.h): outbound=0, inbound=1. The ALE
// flow-established DIRECTION fixed value uses this enum (VM-measured,
// driver30 diag round 2026-08-28, identical for V4 and V6 layers).
#ifndef FWP_DIRECTION_OUTBOUND
#define FWP_DIRECTION_OUTBOUND 0
#endif
#ifndef FWP_DIRECTION_INBOUND
#define FWP_DIRECTION_INBOUND 1
#endif

// FwpsConstructIpHeaderForTransportPacket0 已随第 19 轮传输层重建死代码
// 一并移除（下载限速执行点迁至 INBOUND_IPPACKET 层，见 pacing.c）。

#include "common.h"
#include "types.h"

// Global variables declarations
extern LIST_ENTRY g_RuleList;
extern KSPIN_LOCK g_RuleListLock;
extern BOOLEAN g_DefaultAllow;

extern NETWORK_EVENT g_EventQueue[EVENT_QUEUE_SIZE];
extern ULONG g_EventQueueHead;
extern ULONG g_EventQueueTail;
extern KSPIN_LOCK g_EventQueueLock;

// DNS event queue
extern DNS_EVENT g_DnsEventQueue[EVENT_QUEUE_SIZE];
extern ULONG g_DnsEventQueueHead;
extern ULONG g_DnsEventQueueTail;
extern KSPIN_LOCK g_DnsEventQueueLock;

// Driver entry point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

// Driver unload
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

// Device and IRP handling
NTSTATUS CreateDevice(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS DispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

// WFP Callout registration
NTSTATUS RegisterCallouts(_In_ PDEVICE_OBJECT DeviceObject);
VOID UnregisterCallouts(VOID);

// WFP Callout notify functions
NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter
);

// WFP Callout functions
void NTAPI NetworkLayerCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI RecvAcceptCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// IPv6 对应层 callout（classify 逻辑与 V4 共用，仅固定值字段索引/地址形态不同）
void NTAPI NetworkLayerCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI RecvAcceptCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI StreamThrottleCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI FlowEstablishedCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI OutboundTransportThrottleCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI DnsCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// Stream-layer TCP throttle callout (FWPM_LAYER_STREAM_V4)
void NTAPI StreamThrottleCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// Outbound transport layer (FWPS_LAYER_OUTBOUND_TRANSPORT_V4) TCP shaper.
// BLOCK below TCP keeps the segment in the sender's retransmit queue, so the
// token bucket releases data at the configured rate (real shaping, unlike the
// stream layer where BLOCK drops data the sender will never retransmit).
void NTAPI OutboundTransportThrottleCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// Inbound IP packet layer (FWPS_LAYER_INBOUND_IPPACKET_V4) TCP download
// shaper (Round 19). The inbound transport layer's NBLs carry payload only
// (VM-measured: no IP/TCP headers, clone+retreat yields garbage), so the
// clone-hold-reinject engine moved here. At this layer the NB starts at the
// TCP header; the IP header sits in the NB headroom (metadata ipHeaderSize)
// and is exposed via retreat before cloning (see pacing.c). The callout
// parses the TCP header itself, attributes the flow via the FlowTuple table
// and hands detention to pacing.c (FwpsInjectNetworkReceiveAsync0
// reinjection).
void NTAPI InboundIpPacketThrottleCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI InboundIpPacketThrottleCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// Kernel rate limiting (throttle.c)
VOID ThrottleInit(VOID);
VOID ThrottleClearAll(VOID);
NTSTATUS ThrottleSetEntry(_In_ PTHROTTLE_INPUT input);
BOOLEAN ThrottleCheck(
    _In_ UINT32 processId,
    _In_ BOOLEAN outbound,
    _In_ UINT32 byteCount
);
// 快路径：当前无任何限速条目时返回 FALSE（无锁原子读，任意 IRQL <= DISPATCH）
BOOLEAN ThrottleHasActiveEntries(VOID);
// 进程退出清理：删掉该 PID 的全部限速条目（进程通知回调 PASSIVE_LEVEL 调用，
// 只碰 throttle.c 自有自旋锁）
VOID ThrottleRemoveByPid(_In_ UINT32 pid);
// diag v3：快照时刻的活跃限速条目数（锁内读）
UINT32 ThrottleSnapshotActiveCount(VOID);

// Kernel pacing（pacing.c，第 18 轮）：入站下载限速的"克隆-扣留-定时注入"
// 执行手段。drop-to-throttle 已被实测否决（本机 tcpip 栈重丢包后 RST），
// 本机制一个包不丢：classify 令牌不足时克隆入队（BLOCK+ABSORB），KTIMER
// 1ms 周期 DPC 按令牌逐包注入。详见 pacing.c 头注释与 WFP实现方案.md。
NTSTATUS PacingInit(VOID);
// 指定族的注入句柄是否可用（V4/V6 各一，AF_UNSPEC 对 NETWORK 类型非法）
BOOLEAN PacingEnabled(_In_ BOOLEAN isV6);
// 自识别（classify 最先调用）：本驱动注入句柄注入/曾注入的包返回 TRUE
BOOLEAN PacingIsSelfInjected(_In_ PNET_BUFFER_LIST nbl, _In_ BOOLEAN isV6);
// 该 PID 扣留队列非空？(只拿 hold 锁；快路径前置检查，保证同 PID FIFO)
BOOLEAN PacingPidHasHeld(_In_ UINT32 processId);
// classify 扣留入口（DISPATCH_LEVEL，INBOUND_IPPACKET 层）：返回 TRUE=
// 已入队（调用方 BLOCK+ABSORB），FALSE=未入队（调用方普通 BLOCK 丢弃）。
BOOLEAN PacingHoldPacket(
    _In_ UINT32 processId,
    _In_ BOOLEAN isV6,
    _In_ PNET_BUFFER_LIST originalNbl,
    _In_ UINT32 payloadBytes,
    _In_ const BYTE (*localAddr)[16],
    _In_ const BYTE (*remoteAddr)[16],
    _In_ COMPARTMENT_ID compartmentId,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_ UINT32 interfaceIndex,      // classify 固定值 INTERFACE_INDEX
    _In_ UINT32 subInterfaceIndex    // classify 固定值 SUB_INTERFACE_INDEX
);
// 清退：删除限速/进程退出时立即放行该 PID 的扣留包（PASSIVE_LEVEL）
VOID PacingFlushPid(_In_ UINT32 processId);
// 清退：放空全部队列（IOCTL 清表 / 卸载）
VOID PacingFlushAll(VOID);
// 卸载序：停 1ms 定时器并等在途 DPC 走完（PASSIVE_LEVEL，可阻塞）
VOID PacingStopTimer(VOID);
// 卸载序：放空全部扣留队列（前置条件：PacingStopTimer 已执行）
VOID PacingDrainAll(VOID);
// 注入完成回调（FWPS_INJECT_COMPLETE0）：按 NBL Status 记账并释放克隆
VOID NTAPI PacingInjectComplete(
    _In_ VOID* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
);
// 卸载收尾：放空剩余队列 + 销毁注入句柄（等待在途注入完成；前置：
// PacingStopTimer 已执行）
VOID PacingShutdown(VOID);
// 放行引擎 DPC（KTIMER 1ms 周期）
VOID NTAPI PacingTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);
// 注入单个扣留包；同步失败就地释放克隆并计数（完成回调由 WFP 调）
VOID PacingInjectNow(_In_ VOID* packet);

// Shared ALE classify path (V4/V6 connect and recv-accept layers)
VOID ProcessAleAuth(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_opt_ const void* classifyContext,
    _In_ UINT32 direction, // RULE_DIRECTION_IN / RULE_DIRECTION_OUT
    _In_ UINT32 calloutId,
    _In_ UINT16 fwpsLayerId,
    _In_ BOOLEAN isV6,     // TRUE: 从 V6 层固定值读 16 字节地址
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// Flow-layer byte accounting (flow.c): association at ALE authorization time,
// atomic accumulation from the stream callout, and a TCP_FLOW_CLOSE event on
// flow deletion. Every failure path degrades to the legacy no-counting mode;
// nothing here may block a connection.
VOID NTAPI FlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

UINT32 FlowOnTcpConnectionAllowed(
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_opt_ const void* classifyContext,
    _In_ UINT16 fwpsLayerId,   // FwpsFlowAssociateContext0 层 ID（fwpsk.h 常量，V4/V6 stream 层）
    _In_ UINT32 calloutId,
    _In_ UINT32 processId,
    _In_ UINT32 protocol,
    _In_ UINT32 addressFamily,          // CF_ADDR_FAMILY_*
    _In_ const BYTE (*localAddr)[16],   // 双栈形态
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort,
    _In_ UINT32 direction,
    _In_ const WCHAR* processPath
);

// Flow-established classify: associates the TCP byte-count context (flow.c).
void NTAPI FlowEstablishedCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// Atomic accumulation entry used by the stream callout (flowContext != 0)
VOID FlowCountStreamBytes(
    _In_ UINT64 flowContext,
    _In_ BOOLEAN outbound,
    _In_ UINT32 byteCount
);

// 流层惰性关联：classify 内用本层 flowHandle 就地挂计数上下文
UINT32 FlowLazyAssociateAtStream(
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_ UINT16 fwpsLayerId,            // FwpsFlowAssociateContext0 层 ID（V4/V6 stream 层）
    _In_ UINT32 processId,
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort,
    _In_ UINT32 direction,
    _In_ UINT32 calloutId
);

// 五元组 → PID 关联表（双栈；V4 地址按 types.h 顶部形态存放）
VOID FlowTupleInit(VOID);
VOID FlowTupleRecordPid(
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort,
    _In_ UINT32 processId
);
UINT32 FlowTupleLookupPid(
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*localAddr)[16],
    _In_ UINT16 localPort,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort
);

// 活跃流登记表（flow.c）：关联成功登记 / FlowDeleteFn 摘除；
// 卸载时 FlowRemoveAllContexts 先于 callout 注销逐条 FwpsFlowRemoveContext0
// 主动撤上下文（注销泄漏根因修复，详见 WFP实现方案.md）
VOID FlowRegistryInit(VOID);
VOID FlowRemoveAllContexts(VOID);


// Rule matching engine
BOOLEAN MatchRules(
    _In_ UINT32 processId,
    _In_ const WCHAR* processPath,
    _In_ UINT32 protocol,
    _In_ UINT32 addressFamily,          // CF_ADDR_FAMILY_*（连接的地址族）
    _In_ const BYTE (*remoteAddr)[16],  // 双栈形态（V4: 首 4 字节主机序 u32）
    _In_ UINT16 remotePort,
    _In_ UINT16 localPort,
    _In_ UINT32 direction, // RULE_DIRECTION_IN / RULE_DIRECTION_OUT
    _Out_ PBOOLEAN allowConnection,
    _Out_ PUINT32 matchedRuleId
);

// Rule management
NTSTATUS AddRule(_In_ PRULE_INPUT ruleInput);
NTSTATUS RemoveRule(_In_ UINT32 ruleId);
NTSTATUS UpdateRule(_In_ PRULE_INPUT ruleInput);
NTSTATUS ClearRules(VOID);

// Event management
NTSTATUS QueueEvent(_In_ PNETWORK_EVENT event);
NTSTATUS GetEvent(_Out_ PNETWORK_EVENT event);
NTSTATUS QueueDnsEvent(_In_ PDNS_EVENT event);
NTSTATUS GetDnsEvent(_Out_ PDNS_EVENT event);

// 诊断统计（diag.c，IOCTL_GET_DIAGS 读取；slot 下标见 CF_DIAG_SLOT_*）
VOID CfDiagInit(VOID);
VOID CfDiagRecordRegister(_In_ UINT32 slot, _In_ NTSTATUS status, _In_ UINT32 calloutId);
VOID CfDiagRecordUnregister(_In_ UINT32 slot, _In_ NTSTATUS status, _In_ UINT32 retries);
VOID CfDiagClassifyStream(_In_ BOOLEAN isV6);
VOID CfDiagClassifyFlowEst(_In_ BOOLEAN isV6);
VOID CfDiagAssoc(_In_ BOOLEAN isV6, _In_ BOOLEAN ok);
VOID CfDiagFlowDelete(_In_ BOOLEAN isV6);
VOID CfDiagStreamBytes(_In_ BOOLEAN isV6, _In_ UINT32 byteCount);
VOID CfDiagBumpThrottleNotifyRemove(VOID);
VOID CfDiagClassifyInTransport(_In_ BOOLEAN isV6);
VOID CfDiagInTransportVerdict(_In_ BOOLEAN isV6, _In_ BOOLEAN permitted);
// diag v5：kernel pacing 计数（pacing.c 调用）
VOID CfDiagPacingHeld(VOID);
VOID CfDiagPacingInjected(VOID);
VOID CfDiagPacingInjectFail(VOID);
VOID CfDiagPacingQueueDrop(VOID);
VOID CfDiagPacingQueueDepth(_In_ UINT64 currentBytes); // 记录全局扣留峰值
VOID CfDiagPacingTimerTick(VOID);
VOID CfDiagSnapshot(_Out_ PCF_DIAGS out);
