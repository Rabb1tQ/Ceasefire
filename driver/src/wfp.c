#include "../inc/driver.h"

// Callout IDs
static UINT32 s_CalloutIdV4 = 0;
static UINT32 s_CalloutIdRecvAccept = 0;
static UINT32 s_CalloutIdDns = 0;
static UINT32 s_CalloutIdStream = 0;
static UINT32 s_CalloutIdFlowEstablished = 0;
static UINT32 s_CalloutIdOutTransport = 0;
static UINT32 s_CalloutIdInIpPacket = 0;
// IPv6 对应层（classify 逻辑与 V4 共用，仅固定值读取不同）
static UINT32 s_CalloutIdV6 = 0;
static UINT32 s_CalloutIdRecvAcceptV6 = 0;
static UINT32 s_CalloutIdDnsV6 = 0;
static UINT32 s_CalloutIdStreamV6 = 0;
static UINT32 s_CalloutIdFlowEstablishedV6 = 0;
static UINT32 s_CalloutIdOutTransportV6 = 0;
static UINT32 s_CalloutIdInIpPacketV6 = 0;

// Device object for callout registration
static PDEVICE_OBJECT s_DeviceObject = NULL;

// Callout GUIDs (must match service-side registration)
// IPv4 Callout GUID: {A1B2C3D4-E5F6-4748-9A0B-1C2D3E4F5A6B}
static const GUID CEASEFIRE_CALLOUT_V4_GUID = {0xa1b2c3d4, 0xe5f6, 0x4748, {0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b}};
// DNS capture callout GUID: {C3D4E5F6-A7B8-495A-BC2D-3E4F5A6B7C8D}
static const GUID CEASEFIRE_CALLOUT_DNS_GUID = {0xc3d4e5f6, 0xa7b8, 0x495a, {0xbc, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d}};
// Inbound (recv-accept) callout GUID: {B5C6D7E8-F9A0-4B1C-8D2E-3F4A5B6C7D8E}
static const GUID CEASEFIRE_CALLOUT_RECV_ACCEPT_GUID = {0xb5c6d7e8, 0xf9a0, 0x4b1c, {0x8d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e}};
// Stream-layer throttle callout GUID: {D1E2F3B0-B5C6-4D78-9EAF-2B8C9DAEBFC0}
// 2026-08-28 从 {..A8} 换新：旧 GUID 在 VM 上长期被僵尸注册占用（sc stop
// 泄漏后 FwpsCalloutRegister 同 GUID 实例返回 FWP_E_ALREADY_EXISTS、
// calloutId=0，V4 流层字节计数从未生效而 BFE capture 仍显示 REGISTERED）。
// 僵尸注册拿不到旧 calloutId、无法注销，换 GUID 是最干净的规避（未发布）。
static const GUID CEASEFIRE_CALLOUT_STREAM_GUID = {0xd1e2f3b0, 0xb5c6, 0x4d78, {0x9e, 0xaf, 0x2b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0}};
// ALE flow-established callout GUID: {E5A6B7CE-D9E0-4F12-A3B4-C5D6E7F8091A}
// （同上换新，旧值 {..CC}）。Sole job: associate the stream byte-count
// context on TCP flows. Runs at FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 where
// flowHandle metadata is guaranteed; the association itself targets the
// STREAM layer callout (see flow.c).
static const GUID CEASEFIRE_CALLOUT_FLOWESTABLISHED_GUID = {0xe5a6b7ce, 0xd9e0, 0x4f12, {0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a}};
// Outbound transport shaper callout GUID: {9A0B1C2D-3E4F-4A5B-8C6D-7E8F9A0B1C2D}
static const GUID CEASEFIRE_CALLOUT_OUT_TRANSPORT_GUID = {0x9a0b1c2d, 0x3e4f, 0x4a5b, {0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d}};
// Inbound IP packet shaper callout GUID: {9A0B1C31-3E4F-4A5B-8C6D-7E8F9A0B1C2D}
// 第 19 轮从 INBOUND_TRANSPORT 层（旧 GUID {9A0B1C2F}）迁到 IPPACKET 层并
// 换新 GUID：旧 GUID 的 FWPM callout 对象 applicableLayer 固定在
// INBOUND_TRANSPORT，服务崩溃残留时同 GUID 重注册会 ALREADY_EXISTS、新层
// 过滤器引用即失效——换 GUID 一劳永逸（服务侧保留旧 GUID 做残留清扫）。
// 下载限速（克隆-扣留-定时注入）的执行点。
static const GUID CEASEFIRE_CALLOUT_IN_IPPACKET_GUID = {0x9a0b1c31, 0x3e4f, 0x4a5b, {0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d}};

// ---- IPv6 对应层 callout GUID（与 service/src/wfp/mod.rs 严格一致）----
// V6 连接授权（ALE_AUTH_CONNECT_V6）：{A1B2C3D5-E5F6-4748-9A0B-1C2D3E4F5A6B}
static const GUID CEASEFIRE_CALLOUT_V6_GUID = {0xa1b2c3d5, 0xe5f6, 0x4748, {0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b}};
// V6 入站授权（ALE_AUTH_RECV_ACCEPT_V6）：{B5C6D7E9-F9A0-4B1C-8D2E-3F4A5B6C7D8E}
static const GUID CEASEFIRE_CALLOUT_RECV_ACCEPT_V6_GUID = {0xb5c6d7e9, 0xf9a0, 0x4b1c, {0x8d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e}};
// V6 DNS 抓包（INBOUND_TRANSPORT_V6）：{C3D4E5F7-A7B8-495A-BC2D-3E4F5A6B7C8D}
static const GUID CEASEFIRE_CALLOUT_DNS_V6_GUID = {0xc3d4e5f7, 0xa7b8, 0x495a, {0xbc, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d}};
// V6 流层限速/计数（STREAM_V6）：{D1E2F3A9-B5C6-4D78-9EAF-2B8C9DAEBFC0}
static const GUID CEASEFIRE_CALLOUT_STREAM_V6_GUID = {0xd1e2f3a9, 0xb5c6, 0x4d78, {0x9e, 0xaf, 0x2b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0}};
// V6 flow-established（ALE_FLOW_ESTABLISHED_V6）：{E5A6B7CD-D9E0-4F12-A3B4-C5D6E7F8091A}
static const GUID CEASEFIRE_CALLOUT_FLOWESTABLISHED_V6_GUID = {0xe5a6b7cd, 0xd9e0, 0x4f12, {0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a}};
// V6 出站整形（OUTBOUND_TRANSPORT_V6）：{9A0B1C2E-3E4F-4A5B-8C6D-7E8F9A0B1C2D}
static const GUID CEASEFIRE_CALLOUT_OUT_TRANSPORT_V6_GUID = {0x9a0b1c2e, 0x3e4f, 0x4a5b, {0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d}};
// V6 入站整形（INBOUND_IPPACKET_V6）：{9A0B1C32-3E4F-4A5B-8C6D-7E8F9A0B1C2D}
// （第 19 轮从 INBOUND_TRANSPORT_V6 旧 GUID {9A0B1C30} 换新，理由同 V4）
static const GUID CEASEFIRE_CALLOUT_IN_IPPACKET_V6_GUID = {0x9a0b1c32, 0x3e4f, 0x4a5b, {0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d}};

// Forward declarations for notify functions
NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter
);

// Forward declaration for callout functions
void NTAPI NetworkLayerCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void NTAPI DnsCallout(
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

void NTAPI StreamThrottleCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

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

NTSTATUS RegisterCallouts(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPS_CALLOUT callout = {0};

    s_DeviceObject = DeviceObject;

    KdPrint(("Ceasefire Driver: Registering WFP callouts\n"));


    // Register IPv4 callout
    callout.calloutKey = CEASEFIRE_CALLOUT_V4_GUID;
    callout.classifyFn = NetworkLayerCallout;
    callout.notifyFn = NotifyFn;
    // flowDeleteFn 负责在 TCP 流结束时上报累计字节并释放上下文；仅在 ALE
    // 授权放行且上下文关联成功时才会被挂到具体流上。
    callout.flowDeleteFn = FlowDeleteFn;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdV4);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: Failed to register IPv4 callout: 0x%08X\n", status));
        s_CalloutIdV4 = 0;
        CfDiagRecordRegister(CF_DIAG_SLOT_ALE_CONNECT, status, 0);
        return status;
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_ALE_CONNECT, status, s_CalloutIdV4);

    KdPrint(("Ceasefire Driver: IPv4 callout registered with ID: %u\n", s_CalloutIdV4));

    // Register inbound (ALE_AUTH_RECV_ACCEPT_V4) callout
    callout.calloutKey = CEASEFIRE_CALLOUT_RECV_ACCEPT_GUID;
    callout.classifyFn = RecvAcceptCallout;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdRecvAccept);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: Failed to register recv-accept callout: 0x%08X\n", status));
        FwpsCalloutUnregisterById(s_CalloutIdV4);
        s_CalloutIdV4 = 0;
        CfDiagRecordRegister(CF_DIAG_SLOT_RECV_ACCEPT, status, 0);
        return status;
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_RECV_ACCEPT, status, s_CalloutIdRecvAccept);

    KdPrint(("Ceasefire Driver: recv-accept callout registered with ID: %u\n", s_CalloutIdRecvAccept));

    // Register DNS capture callout (inbound transport, inspection only).
    // Registration failure is non-fatal: DNS capture is a best-effort feature.
    callout.calloutKey = CEASEFIRE_CALLOUT_DNS_GUID;
    callout.classifyFn = DnsCallout;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdDns);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: Failed to register DNS callout: 0x%08X (continuing)\n", status));
        s_CalloutIdDns = 0;
    } else {
        KdPrint(("Ceasefire Driver: DNS callout registered with ID: %u\n", s_CalloutIdDns));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_DNS, status, s_CalloutIdDns);

    // Register stream-layer throttle callout. Failure is non-fatal: rate
    // limiting simply stays inert (everything is permitted).
    callout.calloutKey = CEASEFIRE_CALLOUT_STREAM_GUID;
    callout.classifyFn = StreamThrottleCallout;
    // 与 V6 流层写法完全一致、逐字段显式赋值（此前依赖结构体残留值继承）：
    // 流计数上下文以 (STREAM_V4 层, 本 calloutId) 关联，flow 删除回调按本
    // callout 查找——必须挂 FlowDeleteFn，否则 V4 流上下文泄漏且不报数。
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = FlowDeleteFn;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdStream);
    if (!NT_SUCCESS(status)) {
        // 降级是"非致命"的，但绝不能静默：0x80320009 (FWP_E_ALREADY_EXISTS)
        // 意味着上一实例注销失败留下的僵尸注册，本实例这两个层将完全失效。
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] stream callout register failed: 0x%08X (byte counting + throttling DEAD this session)\n",
            status);
        s_CalloutIdStream = 0;
    } else {
        KdPrint(("Ceasefire Driver: stream throttle callout registered with ID: %u\n", s_CalloutIdStream));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_STREAM, status, s_CalloutIdStream);

    // Flow-established association callout (TCP byte counting). Failure is
    // non-fatal: counting degrades to the service-side EStats fallback.
    callout.calloutKey = CEASEFIRE_CALLOUT_FLOWESTABLISHED_GUID;
    callout.classifyFn = FlowEstablishedCallout;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdFlowEstablished);
    if (!NT_SUCCESS(status)) {
        // 同 stream callout：ALREADY_EXISTS = 上实例泄漏的僵尸注册，显式报出。
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] flow-established callout register failed: 0x%08X (byte counting DEAD this session)\n",
            status);
        s_CalloutIdFlowEstablished = 0;
    } else {
        KdPrint(("Ceasefire Driver: flow-established callout registered with ID: %u\n", s_CalloutIdFlowEstablished));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_FLOW_ESTABLISHED, status, s_CalloutIdFlowEstablished);

    // Outbound transport shaper callout (TCP 带宽整形的真正执行点). Failure
    // is non-fatal: shaping stays inert (everything permitted).
    callout.calloutKey = CEASEFIRE_CALLOUT_OUT_TRANSPORT_GUID;
    callout.classifyFn = OutboundTransportThrottleCallout;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdOutTransport);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] outbound-transport callout register failed: 0x%08X (outbound shaping DEAD this session)\n",
            status);
        s_CalloutIdOutTransport = 0;
    } else {
        KdPrint(("Ceasefire Driver: outbound-transport shaper callout registered with ID: %u\n", s_CalloutIdOutTransport));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_OUT_TRANSPORT, status, s_CalloutIdOutTransport);

    // Inbound IP packet shaper callout (下载限速 clone-hold-reinject 的执行点，
    // 第 19 轮从 INBOUND_TRANSPORT 层迁来——该层 NBL 只含 TCP 载荷、无法
    // 克隆回退重建，IPPACKET 层 NBL = 完整 IP 数据报). Failure is non-fatal:
    // download shaping stays inert (everything permitted).
    callout.calloutKey = CEASEFIRE_CALLOUT_IN_IPPACKET_GUID;
    callout.classifyFn = InboundIpPacketThrottleCallout;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdInIpPacket);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] inbound-ippacket callout register failed: 0x%08X (download shaping DEAD this session)\n",
            status);
        s_CalloutIdInIpPacket = 0;
    } else {
        KdPrint(("Ceasefire Driver: inbound-ippacket shaper callout registered with ID: %u\n", s_CalloutIdInIpPacket));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_IN_TRANSPORT, status, s_CalloutIdInIpPacket);

    // ---- IPv6 对应层 callout（与 V4 逐层对应）。注册失败一律非致命降级：
    // 仅 V6 该层失效（连接不被管控），显式报错绝不静默。0x80320009 =
    // 上实例泄漏的僵尸注册，重启清理。----
    callout.calloutKey = CEASEFIRE_CALLOUT_V6_GUID;
    callout.classifyFn = NetworkLayerCalloutV6;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = FlowDeleteFn;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdV6);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] ale-connect-v6 callout register failed: 0x%08X (IPv6 outbound control DEAD this session)\n",
            status);
        s_CalloutIdV6 = 0;
    } else {
        KdPrint(("Ceasefire Driver: IPv6 callout registered with ID: %u\n", s_CalloutIdV6));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_ALE_CONNECT, status, s_CalloutIdV6);

    callout.calloutKey = CEASEFIRE_CALLOUT_RECV_ACCEPT_V6_GUID;
    callout.classifyFn = RecvAcceptCalloutV6;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdRecvAcceptV6);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] recv-accept-v6 callout register failed: 0x%08X (IPv6 inbound control DEAD this session)\n",
            status);
        s_CalloutIdRecvAcceptV6 = 0;
    } else {
        KdPrint(("Ceasefire Driver: IPv6 recv-accept callout registered with ID: %u\n", s_CalloutIdRecvAcceptV6));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_RECV_ACCEPT, status, s_CalloutIdRecvAcceptV6);

    callout.calloutKey = CEASEFIRE_CALLOUT_DNS_V6_GUID;
    callout.classifyFn = DnsCalloutV6;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdDnsV6);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Ceasefire Driver: Failed to register DNS v6 callout: 0x%08X (continuing)\n", status));
        s_CalloutIdDnsV6 = 0;
    } else {
        KdPrint(("Ceasefire Driver: DNS v6 callout registered with ID: %u\n", s_CalloutIdDnsV6));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_DNS, status, s_CalloutIdDnsV6);

    callout.calloutKey = CEASEFIRE_CALLOUT_STREAM_V6_GUID;
    callout.classifyFn = StreamThrottleCalloutV6;
    // 字节计数上下文以 (STREAM_V6 层, 本 calloutId) 关联，flow 删除回调按
    // 本 callout 查找——必须挂 FlowDeleteFn，否则 V6 流上下文泄漏且不报数。
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = FlowDeleteFn;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdStreamV6);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] stream-v6 callout register failed: 0x%08X (IPv6 byte counting DEAD this session)\n",
            status);
        s_CalloutIdStreamV6 = 0;
    } else {
        KdPrint(("Ceasefire Driver: IPv6 stream throttle callout registered with ID: %u\n", s_CalloutIdStreamV6));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_STREAM, status, s_CalloutIdStreamV6);

    callout.calloutKey = CEASEFIRE_CALLOUT_FLOWESTABLISHED_V6_GUID;
    callout.classifyFn = FlowEstablishedCalloutV6;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdFlowEstablishedV6);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] flow-established-v6 callout register failed: 0x%08X (IPv6 byte counting DEAD this session)\n",
            status);
        s_CalloutIdFlowEstablishedV6 = 0;
    } else {
        KdPrint(("Ceasefire Driver: IPv6 flow-established callout registered with ID: %u\n", s_CalloutIdFlowEstablishedV6));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_FLOW_ESTABLISHED, status, s_CalloutIdFlowEstablishedV6);

    callout.calloutKey = CEASEFIRE_CALLOUT_OUT_TRANSPORT_V6_GUID;
    callout.classifyFn = OutboundTransportThrottleCalloutV6;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdOutTransportV6);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] outbound-transport-v6 callout register failed: 0x%08X (IPv6 outbound shaping DEAD this session)\n",
            status);
        s_CalloutIdOutTransportV6 = 0;
    } else {
        KdPrint(("Ceasefire Driver: IPv6 outbound-transport shaper callout registered with ID: %u\n", s_CalloutIdOutTransportV6));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_OUT_TRANSPORT, status, s_CalloutIdOutTransportV6);

    callout.calloutKey = CEASEFIRE_CALLOUT_IN_IPPACKET_V6_GUID;
    callout.classifyFn = InboundIpPacketThrottleCalloutV6;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &callout, &s_CalloutIdInIpPacketV6);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] inbound-ippacket-v6 callout register failed: 0x%08X (IPv6 download shaping DEAD this session)\n",
            status);
        s_CalloutIdInIpPacketV6 = 0;
    } else {
        KdPrint(("Ceasefire Driver: IPv6 inbound-ippacket shaper callout registered with ID: %u\n", s_CalloutIdInIpPacketV6));
    }
    CfDiagRecordRegister(CF_DIAG_SLOT_IN_TRANSPORT_V6, status, s_CalloutIdInIpPacketV6);

    KdPrint(("Ceasefire Driver: WFP callouts registered successfully\n"));

    return STATUS_SUCCESS;
}

// Notify function for callout events
NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter
)
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType) {
        case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
            KdPrint(("Ceasefire Driver: Filter added\n"));
            break;
        case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
            KdPrint(("Ceasefire Driver: Filter deleted\n"));
            break;
        default:
            break;
    }

    return STATUS_SUCCESS;
}

// 单个 callout 的检查式注销。背景：sc stop 后流层/flow-established 注册
// 残留、.sys 镜像无法卸载的泄漏已实测复现多次——若 FwpsCalloutUnregisterById0
// 没能完成注销（仍被过滤器引用 / 活跃流尚未走完 FlowDeleteFn），旧注册会
// 一直挂在 BFE，之后同 GUID 加载的新实例 FwpsCalloutRegister 返回
// FWP_E_ALREADY_EXISTS 又被当作"非致命降级"吞掉，表现为这两个层完全静默
// 失效。因此这里：
//   * 等待 + 有界重试（DriverUnload 在 PASSIVE_LEVEL，可阻塞），给引擎时间
//     对每条挂着 flow context 的活跃流同步回调 FlowDeleteFn；
//   * 重试窗口 3 秒（30 x 100ms 分片 sleep）：正常路径在
//     FlowRemoveAllContexts 主动撤完上下文后第一次尝试即应成功，重试只为
//     兜住表满未登记的流与服务侧过滤器清扫的收尾时延；
//   * 每次失败 DbgPrintEx 计数留痕，最终结果写入 diag v2 通道
//     （UnregStatus/UnregRetries，cfctl diags 可见）；
//   * 最终失败必须一眼可见：用 DbgPrintEx ERROR 级直接打印（不进限流的
//     KdPrint/FLOW_DBG 通道）。
static VOID UnregisterCalloutByIdChecked(
    _In_ UINT32* calloutId,
    _In_ PCSTR name,
    _In_ UINT32 diagSlot)
{
    UINT32 id = *calloutId;
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 failedAttempts = 0;
    int attempt;

    if (id == 0) {
        return;
    }

    for (attempt = 0; attempt < 30; ++attempt) { // 至多 ~3s (30 x 100ms)
        status = FwpsCalloutUnregisterById(id);
        if (NT_SUCCESS(status)) {
            break;
        }
        failedAttempts++;
        if ((failedAttempts % 10) == 1) { // 每 ~1s 留一次痕，避免刷屏
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[CF-WFP] unregister '%s' (id=%u) attempt %u failed: 0x%08X\n",
                name, id, failedAttempts, status);
        }
        LARGE_INTEGER delay;
        delay.QuadPart = -1000000; // 100ms（相对时间，负值）
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    CfDiagRecordUnregister(diagSlot, status, failedAttempts);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[CF-WFP] FAILED to unregister callout '%s' (id=%u) after %u retries: 0x%08X "
            "-- stale registration will break next load of same GUID; REBOOT to clear\n",
            name, id, failedAttempts, status);
    } else {
        KdPrint(("Ceasefire Driver: %s callout unregistered (retries=%u)\n", name, failedAttempts));
    }

    *calloutId = 0;
}

VOID UnregisterCallouts(VOID)
{
    // 卸载顺序（注销泄漏根因修复，三层缺一不可，详见 WFP实现方案.md）：
    //   1. 服务侧：stop 服务时先 remove_filters 清掉 BFE 里引用本驱动
    //      callout 的所有过滤器（service/src/wfp/filter.rs）——callout 仍被
    //      过滤器引用时 FwpsCalloutUnregisterById0 直接失败；
    //   2. 驱动侧：FlowRemoveAllContexts 逐条 FwpsFlowRemoveContext0 主动
    //      撤销所有已登记的流上下文（同步回调 FlowDeleteFn 报数并释放）。
    //      依赖"引擎注销时兜底回调 flowDeleteFn"的老路径实测不可靠——
    //      活跃流多时注销不干净，正是注册残留的根因；
    //   3. 最后才注销 callout 本体（UnregisterCalloutByIdChecked，3s 有界
    //      重试兜住未登记/在途的流）。
    // 另：绝不能在 FlowDeleteFn 内调用 FwpsFlowRemoveContext0（重入/未定义
    // 行为）；本函数必须先于 DriverUnload 中的 IoDeleteDevice 执行（现顺序
    // 如此），否则 FlowDeleteFn 运行时设备/队列已销毁。
    KdPrint(("Ceasefire Driver: Unregistering WFP callouts\n"));

    FlowRemoveAllContexts();

    UnregisterCalloutByIdChecked(&s_CalloutIdV4, "ale-connect", CF_DIAG_SLOT_ALE_CONNECT);
    UnregisterCalloutByIdChecked(&s_CalloutIdRecvAccept, "ale-recv-accept", CF_DIAG_SLOT_RECV_ACCEPT);
    UnregisterCalloutByIdChecked(&s_CalloutIdDns, "dns", CF_DIAG_SLOT_DNS);
    UnregisterCalloutByIdChecked(&s_CalloutIdStream, "stream", CF_DIAG_SLOT_STREAM);
    UnregisterCalloutByIdChecked(&s_CalloutIdFlowEstablished, "flow-established", CF_DIAG_SLOT_FLOW_ESTABLISHED);
    UnregisterCalloutByIdChecked(&s_CalloutIdOutTransport, "outbound-transport", CF_DIAG_SLOT_OUT_TRANSPORT);
    UnregisterCalloutByIdChecked(&s_CalloutIdV6, "ale-connect-v6", CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_ALE_CONNECT);
    UnregisterCalloutByIdChecked(&s_CalloutIdRecvAcceptV6, "ale-recv-accept-v6", CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_RECV_ACCEPT);
    UnregisterCalloutByIdChecked(&s_CalloutIdDnsV6, "dns-v6", CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_DNS);
    UnregisterCalloutByIdChecked(&s_CalloutIdStreamV6, "stream-v6", CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_STREAM);
    UnregisterCalloutByIdChecked(&s_CalloutIdFlowEstablishedV6, "flow-established-v6", CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_FLOW_ESTABLISHED);
    UnregisterCalloutByIdChecked(&s_CalloutIdOutTransportV6, "outbound-transport-v6", CF_DIAG_SLOT_V6_BASE + CF_DIAG_SLOT_OUT_TRANSPORT);
    UnregisterCalloutByIdChecked(&s_CalloutIdInIpPacket, "inbound-ippacket", CF_DIAG_SLOT_IN_TRANSPORT);
    UnregisterCalloutByIdChecked(&s_CalloutIdInIpPacketV6, "inbound-ippacket-v6", CF_DIAG_SLOT_IN_TRANSPORT_V6);

    s_DeviceObject = NULL;
    KdPrint(("Ceasefire Driver: WFP callouts unregistered\n"));
}

// Fill ProcessPath from the process path carried in FWPS classify metadata
// (NT form \Device\HarddiskVolumeX\...). This is the standard classifyFn
// approach: PsLookupProcessByProcessId/SeLocateProcessImageName must not be
// called here (DISPATCH_LEVEL IRQL violation), and SeLocateProcessImageName
// additionally returns a PUNICODE_STRING the caller must free (leaked every
// event previously). If the metadata is absent the path stays empty.
static VOID GetProcessPath(
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Out_ WCHAR (*processPath)[MAX_PATH_LENGTH])
{
    const FWP_BYTE_BLOB* path;

    if (inMetaValues == NULL ||
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) == 0 ||
        inMetaValues->processPath == NULL ||
        inMetaValues->processPath->size == 0) {
        return;
    }

    path = inMetaValues->processPath;
    // Blob is a wide string (bytes); cap to the event buffer and NUL-terminate.
    ULONG copyLength = min(path->size, (ULONG)((MAX_PATH_LENGTH - 1) * sizeof(WCHAR)));
    RtlCopyMemory(processPath, path->data, copyLength);
    (*processPath)[copyLength / sizeof(WCHAR)] = L'\0';
}

void NTAPI NetworkLayerCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    ProcessAleAuth(inFixedValues, inMetaValues, classifyContext,
        RULE_DIRECTION_OUT, s_CalloutIdV4, FWPS_LAYER_ALE_AUTH_CONNECT_V4,
        FALSE, classifyOut);
}

// IPv6 出站连接授权（ALE_AUTH_CONNECT_V6）
void NTAPI NetworkLayerCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    ProcessAleAuth(inFixedValues, inMetaValues, classifyContext,
        RULE_DIRECTION_OUT, s_CalloutIdV6, FWPS_LAYER_ALE_AUTH_CONNECT_V6,
        TRUE, classifyOut);
}

// Inbound connections are authorized at FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4.
// Field semantics per MSDN ("Filtering conditions available at each filtering
// layer"): LOCAL address/port = the local machine's endpoint being connected
// to; REMOTE address/port = the connecting peer. IPv4 ALE fixed values are in
// HOST byte order at this layer just like at ALE_AUTH_CONNECT_V4, so no byte
// swaps and no local/remote exchange are needed: rule "remote" conditions
// match the peer on both layers.
void NTAPI RecvAcceptCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    ProcessAleAuth(inFixedValues, inMetaValues, classifyContext,
        RULE_DIRECTION_IN, s_CalloutIdRecvAccept,
        FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FALSE, classifyOut);
}

// Inbound IPv6 connections (ALE_AUTH_RECV_ACCEPT_V6)。字段语义与 V4 层一致：
// LOCAL = 本机端点、REMOTE = 对端；地址为 FWP_BYTE_ARRAY16 网络序原样，
// 端口形态假定与 V4 相同（uint16 主机序）——首次实测前有诊断事件确认（见验收）。
void NTAPI RecvAcceptCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    ProcessAleAuth(inFixedValues, inMetaValues, classifyContext,
        RULE_DIRECTION_IN, s_CalloutIdRecvAcceptV6,
        FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6, TRUE, classifyOut);
}

// Shared classify body for the ALE authorization layers
// (V4/V6 x AUTH_CONNECT outbound, AUTH_RECV_ACCEPT inbound).
VOID ProcessAleAuth(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_opt_ const void* classifyContext,
    _In_ UINT32 direction,
    _In_ UINT32 calloutId,
    _In_ UINT16 fwpsLayerId,
    _In_ BOOLEAN isV6,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UINT32 processId;
    UINT32 protocol;
    UINT32 addressFamily;
    BYTE localAddr[16];
    BYTE remoteAddr[16];
    UINT16 localPort;
    UINT16 remotePort;
    BOOLEAN allowConnection = TRUE;
    UINT32 matchedRuleId = 0;
    NETWORK_EVENT event;

    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(fwpsLayerId);

    // B8: if another callout already made a terminating decision, do not
    // overwrite it and do not queue an event for it.
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    // Get process ID from metadata (most reliable at the ALE auth layers)
    processId = 0;
    if (inMetaValues != NULL && (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)inMetaValues->processId;
    }

    if (isV6) {
        addressFamily = CF_ADDR_FAMILY_V6;
        if (direction == RULE_DIRECTION_IN) {
            protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
            CfAddrSetV6(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16);
            localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
            CfAddrSetV6(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16);
            remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
        } else {
            protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
            CfAddrSetV6(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16);
            localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
            CfAddrSetV6(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16);
            remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
        }
    } else {
        addressFamily = CF_ADDR_FAMILY_V4;
        if (direction == RULE_DIRECTION_IN) {
            protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
            CfAddrSetV4(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32);
            localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
            CfAddrSetV4(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32);
            remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
        } else {
            protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
            CfAddrSetV4(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32);
            localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
            CfAddrSetV4(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32);
            remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        }
    }

    // Build the event (process path first: rule matching needs it)
    RtlSecureZeroMemory(&event, sizeof(NETWORK_EVENT));

    // Unified with DnsCallout: KeQueryInterruptTimePrecise (100ns units).
    // The out-parameter is NOT optional: passing NULL makes the kernel write
    // the result to address 0 -> IRQL_NOT_LESS_OR_EQUAL bugcheck 0xA.
    {
        UINT64 interruptTime = 0;
        event.Timestamp = KeQueryInterruptTimePrecise(&interruptTime);
    }
    event.ProcessId = processId;
    event.Protocol = protocol;
    RtlCopyMemory(event.LocalAddr, localAddr, sizeof(event.LocalAddr));
    RtlCopyMemory(event.RemoteAddr, remoteAddr, sizeof(event.RemoteAddr));
    event.AddressFamily = addressFamily;
    event.LocalPort = localPort;
    event.RemotePort = remotePort;
    event.Direction = direction;

    // PID 兜底仅限出站：RECV_ACCEPT 方向的 classify 可能运行在 DPC/系统
    // 线程，PsGetCurrentProcessId() 会把入站连接错归到 System(4)——与流层
    // callout 对入站禁用兜底的口径一致（见 StreamThrottleCommon），入站
    // PID 缺失保持 0（服务端按五元组归因）。
    if (processId == 0 && direction != RULE_DIRECTION_IN) {
        processId = (UINT32)(UINT_PTR)PsGetCurrentProcessId();
        event.ProcessId = processId;
    }

    GetProcessPath(inMetaValues, &event.ProcessPath);

    // Match rules (B9: driver now compares process paths too)
    if (MatchRules(processId, event.ProcessPath, protocol, addressFamily, &event.RemoteAddr, remotePort, localPort, direction, &allowConnection, &matchedRuleId)) {
        KdPrint(("Ceasefire Driver: PID=%u %s connection %s by rule %u\n", processId, direction == RULE_DIRECTION_IN ? "inbound" : "outbound", allowConnection ? "allowed" : "blocked", matchedRuleId));
    } else {
        allowConnection = g_DefaultAllow;
        KdPrint(("Ceasefire Driver: PID=%u %s connection %s by default policy\n", processId, direction == RULE_DIRECTION_IN ? "inbound" : "outbound", allowConnection ? "allowed" : "blocked"));
    }

    event.Allowed = allowConnection ? TRUE : FALSE;
    event.MatchedRuleId = matchedRuleId;
    event.EventType = NETWORK_EVENT_TYPE_CONNECTION;
    event.BytesSent = 0;
    event.BytesReceived = 0;

    // Set terminating classification decision. A terminating callout MUST
    // clear FWPS_RIGHT_ACTION_WRITE (B8).
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    if (allowConnection) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    } else {
        classifyOut->actionType = FWP_ACTION_BLOCK;
    }

    // TCP 连接授权放行时立即做五元组→PID 权威登记（flow-established 之前、
    // 本机发起的连接 100% 经过 ALE_AUTH_CONNECT/RECV_ACCEPT）。表项无生命
    // 周期管理，连接关闭后的残留项会在端口复用时让新连接继承旧 PID——此处
    // 用本次 classify 自带的权威 PID 即时刷新覆盖，归因错误窗口收敛到零。
    if (allowConnection && protocol == PROTOCOL_TCP && processId != 0) {
        FlowTupleRecordPid(addressFamily, &event.LocalAddr, localPort, &event.RemoteAddr, remotePort, processId);
    }

    // Queue event
    QueueEvent(&event);

    KdPrint(("Ceasefire Driver: Event queued for PID=%u, %s (family=%u), lport=%u rport=%u\n",
        processId,
        direction == RULE_DIRECTION_IN ? "IN" : "OUT",
        addressFamily,
        localPort, remotePort));

    // TCP 连接的字节计数上下文改由 flow-established callout 关联
    // （见 FlowEstablishedCallout/Common）：ALE_AUTH 层不保证 flowHandle
    // 元数据，在这里关联从未成功过。
}

// Flow-established classify: TCP byte-count context association (flow.c).
// Runs at FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4/V6 where flowHandle metadata is
// guaranteed. Inspection-only with respect to policy: always permits and
// never clears FWPS_RIGHT_ACTION_WRITE.
static VOID FlowEstablishedCommon(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _In_opt_ const void* classifyContext,
    _In_ BOOLEAN isV6,
    _In_ UINT16 fwpsStreamLayer,
    _In_ UINT32 streamCalloutId,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UINT32 processId = 0;
    UINT32 protocol;
    UINT32 addressFamily;
    BYTE localAddr[16];
    BYTE remoteAddr[16];
    UINT16 localPort;
    UINT16 remotePort;
    UINT32 direction;
    UINT32 rawDirection = 0xDEADBEEF; // TEMP-DIAG: raw DIRECTION fixed value
    WCHAR processPath[MAX_PATH_LENGTH];

    CfDiagClassifyFlowEst(isV6); // 诊断计数：flow-established 是否被调起

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (isV6) {
        addressFamily = CF_ADDR_FAMILY_V6;
        protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
        CfAddrSetV6(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;
        CfAddrSetV6(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16);
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;
        rawDirection = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION].value.uint32;
        // 实测（VM driver30 诊断事件）：本层 DIRECTION 固定值是标准
        // FWP_DIRECTION 枚举——出站=0、入站=1，V4/V6 同值域。旧代码按
        // FWP_CONDITION_FLAG_IS_OUTBOUND(0x1) 位与判定，0&1=0 把出站判成
        // IN、1&1=1 把入站判成 OUT，方向完全颠倒。
        direction = (rawDirection == FWP_DIRECTION_OUTBOUND) ? RULE_DIRECTION_OUT : RULE_DIRECTION_IN;
    } else {
        addressFamily = CF_ADDR_FAMILY_V4;
        protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
        CfAddrSetV4(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
        CfAddrSetV4(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32);
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
        rawDirection = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint32;
        // 同 V6：枚举相等比较（出站=0），位与判定会方向颠倒。
        direction = (rawDirection == FWP_DIRECTION_OUTBOUND) ? RULE_DIRECTION_OUT : RULE_DIRECTION_IN;
    }

    // 五元组→PID 登记必须在任何可能提前返回的检查之前完成：出站传输层
    // 整形只依赖这张表，与 stream 上下文是否可用无关（stream callout 注册
    // 失败时旧的提前 return 会把登记一起断掉，整形就永远归因不到 PID）。
    if (protocol == PROTOCOL_TCP) {
        if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
            processId = (UINT32)inMetaValues->processId;
        }
        if (processId == 0) {
            processId = (UINT32)(UINT_PTR)PsGetCurrentProcessId();
        }
        if (processId != 0) {
            FlowTupleRecordPid(addressFamily, &localAddr, localPort, &remoteAddr, remotePort, processId);
        }
    }

    if (streamCalloutId == 0) {
        return; // stream callout missing: no consumer for the context
    }

    if (protocol != PROTOCOL_TCP) {
        return;
    }

    RtlSecureZeroMemory(processPath, sizeof(processPath));
    GetProcessPath(inMetaValues, &processPath);

    // Associate the byte-count context at the STREAM layer so the stream
    // throttle callout observes a non-zero flowContext and reports the
    // lifetime totals on flow deletion (EventType=1). Any failure is
    // swallowed inside (connection stays permitted; EStats fallback applies).
    FlowOnTcpConnectionAllowed(
        inMetaValues, classifyContext, fwpsStreamLayer, streamCalloutId,
        processId, protocol, addressFamily, &localAddr, localPort,
        &remoteAddr, remotePort, direction, processPath);
}

void NTAPI FlowEstablishedCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    FlowEstablishedCommon(inFixedValues, inMetaValues, classifyContext,
        FALSE, FWPS_LAYER_STREAM_V4, s_CalloutIdStream, classifyOut);
}

void NTAPI FlowEstablishedCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    FlowEstablishedCommon(inFixedValues, inMetaValues, classifyContext,
        TRUE, FWPS_LAYER_STREAM_V6, s_CalloutIdStreamV6, classifyOut);
}

// DNS response capture at FWPM_LAYER_INBOUND_TRANSPORT_V4/V6 (D5).
// Inspection-only callout: copies the DNS payload of inbound UDP/53 packets
// into the DNS event queue for the service to parse.
//
// Limitation: the inbound transport layer does not expose per-packet process
// ID metadata, so DNS_EVENT.ProcessId is filled with 0; the service maps the
// resolved IPs back to processes via connection events.
static VOID DnsCommon(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _Inout_opt_ void* layerData,
    _In_ BOOLEAN isV6
)
{
    UINT8 protocol;
    UINT16 remotePort;
    BYTE remoteAddr[16];
    NET_BUFFER_LIST* nbl;
    NET_BUFFER* nb;
    UINT8 packet[512]; // DNS payload only (max 512)
    PVOID data;
    ULONG dataLen;
    DNS_EVENT event;

    // Filter conditions already restrict to UDP/53, verify defensively
    if (isV6) {
        protocol = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
        CfAddrSetV6(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16);
    } else {
        protocol = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        CfAddrSetV4(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
    }

    if (protocol != 17 || remotePort != 53) {
        return;
    }

    nbl = (NET_BUFFER_LIST*)layerData;
    if (nbl == NULL) {
        return;
    }
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL) {
        return;
    }

    dataLen = min(NET_BUFFER_DATA_LENGTH(nb), sizeof(packet));
    // Per WFP "Packet Indication Format"/"Data offset positions" documentation,
    // at FWPM_LAYER_INBOUND_TRANSPORT the indicated NBL data begins AFTER
    // the transport header: layerData is the DNS payload itself -- no IP
    // header and no UDP header are included. Copy from offset 0.
    if (dataLen < 12) { // minimal DNS header (TransactionID + Flags + counts)
        return;
    }

    data = NdisGetDataBuffer(nb, dataLen, packet, 1, 0);
    if (data == NULL) {
        // Data spans multiple MDLs with discontiguous memory; packet buffer above
        // should have been used, NULL means it could not be linearized - skip.
        return;
    }

    RtlSecureZeroMemory(&event, sizeof(DNS_EVENT));
    // Both callouts stamp events with KeQueryInterruptTimePrecise (100ns
    // units); the service re-stamps with its own wall clock on receipt.
    // The out-parameter is NOT optional (NULL write -> bugcheck 0xA).
    {
        UINT64 interruptTime = 0;
        event.Timestamp = KeQueryInterruptTimePrecise(&interruptTime);
    }
    event.ProcessId = 0; // not available at inbound transport layer
    RtlCopyMemory(event.RemoteAddr, remoteAddr, sizeof(event.RemoteAddr));
    event.AddressFamily = isV6 ? CF_ADDR_FAMILY_V6 : CF_ADDR_FAMILY_V4;
    event.DataLength = (UINT16)min(dataLen, 512);
    RtlCopyMemory(event.Data, (UINT8*)data, event.DataLength);

    QueueDnsEvent(&event);
}

void NTAPI DnsCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut); // inspection callout: no action to set

    DnsCommon(inFixedValues, layerData, FALSE);
}

void NTAPI DnsCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut); // inspection callout: no action to set

    DnsCommon(inFixedValues, layerData, TRUE);
}

// Real per-process TCP rate limiting (feature 5) at FWPM_LAYER_STREAM_V4/V6.
//
// Every TCP segment indicated at the stream layer consumes tokens from its
// process's bucket (per-direction); an empty bucket blocks the segment, so
// the sender retransmits and backs off -- the configured rate becomes actual
// enforced throughput. Buckets are installed from the service via
// IOCTL_SET_THROTTLE; without an entry for the process (and no global entry)
// everything is permitted. Process attribution comes from
// FWPS_METADATA_FIELD_PROCESS_ID (conditional at this layer); when absent the
// data cannot be attributed and is permitted.
//
// Limitation: the stream layer is TCP-only; UDP bandwidth is not throttled.
static VOID StreamThrottleCommon(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_ UINT64 flowContext,
    _In_ BOOLEAN isV6,
    _In_ UINT16 fwpsStreamLayer,
    _In_ UINT32 streamCalloutId,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(classifyOut);

    CfDiagClassifyStream(isV6); // 诊断计数：V4 流层是否被调起的判据

    // 本过滤器注册为 FWP_ACTION_CALLOUT_TERMINATING，WFP 要求 callout 给出
    // 终结判定：不设置 actionType/不清写权时流数据拿不到放行决定，网卡的
    // TCP 数据通道会整体停摆（握手能完成但任何带载数据段都被吞，实测
    // Win10 19045 + VMware NAT 复现；回环与 UDP 不经流层所以幸免）。
    // 因此无论如何都以 PERMIT 终结本层——本 callout 只做统计，不拦数据。
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return; // 别的 callout 已做终结决策，不越权
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    UINT32 processId = 0;
    BOOLEAN outbound;
    BOOLEAN permitted = TRUE;
    FWPS_STREAM_CALLOUT_IO_PACKET* ioPacket;
    FWPS_STREAM_DATA* streamData;
    UINT32 byteCount;
    BYTE localAddr[16];
    BYTE remoteAddr[16];
    UINT16 localPort, remotePort;

    // 流层 layerData 是 FWPS_STREAM_CALLOUT_IO_PACKET（内含 streamData 与
    // streamAction），不是直接的 NBL——此前按 NBL 解析导致 byteCount 恒 0、
    // 且从未设置必需的 streamAction。
    ioPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
    if (ioPacket == NULL || ioPacket->streamData == NULL) {
        return;
    }
    streamData = ioPacket->streamData;
    byteCount = (UINT32)streamData->dataLength;

    // 数据方向以 streamData->flags 为准：固定值里的 DIRECTION 是 ALE 流
    // 方向（连接发起方向），收发两个方向的数据都会带同一个值。
    outbound = (streamData->flags & FWPS_STREAM_FLAG_SEND) != 0;

    if (isV6) {
        CfAddrSetV6(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_LOCAL_ADDRESS].value.byteArray16);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_LOCAL_PORT].value.uint16;
        CfAddrSetV6(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_ADDRESS].value.byteArray16);
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_PORT].value.uint16;
    } else {
        CfAddrSetV4(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value.uint32);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint16;
        CfAddrSetV4(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32);
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint16;
    }

    // PID 归因（按优先级依次尝试），必须在惰性关联之前完成：
    //
    // 1. 流层元数据通常不带 PROCESS_ID（实测恒缺席），但只要带上就是最准
    //    确的来源，不能跳过提取；
    // 2. 已挂在流上的 FLOW_BYTE_CONTEXT 里存着 flow-established（主路径）
    //    或首次归因时抓到的 PID；
    // 3. 最后手段：SEND 方向的流层 classify 一般运行在发送线程上下文中，
    //    可用 PsGetCurrentProcessId 自识别；接收方向可能在 DPC 中运行，
    //    线程上下文不可信（会错归因给 System），不做此兜底。系统保留
    //    PID（0 = 无效、4 = System）一并排除。
    if (inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
        processId = (UINT32)inMetaValues->processId;
    }
    if (processId == 0 && flowContext != 0) {
        processId = ((PFLOW_BYTE_CONTEXT)(UINT_PTR)flowContext)->ProcessId;
    }
    if (processId == 0 && outbound) {
        UINT_PTR currentPid = (UINT_PTR)PsGetCurrentProcessId();
        if (currentPid > 4) {
            processId = (UINT32)currentPid;
        }
    }

    // 惰性关联：兜底路径——正常情况 ALE flow-established 已关联（带 PID/
    // 进程路径）；错过 flow-established 的流在这里补挂上下文，用的是本层
    // 元数据里的 flowHandle，与 flowContext 同源。传入上面已经尽力得到的
    // processId，否则新建上下文里会永久存 0，此后每次 classify 都归因失败。
    if (flowContext == 0) {
        FlowLazyAssociateAtStream(
            inMetaValues, fwpsStreamLayer, processId,
            isV6 ? CF_ADDR_FAMILY_V6 : CF_ADDR_FAMILY_V4,
            &localAddr, localPort,
            &remoteAddr, remotePort,
            outbound ? RULE_DIRECTION_OUT : RULE_DIRECTION_IN,
            streamCalloutId);
    }

    // 限速已整体迁移到 OUTBOUND_TRANSPORT_V4/V6（OutboundTransportThrottleCallout）。
    // 流层不再 BLOCK 任何方向的数据：
    //   * 入站（RECV）：classify 发生在 TCP 已 ACK 之后，被拒数据对端不会
    //     重传——BLOCK 等于静默丢数据（实测 5MB 下载只到 ~0.9MB 且 curl 报
    //     成功）；
    //   * 出站（SEND）：实测 BLOCK 后该数据不会被重新指示给 TCP——TCP 栈里
    //     根本没有这段字节、无重传可言，应用 send buffer 永不释放，连接
    //     完全冻结（实测 6400kbps 限制下 curl 上传 5MB，初始桶放行 ~835KB
    //     后 120 秒零进展）。此前注释声称"出站 BLOCK 安全"是错的。
    // 流层现在只负责字节计数（下方 FlowCountStreamBytes），令牌消耗在传输层
    // 按被放行的 TCP 段负载计费，两个方向不重复扣桶。

    // 流层 callout 必须显式设置 streamAction，NONE 表示不注入/不解耦数据。
    ioPacket->streamAction = FWPS_STREAM_ACTION_NONE;

    // 字节计数与限速互相独立：只要本段流数据被放行就累加到该连接的
    // flow context。PID 归因缺失、未配置限速都不影响统计。
    if (flowContext != 0 && permitted && byteCount > 0) {
        FlowCountStreamBytes(flowContext, outbound, byteCount);
        CfDiagStreamBytes(isV6, byteCount); // 诊断计数：驱动侧实际计到的流字节
    }
}

void NTAPI StreamThrottleCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    StreamThrottleCommon(inFixedValues, inMetaValues, layerData, flowContext,
        FALSE, FWPS_LAYER_STREAM_V4, s_CalloutIdStream, classifyOut);
}

void NTAPI StreamThrottleCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    StreamThrottleCommon(inFixedValues, inMetaValues, layerData, flowContext,
        TRUE, FWPS_LAYER_STREAM_V6, s_CalloutIdStreamV6, classifyOut);
}

// 出站传输层整形（feature 5 的真正执行点，FWPS_LAYER_OUTBOUND_TRANSPORT_V4/V6）。
//
// 为什么在 TCP 之下：此处 BLOCK 的出站段尚未离开本机、未被对端 ACK，会留在
// TCP 发送队列里由重传定时器自然重试，每次重传重新过 classify——令牌桶按
// 配置速率逐步放行，即为真正的整形（代价是重传开销）。流层 BLOCK 则会永久
// 丢数据/冻结连接（见 StreamThrottleCallout 注释），已弃用。
//
// 归因：本层不带进程元数据，用 ALE flow-established / ALE 授权登记的
// 五元组→PID 表（flow.c FlowTuple*）。查不到 PID 的流一律放行——绝不误伤
// 无法归因的流量。过滤器条件已限定 TCP；服务限速配置只装在特定 PID 上，
// 非限速 PID 的流 ThrottleCheck 恒放行。
//
// 计费字节数 = NBL 每个 NET_BUFFER 的长度减去 TCP 头（本层数据偏移从传输头
// 开始，每个 NB 是一个完整段，V4/V6 相同）。纯 ACK（payload=0）直接放行
// 不扣桶。
static VOID OutboundTransportThrottleCommon(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _Inout_opt_ void* layerData,
    _In_ BOOLEAN isV6,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UINT8 protocol;
    BYTE localAddr[16];
    BYTE remoteAddr[16];
    UINT16 localPort, remotePort;
    UINT32 processId;
    UINT32 payloadBytes = 0;
    NET_BUFFER_LIST* nbl;
    NET_BUFFER* nb;
    BOOLEAN permitted;

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return; // 别的 callout 已做终结决策，不越权
    }

    if (isV6) {
        protocol = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;
        CfAddrSetV6(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
        CfAddrSetV6(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16);
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
    } else {
        protocol = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        CfAddrSetV4(&localAddr, inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32);
        localPort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        CfAddrSetV4(&remoteAddr, inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
    }

    if (protocol != PROTOCOL_TCP) {
        return; // 过滤器条件兜底：非 TCP 不经此处处理
    }

    // 传输层与 ALE 层的地址形态按 types.h 顶部约定归一后查表（V4 的
    // uint32 主机序形态与旧实现逐位一致，实测 raw 查表命中）。
    processId = FlowTupleLookupPid(
        isV6 ? CF_ADDR_FAMILY_V6 : CF_ADDR_FAMILY_V4,
        &localAddr, localPort, &remoteAddr, remotePort);

    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    // 无法归因的流（表未命中/溢出被覆盖）一律放行，不扣桶
    if (processId == 0) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    nbl = (NET_BUFFER_LIST*)layerData;
    if (nbl == NULL) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
        UINT8 hdr[20];
        ULONG len = NET_BUFFER_DATA_LENGTH(nb);
        PVOID p;
        UINT32 tcpHdrLen;

        if (len < 20) {
            continue;
        }
        p = NdisGetDataBuffer(nb, sizeof(hdr), hdr, 1, 0);
        if (p == NULL) {
            continue; // 不连续 MDL 且无法线性化到栈缓冲：跳过该段（按放行计费偏保守处理）
        }
        if (p != (PVOID)hdr) {
            RtlCopyMemory(hdr, p, sizeof(hdr));
        }
        tcpHdrLen = ((hdr[12] >> 4) & 0xF) * 4;
        if (len > tcpHdrLen) {
            payloadBytes += len - tcpHdrLen;
        }
    }

    if (payloadBytes == 0) {
        classifyOut->actionType = FWP_ACTION_PERMIT; // 纯 ACK/无法解析：放行
        return;
    }

    permitted = ThrottleCheck(processId, TRUE, payloadBytes);
    classifyOut->actionType = permitted ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
}

void NTAPI OutboundTransportThrottleCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    OutboundTransportThrottleCommon(inFixedValues, layerData, FALSE, classifyOut);
}

void NTAPI OutboundTransportThrottleCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    OutboundTransportThrottleCommon(inFixedValues, layerData, TRUE, classifyOut);
}

// 入站 IP 包层整形（下载限速的执行点，FWPS_LAYER_INBOUND_IPPACKET_V4/V6，
// 第 19 轮从 INBOUND_TRANSPORT 层迁来）。
//
// 为什么迁移：VM 实测证实 INBOUND_TRANSPORT 收方向 NBL 只含 TCP 载荷（NB
// 起点 = 应用数据、len = MSS 载荷、DataOffset = 0），IP/TCP 头不在 NBL 里，
// clone + retreat 拿到的是垃圾——"克隆-回退-重建-注入"在该层不成立（方案
// 级前提错误）。IPPACKET 层实测（驱动 43 探针，Win10 19045）NB 起点 =
// TCP 头、IP 头在 DataOffset 之前同一数据空间里：头是真实的——克隆后
// retreat 即可露出原始 IP 头，无需重建；注入用 FwpsInjectNetworkReceiveAsync0。
//
// 该层在 NAT/策略之前、且为网络层：本 callout 只处理能通过五元组→PID 表
// （与出站整形同一张 FlowTuple 表）归因到本机进程的 TCP 流，其余一律
// PERMIT（转发流量/UDP/分片/解析失败/查不到 PID 都不碰）。地址取本层
// 固定值（与登记方同一 API 落表形态，逐位一致）；端口/协议从 NB 起点的
// TCP 头解析（该层无端口/协议固定值）。
//
// classify 决策树：
//   1. 自识别：FwpsQueryPacketInjectionState0 为 INJECTED/PREVIOUSLY_
//      INJECTED_BY_SELF → 直接放行（自己注入的包再扣会死循环）；
//   2. 解析 TCP 头（NB 起点即 TCP 头）：dataOffset 非法、非 ACK/含 SYN、
//      纯 ACK（payload==0）→ 放行（UDP/分片天然混不过 ACK 位甄别，即便
//      蒙混也会查表 miss 被放行）；
//   3. PID 归因失败（FlowTuple 表未命中）→ 放行，绝不误伤；
//   4. ThrottleCheck 通过 → PERMIT（快路径，到达时消耗令牌）；
//   5. 不足 → PacingHoldPacket 克隆+构造 IP 头后入队：成功 →
//      BLOCK+ABSORB（扣住）；失败（超限/资源不足）→ BLOCK（丢弃——队列
//      已代表多窗口积压）。
//
// 计费口径：payloadBytes = NB 长度 - TCP 头长（NB 从 TCP 头开始）。方向
// 语义不变：入站数据一律计入下载桶（ThrottleCheck outbound=FALSE），令牌
// 在"注入时"消耗（快路径除外）。诊断槽位/计数器沿用 v4/v5 的 InTransport*
// 语义（diag v5 不变版）。
static VOID InboundIpPacketThrottleCommon(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_ BOOLEAN isV6,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    NET_BUFFER_LIST* nbl;
    NET_BUFFER* nb;
    UINT8 tcpLocal[20];
    PVOID p;
    ULONG nbLen;
    UINT32 tcpHeaderLen;
    UINT32 payloadBytes;
    BYTE localAddr[16];
    BYTE remoteAddr[16];
    UINT16 localPort, remotePort;
    UINT32 processId;
    BOOLEAN permitted;
    BOOLEAN held;
    UINT32 ifIndex = 0;
    UINT32 subIfIndex = 0;
    COMPARTMENT_ID compartmentId;

    CfDiagClassifyInTransport(isV6);

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return; // 别的 callout 已做终结决策，不越权
    }

    // 终结决策统一在此之后设置（PERMIT 也要清写权：CALLOUT_TERMINATING）
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->actionType = FWP_ACTION_PERMIT;

    nbl = (NET_BUFFER_LIST*)layerData;
    if (nbl == NULL) {
        CfDiagInTransportVerdict(isV6, TRUE);
        return;
    }

    // 与其他 callout 一致的 NULL 防御：无元数据时无从扣留（ipHeaderSize/
    // compartment 均取自 inMetaValues），放行。
    if (inMetaValues == NULL) {
        CfDiagInTransportVerdict(isV6, TRUE);
        return;
    }

    // 自识别：本驱动注入的包直接放行（必须最先查，防死循环）
    if (PacingIsSelfInjected(nbl, isV6)) {
        CfDiagInTransportVerdict(isV6, TRUE);
        return;
    }

    // pacing 引擎降级防线：注入句柄创建失败（PacingEnabled=FALSE）时本层
    // 的下载限速根本没有可用的扣留/回注通道，绝不能进后面的令牌不足 →
    // BLOCK 路径（PacingHoldPacket 对 NULL 句柄返回 FALSE，调用方会把
    // held=FALSE 判成普通 BLOCK 丢包——等于限速降级变成断网）。承诺语义是
    // "pacing 不可用 = 全部放行"（见 pacing.c 初始化注释），在此整体短路。
    if (!PacingEnabled(isV6)) {
        CfDiagInTransportVerdict(isV6, TRUE);
        return;
    }

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL || NET_BUFFER_NEXT_NB(nb) != NULL) {
        CfDiagInTransportVerdict(isV6, TRUE); // 链化指示（理论不出现）：放行不碰
        return;
    }
    nbLen = NET_BUFFER_DATA_LENGTH(nb);

    // ---- 解析 TCP 头（该层 NB 起点实测 = TCP 头，IP 头在 DataOffset 之前）----
    // 第 19 轮驱动 43 探针实测（b0=1F 4A=8010 网络序源端口、nbLen=1480=20B
    // TCP 头+1460 载荷）：Win10 19045 的 INBOUND_IPPACKET_V4 指示里 NB 数据
    // 从 TCP 头开始，IP 头不在 DataOffset 处——之前"NB=完整 IP 数据报"的
    // 假设错误（版本 nibble 检查恒失败 → 静默放行，限速永不生效）。
    // 因此：TCP 头直接从 NB 起点读；IP 头留给扣留路径对克隆 retreat 露出。
    if (nbLen < 21) { // 至少 20B TCP 头 + 1B 载荷
        CfDiagInTransportVerdict(isV6, TRUE);
        return;
    }
    p = NdisGetDataBuffer(nb, sizeof(tcpLocal), tcpLocal, 1, 0);
    if (p == NULL) {
        CfDiagInTransportVerdict(isV6, TRUE); // 不连续 MDL 无法线性化：放行
        return;
    }
    if (p != (PVOID)tcpLocal) {
        RtlCopyMemory(tcpLocal, p, sizeof(tcpLocal));
    }

    tcpHeaderLen = ((tcpLocal[12] >> 4) & 0xF) * 4;
    // 该层无协议/端口固定值，靠头形态甄别 TCP：
    //   dataOffset 合法（5..15）+ ACK 置位且 SYN 清零（承载载荷的 TCP 段）
    //   + 双端口非零。UDP 头（长度字段落在同偏移）几乎不可能同时满足
    //   （需要长度高 nibble 5..15 且低字节 bit4=1），即使偶发蒙混也会在
    //   五元组查表 miss（表只登记 TCP 流）后被放行。
    if (tcpHeaderLen < 20 || tcpHeaderLen > 60 ||
        nbLen <= tcpHeaderLen ||
        (tcpLocal[13] & 0x10) == 0 ||  // 无 ACK：SYN/FIN/RST/解析噪声，放行
        (tcpLocal[13] & 0x02) != 0) {  // SYN 段不扣留（载荷为 MSS 协商等）
        CfDiagInTransportVerdict(isV6, TRUE);
        return;
    }
    payloadBytes = nbLen - tcpHeaderLen;

    // ---- 地址：本层固定值（登记方 ALE/flow-established 用同一 API 原样
    // 落表，逐位一致，杜绝字节序歧义）----
    if (isV6) {
        CfAddrSetV6(&localAddr, inFixedValues->incomingValue
            [FWPS_FIELD_INBOUND_IPPACKET_V6_IP_LOCAL_ADDRESS].value.byteArray16);
        CfAddrSetV6(&remoteAddr, inFixedValues->incomingValue
            [FWPS_FIELD_INBOUND_IPPACKET_V6_IP_REMOTE_ADDRESS].value.byteArray16);
    } else {
        CfAddrSetV4(&localAddr, inFixedValues->incomingValue
            [FWPS_FIELD_INBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value.uint32);
        CfAddrSetV4(&remoteAddr, inFixedValues->incomingValue
            [FWPS_FIELD_INBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value.uint32);
    }

    // ---- 五元组 → PID（与出站整形同一张 FlowTuple 表）----
    // 端口：TCP 头里是网络序，表里存主机序（与 ALE 固定值一致）。
    remotePort = _byteswap_ushort(*(UINT16*)(tcpLocal + 0)); // 源端口
    localPort = _byteswap_ushort(*(UINT16*)(tcpLocal + 2));  // 目的端口
    processId = FlowTupleLookupPid(
        isV6 ? CF_ADDR_FAMILY_V6 : CF_ADDR_FAMILY_V4,
        &localAddr, localPort, &remoteAddr, remotePort);

    // 无法归因的流（表未命中/转发流量/NAT 前五元组不匹配）一律放行
    if (processId == 0 || processId <= 4) {
        CfDiagInTransportVerdict(isV6, TRUE);
        return;
    }

    // ---- 令牌判定与扣留 ----
    // 同 PID 扣留队列非空时跳过快路径、无条件走扣留入队：队头大包攒令牌
    // 等待期间，后到小包若走快路径先注入，同流乱序 + 接收端重传重复投递，
    // 且小包持续偷走令牌让队头近似饥饿。PacingPidHasHeld 只拿 hold 锁
    // （锁序：全局约定"先 throttle 锁再 hold 锁"，此处调用点未持任何锁，
    // 不构成反序嵌套，论证见 pacing.c 该函数注释）。
    if (PacingPidHasHeld(processId)) {
        permitted = FALSE; // 同 PID 严格 FIFO：直接排到队尾
    } else {
        permitted = ThrottleCheck(processId, FALSE, payloadBytes); // FALSE = 下载桶
        if (permitted) {
            CfDiagInTransportVerdict(isV6, TRUE); // 快路径：到达时消耗令牌
            return;
        }
    }

    ifIndex = inFixedValues->incomingValue[isV6
        ? FWPS_FIELD_INBOUND_IPPACKET_V6_INTERFACE_INDEX
        : FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
    subIfIndex = inFixedValues->incomingValue[isV6
        ? FWPS_FIELD_INBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX
        : FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;

    // 令牌不足 → 克隆扣留（PacingHoldPacket 内部构造 IP 头使克隆成为完整
    // IP 数据报）。ABSORB = 静默扣住（非丢弃）；扣留失败回落普通 BLOCK 丢弃。
    compartmentId = (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) != 0
        ? inMetaValues->compartmentId
        : inFixedValues->incomingValue[isV6
            ? FWPS_FIELD_INBOUND_IPPACKET_V6_COMPARTMENT_ID
            : FWPS_FIELD_INBOUND_IPPACKET_V4_COMPARTMENT_ID].value.uint32;
    held = PacingHoldPacket(processId, isV6, nbl, payloadBytes,
        &localAddr, &remoteAddr, compartmentId, inMetaValues, ifIndex, subIfIndex);

    if (held) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB; // 扣住，非丢弃
    } else {
        classifyOut->actionType = FWP_ACTION_BLOCK; // 队列已代表多窗口积压
    }
    CfDiagInTransportVerdict(isV6, FALSE);
}

void NTAPI InboundIpPacketThrottleCallout(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    InboundIpPacketThrottleCommon(inFixedValues, inMetaValues, layerData, FALSE, classifyOut);
}

void NTAPI InboundIpPacketThrottleCalloutV6(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    InboundIpPacketThrottleCommon(inFixedValues, inMetaValues, layerData, TRUE, classifyOut);
}
