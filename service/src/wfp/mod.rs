//! Windows Filtering Platform (WFP) management module
//! 
//! This module provides user-mode WFP filter management using the Windows Firewall API.
//! It registers filters that point to the kernel driver's callouts.

pub mod engine;
pub mod filter;

pub use engine::WfpEngine;
pub use filter::{
    add_persistent_block_filters, remove_persistent_block_filters,
    remove_persistent_block_filters_standalone, WfpFilterManager,
};

// Callout GUIDs - must match driver-side GUIDs exactly!
// IPv4 Callout GUID: {A1B2C3D4-E5F6-4748-9A0B-1C2D3E4F5A6B}
pub const CEASEFIRE_CALLOUT_V4_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xa1b2c3d4,
    0xe5f6,
    0x4748,
    [0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b],
);

// DNS IPv4 Callout GUID: {C3D4E5F6-A7B8-495A-BC2D-3E4F5A6B7C8D}
pub const CEASEFIRE_DNS_CALLOUT_V4_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xc3d4e5f6,
    0xa7b8,
    0x495a,
    [0xbc, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d],
);

// Inbound (ALE_AUTH_RECV_ACCEPT_V4) callout GUID: {B5C6D7E8-F9A0-4B1C-8D2E-3F4A5B6C7D8E}
// Must match driver-side CEASEFIRE_CALLOUT_RECV_ACCEPT_GUID
pub const CEASEFIRE_CALLOUT_RECV_ACCEPT_V4_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xb5c6d7e8,
    0xf9a0,
    0x4b1c,
    [0x8d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e],
);

// Stream-layer (FWPM_LAYER_STREAM_V4) throttle callout GUID:
// {D1E2F3B0-B5C6-4D78-9EAF-2B8C9DAEBFC0}
// Must match driver-side CEASEFIRE_CALLOUT_STREAM_GUID.
// 2026-08-28 从 {..A8} 换新：旧 GUID 被泄漏的僵尸 callout 注册占用
// （FwpsCalloutRegister 同 GUID 返回 FWP_E_ALREADY_EXISTS、calloutId=0，
// V4 流层计数静默失效），僵尸注册无法注销，换 GUID 规避。
pub const CEASEFIRE_CALLOUT_STREAM_V4_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xd1e2f3b0,
    0xb5c6,
    0x4d78,
    [0x9e, 0xaf, 0x2b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0],
);

// ALE flow-established (FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4) association callout
// GUID: {E5A6B7CE-D9E0-4F12-A3B4-C5D6E7F8091A}
// Must match driver-side CEASEFIRE_CALLOUT_FLOWESTABLISHED_GUID
// （同 stream v4 换新，旧值 {..CC}）
pub const CEASEFIRE_CALLOUT_FLOWESTABLISHED_V4_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0xe5a6b7ce,
        0xd9e0,
        0x4f12,
        [0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a],
    );

// Outbound transport (FWPM_LAYER_OUTBOUND_TRANSPORT_V4) TCP shaper callout
// GUID: {9A0B1C2D-3E4F-4A5B-8C6D-7E8F9A0B1C2D}
// Must match driver-side CEASEFIRE_CALLOUT_OUT_TRANSPORT_GUID
pub const CEASEFIRE_CALLOUT_OUT_TRANSPORT_V4_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0x9a0b1c2d,
        0x3e4f,
        0x4a5b,
        [0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d],
    );

// 入站整形 callout。第 19 轮下载限速从 INBOUND_TRANSPORT 层迁到
// INBOUND_IPPACKET 层（传输层收方向 NBL 只含 TCP 载荷、无法克隆回退重建，
// 实测证伪）并换新 GUID：旧 GUID 的 FWPM callout 对象 applicableLayer 固定
// 在 INBOUND_TRANSPORT，服务崩溃残留时同 GUID 重注册会 ALREADY_EXISTS、新
// 层过滤器引用即失效。旧 GUID 保留用于残留过滤器/callout 对象清扫。
// Must match driver-side CEASEFIRE_CALLOUT_IN_IPPACKET_GUID
pub const CEASEFIRE_CALLOUT_IN_IPPACKET_V4_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0x9a0b1c31,
        0x3e4f,
        0x4a5b,
        [0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d],
    );

// 旧 INBOUND_TRANSPORT_V4 下载整形 callout（第 19 轮弃用，仅清扫用）
pub const CEASEFIRE_CALLOUT_IN_TRANSPORT_V4_LEGACY_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0x9a0b1c2f,
        0x3e4f,
        0x4a5b,
        [0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d],
    );

// ---- IPv6 对应层 callout GUID（必须与驱动侧 wfp.c 逐个一致）----
// V6 连接授权（FWPM_LAYER_ALE_AUTH_CONNECT_V6）：{A1B2C3D5-E5F6-4748-9A0B-1C2D3E4F5A6B}
pub const CEASEFIRE_CALLOUT_V6_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xa1b2c3d5,
    0xe5f6,
    0x4748,
    [0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b],
);

// V6 入站授权（FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6）：{B5C6D7E9-F9A0-4B1C-8D2E-3F4A5B6C7D8E}
pub const CEASEFIRE_CALLOUT_RECV_ACCEPT_V6_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0xb5c6d7e9,
        0xf9a0,
        0x4b1c,
        [0x8d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e],
    );

// V6 DNS 抓包（FWPM_LAYER_INBOUND_TRANSPORT_V6）：{C3D4E5F7-A7B8-495A-BC2D-3E4F5A6B7C8D}
pub const CEASEFIRE_DNS_CALLOUT_V6_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xc3d4e5f7,
    0xa7b8,
    0x495a,
    [0xbc, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d],
);

// V6 流层限速/计数（FWPM_LAYER_STREAM_V6）：{D1E2F3A9-B5C6-4D78-9EAF-2B8C9DAEBFC0}
pub const CEASEFIRE_CALLOUT_STREAM_V6_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0xd1e2f3a9,
        0xb5c6,
        0x4d78,
        [0x9e, 0xaf, 0x2b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0],
    );

// V6 flow-established（FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6）：{E5A6B7CD-D9E0-4F12-A3B4-C5D6E7F8091A}
pub const CEASEFIRE_CALLOUT_FLOWESTABLISHED_V6_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0xe5a6b7cd,
        0xd9e0,
        0x4f12,
        [0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a],
    );

// V6 出站整形（FWPM_LAYER_OUTBOUND_TRANSPORT_V6）：{9A0B1C2E-3E4F-4A5B-8C6D-7E8F9A0B1C2D}
pub const CEASEFIRE_CALLOUT_OUT_TRANSPORT_V6_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0x9a0b1c2e,
        0x3e4f,
        0x4a5b,
        [0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d],
    );

// V6 入站整形（FWPM_LAYER_INBOUND_IPPACKET_V6）：{9A0B1C32-3E4F-4A5B-8C6D-7E8F9A0B1C2D}
// （第 19 轮从 INBOUND_TRANSPORT_V6 旧 GUID {9A0B1C30} 换新，理由同 V4）
pub const CEASEFIRE_CALLOUT_IN_IPPACKET_V6_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0x9a0b1c32,
        0x3e4f,
        0x4a5b,
        [0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d],
    );

// 旧 INBOUND_TRANSPORT_V6 下载整形 callout（第 19 轮弃用，仅清扫用）
pub const CEASEFIRE_CALLOUT_IN_TRANSPORT_V6_LEGACY_GUID: windows::core::GUID =
    windows::core::GUID::from_values(
        0x9a0b1c30,
        0x3e4f,
        0x4a5b,
        [0x8c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d],
    );

// Provider GUID for Ceasefire Firewall: {D4E5F6A7-B8C9-4960-CD3E-4F5A6B7C8D9E}
pub const CEASEFIRE_PROVIDER_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xd4e5f6a7,
    0xb8c9,
    0x4960,
    [0xcd, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e],
);

// Sublayer GUID for Ceasefire filters: {D4E5F6A7-B8C9-4A71-CD3E-4F5A6B7C8D9E}
pub const CEASEFIRE_SUBLAYER_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xd4e5f6a7,
    0xb8c9,
    0x4a71,
    [0xcd, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e],
);
