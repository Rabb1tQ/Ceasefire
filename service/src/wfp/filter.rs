//! WFP Filter management
//!
//! Manages WFP filters that point to the driver's callouts.
//!
//! V4/V6 全对齐：每个 callout 过滤层都有对应的 V6 版本（ALE_AUTH_CONNECT、
//! ALE_AUTH_RECV_ACCEPT、STREAM、ALE_FLOW_ESTABLISHED、OUTBOUND_TRANSPORT、
//! INBOUND_TRANSPORT/DNS）。V6 层驱动 classify 用 FWP_BYTE_ARRAY16 读地址，
//! 与 V4 层共用业务逻辑。kill-switch 持久过滤器同样双栈。

use super::super::error::{Result, ServiceError};
use super::engine::WfpEngine;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use std::ptr;
use std::sync::Arc;

pub struct WfpFilterManager {
    engine: Arc<WfpEngine>,
    filter_id_v4: Option<u64>,
    filter_id_recv_accept: Option<u64>,
    filter_id_dns: Option<u64>,
    filter_id_stream: Option<u64>,
    filter_id_flow_established: Option<u64>,
    filter_id_out_transport: Option<u64>,
    filter_id_in_transport: Option<u64>,
    // IPv6 对应层（与 V4 逐层对齐，见 add_filter_v6_* 系列）
    filter_id_v6: Option<u64>,
    filter_id_recv_accept_v6: Option<u64>,
    filter_id_dns_v6: Option<u64>,
    filter_id_stream_v6: Option<u64>,
    filter_id_flow_established_v6: Option<u64>,
    filter_id_out_transport_v6: Option<u64>,
    filter_id_in_transport_v6: Option<u64>,
}

impl WfpFilterManager {
    /// Create a new filter manager
    pub fn new(engine: Arc<WfpEngine>) -> Self {
        WfpFilterManager {
            engine,
            filter_id_v4: None,
            filter_id_recv_accept: None,
            filter_id_dns: None,
            filter_id_stream: None,
            filter_id_flow_established: None,
            filter_id_out_transport: None,
            filter_id_in_transport: None,
            filter_id_v6: None,
            filter_id_recv_accept_v6: None,
            filter_id_dns_v6: None,
            filter_id_stream_v6: None,
            filter_id_flow_established_v6: None,
            filter_id_out_transport_v6: None,
            filter_id_in_transport_v6: None,
        }
    }

    /// Register callouts with WFP (user-mode registration)
    pub fn register_callouts(&mut self) -> Result<()> {
        tracing::info!("Registering WFP callouts");

        self.register_callout_v4()?;
        self.register_callout_recv_accept()?;
        // DNS 抓包 callout 注册失败不影响主过滤功能
        if let Err(e) = self.register_callout_stream() {
            tracing::warn!("Stream throttle callout registration failed (rate limiting disabled): {}", e);
        }

        if let Err(e) = self.register_callout_flow_established() {
            tracing::warn!("Flow-established callout registration failed (per-flow byte counting disabled): {}", e);
        }

        if let Err(e) = self.register_callout_out_transport() {
            tracing::warn!("Outbound-transport callout registration failed (outbound shaping disabled): {}", e);
        }

        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_CALLOUT_IN_IPPACKET_V4_GUID,
            &FWPM_LAYER_INBOUND_IPPACKET_V4,
            "Ceasefire Inbound IP Packet Shaper Callout",
            "Per-process TCP download shaping at the inbound IP packet layer",
        ) {
            tracing::warn!("Inbound-ippacket callout registration failed (download shaping disabled): {}", e);
        }

        if let Err(e) = self.register_callout_dns() {
            tracing::warn!("DNS callout registration failed (DNS capture disabled): {}", e);
        }

        // ---- IPv6 对应层（注册失败仅该 V6 层失效，逐个告警不阻断）----
        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_CALLOUT_V6_GUID,
            &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "Ceasefire IPv6 Callout",
            "Callout for IPv6 connection filtering",
        ) {
            tracing::warn!("IPv6 connect callout registration failed (IPv6 outbound control disabled): {}", e);
        }
        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V6_GUID,
            &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "Ceasefire Inbound IPv6 Callout",
            "Callout for inbound IPv6 connection filtering",
        ) {
            tracing::warn!("IPv6 recv-accept callout registration failed (IPv6 inbound control disabled): {}", e);
        }
        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_CALLOUT_STREAM_V6_GUID,
            &FWPM_LAYER_STREAM_V6,
            "Ceasefire Stream Throttle IPv6 Callout",
            "Callout for per-process IPv6 TCP bandwidth limiting",
        ) {
            tracing::warn!("IPv6 stream callout registration failed (IPv6 rate limiting disabled): {}", e);
        }
        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V6_GUID,
            &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
            "Ceasefire Flow-Established IPv6 Callout",
            "Associates per-IPv6-TCP-flow byte counting context",
        ) {
            tracing::warn!("IPv6 flow-established callout registration failed (IPv6 byte counting disabled): {}", e);
        }
        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V6_GUID,
            &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
            "Ceasefire Outbound Transport Shaper IPv6 Callout",
            "Per-process IPv6 TCP egress shaping below the TCP layer",
        ) {
            tracing::warn!("IPv6 outbound-transport callout registration failed (IPv6 outbound shaping disabled): {}", e);
        }
        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_CALLOUT_IN_IPPACKET_V6_GUID,
            &FWPM_LAYER_INBOUND_IPPACKET_V6,
            "Ceasefire Inbound IP Packet Shaper IPv6 Callout",
            "Per-process IPv6 TCP download shaping at the inbound IP packet layer",
        ) {
            tracing::warn!("Inbound-ippacket-v6 callout registration failed (IPv6 download shaping disabled): {}", e);
        }
        if let Err(e) = self.register_callout_generic(
            &super::CEASEFIRE_DNS_CALLOUT_V6_GUID,
            &FWPM_LAYER_INBOUND_TRANSPORT_V6,
            "Ceasefire DNS Capture IPv6 Callout",
            "Inspection callout for IPv6 DNS response capture (UDP/53)",
        ) {
            tracing::warn!("IPv6 DNS callout registration failed (IPv6 DNS capture disabled): {}", e);
        }

        tracing::info!("WFP callouts registered successfully");
        Ok(())
    }

    /// 通用 callout 注册（V6 各层与 V4 语义一致：ALREADY_EXISTS 视为成功）
    fn register_callout_generic(
        &self,
        callout_key: &windows::core::GUID,
        layer_key: &windows::core::GUID,
        name: &str,
        description: &str,
    ) -> Result<()> {
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_w: Vec<u16> = description.encode_utf16().chain(std::iter::once(0)).collect();

        let callout = FWPM_CALLOUT0 {
            calloutKey: *callout_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_w.as_ptr() as *mut u16),
                description: windows::core::PWSTR(desc_w.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            applicableLayer: *layer_key,
            calloutId: 0,
        };

        unsafe {
            let result = FwpmCalloutAdd0(self.engine.handle(), &callout, None, None);
            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register callout '{}': error code 0x{:08X}",
                    name, result
                )));
            }
        }
        Ok(())
    }

    /// 通用 callout 过滤器添加（会话级；conditions 为空 = 匹配该层全部流量）。
    /// 返回引擎分配的 filterId；调用方负责记录并在 remove_filters 删除。
    fn add_filter_generic(
        &mut self,
        layer_key: &windows::core::GUID,
        callout_key: &windows::core::GUID,
        name: &str,
        description: &str,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> Result<u64> {
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_w: Vec<u16> = description.encode_utf16().chain(std::iter::once(0)).collect();

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_w.as_ptr() as *mut u16),
                description: windows::core::PWSTR(desc_w.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: *layer_key,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                ptr::null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 { calloutKey: *callout_key },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;
        unsafe {
            let result = FwpmFilterAdd0(self.engine.handle(), &filter, None, Some(&mut filter_id));
            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add filter '{}': error code 0x{:08X}",
                    name, result
                )));
            }
        }
        tracing::info!("Filter '{}' added with ID: {}", name, filter_id);
        Ok(filter_id)
    }

    /// TCP 协议条件（V4/V6 层的 IP_PROTOCOL 条件键相同）
    fn tcp_condition() -> FWPM_FILTER_CONDITION0 {
        let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        c.matchType = FWP_MATCH_EQUAL;
        c.conditionValue.r#type = FWP_UINT8;
        c.conditionValue.Anonymous.uint8 = 6;
        c
    }

    /// loopback 排除条件（V4/V6 通用：FLAGS 条件键两族相同）。
    /// 终止型（CALLOUT_TERMINATING）流层过滤器挂在 loopback 会话上时，
    /// 即使 callout 只返回 ACTION_NONE 也会令数据路径停摆，本机 TCP 全挂
    /// （VM 实测 2026-08-28 过滤器二分定位），因此流层只匹配 loopback 位
    /// 未置位的流量。windows crate 无 FWP_MATCH_FLAGS_NOT_ALL_SET，对单
    /// bit 值 FLAGS_NONE_SET 语义等价：IS_LOOPBACK 未置位才匹配
    fn loopback_exclusion_condition() -> FWPM_FILTER_CONDITION0 {
        let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        c.fieldKey = FWPM_CONDITION_FLAGS;
        c.matchType = FWP_MATCH_FLAGS_NONE_SET;
        c.conditionValue.r#type = FWP_UINT32;
        c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        c
    }

    /// Register IPv4 callout
    fn register_callout_v4(&mut self) -> Result<()> {
        tracing::info!("Registering IPv4 callout");

        let callout_name = windows::core::w!("Ceasefire IPv4 Callout");
        let callout_description = windows::core::w!("Callout for IPv4 connection filtering");

        let callout = FWPM_CALLOUT0 {
            calloutKey: super::CEASEFIRE_CALLOUT_V4_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(callout_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(callout_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            applicableLayer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            calloutId: 0,
        };

        unsafe {
            let result = FwpmCalloutAdd0(
                self.engine.handle(),
                &callout,
                None,
                None,
            );

            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register IPv4 callout: error code 0x{:08X}",
                    result
                )));
            }
        }

        tracing::info!("IPv4 callout registered successfully");
        Ok(())
    }

    /// Register inbound (recv-accept) callout
    fn register_callout_recv_accept(&mut self) -> Result<()> {
        tracing::info!("Registering inbound (recv-accept) callout");

        let callout_name = windows::core::w!("Ceasefire Inbound Callout");
        let callout_description = windows::core::w!("Callout for inbound IPv4 connection filtering");

        let callout = FWPM_CALLOUT0 {
            calloutKey: super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V4_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(callout_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(callout_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            applicableLayer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            calloutId: 0,
        };

        unsafe {
            let result = FwpmCalloutAdd0(
                self.engine.handle(),
                &callout,
                None,
                None,
            );

            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register inbound callout: error code 0x{:08X}",
                    result
                )));
            }
        }

        tracing::info!("Inbound callout registered successfully");
        Ok(())
    }

    /// Register stream-layer throttle callout (TCP rate limiting)
    fn register_callout_stream(&mut self) -> Result<()> {
        tracing::info!("Registering stream throttle callout");

        let callout_name = windows::core::w!("Ceasefire Stream Throttle Callout");
        let callout_description = windows::core::w!("Callout for per-process TCP bandwidth limiting");

        let callout = FWPM_CALLOUT0 {
            calloutKey: super::CEASEFIRE_CALLOUT_STREAM_V4_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(callout_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(callout_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            applicableLayer: FWPM_LAYER_STREAM_V4,
            calloutId: 0,
        };

        unsafe {
            let result = FwpmCalloutAdd0(
                self.engine.handle(),
                &callout,
                None,
                None,
            );

            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register stream throttle callout: error code 0x{:08X}",
                    result
                )));
            }
        }

        tracing::info!("Stream throttle callout registered successfully");
        Ok(())
    }

    /// Add stream-layer throttle filter (loopback excluded: a terminating
    /// stream callout stalls loopback TCP data flow even when it permits;
    /// the callout permits everything unless a throttle entry
    /// matches the stream's process)
    fn add_filter_stream(&mut self) -> Result<()> {
        tracing::info!("Adding stream throttle filter");

        let filter_name = windows::core::w!("Ceasefire Stream Throttle Filter");
        let filter_description = windows::core::w!("Per-process TCP bandwidth limiting");

        let mut conditions = [Self::loopback_exclusion_condition()];

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: FWPM_LAYER_STREAM_V4,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: super::CEASEFIRE_CALLOUT_STREAM_V4_GUID,
                },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(
                self.engine.handle(),
                &filter,
                None,
                Some(&mut filter_id),
            );

            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add stream throttle filter: error code 0x{:08X}",
                    result
                )));
            }
        }

        self.filter_id_stream = Some(filter_id);
        tracing::info!("Stream throttle filter added with ID: {}", filter_id);
        Ok(())
    }

    /// Register ALE flow-established callout (association-only).
    /// Drives per-flow byte counting; losing it just falls back to EStats.
    fn register_callout_flow_established(&mut self) -> Result<()> {
        tracing::info!("Registering flow-established association callout");

        let callout_name = windows::core::w!("Ceasefire Flow-Established Callout");
        let callout_description =
            windows::core::w!("Associates per-TCP-flow byte counting context");

        let callout = FWPM_CALLOUT0 {
            calloutKey: super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V4_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(callout_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(callout_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            applicableLayer: FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            calloutId: 0,
        };

        unsafe {
            let result = FwpmCalloutAdd0(
                self.engine.handle(),
                &callout,
                None,
                None,
            );

            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register flow-established callout: error code 0x{:08X}",
                    result
                )));
            }
        }

        tracing::info!("Flow-established callout registered successfully");
        Ok(())
    }

    /// Add flow-established filter that only matches TCP flows. The callout
    /// permits everything; it exists to hand each TCP flow a byte-count context.
    fn add_filter_flow_established(&mut self) -> Result<()> {
        tracing::info!("Adding flow-established association filter");

        let filter_name = windows::core::w!("Ceasefire Flow-Established Filter");
        let filter_description =
            windows::core::w!("Per-flow byte counting context association");

        let mut conditions: [FWPM_FILTER_CONDITION0; 1] = unsafe { std::mem::zeroed() };

        // IP protocol == TCP (6)
        conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.r#type = FWP_UINT8;
        conditions[0].conditionValue.Anonymous.uint8 = 6;

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: 1,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V4_GUID,
                },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(
                self.engine.handle(),
                &filter,
                None,
                Some(&mut filter_id),
            );

            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add flow-established filter: error code 0x{:08X}",
                    result
                )));
            }
        }

        self.filter_id_flow_established = Some(filter_id);
        tracing::info!("Flow-established filter added with ID: {}", filter_id);
        Ok(())
    }

    /// Register DNS capture callout at inbound transport layer
    fn register_callout_dns(&mut self) -> Result<()> {
        tracing::info!("Registering DNS capture callout");

        let callout_name = windows::core::w!("Ceasefire DNS Capture Callout");
        let callout_description = windows::core::w!("Inspection callout for DNS response capture (UDP/53)");

        let callout = FWPM_CALLOUT0 {
            calloutKey: super::CEASEFIRE_DNS_CALLOUT_V4_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(callout_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(callout_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            applicableLayer: FWPM_LAYER_INBOUND_TRANSPORT_V4,
            calloutId: 0,
        };

        unsafe {
            let result = FwpmCalloutAdd0(
                self.engine.handle(),
                &callout,
                None,
                None,
            );

            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register DNS callout: error code 0x{:08X}",
                    result
                )));
            }
        }

        tracing::info!("DNS capture callout registered successfully");
        Ok(())
    }

    /// Register outbound transport shaper callout (real TCP egress shaping).
    fn register_callout_out_transport(&mut self) -> Result<()> {
        tracing::info!("Registering outbound transport shaper callout");

        let callout_name = windows::core::w!("Ceasefire Outbound Transport Shaper Callout");
        let callout_description =
            windows::core::w!("Per-process TCP egress shaping below the TCP layer");

        let callout = FWPM_CALLOUT0 {
            calloutKey: super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V4_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(callout_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(callout_description.as_ptr() as *mut u16),
            },
            flags: 0,
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            applicableLayer: FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            calloutId: 0,
        };

        unsafe {
            let result = FwpmCalloutAdd0(
                self.engine.handle(),
                &callout,
                None,
                None,
            );

            // ERROR_FWP_ALREADY_EXISTS (0x80320009) is OK
            if result != 0 && result != 0x80320009 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to register outbound transport callout: error code 0x{:08X}",
                    result
                )));
            }
        }

        tracing::info!("Outbound transport shaper callout registered successfully");
        Ok(())
    }

    /// Add outbound transport shaper filter (TCP only). The callout permits
    /// everything unless the flow's process has a throttle entry.
    fn add_filter_out_transport(&mut self) -> Result<()> {
        tracing::info!("Adding outbound transport shaper filter");

        let filter_name = windows::core::w!("Ceasefire Outbound Transport Shaper Filter");
        let filter_description = windows::core::w!("Per-process TCP egress shaping");

        let mut conditions: [FWPM_FILTER_CONDITION0; 1] = unsafe { std::mem::zeroed() };

        // IP protocol == TCP (6)
        conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.r#type = FWP_UINT8;
        conditions[0].conditionValue.Anonymous.uint8 = 6;

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: 1,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V4_GUID,
                },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(
                self.engine.handle(),
                &filter,
                None,
                Some(&mut filter_id),
            );

            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add outbound transport shaper filter: error code 0x{:08X}",
                    result
                )));
            }
        }

        self.filter_id_out_transport = Some(filter_id);
        tracing::info!("Outbound transport shaper filter added with ID: {}", filter_id);
        Ok(())
    }

    /// Add inbound IP packet shaper filter (download shaping, Round 19: moved
    /// from INBOUND_TRANSPORT — that layer's inbound NBLs carry TCP payload
    /// only and clone+retreat cannot reconstruct headers; INBOUND_IPPACKET
    /// NBLs are complete IP datagrams). The callout parses the IP header
    /// itself and permits everything it cannot attribute, so no protocol
    /// condition here: FWPM_CONDITION_IP_PROTOCOL is not a valid field at the
    /// IPPACKET layers (filter add would fail 0x80320002). Only loopback is
    /// excluded; TCP/fragment/tuple filtering all happen in the callout.
    fn add_filter_in_transport(&mut self) -> Result<()> {
        tracing::info!("Adding inbound ip packet shaper filter");

        let filter_name = windows::core::w!("Ceasefire Inbound IP Packet Shaper Filter");
        let filter_description = windows::core::w!("Per-process TCP download shaping");

        let mut conditions = [Self::loopback_exclusion_condition()];

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: FWPM_LAYER_INBOUND_IPPACKET_V4,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: super::CEASEFIRE_CALLOUT_IN_IPPACKET_V4_GUID,
                },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(
                self.engine.handle(),
                &filter,
                None,
                Some(&mut filter_id),
            );

            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add inbound ip packet shaper filter: error code 0x{:08X}",
                    result
                )));
            }
        }

        self.filter_id_in_transport = Some(filter_id);
        tracing::info!("Inbound ip packet shaper filter added with ID: {}", filter_id);
        Ok(())
    }

    /// IPv6 各层 callout 过滤器（与 V4 逐层对齐；失败仅该层失效不阻断）。
    fn add_filter_v6(&mut self) -> Result<()> {
        // ALE_AUTH_CONNECT_V6（无条件：全部 V6 出站连接）
        self.filter_id_v6 = self
            .add_filter_generic(
                &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                &super::CEASEFIRE_CALLOUT_V6_GUID,
                "Ceasefire IPv6 Filter",
                "Filter for IPv6 outbound connections",
                &mut [],
            )
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        // ALE_AUTH_RECV_ACCEPT_V6
        self.filter_id_recv_accept_v6 = self
            .add_filter_generic(
                &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                &super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V6_GUID,
                "Ceasefire Inbound IPv6 Filter",
                "Filter for IPv6 inbound connections",
                &mut [],
            )
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        // STREAM_V6（loopback 排除，与 V4 对齐：流层只对 TCP 流数据生效，
        // 且 STREAM 层不提供 FWPM_CONDITION_IP_PROTOCOL 字段，加条件会
        // 0x80320002 CONDITION_NOT_FOUND；终止型流层过滤器必须排除
        // loopback，否则本机 TCP 挂死，见 loopback_exclusion_condition）
        let mut cond = [Self::loopback_exclusion_condition()];
        self.filter_id_stream_v6 = self
            .add_filter_generic(
                &FWPM_LAYER_STREAM_V6,
                &super::CEASEFIRE_CALLOUT_STREAM_V6_GUID,
                "Ceasefire Stream Throttle IPv6 Filter",
                "Per-process IPv6 TCP bandwidth limiting",
                &mut cond,
            )
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        // ALE_FLOW_ESTABLISHED_V6（TCP only）
        let mut cond = [Self::tcp_condition()];
        self.filter_id_flow_established_v6 = self
            .add_filter_generic(
                &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
                &super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V6_GUID,
                "Ceasefire Flow-Established IPv6 Filter",
                "Per-flow byte counting context association (IPv6)",
                &mut cond,
            )
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        // OUTBOUND_TRANSPORT_V6（TCP only，真正的 V6 出站整形执行点）
        let mut cond = [Self::tcp_condition()];
        self.filter_id_out_transport_v6 = self
            .add_filter_generic(
                &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                &super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V6_GUID,
                "Ceasefire Outbound Transport Shaper IPv6 Filter",
                "Per-process IPv6 TCP egress shaping",
                &mut cond,
            )
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        // INBOUND_IPPACKET_V6（V6 下载整形执行点，第 19 轮自 INBOUND_TRANSPORT
        // 迁来；条件仅 loopback 排除，理由同 V4——IP_PROTOCOL 非本层合法字段。
        // 注意与本层无关的 DNS 抓包过滤器仍在 INBOUND_TRANSPORT_V6 上）
        let mut cond = [Self::loopback_exclusion_condition()];
        self.filter_id_in_transport_v6 = self
            .add_filter_generic(
                &FWPM_LAYER_INBOUND_IPPACKET_V6,
                &super::CEASEFIRE_CALLOUT_IN_IPPACKET_V6_GUID,
                "Ceasefire Inbound IP Packet Shaper IPv6 Filter",
                "Per-process IPv6 TCP download shaping",
                &mut cond,
            )
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        // INBOUND_TRANSPORT_V6（UDP 源端口 53，DNS 抓包，inspection）
        let mut dns_conds: [FWPM_FILTER_CONDITION0; 2] = unsafe { std::mem::zeroed() };
        dns_conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        dns_conds[0].matchType = FWP_MATCH_EQUAL;
        dns_conds[0].conditionValue.r#type = FWP_UINT8;
        dns_conds[0].conditionValue.Anonymous.uint8 = 17;
        dns_conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        dns_conds[1].matchType = FWP_MATCH_EQUAL;
        dns_conds[1].conditionValue.r#type = FWP_UINT16;
        dns_conds[1].conditionValue.Anonymous.uint16 = 53;
        self.filter_id_dns_v6 = self
            .add_filter_generic(
                &FWPM_LAYER_INBOUND_TRANSPORT_V6,
                &super::CEASEFIRE_DNS_CALLOUT_V6_GUID,
                "Ceasefire DNS Capture IPv6 Filter",
                "Capture inbound IPv6 DNS responses (UDP source port 53)",
                &mut dns_conds,
            )
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        Ok(())
    }

    /// Add filters to intercept connections
    pub fn add_filters(&mut self) -> Result<()> {
        tracing::info!("Adding WFP filters");

        // 排障开关：CEASEFIRE_SKIP_FILTERS 位掩码，跳过添加对应过滤器
        // （1=DNS 抓包 2=流层 4=flow-established 8=出站整形 16=入站整形 32=V6 全部）
        let skip = std::env::var("CEASEFIRE_SKIP_FILTERS")
            .ok()
            .and_then(|v| u32::from_str_radix(v.trim(), 10).ok())
            .unwrap_or(0);
        if skip != 0 {
            tracing::warn!("CEASEFIRE_SKIP_FILTERS={} active, some filters will NOT be added", skip);
        }

        self.add_filter_v4()?;
        self.add_filter_recv_accept()?;
        // DNS 过滤器添加失败不影响主过滤功能
        if skip & 1 == 0 {
            if let Err(e) = self.add_filter_dns() {
                tracing::warn!("DNS filter add failed (DNS capture disabled): {}", e);
            }
        }
        // 限速过滤器失败仅意味着限速不生效，不影响拦截
        if skip & 2 == 0 {
            if let Err(e) = self.add_filter_stream() {
                tracing::warn!("Stream throttle filter add failed (rate limiting disabled): {}", e);
            }
        }

// flow-established 关联过滤器失败只是退回 EStats 兜底
        if skip & 4 == 0 {
            if let Err(e) = self.add_filter_flow_established() {
                tracing::warn!("Flow-established filter add failed (per-flow byte counting disabled): {}", e);
            }
        }

        // 出站整形过滤器失败意味着出站限速退化为仅统计
        if skip & 8 == 0 {
            if let Err(e) = self.add_filter_out_transport() {
                tracing::warn!("Outbound transport shaper filter add failed (outbound shaping disabled): {}", e);
            }
        }

        // 入站整形（下载限速）过滤器失败仅意味着下载限速不生效
        if skip & 16 == 0 {
            if let Err(e) = self.add_filter_in_transport() {
                tracing::warn!("Inbound ip packet shaper filter add failed (download shaping disabled): {}", e);
            }
        }

        // IPv6 各层过滤器（与 V4 逐层对齐）；add_filter_v6 内部已逐项告警
        if let Err(e) = self.add_filter_v6() {
            tracing::warn!("IPv6 filter add failed: {}", e);
        }

        tracing::info!("WFP filters added successfully");
        Ok(())
    }

    /// Add IPv4 filter
    fn add_filter_v4(&mut self) -> Result<()> {
        tracing::info!("Adding IPv4 filter");

        let filter_name = windows::core::w!("Ceasefire IPv4 Filter");
        let filter_description = windows::core::w!("Filter for IPv4 outbound connections");

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: 0,
            filterCondition: ptr::null_mut(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: super::CEASEFIRE_CALLOUT_V4_GUID,
                },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(
                self.engine.handle(),
                &filter,
                None,
                Some(&mut filter_id),
            );

            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add IPv4 filter: error code 0x{:08X}",
                    result
                )));
            }
        }

        self.filter_id_v4 = Some(filter_id);
        tracing::info!("IPv4 filter added with ID: {}", filter_id);
        Ok(())
    }

    /// Add inbound filter at ALE_AUTH_RECV_ACCEPT_V4
    fn add_filter_recv_accept(&mut self) -> Result<()> {
        tracing::info!("Adding inbound (recv-accept) filter");

        let filter_name = windows::core::w!("Ceasefire Inbound Filter");
        let filter_description = windows::core::w!("Filter for IPv4 inbound connections");

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: 0,
            filterCondition: ptr::null_mut(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_TERMINATING,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V4_GUID,
                },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(
                self.engine.handle(),
                &filter,
                None,
                Some(&mut filter_id),
            );

            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add inbound filter: error code 0x{:08X}",
                    result
                )));
            }
        }

        self.filter_id_recv_accept = Some(filter_id);
        tracing::info!("Inbound filter added with ID: {}", filter_id);
        Ok(())
    }

    /// Add DNS capture filter: inbound UDP from source port 53, inspection only
    fn add_filter_dns(&mut self) -> Result<()> {
        tracing::info!("Adding DNS capture filter");

        let filter_name = windows::core::w!("Ceasefire DNS Capture Filter");
        let filter_description = windows::core::w!("Capture inbound DNS responses (UDP source port 53)");

        let mut conditions: [FWPM_FILTER_CONDITION0; 2] = unsafe { std::mem::zeroed() };

        // IP protocol == UDP (17)
        conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.r#type = FWP_UINT8;
        conditions[0].conditionValue.Anonymous.uint8 = 17;

        // Remote (source) port == 53
        conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[1].matchType = FWP_MATCH_EQUAL;
        conditions[1].conditionValue.r#type = FWP_UINT16;
        conditions[1].conditionValue.Anonymous.uint16 = 53;

        let filter = FWPM_FILTER0 {
            filterKey: windows::core::GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
            },
            flags: FWPM_FILTER_FLAGS(0),
            providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: FWPM_LAYER_INBOUND_TRANSPORT_V4,
            subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 1 },
            },
            numFilterConditions: 2,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_CALLOUT_INSPECTION,
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: super::CEASEFIRE_DNS_CALLOUT_V4_GUID,
                },
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;

        unsafe {
            let result = FwpmFilterAdd0(
                self.engine.handle(),
                &filter,
                None,
                Some(&mut filter_id),
            );

            if result != 0 {
                return Err(ServiceError::Wfp(format!(
                    "Failed to add DNS capture filter: error code 0x{:08X}",
                    result
                )));
            }
        }

        self.filter_id_dns = Some(filter_id);
        tracing::info!("DNS capture filter added with ID: {}", filter_id);
        Ok(())
    }

    /// Remove all filters
    pub fn remove_filters(&mut self) -> Result<()> {
        tracing::info!("Removing WFP filters");

        unsafe {
            if let Some(filter_id) = self.filter_id_v4 {
                let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                if result != 0 {
                    tracing::warn!("Failed to delete IPv4 filter: error code 0x{:08X}", result);
                } else {
                    tracing::info!("IPv4 filter removed");
                }
                self.filter_id_v4 = None;
            }

            if let Some(filter_id) = self.filter_id_recv_accept {
                let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                if result != 0 {
                    tracing::warn!("Failed to delete inbound filter: error code 0x{:08X}", result);
                } else {
                    tracing::info!("Inbound filter removed");
                }
                self.filter_id_recv_accept = None;
            }

            if let Some(filter_id) = self.filter_id_dns {
                let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                if result != 0 {
                    tracing::warn!("Failed to delete DNS filter: error code 0x{:08X}", result);
                } else {
                    tracing::info!("DNS filter removed");
                }
                self.filter_id_dns = None;
            }

            if let Some(filter_id) = self.filter_id_stream {
                let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                if result != 0 {
                    tracing::warn!("Failed to delete stream throttle filter: error code 0x{:08X}", result);
                } else {
                    tracing::info!("Stream throttle filter removed");
                }
                self.filter_id_stream = None;
            }

            if let Some(filter_id) = self.filter_id_flow_established {
                let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                if result != 0 {
                    tracing::warn!("Failed to delete flow-established filter: error code 0x{:08X}", result);
                } else {
                    tracing::info!("Flow-established filter removed");
                }
                self.filter_id_flow_established = None;
            }

            if let Some(filter_id) = self.filter_id_out_transport {
                let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                if result != 0 {
                    tracing::warn!("Failed to delete outbound transport shaper filter: error code 0x{:08X}", result);
                } else {
                    tracing::info!("Outbound transport shaper filter removed");
                }
                self.filter_id_out_transport = None;
            }

            if let Some(filter_id) = self.filter_id_in_transport {
                let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                if result != 0 {
                    tracing::warn!("Failed to delete inbound transport shaper filter: error code 0x{:08X}", result);
                } else {
                    tracing::info!("Inbound transport shaper filter removed");
                }
                self.filter_id_in_transport = None;
            }

            // IPv6 各层（逐个按 id 删；None = 安装时已失败，无需删除）
            let v6_entries: [(&str, &mut Option<u64>); 7] = [
                ("IPv6 connect", &mut self.filter_id_v6),
                ("IPv6 recv-accept", &mut self.filter_id_recv_accept_v6),
                ("IPv6 DNS capture", &mut self.filter_id_dns_v6),
                ("IPv6 stream throttle", &mut self.filter_id_stream_v6),
                ("IPv6 flow-established", &mut self.filter_id_flow_established_v6),
                ("IPv6 outbound transport shaper", &mut self.filter_id_out_transport_v6),
                ("IPv6 inbound transport shaper", &mut self.filter_id_in_transport_v6),
            ];
            for (name, slot) in v6_entries {
                if let Some(filter_id) = *slot {
                    let result = FwpmFilterDeleteById0(self.engine.handle(), filter_id);
                    if result != 0 {
                        tracing::warn!("Failed to delete {} filter: error code 0x{:08X}", name, result);
                    } else {
                        tracing::info!("{} filter removed", name);
                    }
                    *slot = None;
                }
            }

            // 按 callout key 兜底清扫：以上只删本会话记录了 id 的过滤器。
            // 服务崩溃重启 / 手工 stop 后残留的同子层过滤器（id 已丢失）仍
            // 会引用驱动 callout，导致内核侧 FwpsCalloutUnregisterById0 注销
            // 不干净——实测表现为 sc stop 驱动后 .sys 镜像无法卸载、流层/
            // flow-established 的 GUID 注册泄漏，下次加载同 GUID 实例时这两个
            // 层静默失效。这里把五个 callout 名下所有残余过滤器强制删除，
            // 保证 sc stop 驱动前 BFE 无引用。（windows 0.58 没有
            // FwpmFilterDeleteByCalloutKey0，用按 calloutKey 枚举 + 删除替代。
            // kill-switch 是纯 BLOCK 过滤器、action 不是 CALLOUT_*，不会命中。）
            // 指定 calloutKey 枚举时 BFE 要求 layer 必须是该 callout 的有效
            // 层 GUID，留空返回 FWP_E_LAYER_NOT_FOUND (0x80320004)。
            let sweep_callout_filters = |callout_guid: &windows::core::GUID, layer_guid: &windows::core::GUID| {
                let tmpl = windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_ENUM_TEMPLATE0 {
                    // actionMask 用 FWP_ACTION_FLAG 位掩码；留 0（Default）
                    // 会让 BFE 返回 FWP_E_NEVER_MATCH (0x80320033)，枚举空手
                    // 而归（实测 WARN 已复现）。我们的过滤器都是 callout 终结
                    // 动作，TERMINATING | CALLOUT 即可覆盖。
                    actionMask: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_FLAG_TERMINATING
                        | windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_FLAG_CALLOUT,
                    calloutKey: callout_guid as *const _ as *mut _,
                    layerKey: *layer_guid,
                    ..Default::default()
                };
                let mut enum_handle = windows::Win32::Foundation::HANDLE::default();
                let result = FwpmFilterCreateEnumHandle0(
                    self.engine.handle(),
                    Some(&tmpl),
                    &mut enum_handle,
                );
                if result != 0 {
                    tracing::warn!(
                        "Residual-sweep: create enum handle failed 0x{:08X}",
                        result
                    );
                    return;
                }

                loop {
                    let mut entries: *mut *mut windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0 = std::ptr::null_mut();
                    let mut returned: u32 = 0;
                    let result = FwpmFilterEnum0(
                        self.engine.handle(),
                        enum_handle,
                        10,
                        &mut entries,
                        &mut returned,
                    );
                    if result != 0 || returned == 0 || entries.is_null() {
                        if result != 0 && result != 0x80320003 {
                            // 0x80320003 = FWP_E_FILTER_NOT_FOUND（无残留即目标状态）
                            tracing::warn!(
                                "Residual-sweep: enumerate failed 0x{:08X}",
                                result
                            );
                        }
                        break;
                    }
                    for i in 0..returned as isize {
                        // entries.add(i) 是 *mut *mut FWPM_FILTER0，需两次解引用
                        let f = core::ptr::read(*entries.add(i as usize));
                        if f.filterId != 0 {
                            let d = FwpmFilterDeleteById0(self.engine.handle(), f.filterId);
                            if d != 0 {
                                tracing::warn!(
                                    "Residual-sweep: delete filter id {} failed 0x{:08X}",
                                    f.filterId, d
                                );
                            } else {
                                tracing::info!("Residual-sweep: deleted orphaned callout filter {}", f.filterId);
                            }
                        }
                    }
                    // FwpmFreeMemory0 要的是"指向 entries 变量的地址"（void**），
                    // 传 entries 本身会把数组首槽里的 FWPM_FILTER0*（BFE 堆内部
                    // 指针）当堆块基址 free——立即堆损坏 c0000374（崩溃栈定位：
                    // remove_filters → 本行之后的下一条堆操作触发检测）。
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFreeMemory0(
                        &mut entries as *mut _ as *mut *mut core::ffi::c_void,
                    );
                }

                FwpmFilterDestroyEnumHandle0(self.engine.handle(), enum_handle);
            };

            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V4);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V4_GUID, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
            sweep_callout_filters(&super::CEASEFIRE_DNS_CALLOUT_V4_GUID, &FWPM_LAYER_INBOUND_TRANSPORT_V4);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_STREAM_V4_GUID, &FWPM_LAYER_STREAM_V4);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V4_GUID, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V4_GUID, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4);
            // 下载整形（第 19 轮起在 IPPACKET 层 + 新 GUID；旧 transport 层
            // GUID 同样清扫，兜住升级前残留的旧层过滤器/对象）
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_IN_IPPACKET_V4_GUID, &FWPM_LAYER_INBOUND_IPPACKET_V4);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_IN_TRANSPORT_V4_LEGACY_GUID, &FWPM_LAYER_INBOUND_TRANSPORT_V4);
            // V6 对应层同样纳入清扫（泄漏场景：callout 注销不干净 → 镜像无法卸载）
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V6);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V6_GUID, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
            sweep_callout_filters(&super::CEASEFIRE_DNS_CALLOUT_V6_GUID, &FWPM_LAYER_INBOUND_TRANSPORT_V6);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_STREAM_V6_GUID, &FWPM_LAYER_STREAM_V6);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V6_GUID, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V6_GUID, &FWPM_LAYER_OUTBOUND_TRANSPORT_V6);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_IN_IPPACKET_V6_GUID, &FWPM_LAYER_INBOUND_IPPACKET_V6);
            sweep_callout_filters(&super::CEASEFIRE_CALLOUT_IN_TRANSPORT_V6_LEGACY_GUID, &FWPM_LAYER_INBOUND_TRANSPORT_V6);
        }

        tracing::info!("WFP filters removed");
        Ok(())
    }

    /// Unregister callouts
    pub fn unregister_callouts(&self) -> Result<()> {
        tracing::info!("Unregistering WFP callouts");

        unsafe {
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_V4_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V4_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_DNS_CALLOUT_V4_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_STREAM_V4_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V4_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V4_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_IN_IPPACKET_V4_GUID,
            );
            // 旧 transport 层下载整形 callout 对象（升级残留，静默删）
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_IN_TRANSPORT_V4_LEGACY_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_V6_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_RECV_ACCEPT_V6_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_DNS_CALLOUT_V6_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_STREAM_V6_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_FLOWESTABLISHED_V6_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_OUT_TRANSPORT_V6_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_IN_IPPACKET_V6_GUID,
            );
            let _ = FwpmCalloutDeleteByKey0(
                self.engine.handle(),
                &super::CEASEFIRE_CALLOUT_IN_TRANSPORT_V6_LEGACY_GUID,
            );
        }

        tracing::info!("WFP callouts unregistered");
        Ok(())
    }
}

impl Drop for WfpFilterManager {
    fn drop(&mut self) {
        let _ = self.remove_filters();
    }
}

// ---------------------------------------------------------------------------
// "服务未运行时拦截" kill-switch：常驻（FWPM_FILTER_FLAG_PERSISTENT）的
// 纯 BLOCK 过滤器，位于同一子层但权重最低（0）。服务运行期间 callout
// 过滤器（权重 15）在同子层内胜出，kill-switch 被压制；服务停止/崩溃
// 后会话过滤器随引擎会话消失，只剩 kill-switch → 全机出/入站拦截。
// 固定 filterKey 使安装幂等、可按键删除。
// ---------------------------------------------------------------------------

// Outbound kill-switch filter: {D4E5F6A7-B8C9-4B72-CD3E-4F5A6B7C8D9E}
pub const KILL_SWITCH_OUT_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xd4e5f6a7, 0xb8c9, 0x4b72, [0xcd, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e],
);
// Inbound kill-switch filter: {D4E5F6A7-B8C9-4B73-CD3E-4F5A6B7C8D9E}
pub const KILL_SWITCH_IN_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xd4e5f6a7, 0xb8c9, 0x4b73, [0xcd, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e],
);
// IPv6 outbound kill-switch filter: {D4E5F6A7-B8C9-4B75-CD3E-4F5A6B7C8D9E}
pub const KILL_SWITCH_OUT_V6_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xd4e5f6a7, 0xb8c9, 0x4b75, [0xcd, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e],
);
// IPv6 inbound kill-switch filter: {D4E5F6A7-B8C9-4B76-CD3E-4F5A6B7C8D9E}
pub const KILL_SWITCH_IN_V6_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xd4e5f6a7, 0xb8c9, 0x4b76, [0xcd, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e],
);

fn kill_switch_filter(layer: windows::core::GUID, key: windows::core::GUID) -> FWPM_FILTER0 {
    let filter_name = windows::core::w!("Ceasefire Kill-Switch (block when not running)");
    let filter_description = windows::core::w!("Persistent block-all fallback active only while the Ceasefire service is not running");
    FWPM_FILTER0 {
        filterKey: key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(filter_description.as_ptr() as *mut u16),
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &super::CEASEFIRE_PROVIDER_GUID as *const _ as *mut _,
        providerData: FWP_BYTE_BLOB::default(),
        layerKey: layer,
        subLayerKey: super::CEASEFIRE_SUBLAYER_GUID,
        // 权重 0：低于 callout 过滤器（15），服务运行时不生效
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: 0 },
        },
        numFilterConditions: 0,
        filterCondition: ptr::null_mut(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0::default(),
        },
        Anonymous: FWPM_FILTER0_0::default(),
        reserved: ptr::null_mut(),
        filterId: 0,
        effectiveWeight: FWP_VALUE0::default(),
    }
}

/// 安装 kill-switch 常驻过滤器（幂等）。持久过滤器必须在读写事务中添加。
/// V4/V6 出入站全对齐：服务未运行期间双栈全拦截。
pub fn add_persistent_block_filters(engine: &WfpEngine) -> Result<()> {
    tracing::info!("Installing persistent kill-switch filters");
    unsafe {
        let result = FwpmTransactionBegin0(engine.handle(), 0);
        if result != 0 {
            return Err(ServiceError::Wfp(format!("FwpmTransactionBegin0 failed: 0x{:08X}", result)));
        }

        // 已存在则先删（按键），保证幂等
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_OUT_GUID);
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_IN_GUID);
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_OUT_V6_GUID);
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_IN_V6_GUID);

        let entries: [(windows::core::GUID, windows::core::GUID, &str); 4] = [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, KILL_SWITCH_OUT_GUID, "outbound"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, KILL_SWITCH_IN_GUID, "inbound"),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, KILL_SWITCH_OUT_V6_GUID, "IPv6 outbound"),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, KILL_SWITCH_IN_V6_GUID, "IPv6 inbound"),
        ];
        for (layer, key, label) in entries {
            let filter = kill_switch_filter(layer, key);
            let result = FwpmFilterAdd0(engine.handle(), &filter, None, None);
            if result != 0 {
                let _ = FwpmTransactionAbort0(engine.handle());
                return Err(ServiceError::Wfp(format!(
                    "Failed to add {} kill-switch: 0x{:08X}",
                    label, result
                )));
            }
        }

        let result = FwpmTransactionCommit0(engine.handle());
        if result != 0 {
            // commit 失败必须显式 Abort：事务状态挂在 engine 会话上，不
            // 清掉的话该句柄后续所有事务都会 FWP_E_TXN_IN_PROGRESS 连锁
            // 失败（与上方 FilterAdd 失败分支的 Abort 对称）
            let _ = FwpmTransactionAbort0(engine.handle());
            return Err(ServiceError::Wfp(format!("FwpmTransactionCommit0 failed: 0x{:08X}", result)));
        }
    }
    tracing::info!("Persistent kill-switch filters installed");
    Ok(())
}

/// 移除 kill-switch 常驻过滤器（不存在时静默成功）
pub fn remove_persistent_block_filters(engine: &WfpEngine) -> Result<()> {
    unsafe {
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_OUT_GUID);
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_IN_GUID);
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_OUT_V6_GUID);
        let _ = FwpmFilterDeleteByKey0(engine.handle(), &KILL_SWITCH_IN_V6_GUID);
    }
    tracing::info!("Persistent kill-switch filters removed (if present)");
    Ok(())
}

/// 独立进程（如 uninstall）用的按键删除：自建临时引擎会话。
pub fn remove_persistent_block_filters_standalone() -> Result<()> {
    let engine = WfpEngine::new()?;
    remove_persistent_block_filters(&engine)
}
