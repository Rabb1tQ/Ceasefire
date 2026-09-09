//! Driver Handle - handles communication with WFP driver

use super::super::error::{Result, ServiceError};
use super::super::models::*;
use std::sync::Arc;
use tokio::sync::Mutex;

const DRIVER_DEVICE: &str = r"\\.\CeasefireDriver";
const EVENT_BUFFER_SIZE: usize = 4096;

pub struct DriverHandle {
    /// 句柄仓：std::sync::Mutex 只在取/放 Arc<File> 时短暂持有，绝不跨
    /// 阻塞 DeviceIoControl 持有（原 tokio::Mutex 全程持有会把驱动卡死
    /// 传染到整个 async 运行时）。
    file: std::sync::Mutex<Option<Arc<std::fs::File>>>,
    /// IO 串行化门：同一时刻只允许一个 DeviceIoControl 在途（保持原实现
    /// tokio::Mutex 全程持有的发送端串行语义）。这是 async 锁，阻塞等待
    /// 期间不占 worker 线程。
    io_gate: Mutex<()>,
}

impl DriverHandle {
    pub fn new() -> Result<Self> {
        Ok(DriverHandle {
            file: std::sync::Mutex::new(None),
            io_gate: Mutex::new(()),
        })
    }

    /// 取当前驱动句柄副本（Arc clone），锁只在克隆瞬间持有。返回后即使
    /// close() 清空句柄仓，在途 IO 也由 Arc 保活，raw HANDLE 不会失效。
    fn current_file(&self) -> Result<Arc<std::fs::File>> {
        self.file
            .lock()
            .map_err(|_| ServiceError::Driver("driver handle mutex poisoned".to_string()))?
            .clone()
            .ok_or_else(|| ServiceError::Driver("Driver not open".to_string()))
    }

    /// 在 blocking 线程池执行一次同步 IOCTL：串行门 + 句柄 Arc 都在进入
    /// spawn_blocking 前取得，std 锁不进入闭包、不跨 await 持有。
    async fn run_ioctl<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&std::fs::File) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let file = self.current_file()?;
        let _gate = self.io_gate.lock().await;
        match tokio::task::spawn_blocking(move || f(&file)).await {
            Ok(res) => res,
            Err(e) => Err(ServiceError::Driver(format!("ioctl join failed: {}", e))),
        }
    }

    /// Open driver device
    pub async fn open(&self) -> Result<()> {
        let mut guard = self.file.lock().map_err(|_| {
            ServiceError::Driver("driver handle mutex poisoned".to_string())
        })?;

        if guard.is_some() {
            tracing::warn!("Driver already open");
            return Ok(());
        }

        // Synchronous handle: ioctl helpers use blocking DeviceIoControl
        // (lpOverlapped = NULL), so FILE_FLAG_OVERLAPPED must NOT be set.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(DRIVER_DEVICE)
        {
            Ok(file) => {
                *guard = Some(Arc::new(file));
                tracing::info!("Driver opened successfully");
                Ok(())
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Err(ServiceError::Driver(
                        "Driver not found. Please install the WFP driver first.".to_string(),
                    ))
                } else if e.raw_os_error() == Some(5) {
                    // ERROR_ACCESS_DENIED
                    Err(ServiceError::Driver(
                        "Access denied. Administrator privileges required.".to_string(),
                    ))
                } else {
                    Err(ServiceError::Driver(format!("Failed to open driver: {}", e)))
                }
            }
        }
    }

    /// Close driver device
    pub async fn close(&self) -> Result<()> {
        // 在途 IO 由 Arc 保活安全完成；关闭后新 IO 一律 "Driver not open"
        let mut guard = self.file.lock().map_err(|_| {
            ServiceError::Driver("driver handle mutex poisoned".to_string())
        })?;
        *guard = None;
        tracing::info!("Driver closed");
        Ok(())
    }

    /// Add rule to driver
    pub async fn add_rule(&self, rule: &Rule) -> Result<()> {
        let driver_input = super::converter::rule_to_driver_input(rule)?;

        // Log the rule being sent with full details
        tracing::info!(
            "Sending rule to driver: id={}, name='{}', priority={}, enabled={}, action={:?}, is_allow={}, process_id={}, protocol={}",
            driver_input.rule_id,
            rule.name,
            driver_input.priority,
            driver_input.enabled,
            rule.action,
            driver_input.is_allow,
            driver_input.process_id,
            driver_input.protocol
        );

        let data = driver_input.as_bytes().to_vec();

        self.run_ioctl(move |file| {
            super::ioctl::send_ioctl(file, super::ioctl::IOCTL_ADD_RULE, &data)
        })
        .await
    }

    /// Remove rule from driver
    pub async fn remove_rule(&self, rule_id: u32) -> Result<()> {
        let data = rule_id.to_le_bytes();
        self.run_ioctl(move |file| {
            super::ioctl::send_ioctl(file, super::ioctl::IOCTL_REMOVE_RULE, &data)
        })
        .await
    }

    /// Update rule in driver
    pub async fn update_rule(&self, rule: &Rule) -> Result<()> {
        let driver_input = super::converter::rule_to_driver_input(rule)?;
        let data = driver_input.as_bytes().to_vec();

        self.run_ioctl(move |file| {
            super::ioctl::send_ioctl(file, super::ioctl::IOCTL_UPDATE_RULE, &data)
        })
        .await
    }

    /// Clear all rules from driver
    pub async fn clear_rules(&self) -> Result<()> {
        self.run_ioctl(move |file| {
            super::ioctl::send_ioctl(file, super::ioctl::IOCTL_CLEAR_RULES, &[])
        })
        .await
    }

    /// Push default policy to driver: true = allow unmatched, false = block
    pub async fn set_default_policy(&self, allow: bool) -> Result<()> {
        let data: u32 = if allow { 1 } else { 0 };
        let data = data.to_le_bytes();
        self.run_ioctl(move |file| {
            super::ioctl::send_ioctl(file, super::ioctl::IOCTL_SET_DEFAULT_POLICY, &data)
        })
        .await?;
        tracing::info!("Driver default policy set to {}", if allow { "ALLOW" } else { "BLOCK" });
        Ok(())
    }

    /// Install/remove a kernel stream-layer throttle entry.
    /// process_id 0 = global entry; both rates 0 removes the entry only
    /// (including the pid-0 global entry itself). Clearing the whole table
    /// is clear_throttle_table()'s job.
    pub async fn set_throttle(&self, process_id: u32, rate_up_bps: u32, rate_down_bps: u32) -> Result<()> {
        let input = super::ioctl::DriverThrottleInput {
            process_id,
            rate_up_bps,
            rate_down_bps,
        };
        self.run_ioctl(move |file| {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &input as *const _ as *const u8,
                    std::mem::size_of::<super::ioctl::DriverThrottleInput>(),
                )
            };
            super::ioctl::send_ioctl(file, super::ioctl::IOCTL_SET_THROTTLE, bytes)
        })
        .await?;
        tracing::debug!(
            "Driver throttle entry set: pid={}, up={} B/s, down={} B/s",
            process_id, rate_up_bps, rate_down_bps
        );
        Ok(())
    }

    /// Clear the whole kernel throttle table (IOCTL_CLEAR_THROTTLE).
    /// 仅服务停止/显式回收使用：全局开关关闭走 set_throttle(0,0,0)
    /// 单独删除 pid-0 条目，不得牵连按进程限速条目。
    pub async fn clear_throttle_table(&self) -> Result<()> {
        self.run_ioctl(move |file| {
            super::ioctl::send_ioctl(file, super::ioctl::IOCTL_CLEAR_THROTTLE, &[])
        })
        .await?;
        tracing::info!("Driver throttle table cleared");
        Ok(())
    }

    /// Get next event from driver
    pub async fn get_event(&self) -> Result<NetworkEvent> {
        let buffer = self
            .run_ioctl(move |file| {
                let mut buffer = vec![0u8; EVENT_BUFFER_SIZE];
                let bytes_read = super::ioctl::get_event_ioctl(file, &mut buffer)?;
                Ok::<_, ServiceError>(buffer[..bytes_read].to_vec())
            })
            .await?;

        if buffer.is_empty() {
            return Err(ServiceError::Driver("No event available".to_string()));
        }

        // Deserialize raw C struct from driver
        let driver_event = super::converter::DriverEvent::from_bytes(&buffer)?;

        // Convert to service NetworkEvent
        driver_event.to_network_event()
    }

    /// Fetch the driver's diagnostics snapshot (callout register statuses,
    /// classify/association counters). Ok(None) on drivers predating
    /// IOCTL_GET_DIAGS.
    pub async fn get_diags(&self) -> Result<Option<super::ioctl::DriverDiagsRaw>> {
        self.run_ioctl(move |file| super::ioctl::get_diags_ioctl(file))
            .await
            .map_or_else(
                |e| match e {
                    ServiceError::Driver(msg)
                        if msg.contains("incorrect function") || msg.contains("not supported") =>
                    {
                        // 旧驱动没有 IOCTL_GET_DIAGS（ERROR_NOT_SUPPORTED /
                        // ERROR_INVALID_FUNCTION），按无诊断能力处理
                        Ok(None)
                    }
                    other => Err(other),
                },
                |d| Ok(Some(d)),
            )
    }

    /// Get next DNS event from driver. Ok(None) when the queue is empty.
    pub async fn get_dns_event(&self) -> Result<Option<super::converter::DriverDnsEvent>> {
        self.run_ioctl(move |file| {
            let mut buffer = vec![0u8; std::mem::size_of::<super::converter::DriverDnsEvent>() + 8];
            let bytes_read = super::ioctl::get_dns_event_ioctl(file, &mut buffer)?;
            if bytes_read == 0 {
                return Ok(None);
            }
            Ok(Some(super::converter::DriverDnsEvent::from_bytes(&buffer[..bytes_read])?))
        })
        .await
    }
}

impl Default for DriverHandle {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// 诊断数组下标命名，与驱动 CF_DIAG_SLOT_* 一致（V4 0..5，V6 6..11）
pub const DIAG_CALLOUT_NAMES: [&str; 12] = [
    "ale-connect-v4",
    "ale-recv-accept-v4",
    "dns-v4",
    "stream-v4",
    "flow-established-v4",
    "outbound-transport-v4",
    "ale-connect-v6",
    "ale-recv-accept-v6",
    "dns-v6",
    "stream-v6",
    "flow-established-v6",
    "outbound-transport-v6",
];

/// 把 IOCTL 原始快照转成 IPC 可序列化模型
pub fn diags_raw_to_model(raw: &super::ioctl::DriverDiagsRaw) -> crate::models::DriverDiagnostics {
    crate::models::DriverDiagnostics {
        callouts: DIAG_CALLOUT_NAMES
            .iter()
            .enumerate()
            .map(|(i, name)| crate::models::DriverCalloutDiag {
                name: (*name).to_string(),
                reg_status: raw.reg_status[i],
                callout_id: raw.callout_id[i],
                unreg_status: raw.unreg_status[i],
                unreg_retries: raw.unreg_retries[i],
            })
            .collect(),
        classify_stream: raw.classify_stream,
        classify_flow_est: raw.classify_flow_est,
        assoc_ok: raw.assoc_ok,
        assoc_fail: raw.assoc_fail,
        flow_delete: raw.flow_delete,
        stream_bytes_counted: raw.stream_bytes_counted,
        throttle_active_entries: raw.throttle_active_entries,
        throttle_notify_removes: raw.throttle_notify_removes,
        in_transport_classify: raw.in_transport_classify,
        in_transport_permit: raw.in_transport_permit,
        in_transport_block: raw.in_transport_block,
        in_transport_reg_status: raw.in_transport_reg_status,
        in_transport_callout_id: raw.in_transport_callout_id,
        in_transport_unreg_status: raw.in_transport_unreg_status,
        in_transport_unreg_retries: raw.in_transport_unreg_retries,
        pacing_held: raw.pacing_held,
        pacing_injected: raw.pacing_injected,
        pacing_inject_fail: raw.pacing_inject_fail,
        pacing_queue_drop: raw.pacing_queue_drop,
        pacing_queue_depth_max: raw.pacing_queue_depth_max,
        pacing_timer_ticks: raw.pacing_timer_ticks,
        diag_version: raw.version,
    }
}

/// 把诊断快照写成一行人类可读日志（服务启动时用）
pub fn log_driver_diags(raw: &super::ioctl::DriverDiagsRaw) {
    for (i, name) in DIAG_CALLOUT_NAMES.iter().enumerate() {
        if raw.reg_status[i] != 0 {
            // 0x80320009 = FWP_E_ALREADY_EXISTS：上一实例注销失败留下的
            // 僵尸注册，本会话该层完全失效
            tracing::error!(
                "driver diag: {} register FAILED 0x{:08X} calloutId={} (layer DEAD this session)",
                name, raw.reg_status[i], raw.callout_id[i]
            );
        } else {
            tracing::info!(
                "driver diag: {} registered calloutId={}",
                name, raw.callout_id[i]
            );
        }
    }
    for (i, name) in DIAG_CALLOUT_NAMES.iter().enumerate() {
        // 本会话的注销结果（diag v2 起有值）：非 0 说明上次/本次卸载时该层
        // 注销失败，注册已泄漏，同 GUID 下次加载必现 0x80320009
        if raw.unreg_status[i] != 0 {
            tracing::error!(
                "driver diag: {} unregister FAILED 0x{:08X} after {} retries (registration LEAKED)",
                name, raw.unreg_status[i], raw.unreg_retries[i]
            );
        }
    }
    // 入站传输层（下载限速）两个 callout（diag v4 起有值，槽位在尾部独立
    // 数组；v1..v3 驱动该区域已按版本清零，跳过避免误报 registered calloutId=0）
    if raw.version >= 4 {
        for (name, status, callout_id, unreg_status, unreg_retries) in [
        ("inbound-transport-v4", raw.in_transport_reg_status[0], raw.in_transport_callout_id[0], raw.in_transport_unreg_status[0], raw.in_transport_unreg_retries[0]),
        ("inbound-transport-v6", raw.in_transport_reg_status[1], raw.in_transport_callout_id[1], raw.in_transport_unreg_status[1], raw.in_transport_unreg_retries[1]),
    ] {
        if status != 0 {
            tracing::error!(
                "driver diag: {} register FAILED 0x{:08X} calloutId={} (download shaping DEAD this session)",
                name, status, callout_id
            );
        } else if unreg_status != 0 {
            tracing::error!(
                "driver diag: {} unregister FAILED 0x{:08X} after {} retries (registration LEAKED)",
                name, unreg_status, unreg_retries
            );
        } else {
            tracing::info!("driver diag: {} registered calloutId={}", name, callout_id);
        }
        }
    }
}