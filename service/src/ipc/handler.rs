//! Request Handler - handles IPC requests

use super::super::models::*;
use super::super::database::Database;
use super::super::rule::manager::RuleManager;
use super::super::connection::tracker::ConnectionTracker;
use super::super::app_group::manager::AppGroupManager;
use super::super::connection_decision::manager::ConnectionDecisionManager;
use super::super::network_history::manager::NetworkHistoryManager;
use super::super::bandwidth::{BandwidthLimiter, KernelThrottleSync};
use super::super::geoip::GeoIpService;
use super::super::dns_cache::DnsCache;
use super::super::notification::notifier::Notifier;
use super::super::driver::DriverHandle;
use super::super::wfp::WfpEngine;
use super::super::error::{Result, ServiceError};
use std::sync::Arc;

/// WFP 引擎共享槽：engine 在服务 start() 时才创建，IPC 处理器通过它访问
pub type WfpEngineSlot = Arc<std::sync::Mutex<Option<Arc<WfpEngine>>>>;

pub struct RequestHandler {
    rule_manager: Arc<RuleManager>,
    connection_tracker: Arc<ConnectionTracker>,
    db: Arc<Database>,
    app_group_manager: Arc<AppGroupManager>,
    decision_manager: Arc<ConnectionDecisionManager>,
    history_manager: Arc<NetworkHistoryManager>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    kernel_throttle: Arc<KernelThrottleSync>,
    geoip_service: Arc<GeoIpService>,
    dns_cache: Arc<DnsCache>,
    notifier: Arc<Notifier>,
    driver: Arc<DriverHandle>,
    wfp_engine: WfpEngineSlot,
}

impl RequestHandler {
    pub fn new(
        rule_manager: Arc<RuleManager>,
        connection_tracker: Arc<ConnectionTracker>,
        db: Arc<Database>,
        app_group_manager: Arc<AppGroupManager>,
        decision_manager: Arc<ConnectionDecisionManager>,
        history_manager: Arc<NetworkHistoryManager>,
        bandwidth_limiter: Arc<BandwidthLimiter>,
        kernel_throttle: Arc<KernelThrottleSync>,
        geoip_service: Arc<GeoIpService>,
        dns_cache: Arc<DnsCache>,
        notifier: Arc<Notifier>,
        driver: Arc<DriverHandle>,
        wfp_engine: WfpEngineSlot,
    ) -> Self {
        RequestHandler {
            rule_manager,
            connection_tracker,
            db,
            app_group_manager,
            decision_manager,
            history_manager,
            bandwidth_limiter,
            kernel_throttle,
            geoip_service,
            dns_cache,
            notifier,
            driver,
            wfp_engine,
        }
    }

    /// Get combined global stats from active connections and historical data
    async fn get_combined_global_stats(&self) -> Result<GlobalStats> {
        // Get active connection stats
        let active_stats = self.connection_tracker.get_global_stats().await?;
        
        // Get historical stats from last 24 hours
        // 数据库侧 SUM 聚合：绝不能走 get_history（默认 limit 100 行，
        // 会让 24 小时总量退化成"最新 100 行"的总量）
        let (total_bytes_sent, total_bytes_received) =
            self.history_manager.get_history_traffic_totals(24).await?;

        // Combine with active connection stats (avoid double counting)
        // Use the maximum of historical and active stats
        let combined_bytes_sent = total_bytes_sent.max(active_stats.total_bytes_sent);
        let combined_bytes_received = total_bytes_received.max(active_stats.total_bytes_received);
        
        Ok(GlobalStats {
            active_connections: active_stats.active_connections,
            total_bytes_sent: combined_bytes_sent,
            total_bytes_received: combined_bytes_received,
            total_packets_sent: active_stats.total_packets_sent,
            total_packets_received: active_stats.total_packets_received,
            blocked_connections: active_stats.blocked_connections,
            allowed_connections: active_stats.allowed_connections,
            suspicious_connections: active_stats.suspicious_connections,
        })
    }

    /// 分组结构/成员变化后重载内核规则；失败只记日志不打断 IPC 应答
    ///（与成员增删路径的容错口径一致）
    async fn reload_rules_quietly(&self) {
        if let Err(e) = self.rule_manager.reload_rules_to_driver().await {
            tracing::warn!("Failed to reload driver rules after app group change: {}", e);
        }
    }

    pub async fn handle_request(&self, request: IpcRequest) -> IpcResponse {
        match request {
            IpcRequest::CreateRule(rule) => {
                match self.rule_manager.create_rule(rule).await {
                    Ok(rule) => IpcResponse::Rule(rule),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::UpdateRule { id, rule } => {
                match self.rule_manager.update_rule(id, rule).await {
                    Ok(()) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::DeleteRule(id) => {
                match self.rule_manager.delete_rule(id).await {
                    Ok(()) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::ListRules { offset, limit, search } => {
                match self.rule_manager.list_rules_page(offset, limit, search).await {
                    Ok(page) => IpcResponse::RulePage(page),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::ExportRules => {
                match self.rule_manager.export_rules().await {
                    Ok(data) => IpcResponse::ExportData(data),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::ImportRules { rules, mode } => {
                match self.rule_manager.import_rules(rules, mode).await {
                    Ok(stats) => IpcResponse::ImportStats(stats),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetActiveConnections => {
                match self.connection_tracker.get_active_connections().await {
                    Ok(connections) => IpcResponse::Connections(connections),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetGlobalStats => {
                // Get stats from both active connections and historical data
                match self.get_combined_global_stats().await {
                    Ok(stats) => IpcResponse::GlobalStats(stats),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetSettings => {
                match self.db.get_settings().await {
                    Ok(settings) => IpcResponse::Settings(settings),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::UpdateSettings(settings) => {
                match self.db.update_settings(&settings).await {
                    Ok(()) => {
                        // 不能只写库：通知开关和全局带宽限值是内存态，必须同步生效
                        self.notifier.set_enabled(settings.notifications_enabled);
                        self.notifier.set_ask_mode(settings.ask_to_connect_enabled && !settings.default_allow);
                        if settings.global_bandwidth_limit_enabled {
                            self.bandwidth_limiter.set_global_limits(
                                settings.global_upload_limit_kbps,
                                settings.global_download_limit_kbps,
                            ).await;
                        } else {
                            self.bandwidth_limiter.set_global_limits(None, None).await;
                        }
                        // 内核限速表同步全局条目（PID 0）
                        self.kernel_throttle.update_global(
                            &self.driver,
                            settings.global_bandwidth_limit_enabled,
                            settings.global_upload_limit_kbps.unwrap_or(0),
                            settings.global_download_limit_kbps.unwrap_or(0),
                        ).await;
                        // 默认策略实时下推驱动；系统豁免规则按开关安装/移除
                        if let Err(e) = self.driver.set_default_policy(settings.default_allow).await {
                            tracing::error!("Failed to push default policy to driver: {}", e);
                        }
                        if settings.system_rules_enabled && !settings.default_allow {
                            let _ = crate::rule::system_rules::ensure_installed(&self.rule_manager).await;
                        } else if !settings.system_rules_enabled {
                            let _ = crate::rule::system_rules::remove_all(&self.rule_manager).await;
                        }
                        // kill-switch 常驻过滤器按开关实时安装/移除
                        // （std Mutex 守卫不能跨 await，先 clone 出 engine 再释放）
                        let engine_opt = self.wfp_engine.lock().ok().and_then(|s| s.clone());
                        if let Some(engine) = engine_opt {
                            let result = if settings.protect_when_not_running {
                                crate::wfp::add_persistent_block_filters(&engine)
                            } else {
                                crate::wfp::remove_persistent_block_filters(&engine)
                            };
                            if let Err(e) = result {
                                tracing::warn!("Failed to update kill-switch filters: {}", e);
                            }
                        }
                        IpcResponse::Success
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // Application Groups
            IpcRequest::ListAppGroups => {
                match self.app_group_manager.list_groups().await {
                    Ok(groups) => IpcResponse::AppGroups(groups),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetAppGroupMembers(group_id) => {
                match self.app_group_manager.get_members(group_id).await {
                    Ok(members) => IpcResponse::AppGroupMembers(members),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::AddAppGroupMember { group_id, process_path, process_name } => {
                match self.app_group_manager.add_member(group_id, &process_path, process_name).await {
                    Ok(()) => {
                        // 分组成员变化会影响分组规则在内核的展开条目，整体重载
                        if let Err(e) = self.rule_manager.reload_rules_to_driver().await {
                            tracing::warn!("Failed to reload driver rules after group member change: {}", e);
                        }
                        IpcResponse::Success
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::RemoveAppGroupMember { group_id, process_path } => {
                match self.app_group_manager.remove_member(group_id, &process_path).await {
                    Ok(()) => {
                        if let Err(e) = self.rule_manager.reload_rules_to_driver().await {
                            tracing::warn!("Failed to reload driver rules after group member change: {}", e);
                        }
                        IpcResponse::Success
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::InitializePredefinedGroups => {
                match self.app_group_manager.initialize_predefined().await {
                    Ok(_) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // 自定义分组管理：建/改/删/启停。分组本身及其成员变化都会影响
            // 分组规则在内核的展开条目，成功后整体重载（与成员增删同口径）
            IpcRequest::CreateAppGroup { group } => {
                match self.app_group_manager.create_group(&group).await {
                    Ok(created) => {
                        self.reload_rules_quietly().await;
                        IpcResponse::AppGroupCreated(created)
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::UpdateAppGroup { id, group } => {
                match self.app_group_manager.update_group(id, &group).await {
                    Ok(()) => {
                        self.reload_rules_quietly().await;
                        IpcResponse::Success
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::DeleteAppGroup { id } => {
                match self.app_group_manager.delete_group(id).await {
                    Ok(()) => {
                        self.reload_rules_quietly().await;
                        IpcResponse::Success
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::SetAppGroupEnabled { id, enabled } => {
                let result = if enabled {
                    self.app_group_manager.enable_group(id).await
                } else {
                    self.app_group_manager.disable_group(id).await
                };
                match result {
                    Ok(()) => {
                        self.reload_rules_quietly().await;
                        IpcResponse::Success
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // Connection Decisions
            IpcRequest::RecordConnectionDecision(decision) => {
                match self.db.create_connection_decision(&decision).await {
                    Ok(id) => {
                        let mut new_decision = decision.clone();
                        new_decision.id = Some(id);
                        IpcResponse::ConnectionDecision(new_decision)
                    },
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::ListConnectionDecisions => {
                match self.decision_manager.list_decisions().await {
                    Ok(decisions) => IpcResponse::ConnectionDecisions(decisions),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::DeleteConnectionDecision(id) => {
                match self.decision_manager.delete_decision(id).await {
                    Ok(()) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::ClearExpiredDecisions => {
                // 由 decision_manager 按各条记录的 created_at 过期判断逐条删除
                match self.decision_manager.clear_expired_decisions().await {
                    Ok(count) => IpcResponse::DeletedCount(count),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // Network History
            IpcRequest::GetNetworkHistory(filters) => {
                match self.history_manager.get_history(&filters).await {
                    Ok(records) => IpcResponse::NetworkHistoryRecords(records),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::ExportNetworkHistory { filters, format } => {
                match super::export::export_network_history(&self.db, &filters, format).await {
                    Ok(data) => IpcResponse::ExportData(data),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // Bandwidth Limits
            IpcRequest::SetProcessBandwidthLimit(limit) => {
                // 零值归一：upload/download 均为 None 或 Some(0)（cfctl
                // "throttle-path X 0 0 = remove" 的语义）时走真正的删除路径。
                // 否则 (0,0) 会残留为限速条目：sync_event 对每个连接事件下发
                // set_throttle(pid,0,0)，而驱动对不存在的 PID 报错，且 DB 里
                // 留下一条 0/0 的"僵尸"限速行在 GUI 上迷惑人。
                let up = limit.upload_limit_kbps.filter(|v| *v > 0);
                let down = limit.download_limit_kbps.filter(|v| *v > 0);
                if up.is_none() && down.is_none() {
                    self.bandwidth_limiter.set_limits(&limit.process_path, None, None).await;
                    self.kernel_throttle.update_path_limit(
                        &self.driver,
                        &limit.process_path,
                        None,
                        None,
                    ).await;
                    match self.db.delete_process_bandwidth_limit(&limit.process_path).await {
                        Ok(0) => IpcResponse::Error(format!(
                            "no bandwidth limit found for path: {} (already removed?)",
                            limit.process_path
                        )),
                        Ok(_) => IpcResponse::Success,
                        Err(e) => IpcResponse::Error(e.to_string()),
                    }
                } else {
                    // 持久化到数据库，并同步内存限流器（重启后仍在 GUI 中可见）
                    let mut limit = limit;
                    limit.upload_limit_kbps = up;
                    limit.download_limit_kbps = down;
                    let persist = self.db.set_process_bandwidth_limit(&limit).await;
                    // 与服务重启恢复路径（firewall_service 的 if limit.enabled）
                    // 同口径：enabled=false 仅持久化 DB，并主动撤销当前生效条目
                    // （内存限流桶 + 内核限速表），保证"关掉即刻生效"、语义不随
                    // 重启漂移；enabled=true 维持原样下发限值。
                    let (up_now, down_now) = if limit.enabled {
                        (limit.upload_limit_kbps, limit.download_limit_kbps)
                    } else {
                        (None, None)
                    };
                    self.bandwidth_limiter.set_limits(
                        &limit.process_path,
                        up_now,
                        down_now,
                    ).await;
                    // 同步内核限速表：撤销旧条目，新条目在下一次该路径的连接事件时下发
                    self.kernel_throttle.update_path_limit(
                        &self.driver,
                        &limit.process_path,
                        up_now,
                        down_now,
                    ).await;
                    match persist {
                        Ok(_) => IpcResponse::Success,
                        Err(e) => IpcResponse::Error(e.to_string()),
                    }
                }
            }
            IpcRequest::ListProcessBandwidthLimits => {
                match self.db.list_process_bandwidth_limits().await {
                    Ok(limits) => IpcResponse::ProcessBandwidthLimits(limits),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::DeleteProcessBandwidthLimit(process_path) => {
                // 真正的删除：清数据库记录并解除内存限流
                self.bandwidth_limiter.set_limits(&process_path, None, None).await;
                // 同步撤销内核限速条目
                self.kernel_throttle.update_path_limit(&self.driver, &process_path, None, None).await;
                match self.db.delete_process_bandwidth_limit(&process_path).await {
                    Ok(0) => IpcResponse::Error(format!(
                        "no bandwidth limit found for path: {} (already removed?)",
                        process_path
                    )),
                    Ok(_) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::SetGlobalBandwidthLimit { upload_limit_kbps, download_limit_kbps, enabled } => {
                // enabled 语义：
                // - None：旧调用方兼容路径，按限值有无推断开关（全 None = 清除）
                // - Some(false)：仅关闭全局开关并摘除内核条目，限值照旧持久化，
                //   用户配置不被清空，重开无需重填
                // - Some(true)：开启开关并下发限值
                // 归一化（见 normalize_global_limit）：Some(0) 限值视作未设置；
                // "开关开但双限值均空/0" 归一为关闭，防止旧内核条目残留限速 +
                // 用户态双 0 桶产生假告警。
                let (enabled, up, down) = crate::bandwidth::kernel_sync::normalize_global_limit(
                    enabled,
                    upload_limit_kbps,
                    download_limit_kbps,
                );
                // 用户态令牌桶与内核同步：关闭（含归一化关闭）时摘桶——内核已
                // 无全局限速，桶若继续计数会让 allow_upload/allow_download 产生
                // 假告警。开启时按归一化后的限值装桶（限值仍在 DB，重开免重填）。
                if enabled {
                    self.bandwidth_limiter.set_global_limits(up, down).await;
                } else {
                    self.bandwidth_limiter.set_global_limits(None, None).await;
                }
                // 内核限速表同步全局条目（PID 0）：关闭时删除 PID 0 条目（仅此
                // 一条，按进程条目不受影响），由 update_global 负责摘除已下发的
                // 全局兜底条目
                self.kernel_throttle.update_global(
                    &self.driver,
                    enabled,
                    up.unwrap_or(0),
                    down.unwrap_or(0),
                ).await;
                match self.db.get_settings().await {
                    Ok(mut settings) => {
                        // 限值持久化保留用户原始输入（0 不改写为 NULL 语义由
                        // 前端表达），开关持久化用归一化后的值
                        settings.global_upload_limit_kbps = upload_limit_kbps;
                        settings.global_download_limit_kbps = download_limit_kbps;
                        settings.global_bandwidth_limit_enabled = enabled;
                        match self.db.update_settings(&settings).await {
                            Ok(()) => IpcResponse::Success,
                            Err(e) => IpcResponse::Error(e.to_string()),
                        }
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // Statistics
            IpcRequest::GetAppTrafficStats(hours) => {
                match self.history_manager.get_app_traffic_stats(hours).await {
                    Ok(stats) => IpcResponse::AppTrafficStats(stats),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetProtocolTrafficStats(hours) => {
                match self.history_manager.get_protocol_traffic_stats(hours).await {
                    Ok(stats) => IpcResponse::ProtocolTrafficStats(stats),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetCountryTrafficStats(hours) => {
                match self.history_manager.get_country_traffic_stats(hours).await {
                    Ok(stats) => IpcResponse::CountryTrafficStats(stats),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetTrafficTrend { hours } => {
                match self.history_manager.get_traffic_trend(hours).await {
                    Ok(trend) => IpcResponse::TrafficTrend(trend),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetAppTrafficTimeline { hours } => {
                match self.history_manager.get_app_traffic_timeline(hours).await {
                    Ok(points) => IpcResponse::AppTrafficTimeline(points),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetActionTrend { hours } => {
                match self.history_manager.get_action_trend(hours).await {
                    Ok(points) => IpcResponse::ActionTrend(points),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetTopHosts { hours, limit } => {
                match self.history_manager.get_top_hosts(hours, limit).await {
                    // 域名反查走 DNS 缓存：命中则填充，未命中保持 None
                    Ok(mut hosts) => {
                        for host in hosts.iter_mut() {
                            if let Ok(addr) = host.remote_addr.parse::<std::net::IpAddr>() {
                                host.domain = self.dns_cache.lookup(&addr).await;
                            }
                        }
                        IpcResponse::TopHosts(hosts)
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetRemoteHostDetails { remote_addr, hours } => {
                match self.history_manager.get_remote_address_details(&remote_addr, hours).await {
                    Ok(details) => IpcResponse::RemoteHostDetails(Some(details)),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // GeoIP
            IpcRequest::LookupDomain(ip) => {
                let domain = match ip.parse::<std::net::IpAddr>() {
                    Ok(addr) => self.dns_cache.lookup(&addr).await,
                    Err(_) => None,
                };
                IpcResponse::Domain(domain)
            }
            IpcRequest::LookupGeoLocationBatch(ips) => {
                match self.geoip_service.lookup_batch(ips).await {
                    Ok(locations) => {
                        let tauri_locations: std::collections::HashMap<String, TauriGeoLocation> = locations
                            .into_iter()
                            .map(|(k, v)| (k, v.into()))
                            .collect();
                        IpcResponse::GeoLocationBatch(tauri_locations)
                    },
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::CleanupGeoCache => {
                match self.geoip_service.cleanup_cache().await {
                    Ok(count) => IpcResponse::DeletedCount(count),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetGeoCacheStats => {
                match self.geoip_service.get_cache_stats().await {
                    Ok(stats) => IpcResponse::GeoCacheStats(stats.into()),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::PollNotifications(max) => {
                let items = self.notifier.drain(max.max(1) as usize).await;
                IpcResponse::Notifications(items)
            }
            // Process Management
            IpcRequest::KillProcess(pid) => {
                match kill_process(pid) {
                    Ok(()) => IpcResponse::Success,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            // 驱动诊断快照（cfctl diags；旧驱动无此 IOCTL 时返回 None）
            IpcRequest::GetDriverDiags => match self.driver.get_diags().await {
                Ok(Some(raw)) => {
                    IpcResponse::DriverDiags(Some(super::super::driver::diags_raw_to_model(&raw)))
                }
                Ok(None) => IpcResponse::DriverDiags(None),
                Err(e) => IpcResponse::Error(e.to_string()),
            },
        }
    }
}

/// Kill a process by PID。用 OpenProcess(PROCESS_TERMINATE) + TerminateProcess
/// 直接终止，不再依赖 PATH 里的 taskkill（服务环境变量不保证含 System32）。
fn kill_process(pid: u32) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| {
                ServiceError::Service(format!("Failed to open process {}: {}", pid, e))
            })?;
            let result = TerminateProcess(handle, 1).map_err(|e| {
                ServiceError::Service(format!("Failed to kill process {}: {}", pid, e))
            });
            let _ = CloseHandle(handle);
            result
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
            .map_err(|e| ServiceError::Service(format!("Failed to kill process: {}", e)))?;
        Ok(())
    }
}
