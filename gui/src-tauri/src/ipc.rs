// IPC 载荷类型全部直接复用 service crate 的定义，
// 保证 bincode 布局（字段数/顺序/枚举变体索引）与服务端严格一致，不再手工镜像。
//
// ⚠️ HistoryFilters 在本批改为 Option<String> 筛选字段并新增 sort_by/sort_order
//（见 service/src/models.rs 的 HistoryFilters 注释），属 bincode wire 变更：
// GUI 与服务必须同次构建一起部署，混跑新旧版本会因布局错位报反序列化失败断管。
pub use ceasefire_service::models::{
    AppGroup, AppGroupMember, AppTrafficStats, ConnectionDecision, ConnectionInfo,
    CountryTrafficStats, DriverDiagnostics, ExportFormat, GlobalStats, HistoryFilters, IpcRequest,
    IpcResponse, NetworkHistoryRecord, NotificationItem, ProcessBandwidthLimit,
    ProtocolTrafficStats, Rule, RulePage, Settings, TrafficTrendPoint, ExportedRule, ImportMode,
    ImportStats, AppTimelinePoint, ActionTrendPoint, TopHostStats,
    RemoteAddressDetails,
};

/// GUI 侧沿用 GeoLocation 这个名字，对应服务端的 TauriGeoLocation（无 ip 字段版本）
pub use ceasefire_service::models::TauriGeoLocation as GeoLocation;

use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::core::HSTRING;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};

/// 单次请求的取消槽：持有本次 spawn 的阻塞线程的句柄副本。
/// 必须每请求独立——客户端级全局单槽会被最新进入的线程（含排队等锁、
/// 尚未开始 IO 的线程）刷新，导致超时取消落空或误取消其他慢请求。
type CancelSlot = std::sync::Arc<std::sync::Mutex<Option<std::os::windows::io::OwnedHandle>>>;

pub struct IpcClient {
    pipe_name: String,
    client: std::sync::Arc<std::sync::Mutex<Option<NamedPipeClient>>>,
}

impl IpcClient {
    pub fn new(pipe_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(IpcClient {
            pipe_name: pipe_name.to_string(),
            client: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    // 阻塞 IO 在 spawn_blocking 中执行，避免在 async 上下文中持有 std::sync::Mutex 阻塞运行时；
    // 外层加 10 秒超时防止服务无响应时卡死界面。
    async fn send_request(&self, request: IpcRequest) -> Result<IpcResponse, Box<dyn std::error::Error>> {
        let request_data = bincode::serialize(&request)?;
        let pipe_name = self.pipe_name.clone();
        let client_slot = self.client.clone();
        let cancel_slot: CancelSlot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let worker_cancel_slot = cancel_slot.clone();
        let worker_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_done_flag = worker_done.clone();

        let task = tokio::task::spawn_blocking(move || -> Result<IpcResponse, String> {
            // 登记取消目标为本线程：CancelSynchronousIo 只能取消指定线程的同步 IO。
            // 槽位与本次请求一一对应，超时方只取消自己这一次请求的线程。
            {
                let mut slot = match worker_cancel_slot.lock() {
                    Ok(s) => s,
                    Err(_) => return Err("IPC 取消句柄槽损坏".to_string()),
                };
                *slot = duplicate_current_thread_handle();
            }

            let mut guard = client_slot
                .lock()
                .map_err(|_| "IPC 连接锁损坏".to_string())?;

            if guard.is_none() {
                let connected = NamedPipeClient::connect(&pipe_name).map_err(|e| {
                    format!("无法连接服务 ({}): {}。请确认 Ceasefire 服务正在运行。", pipe_name, e)
                });
                match connected {
                    Ok(c) => *guard = Some(c),
                    Err(e) => return Err(e),
                }
            }

            let result = {
                let client = guard
                    .as_mut()
                    .ok_or_else(|| "未连接到服务".to_string())?;

                let mut io = || -> Result<IpcResponse, String> {
                    let len = request_data.len() as u32;
                    client
                        .write_all(&len.to_le_bytes())
                        .map_err(|e| format!("发送请求长度失败: {}。服务是否正在运行？", e))?;
                    client
                        .write_all(&request_data)
                        .map_err(|e| format!("发送请求数据失败: {}。服务是否正在运行？", e))?;
                    client
                        .flush()
                        .map_err(|e| format!("发送请求失败: {}。服务是否正在运行？", e))?;

                    let mut len_buf = [0u8; 4];
                    client
                        .read_exact(&mut len_buf)
                        .map_err(|e| format!("读取响应长度失败: {}。（连接被服务端关闭，通常是请求版本与服务不匹配或服务已重启）", e))?;
                    let response_len = u32::from_le_bytes(len_buf) as usize;
                    if response_len == 0 || response_len > 100_000_000 {
                        return Err(format!(
                            "无效的响应长度: {}。服务可能出现故障。",
                            response_len
                        ));
                    }

                    let mut response_data = vec![0u8; response_len];
                    client
                        .read_exact(&mut response_data)
                        .map_err(|e| format!("读取响应数据失败（期望 {} 字节）: {}。服务可能已崩溃。", response_len, e))?;

                    bincode::deserialize(&response_data).map_err(|e| {
                        format!("解析响应失败: {}。服务版本可能不兼容。", e)
                    })
                };

                io()
            };

            // 任何失败（连接/IO/断管）都使当前连接失效，下次请求重连
            if result.is_err() {
                *guard = None;
            }
            // 标记本 worker 即将返回：超时方据此判断补发的 CancelSynchronousIo
            // 是否还有意义（线程已退出后取消是无害空操作，但不值得等）。
            worker_done_flag.store(true, std::sync::atomic::Ordering::Release);
            result
        });

        // 超时后的取消动作：只取消本次请求专属槽位里的线程，句柄不消费，
        // 可重复尝试。
        let cancel_worker = || -> bool {
            if let Ok(slot) = cancel_slot.lock() {
                if let Some(h) = slot.as_ref() {
                    unsafe {
                        let _ = windows::Win32::System::IO::CancelSynchronousIo(
                            HANDLE(h.as_raw_handle() as *mut _),
                        );
                    }
                    return true;
                }
            }
            false
        };

        match tokio::time::timeout(std::time::Duration::from_secs(10), task).await {
            Ok(Ok(result)) => result.map_err(Into::into),
            Ok(Err(e)) => Err(format!("IPC 请求任务失败: {}", e).into()),
            Err(_) => {
                // 超时后 spawn_blocking 无法被 await 取消，阻塞读仍持有连接锁。
                // 按官方文档，取消同步 ReadFile 需要 CancelSynchronousIo + 线程句柄
                // （CancelIoEx 不保证能取消同步 IO）。
                //
                // 首次取消可能落空：worker 此刻可能还没登记句柄（slot 为 None），
                // 或还在排队等 client_slot 锁（尚未进入 IO，CancelSynchronousIo
                // 无效）。等 200ms 让 worker 走到 IO 段后补一次取消；若期间
                // worker 已自行完成则跳过。
                let first = cancel_worker();
                if first {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    if !worker_done.load(std::sync::atomic::Ordering::Acquire) {
                        cancel_worker();
                    }
                }
                Err("IPC 请求超时（10 秒），服务无响应。".into())
            }
        }
    }

    pub async fn create_rule(&self, rule: Rule) -> Result<i64, Box<dyn std::error::Error>> {
        let request = IpcRequest::CreateRule(rule);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Rule(r) => Ok(r.id.map(|i| i as i64).unwrap_or(0)),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn update_rule(&self, id: u32, rule: Rule) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::UpdateRule { id, rule };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn delete_rule(&self, id: u32) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::DeleteRule(id);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn list_rules(&self, offset: u32, limit: u32, search: Option<String>) -> Result<RulePage, Box<dyn std::error::Error>> {
        let request = IpcRequest::ListRules { offset, limit, search };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::RulePage(page) => Ok(page),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn export_rules(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let request = IpcRequest::ExportRules;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ExportData(data) => Ok(data),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn import_rules(
        &self,
        rules: Vec<ExportedRule>,
        mode: ImportMode,
    ) -> Result<ImportStats, Box<dyn std::error::Error>> {
        let request = IpcRequest::ImportRules { rules, mode };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ImportStats(stats) => Ok(stats),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_app_traffic_timeline(
        &self,
        hours: u32,
    ) -> Result<Vec<AppTimelinePoint>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetAppTrafficTimeline { hours };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::AppTrafficTimeline(points) => Ok(points),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_action_trend(
        &self,
        hours: u32,
    ) -> Result<Vec<ActionTrendPoint>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetActionTrend { hours };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ActionTrend(points) => Ok(points),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_top_hosts(
        &self,
        hours: u32,
        limit: u32,
    ) -> Result<Vec<TopHostStats>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetTopHosts { hours, limit };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::TopHosts(hosts) => Ok(hosts),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_remote_host_details(
        &self,
        remote_addr: String,
        hours: u32,
    ) -> Result<Option<RemoteAddressDetails>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetRemoteHostDetails { remote_addr, hours };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::RemoteHostDetails(details) => Ok(details),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_connections(&self) -> Result<Vec<ConnectionInfo>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetActiveConnections;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Connections(conns) => Ok(conns),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_global_stats(&self) -> Result<GlobalStats, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetGlobalStats;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::GlobalStats(stats) => Ok(stats),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_settings(&self) -> Result<Settings, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetSettings;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Settings(settings) => Ok(settings),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn update_settings(&self, settings: Settings) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::UpdateSettings(settings);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // Application Groups
    pub async fn list_app_groups(&self) -> Result<Vec<AppGroup>, Box<dyn std::error::Error>> {
        let request = IpcRequest::ListAppGroups;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::AppGroups(groups) => Ok(groups),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_app_group_members(&self, group_id: u32) -> Result<Vec<AppGroupMember>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetAppGroupMembers(group_id);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::AppGroupMembers(members) => Ok(members),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn add_app_group_member(&self, group_id: u32, process_path: String, process_name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::AddAppGroupMember { group_id, process_path, process_name };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn remove_app_group_member(&self, group_id: u32, process_path: String) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::RemoveAppGroupMember { group_id, process_path };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn initialize_predefined_groups(&self) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::InitializePredefinedGroups;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // 自定义分组管理（与服务端新追加的 IPC 变体配对）
    pub async fn create_app_group(&self, group: AppGroup) -> Result<AppGroup, Box<dyn std::error::Error>> {
        let request = IpcRequest::CreateAppGroup { group };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::AppGroupCreated(group) => Ok(group),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn update_app_group(&self, id: u32, group: AppGroup) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::UpdateAppGroup { id, group };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn delete_app_group(&self, id: u32) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::DeleteAppGroup { id };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn set_app_group_enabled(&self, id: u32, enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::SetAppGroupEnabled { id, enabled };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // Connection Decisions
    pub async fn record_connection_decision(&self, decision: ConnectionDecision) -> Result<ConnectionDecision, Box<dyn std::error::Error>> {
        let request = IpcRequest::RecordConnectionDecision(decision);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ConnectionDecision(decision) => Ok(decision),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn list_connection_decisions(&self) -> Result<Vec<ConnectionDecision>, Box<dyn std::error::Error>> {
        let request = IpcRequest::ListConnectionDecisions;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ConnectionDecisions(decisions) => Ok(decisions),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn delete_connection_decision(&self, id: u32) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::DeleteConnectionDecision(id);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn clear_expired_decisions(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let request = IpcRequest::ClearExpiredDecisions;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::DeletedCount(count) => Ok(count),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // Network History
    pub async fn get_network_history(&self, filters: Option<HistoryFilters>) -> Result<Vec<NetworkHistoryRecord>, Box<dyn std::error::Error>> {
        let filters = filters.unwrap_or_default();
        let request = IpcRequest::GetNetworkHistory(filters);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::NetworkHistoryRecords(records) => Ok(records),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    /// 连接记录真实总数（分页器"共 N 条"用），筛选条件与 get_network_history 一致
    pub async fn get_network_history_count(&self, filters: Option<HistoryFilters>) -> Result<u64, Box<dyn std::error::Error>> {
        let filters = filters.unwrap_or_default();
        let request = IpcRequest::GetNetworkHistoryCount(filters);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::NetworkHistoryCount(count) => Ok(count),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn export_network_history(&self, filters: HistoryFilters, format: String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let export_format = match format.as_str() {
            "csv" => ExportFormat::Csv,
            "json" => ExportFormat::Json,
            _ => ExportFormat::Json,
        };
        let request = IpcRequest::ExportNetworkHistory { filters, format: export_format };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ExportData(data) => Ok(data),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // Bandwidth Limits
    pub async fn set_process_bandwidth_limit(&self, limit: ProcessBandwidthLimit) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::SetProcessBandwidthLimit(limit);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn list_process_bandwidth_limits(&self) -> Result<Vec<ProcessBandwidthLimit>, Box<dyn std::error::Error>> {
        let request = IpcRequest::ListProcessBandwidthLimits;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ProcessBandwidthLimits(limits) => Ok(limits),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn set_global_bandwidth_limit(&self, upload_limit_kbps: Option<u32>, download_limit_kbps: Option<u32>, enabled: Option<bool>) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::SetGlobalBandwidthLimit { upload_limit_kbps, download_limit_kbps, enabled };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn delete_process_bandwidth_limit(&self, process_path: String) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::DeleteProcessBandwidthLimit(process_path);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // Suspicious Rules
    // Statistics
    pub async fn get_app_traffic_stats(&self, hours: u32) -> Result<Vec<AppTrafficStats>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetAppTrafficStats(hours);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::AppTrafficStats(stats) => Ok(stats),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_protocol_traffic_stats(&self, hours: u32) -> Result<Vec<ProtocolTrafficStats>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetProtocolTrafficStats(hours);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::ProtocolTrafficStats(stats) => Ok(stats),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_country_traffic_stats(&self, hours: u32) -> Result<Vec<CountryTrafficStats>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetCountryTrafficStats(hours);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::CountryTrafficStats(stats) => Ok(stats),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    pub async fn get_traffic_trend(&self, hours: u32) -> Result<Vec<TrafficTrendPoint>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetTrafficTrend { hours };
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::TrafficTrend(trend) => Ok(trend),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // GeoIP
    pub async fn lookup_geo_location_batch(&self, ips: Vec<String>) -> Result<std::collections::HashMap<String, GeoLocation>, Box<dyn std::error::Error>> {
        let request = IpcRequest::LookupGeoLocationBatch(ips);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::GeoLocationBatch(locations) => Ok(locations),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    /// DNS 缓存：IP → 域名反查
    pub async fn lookup_domain(&self, ip: String) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let request = IpcRequest::LookupDomain(ip);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Domain(domain) => Ok(domain),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    /// 通知轮询：取走服务端待处理通知（service→GUI 事件通道）
    pub async fn poll_notifications(&self, max: u32) -> Result<Vec<NotificationItem>, Box<dyn std::error::Error>> {
        let request = IpcRequest::PollNotifications(max);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Notifications(items) => Ok(items),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    // Process Management
    pub async fn kill_process(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let request = IpcRequest::KillProcess(pid);
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::Success => Ok(()),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }

    /// 驱动诊断快照（旧驱动无此 IOCTL 时返回 None，前端按占位文案处理）
    pub async fn get_driver_diags(&self) -> Result<Option<DriverDiagnostics>, Box<dyn std::error::Error>> {
        let request = IpcRequest::GetDriverDiags;
        let response = self.send_request(request).await?;

        match response {
            IpcResponse::DriverDiags(diags) => Ok(diags),
            IpcResponse::Error(message) => Err(message.into()),
            _ => Err("Unexpected response".into()),
        }
    }
}

struct NamedPipeClient {
    handle: std::os::windows::io::OwnedHandle,
}

impl NamedPipeClient {
    fn connect(pipe_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        use windows::Win32::Foundation::ERROR_PIPE_BUSY;
        use windows::core::HRESULT;
        use windows::Win32::System::Pipes::WaitNamedPipeW;

        // 服务端是单实例串行 accept，两次连接之间存在短暂空窗：上一个客户端
        // 断开后服务端要先回到 accept 循环重建管道实例。期间 CreateFileW 会
        // 报 ERROR_PIPE_BUSY（os error 231）或管道暂不存在——对 busy 用
        // WaitNamedPipeW 等待实例可用并短退避重试，超限才报错。
        let mut last_err: Option<windows::core::Error> = None;
        for attempt in 0..3u32 {
            let name = HSTRING::from(pipe_name);
            match unsafe {
                CreateFileW(
                    &name,
                    (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    Default::default(), // Remove FILE_FLAG_OVERLAPPED for synchronous I/O
                    None,
                )
            } {
                Ok(handle) => {
                    return Ok(unsafe {
                        NamedPipeClient {
                            handle: OwnedHandle::from_raw_handle(handle.0 as *mut _),
                        }
                    });
                }
                Err(e) => {
                    let busy = e.code() == HRESULT::from_win32(ERROR_PIPE_BUSY.0);
                    last_err = Some(e);
                    if !busy || attempt == 2 {
                        break;
                    }
                    unsafe {
                        let _ = WaitNamedPipeW(&name, 500);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
        Err(match last_err {
            Some(e) => format!("无法连接服务 ({}): {}。请确认 Ceasefire 服务正在运行。", pipe_name, e).into(),
            None => "无法连接服务：未知错误。".into(),
        })
    }
}

impl Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let raw_handle = self.handle.as_raw_handle();
        let handle = HANDLE(raw_handle as *mut _);
        unsafe {
            let mut bytes_read = 0u32;
            let result = windows::Win32::Storage::FileSystem::ReadFile(
                handle,
                Some(buf),
                Some(&mut bytes_read),
                None,
            );
            result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(bytes_read as usize)
        }
    }
}

impl Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let raw_handle = self.handle.as_raw_handle();
        let handle = HANDLE(raw_handle as *mut _);
        unsafe {
            let mut bytes_written = 0u32;
            let result = windows::Win32::Storage::FileSystem::WriteFile(
                handle,
                Some(buf),
                Some(&mut bytes_written),
                None,
            );
            result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(bytes_written as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let raw_handle = self.handle.as_raw_handle();
        let handle = HANDLE(raw_handle as *mut _);
        unsafe {
            windows::Win32::Storage::FileSystem::FlushFileBuffers(handle)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
        Ok(())
    }
}

/// Duplicate the calling thread's own handle (GetCurrentThread returns a
/// pseudo handle only valid in this thread). The duplicate is a real handle
/// usable from another thread by CancelSynchronousIo.
fn duplicate_current_thread_handle() -> Option<OwnedHandle> {
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, BOOL};
    use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

    unsafe {
        let process = GetCurrentProcess();
        let mut dup = HANDLE::default();
        let ok = DuplicateHandle(
            process,
            GetCurrentThread(),
            process,
            &mut dup,
            0,
            BOOL(0),
            DUPLICATE_SAME_ACCESS,
        );
        if ok.is_ok() {
            Some(OwnedHandle::from_raw_handle(dup.0 as *mut _))
        } else {
            log::warn!("复制 IPC 工作线程句柄失败，超时后将无法取消其阻塞 IO");
            None
        }
    }
}
