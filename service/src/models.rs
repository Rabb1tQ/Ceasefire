//! Data Models for Ceasefire Firewall Service

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Option<u32>,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub action: RuleAction,
    pub direction: Direction,
    pub protocol: Option<Protocol>,
    pub process_id: Option<u32>,
    pub process_path: Option<String>,
    pub remote_addr: Option<String>,
    pub remote_addr_mask: Option<u8>,
    /// 域名匹配条件（精确 a.example.com 或前导通配 *.example.com），与
    /// remote_addr 互斥。内核无域名概念：该规则不直接下发驱动，由
    /// domain_expander 在 DNS 命中时展开成按 IP 的影子规则下发。
    pub remote_domain: Option<String>,
    pub remote_port: Option<PortRange>,
    pub local_addr: Option<String>,
    pub local_addr_mask: Option<u8>,
    pub local_port: Option<PortRange>,
    pub network_zone: Option<NetworkZone>,
    pub app_group_id: Option<u32>,
    // RFC3339 字符串：IPC 载荷统一用字符串时间，保证与 GUI 侧 bincode 布局一致
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Port range for rule matching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortRange {
    Single(u16),
    Range(u16, u16),
}

impl PortRange {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortRange::Single(p) => *p == port,
            PortRange::Range(start, end) => port >= *start && port <= *end,
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<u16>()
                    .map_err(|_| format!("Invalid start port: {}", parts[0]))?;
                let end = parts[1].parse::<u16>()
                    .map_err(|_| format!("Invalid end port: {}", parts[1]))?;
                if start <= end {
                    Ok(PortRange::Range(start, end))
                } else {
                    Err(format!("Start port {} must be <= end port {}", start, end))
                }
            } else {
                Err(format!("Invalid port range format: {}", s))
            }
        } else {
            let port = s.parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", s))?;
            Ok(PortRange::Single(port))
        }
    }
}

/// Network zone classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum NetworkZone {
    #[default]
    Internet,
    Localhost,
    Lan,
}

impl std::fmt::Display for NetworkZone {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NetworkZone::Localhost => write!(f, "Localhost"),
            NetworkZone::Lan => write!(f, "Lan"),
            NetworkZone::Internet => write!(f, "Internet"),
        }
    }
}

/// 规则分页结果（ListRules 响应；排序固定 priority, id 保证翻页稳定）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePage {
    pub total: u64,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub enum RuleAction {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum Direction {
    #[default]
    Both,
    Inbound,
    Outbound,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Direction::Inbound => write!(f, "Inbound"),
            Direction::Outbound => write!(f, "Outbound"),
            Direction::Both => write!(f, "Both"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum Protocol {
    #[default]
    Any,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "Tcp"),
            Protocol::Udp => write!(f, "Udp"),
            Protocol::Icmp => write!(f, "Icmp"),
            Protocol::Icmpv6 => write!(f, "Icmpv6"),
            Protocol::Any => write!(f, "Any"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Option<u32>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: EventAction,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub rule_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum EventAction {
    #[default]
    Allow,
    Block,
    Close,
}

impl std::fmt::Display for EventAction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EventAction::Allow => write!(f, "Allow"),
            EventAction::Block => write!(f, "Block"),
            EventAction::Close => write!(f, "Close"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub direction: Direction,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub state: ConnectionState,
    // RFC3339 字符串（字符串比较即可按时间排序）
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    Established,
    Closing,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessStats {
    pub process_id: u32,
    pub process_name: String,
    pub active_connections: u32,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalStats {
    pub active_connections: u32,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub blocked_connections: u32,
    pub allowed_connections: u32,
    pub suspicious_connections: u32,
}

/// Application group for batch rule management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppGroup {
    pub id: Option<u32>,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub is_predefined: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Application group member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppGroupMember {
    pub id: Option<u32>,
    pub group_id: u32,
    pub process_path: String,
    pub process_name: Option<String>,
    pub added_at: Option<String>,
}

/// Application group statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppGroupStats {
    pub group_id: u32,
    pub group_name: String,
    pub active_connections: u32,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

/// Connection decision for "Ask to Connect" mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDecision {
    pub id: Option<u32>,
    pub process_path: String,
    pub process_name: Option<String>,
    pub remote_addr: String,
    pub remote_port: u16,
    pub decision: DecisionAction,
    pub remember: bool,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DecisionAction {
    #[default]
    Allow,
    Block,
}

/// Suspicious connection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousRule {
    pub id: Option<u32>,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub conditions: SuspiciousConditions,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousConditions {
    pub blacklisted_ip_ranges: Vec<String>,
    pub sensitive_ports: Vec<u16>,
    pub unknown_process_threshold: bool,
    pub port_scan_detection: bool,
}

/// Bandwidth limit configuration for process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBandwidthLimit {
    pub id: Option<u32>,
    pub process_path: String,
    pub process_name: Option<String>,
    pub upload_limit_kbps: Option<u32>,
    pub download_limit_kbps: Option<u32>,
    pub enabled: bool,
    // RFC3339 字符串，保持与 GUI 侧 bincode 布局一致
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Global bandwidth limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalBandwidthLimit {
    pub id: u32,
    pub upload_limit_kbps: Option<u32>,
    pub download_limit_kbps: Option<u32>,
    pub enabled: bool,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Historical connection record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: Option<u32>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub action: EventAction,
    pub is_anomaly: bool,
    pub anomaly_type: Option<String>,
}

/// Traffic aggregation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAggregation {
    pub id: Option<u32>,
    pub period: AggregationPeriod,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub dimension: AggregationDimension,
    pub dimension_value: String,
    pub protocol: Option<Protocol>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AggregationPeriod {
    #[default]
    Hour,
    Day,
    Week,
    Month,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AggregationDimension {
    Application,
    Protocol,
    Country,
    Global,
}

/// GeoIP location data (matches Tauri client definition)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip: String,
    pub country_code: String,
    pub country_name: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub cached_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// GeoIP location for Tauri (without ip field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TauriGeoLocation {
    pub country_code: String,
    pub country_name: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub isp: String,
    pub asn: Option<String>,
}

impl From<GeoLocation> for TauriGeoLocation {
    fn from(loc: GeoLocation) -> Self {
        TauriGeoLocation {
            country_code: loc.country_code,
            country_name: loc.country_name,
            city: loc.city.unwrap_or_else(|| String::from("Unknown")),
            latitude: loc.latitude.unwrap_or(0.0),
            longitude: loc.longitude.unwrap_or(0.0),
            timezone: String::from("UTC"),
            isp: String::from("Unknown"),
            asn: None,
        }
    }
}

/// Traffic statistics by application
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppTrafficStats {
    pub process_name: String,
    pub process_path: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u32,
    // 最近一次记录的进程 ID，供 GUI 终止进程使用
    pub process_id: Option<u32>,
    // 最近一次活动时间（RFC3339），由历史记录聚合而来
    pub last_seen: Option<String>,
}

/// Traffic statistics by protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolTrafficStats {
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u32,
}

/// Traffic statistics by country
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CountryTrafficStats {
    pub country_code: String,
    pub country_name: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u32,
}

/// Traffic trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficTrendPoint {
    pub timestamp: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u32,
}

/// Network history record (extended with more fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHistoryRecord {
    pub id: Option<u32>,
    pub timestamp: String,
    pub action: RuleAction,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub rule_id: Option<u32>,
}

/// History filters for network history queries
///
/// ⚠️ wire 结构（bincode 布局）：本结构同时被 GUI（JSON → Tauri → bincode）与
/// cfctl 消费，action/protocol/direction/sort_by/sort_order 一律用
/// Option<String>（枚举名字符串），由服务端消费处解析成枚举。禁止改回枚举 +
/// deserialize_with：bincode 序列化 Option<Enum>（tag+变体序号）与
/// Option<String>（tag+长度+字节）编码不同，deserialize_with 只改解码侧，
/// 会导致编码/解码错位、反序列化 io error 断管。任何字段增删都是 wire 变更，
/// 服务端与 GUI 必须同次构建一起部署。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFilters {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub hours: Option<u32>,
    // 未选中的筛选键在 GUI 传 JSON 时直接缺席，显式 #[serde(default)] 使其
    // 按 None 处理（普通 Option 字段 serde 默认就允许缺失，此处为可读性保留）
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    pub process_path: Option<String>,
    pub remote_addr: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    /// 排序字段：timestamp / bytes_sent / bytes_received / remote_addr /
    /// process_name，白名单外的值由服务端回退 timestamp
    #[serde(default)]
    pub sort_by: Option<String>,
    /// 排序方向：ascending / descending，白名单外的值由服务端回退默认
    #[serde(default)]
    pub sort_order: Option<String>,
}

impl Default for HistoryFilters {
    fn default() -> Self {
        HistoryFilters {
            limit: Some(100),
            offset: Some(0),
            hours: Some(24),
            action: None,
            protocol: None,
            process_path: None,
            remote_addr: None,
            direction: None,
            sort_by: None,
            sort_order: None,
        }
    }
}

/// Network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatistics {
    pub total_connections: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub by_protocol: std::collections::HashMap<Protocol, usize>,
    pub by_app: std::collections::HashMap<String, usize>,
    pub top_remote_addrs: std::collections::HashMap<String, usize>,
    pub blocked_count: usize,
    pub allowed_count: usize,
}

/// Remote address details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAddressDetails {
    pub remote_addr: String,
    pub connection_count: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub protocols: Vec<String>,
    pub local_ports: Vec<u16>,
    pub remote_ports: Vec<u16>,
}

impl ConnectionDecision {
    /// Check if decision is expired (one day old)
    pub fn is_expired(&self) -> bool {
        // created_at 为 RFC3339 字符串；解析失败按已过期处理
        match self.created_at.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
            Some(created_at) => chrono::Utc::now() - created_at.with_timezone(&chrono::Utc) > chrono::Duration::days(1),
            None => true,
        }
    }
}

/// History query with extended filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub action: Option<EventAction>,
    pub protocol: Option<Protocol>,
    pub process_id: Option<u32>,
    pub process_path: Option<String>,
    pub remote_addr: Option<String>,
    pub country_code: Option<String>,
    pub is_anomaly: Option<bool>,
    pub sort_by: Option<HistorySortField>,
    pub sort_order: Option<SortOrder>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HistorySortField {
    Timestamp,
    BytesSent,
    BytesReceived,
    ProcessName,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
}

/// Report export format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ReportFormat {
    Pdf,
    Html,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub notifications_enabled: bool,
    pub ask_to_connect_enabled: bool,
    pub remember_decisions: bool,
    pub global_bandwidth_limit_enabled: bool,
    pub global_upload_limit_kbps: Option<u32>,
    pub global_download_limit_kbps: Option<u32>,
    /// 驱动默认策略：true=未匹配规则时放行，false=拦截。
    /// serde 默认值兼容旧客户端少发的字段。
    #[serde(default = "default_true")]
    pub default_allow: bool,
    /// 默认拦截模式下自动安装的内置系统进程豁免规则（[System] 前缀）
    #[serde(default = "default_true")]
    pub system_rules_enabled: bool,
    /// 服务未运行时拦截（kill-switch）：常驻 WFP 持久过滤器兜底
    #[serde(default)]
    pub protect_when_not_running: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: EventAction,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub packets_sent: Option<u64>,
    pub packets_received: Option<u64>,
    pub rule_id: Option<u32>,
}



/// 驱动诊断：单个 callout 的注册状态（IOCTL_GET_DIAGS 快照）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverCalloutDiag {
    pub name: String,
    /// FwpsCalloutRegister NTSTATUS（0=成功；0x80320009=僵尸注册 FWP_E_ALREADY_EXISTS）
    pub reg_status: u32,
    /// 最终 calloutId（0=注册失败，该层本会话静默失效）
    pub callout_id: u32,
    /// FwpsCalloutUnregisterById0 最终返回码（0=成功；diag v1 驱动恒 0）
    pub unreg_status: u32,
    /// 注销失败重试次数（0=一次成功）
    pub unreg_retries: u32,
}

/// 驱动诊断快照（计数器数组下标 [0]=V4、[1]=V6）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverDiagnostics {
    pub callouts: Vec<DriverCalloutDiag>,
    pub classify_stream: [u64; 2],
    pub classify_flow_est: [u64; 2],
    pub assoc_ok: [u64; 2],
    pub assoc_fail: [u64; 2],
    pub flow_delete: [u64; 2],
    pub stream_bytes_counted: [u64; 2],
    /// 快照时刻限速表活跃条目数（diag v3；旧驱动恒 0）
    #[serde(default)]
    pub throttle_active_entries: u32,
    /// 进程退出通知回调累计清理次数（diag v3；旧驱动恒 0）
    #[serde(default)]
    pub throttle_notify_removes: u32,
    /// 入站传输层（下载限速）classify 次数，[0]=V4、[1]=V6（diag v4；旧驱动恒 0）
    #[serde(default)]
    pub in_transport_classify: [u64; 2],
    /// 入站传输层终结 PERMIT 次数（含无法归因/纯 ACK 放行；diag v4）
    #[serde(default)]
    pub in_transport_permit: [u64; 2],
    /// 入站传输层终结 BLOCK 次数（第 19 轮起 = 扣留成功 BLOCK+ABSORORB 计数，
    /// 包由 pacing 引擎定时再注入，不再丢包；diag v4）
    #[serde(default)]
    pub in_transport_block: [u64; 2],
    /// 入站传输层 callout 注册/注销状态（[0]=V4、[1]=V6；diag v4；旧驱动恒 0）
    #[serde(default)]
    pub in_transport_reg_status: [u32; 2],
    #[serde(default)]
    pub in_transport_callout_id: [u32; 2],
    #[serde(default)]
    pub in_transport_unreg_status: [u32; 2],
    #[serde(default)]
    pub in_transport_unreg_retries: [u32; 2],
    /// kernel pacing 扣留包数（diag v5；旧驱动恒 0）
    #[serde(default)]
    pub pacing_held: u64,
    /// kernel pacing 注入成功数（diag v5）
    #[serde(default)]
    pub pacing_injected: u64,
    /// kernel pacing 注入失败数（当丢包；diag v5）
    #[serde(default)]
    pub pacing_inject_fail: u64,
    /// kernel pacing 超限丢弃数（每 PID 512KB / 全局 4MB；diag v5）
    #[serde(default)]
    pub pacing_queue_drop: u64,
    /// kernel pacing 全局扣留峰值字节数（diag v5）
    #[serde(default)]
    pub pacing_queue_depth_max: u64,
    /// kernel pacing 放行定时器触发次数（diag v5）
    #[serde(default)]
    pub pacing_timer_ticks: u64,
    /// 驱动诊断结构版本（CF_DIAGS_VERSION；老 IPC 不带该字段时默认 0）
    #[serde(default)]
    pub diag_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    CreateRule(Rule),
    UpdateRule { id: u32, rule: Rule },
    DeleteRule(u32),
    ListRules { offset: u32, limit: u32, search: Option<String> },
    GetActiveConnections,
    GetGlobalStats,
    GetSettings,
    UpdateSettings(Settings),
    // Application Groups
    ListAppGroups,
    GetAppGroupMembers(u32),
    AddAppGroupMember { group_id: u32, process_path: String, process_name: Option<String> },
    RemoveAppGroupMember { group_id: u32, process_path: String },
    InitializePredefinedGroups,
    // Connection Decisions
    RecordConnectionDecision(ConnectionDecision),
    ListConnectionDecisions,
    DeleteConnectionDecision(u32),
    ClearExpiredDecisions,
    // Network History
    GetNetworkHistory(HistoryFilters),
    ExportNetworkHistory { filters: HistoryFilters, format: ExportFormat },
    // Bandwidth Limits
    SetProcessBandwidthLimit(ProcessBandwidthLimit),
    ListProcessBandwidthLimits,
    // enabled: None = 旧调用方语义（按限值有无推断开关，全 None = 清除）；
    // Some(false) = 仅摘除全局条目/关闭开关，限值配置原样保留，重开无需重填。
    // 注意：pipe 协议是 bincode（非自描述格式），新增字段后新旧端不能混跑——
    // 旧客户端发两字段、新端读三字段必失败；"省略字段"仅在 Rust 构造时成立
    //（省略 = None 序列化为一个字节），不是线格式层面的向后兼容。服务端与
    // GUI/cfctl 必须同版本部署。
    SetGlobalBandwidthLimit { upload_limit_kbps: Option<u32>, download_limit_kbps: Option<u32>, enabled: Option<bool> },
    DeleteProcessBandwidthLimit(String),
    // Statistics
    GetAppTrafficStats(u32),
    GetProtocolTrafficStats(u32),
    GetCountryTrafficStats(u32),
    GetTrafficTrend { hours: u32 },
    // GeoIP
    // DNS 缓存：IP → 域名反查
    LookupDomain(String),
    LookupGeoLocationBatch(Vec<String>),
    CleanupGeoCache,
    GetGeoCacheStats,
    // Process Management
    KillProcess(u32),
    // 通知轮询：取走最多 max 条待处理通知（服务→GUI 事件通道）
    PollNotifications(u32),
    // 驱动诊断快照（cfctl diags；旧驱动无此 IOCTL 时返回 None）
    GetDriverDiags,
    // 规则导入/导出（GUI 规则管理页）
    ExportRules,
    ImportRules { rules: Vec<ExportedRule>, mode: ImportMode },
    // Dashboard 图表增强：按应用堆叠时序 / 放行-拦截趋势 / 目标主机排行+明细
    GetAppTrafficTimeline { hours: u32 },
    GetActionTrend { hours: u32 },
    GetTopHosts { hours: u32, limit: u32 },
    GetRemoteHostDetails { remote_addr: String, hours: u32 },
    // 自定义分组管理（GUI 分组页）：只在枚举末尾追加（bincode 变体索引按
    // 顺序编码，中间插入会破坏新旧端布局），服务与 GUI 需同批部署
    CreateAppGroup { group: AppGroup },
    UpdateAppGroup { id: u32, group: AppGroup },
    DeleteAppGroup { id: u32 },
    SetAppGroupEnabled { id: u32, enabled: bool },
    // 连接记录分页：真实总数（与 GetNetworkHistory 同一套筛选条件做 COUNT）
    GetNetworkHistoryCount(HistoryFilters),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Success,
    Rule(Rule),
    RulePage(RulePage),
    Connections(Vec<ConnectionInfo>),
    GlobalStats(GlobalStats),
    ExportData(Vec<u8>),
    Settings(Settings),
    // Application Groups
    AppGroups(Vec<AppGroup>),
    AppGroupMembers(Vec<AppGroupMember>),
    // Connection Decisions
    ConnectionDecision(ConnectionDecision),
    ConnectionDecisions(Vec<ConnectionDecision>),
    DeletedCount(u32),
    // Network History
    NetworkHistoryRecords(Vec<NetworkHistoryRecord>),
    // Bandwidth Limits
    ProcessBandwidthLimit(Option<ProcessBandwidthLimit>),
    ProcessBandwidthLimits(Vec<ProcessBandwidthLimit>),
    // Statistics
    AppTrafficStats(Vec<AppTrafficStats>),
    ProtocolTrafficStats(Vec<ProtocolTrafficStats>),
    CountryTrafficStats(Vec<CountryTrafficStats>),
    TrafficTrend(Vec<TrafficTrendPoint>),
    // GeoIP
    Domain(Option<String>),
    GeoLocationBatch(std::collections::HashMap<String, TauriGeoLocation>),
    GeoCacheStats(TauriGeoIpCacheStats),
    Notifications(Vec<NotificationItem>),
    DriverDiags(Option<DriverDiagnostics>),
    ImportStats(ImportStats),
    AppTrafficTimeline(Vec<AppTimelinePoint>),
    ActionTrend(Vec<ActionTrendPoint>),
    TopHosts(Vec<TopHostStats>),
    RemoteHostDetails(Option<RemoteAddressDetails>),
    Error(String),
    // 自定义分组管理（与 IpcRequest 末尾追加的新变体配对，见其注释）。
    // 同样只在枚举末尾追加，不改动既有变体（含 Error）的索引
    AppGroupCreated(AppGroup),
    // 连接记录真实总数（与 IpcRequest 末尾追加的 GetNetworkHistoryCount 配对）
    NetworkHistoryCount(u64),
}

/// GeoIP cache statistics for Tauri
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TauriGeoIpCacheStats {
    pub memory_cache_size: usize,
    pub database_cache_size: u32,
    pub cache_ttl_hours: i64,
    pub database_loaded: bool,
}

impl From<crate::geoip::GeoIpCacheStats> for TauriGeoIpCacheStats {
    fn from(stats: crate::geoip::GeoIpCacheStats) -> Self {
        TauriGeoIpCacheStats {
            memory_cache_size: stats.memory_cache_size,
            database_cache_size: stats.database_cache_size,
            cache_ttl_hours: stats.cache_ttl_hours,
            database_loaded: stats.database_loaded,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ExportFormat {
    Csv,
    Json,
}

/// service→GUI 通知条目（GUI 轮询拉取）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationItem {
    pub id: u64,
    /// Blocked = 普通拦截通知；Ask = 未知程序询问（弹 Allow/Block/Skip）
    pub kind: NotificationKind,
    pub timestamp: String,
    pub process_path: Option<String>,
    pub process_name: Option<String>,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub direction: String,
    pub rule_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum NotificationKind {
    Blocked,
    Ask,
}
/// 规则导入/导出条目（schema 1）。与 Rule 的差异：app_group_id 换成分组名
/// （跨库导入按名回映射，找不到则创建）、process_id/id/时间戳不导出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub action: RuleAction,
    pub direction: Direction,
    pub protocol: Option<Protocol>,
    pub process_path: Option<String>,
    pub remote_addr: Option<String>,
    pub remote_addr_mask: Option<u8>,
    pub remote_domain: Option<String>,
    pub remote_port: Option<PortRange>,
    pub local_addr: Option<String>,
    pub local_addr_mask: Option<u8>,
    pub local_port: Option<PortRange>,
    pub network_zone: Option<NetworkZone>,
    /// 所属分组名（None = 不属于任何分组）
    pub group: Option<String>,
}

/// 导出文件结构（JSON）。schema 不认识就整批拒绝，为未来字段演进留口。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExportFile {
    pub schema: u32,
    /// RFC3339 字符串
    pub exported_at: String,
    pub rules: Vec<ExportedRule>,
}

/// 当前 schema 版本
pub const RULE_EXPORT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImportMode {
    /// 按 name+process_path 判重，重复跳过、新规则追加
    Merge,
    /// 清空全部用户规则（[System] 内置规则不动）后导入
    Replace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportStats {
    pub imported: usize,
    pub skipped: usize,
    /// 按名回映射时新建的分组数
    pub groups_created: usize,
}

/// 按应用堆叠流量时序的单点（Dashboard 堆叠面积图）。timestamp 为桶起点
/// RFC3339；同一 (timestamp, process_path) 一行。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTimelinePoint {
    pub timestamp: String,
    pub process_path: String,
    pub process_name: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// 放行/拦截趋势的单桶（Dashboard 双序列图）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTrendPoint {
    pub timestamp: String,
    pub allowed_bytes: u64,
    pub blocked_bytes: u64,
    pub allowed_count: u64,
    pub blocked_count: u64,
}

/// 目标主机排行条目（按 remote_addr 聚合；domain 由 DNS 缓存反查填充）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopHostStats {
    pub remote_addr: String,
    pub domain: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u64,
}

/// 路径归一化的唯一入口：小写 + 正斜杠转反斜杠。
/// 配置侧（GUI/cfctl 常传 C:/xxx）与事件侧（系统返回 C:\xxx）必须经同一
/// 函数后再作为表 key / 查找 key（内存表 kernel_sync 与 DB 层共用），
/// 任何一处分流实现都会重新引入不匹配。
pub(crate) fn normalize_path(p: &str) -> String {
    p.to_lowercase().replace('/', "\\")
}
