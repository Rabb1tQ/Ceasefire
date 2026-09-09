//! Driver Rule Converter - converts service rules to driver format

use super::super::error::{Result, ServiceError};
use super::super::models::*;
use std::net::{IpAddr, Ipv6Addr};

// 地址族常量（与 driver/inc/types.h CF_ADDR_FAMILY_* 一致）
pub const CF_ADDR_FAMILY_V4: u32 = 4;
pub const CF_ADDR_FAMILY_V6: u32 = 6;

/// Driver rule structure matching C RULE_INPUT
/// Must match the exact layout in driver/inc/types.h
///
/// 双栈地址约定（与 types.h 顶部一致）：
/// * family = 4：`remote_addr[0..4]` 存放"主机序 u32"的本机字节序（LE）表示，
///   与旧 u32 字段位形态逐位相同；驱动端 RtlCopyMemory 回 UINT32 后按旧的
///   `(conn & mask) == (rule & mask)` 语义比较。
/// * family = 6：16 字节网络序原样（IPv6 无字节交换问题）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverRuleInput {
    pub rule_id: u32,              // UINT32 RuleId - offset 0
    pub priority: u32,             // UINT32 Priority - offset 4
    pub enabled: u8,               // BOOLEAN Enabled - offset 8
    pub is_allow: u8,              // BOOLEAN IsAllow - offset 9
    pub _padding1: u16,            // Padding to align ProcessId to 4 bytes - offset 10
    pub process_id: u32,           // UINT32 ProcessId - offset 12
    pub process_path: [u16; 260],  // WCHAR ProcessPath[MAX_PATH_LENGTH] - offset 16
    pub protocol: u32,             // UINT32 Protocol - offset 536
    pub remote_addr: [u8; 16],     // BYTE RemoteAddr[16] - offset 540（双栈形态见上）
    pub remote_addr_mask: [u8; 16],// BYTE RemoteAddrMask[16] - offset 556
    pub address_family: u32,       // UINT32 AddressFamily - offset 572 (CF_ADDR_FAMILY_*)
    pub remote_port: u16,          // UINT16 RemotePort - offset 576
    pub local_port: u16,           // UINT16 LocalPort - offset 578
    pub direction: u32,            // UINT32 Direction - offset 580 (0=Both,1=In,2=Out)
    pub remote_port_end: u16,      // UINT16 RemotePortEnd - offset 584（端口区间终点）
    pub local_port_end: u16,       // UINT16 LocalPortEnd - offset 586（端口区间终点）
}                                  // Total: 588 bytes

impl DriverRuleInput {
    pub fn from_rule(rule: &Rule) -> Result<Self> {
        // Convert process path to WCHAR array
        let mut process_path = [0u16; 260];
        if let Some(ref path) = rule.process_path {
            // 驱动侧进程路径来自 FWPS 元数据，是 NT 形态（\Device\HarddiskVolumeX\...）。
            // 规则里存的是 DOS 路径（C:\...），下发前必须转换，否则永远匹配不上。
            let effective_path = convert_dos_path_to_nt(path).unwrap_or_else(|| {
                tracing::warn!("Could not convert rule process path to NT form, sending as-is: {}", path);
                path.clone()
            });
            let path_wide: Vec<u16> = effective_path.encode_utf16().collect();
            let copy_len = path_wide.len().min(259); // Leave room for null terminator
            process_path[..copy_len].copy_from_slice(&path_wide[..copy_len]);
        }

        // Convert remote address (IPv4/IPv6, 可选 "/prefix" 后缀；无前缀 = 精确
        // 匹配 /32 或 /128) to the dual-stack wire form documented above.
        let mut remote_addr = [0u8; 16];
        let mut remote_addr_mask = [0u8; 16];
        let mut address_family: u32 = 0;
        if let Some(ref addr_str) = rule.remote_addr {
            let (ip_part, prefix): (&str, Option<u8>) = match addr_str.rsplit_once('/') {
                Some((ip, p)) => (
                    ip,
                    Some(p.parse::<u8>().map_err(|_| {
                        ServiceError::Validation(format!("Invalid address prefix: {}", addr_str))
                    })?),
                ),
                None => (addr_str.as_str(), None),
            };
            match ip_part.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => {
                    let bits = prefix.or(rule.remote_addr_mask).unwrap_or(32);
                    if bits > 32 {
                        return Err(ServiceError::Validation(format!(
                            "IPv4 prefix out of range: {}",
                            addr_str
                        )));
                    }
                    address_family = CF_ADDR_FAMILY_V4;
                    // 旧语义：u32::from_be_bytes(octets)（首八进制段为最高字节）
                    // 的主机序数值，按本机字节序（LE）写入首 4 字节
                    let value = u32::from_be_bytes(v4.octets());
                    let mask: u32 = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
                    remote_addr[..4].copy_from_slice(&value.to_le_bytes());
                    remote_addr_mask[..4].copy_from_slice(&mask.to_le_bytes());
                }
                Ok(IpAddr::V6(v6)) => {
                    let bits = prefix.or(rule.remote_addr_mask).unwrap_or(128);
                    if bits > 128 {
                        return Err(ServiceError::Validation(format!(
                            "IPv6 prefix out of range: {}",
                            addr_str
                        )));
                    }
                    address_family = CF_ADDR_FAMILY_V6;
                    remote_addr = v6.octets();
                    let full_bytes = (bits / 8) as usize;
                    remote_addr_mask[..full_bytes].fill(0xFF);
                    let rem = bits % 8;
                    if full_bytes < 16 && rem > 0 {
                        remote_addr_mask[full_bytes] = !0u8 << (8 - rem);
                    }
                }
                Err(_) => {
                    return Err(ServiceError::Validation(format!(
                        "Invalid remote address: {}",
                        addr_str
                    )));
                }
            }
        }

        // Convert protocol to IPPROTO values
        let protocol = rule.protocol.map(|p| match p {
            Protocol::Tcp => 6,   // IPPROTO_TCP
            Protocol::Udp => 17,  // IPPROTO_UDP
            Protocol::Icmp => 1,  // IPPROTO_ICMP
            Protocol::Icmpv6 => 58, // IPPROTO_ICMPV6
            Protocol::Any => 0,
        }).unwrap_or(0);

        // 端口条件：任意 → (0,0)；单端口 p → (p,p)；区间 → (start,end)。
        // 驱动侧 rules.c 按 start==0 && end==0 视为通配，否则 start<=port<=end。
        fn port_bounds(range: Option<&PortRange>) -> (u16, u16) {
            match range {
                None => (0, 0),
                Some(PortRange::Single(p)) => (*p, *p),
                Some(PortRange::Range(start, end)) => (*start, *end),
            }
        }
        let (remote_port, remote_port_end) = port_bounds(rule.remote_port.as_ref());
        let (local_port, local_port_end) = port_bounds(rule.local_port.as_ref());

        Ok(DriverRuleInput {
            rule_id: rule.id.unwrap_or(0),
            priority: rule.priority,
            enabled: if rule.enabled { 1 } else { 0 },
            is_allow: if rule.action == RuleAction::Allow { 1 } else { 0 },
            _padding1: 0,
            process_id: rule.process_id.unwrap_or(0),
            process_path,
            protocol,
            remote_addr,
            remote_addr_mask,
            address_family,
            remote_port,
            remote_port_end,
            local_port,
            local_port_end,
            direction: match rule.direction {
                Direction::Both => 0,
                Direction::Inbound => 1,
                Direction::Outbound => 2,
            },
        })
    }

    /// Convert to raw bytes for sending to driver
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

// Wire contract with driver/inc/types.h RULE_INPUT.
const _: () = assert!(
    std::mem::size_of::<DriverRuleInput>() == 588,
    "DriverRuleInput must be exactly 588 bytes (C RULE_INPUT)"
);
const _: () = assert!(std::mem::offset_of!(DriverRuleInput, process_path) == 16);
const _: () = assert!(std::mem::offset_of!(DriverRuleInput, remote_addr) == 540);
const _: () = assert!(std::mem::offset_of!(DriverRuleInput, remote_addr_mask) == 556);
const _: () = assert!(std::mem::offset_of!(DriverRuleInput, address_family) == 572);
const _: () = assert!(std::mem::offset_of!(DriverRuleInput, direction) == 580);
const _: () = assert!(std::mem::offset_of!(DriverRuleInput, remote_port_end) == 584);
const _: () = assert!(std::mem::offset_of!(DriverRuleInput, local_port_end) == 586);

// Keep old DriverRule for backward compatibility (not used for driver communication)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriverRule {
    pub id: u32,
    pub priority: u32,
    pub action: u32,
    pub direction: u32,
    pub protocol: Option<u32>,
    pub process_id: Option<u32>,
    pub process_path: Option<String>,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub local_port: Option<u16>,
}

/// Driver event structure matching C NETWORK_EVENT
/// Must match the layout in driver/inc/types.h
/// C 侧 NETWORK_EVENT 用 #pragma pack(push, 1) 打包，总长精确 606 字节；
/// Rust 侧必须用 packed 镜像同一语义。repr(C, packed) 不改变任何偏移，
/// 字段偏移由下方 offset 断言锁定（与本文件历史注释一致：任何漂移在
/// 编译期失败，而不是静默丢弃每一条事件）。
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DriverEvent {
    pub timestamp: u64,            // 8 bytes, offset 0
    pub process_id: u32,           // 4 bytes, offset 8
    pub event_type: u32,           // 4 bytes, offset 12 (0=连接事件/legacy，1=TCP flow 关闭字节上报)
    pub process_path: [u16; 260],  // 520 bytes (260 * 2), offset 16
    pub protocol: u32,             // 4 bytes, offset 536
    pub local_addr: [u8; 16],      // 16 bytes, offset 540（双栈形态见 converter 顶部注释）
    pub remote_addr: [u8; 16],     // 16 bytes, offset 556
    pub local_port: u16,           // 2 bytes, offset 572
    pub remote_port: u16,          // 2 bytes, offset 574
    pub allowed: u8,               // 1 byte, offset 576 (BOOLEAN)
    pub _padding3: [u8; 1],        // 1 byte, offset 577
    pub matched_rule_id: u32,      // 4 bytes, offset 578
    pub bytes_sent: u64,           // 8 bytes, offset 582
    pub bytes_received: u64,       // 8 bytes, offset 590
    pub address_family: u32,       // 4 bytes, offset 598 (CF_ADDR_FAMILY_*)
    pub direction: u32,            // 4 bytes, offset 602 (0=legacy/unknown,1=In,2=Out)
}                                  // Total: 606 bytes

// Wire contract with driver/inc/types.h NETWORK_EVENT (pack(1), 606 bytes).
// Any drift here fails the build instead of silently dropping every event.
pub const EVENT_TYPE_CONNECTION: u32 = 0;
pub const EVENT_TYPE_TCP_FLOW_CLOSE: u32 = 1;

const _: () = assert!(
    std::mem::size_of::<DriverEvent>() == 606,
    "DriverEvent must be exactly 606 bytes (C NETWORK_EVENT is pack(1)/606)"
);
const _: () = assert!(std::mem::offset_of!(DriverEvent, event_type) == 12);
const _: () = assert!(std::mem::offset_of!(DriverEvent, local_addr) == 540);
const _: () = assert!(std::mem::offset_of!(DriverEvent, remote_addr) == 556);
const _: () = assert!(std::mem::offset_of!(DriverEvent, local_port) == 572);
const _: () = assert!(std::mem::offset_of!(DriverEvent, bytes_sent) == 582);
const _: () = assert!(std::mem::offset_of!(DriverEvent, bytes_received) == 590);
const _: () = assert!(std::mem::offset_of!(DriverEvent, address_family) == 598);
const _: () = assert!(std::mem::offset_of!(DriverEvent, direction) == 602);

impl DriverRule {
    pub fn from_rule(rule: &Rule) -> Result<Self> {
        Ok(DriverRule {
            id: rule.id.unwrap_or(0),
            priority: rule.priority,
            action: match rule.action {
                RuleAction::Allow => 1,
                RuleAction::Block => 2,
            },
            direction: match rule.direction {
                Direction::Inbound => 1,
                Direction::Outbound => 2,
                Direction::Both => 3,
            },
            protocol: rule.protocol.map(|p| match p {
                Protocol::Tcp => 1,
                Protocol::Udp => 2,
                Protocol::Icmp => 3,
                Protocol::Icmpv6 => 4,
                Protocol::Any => 0,
            }),
            process_id: rule.process_id,
            process_path: rule.process_path.clone(),
            remote_addr: rule.remote_addr.clone(),
            remote_port: rule.remote_port.as_ref().map(|p| match p {
                PortRange::Single(port) => *port,
                PortRange::Range(start, _) => *start,
            }),
            local_port: rule.local_port.as_ref().map(|p| match p {
                PortRange::Single(port) => *port,
                PortRange::Range(start, _) => *start,
            }),
        })
    }
}

pub fn rule_to_driver_input(rule: &Rule) -> Result<DriverRuleInput> {
    DriverRuleInput::from_rule(rule)
}

/// 把双栈地址字节数组按 V4 形态格式化（首 4 字节 = 主机序 u32 的 LE 表示）
fn format_v4_bytes(buf: &[u8; 16]) -> String {
    let v = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xFF,
        (v >> 16) & 0xFF,
        (v >> 8) & 0xFF,
        v & 0xFF
    )
}

impl DriverEvent {
    /// Convert driver event to service NetworkEvent
    pub fn to_network_event(&self) -> Result<NetworkEvent> {
        // Convert WCHAR array to String (copy out of the packed struct first —
        // references directly into packed fields are unaligned and rejected by rustc)
        let raw_process_path = {
            let path_buf = self.process_path;
            self.wchar_to_string(&path_buf)
        };
        
        // Log the raw path for debugging
        if let Some(ref raw_path) = raw_process_path {
            tracing::trace!("Raw process path from driver: {}", raw_path);
        }
        
        // Convert NT path to DOS path (e.g., \Device\HarddiskVolume3\... -> C:\...)
        let process_path = raw_process_path.as_ref().and_then(|p| Self::convert_nt_path_to_dos(p));
        
        // Log the converted path
        if let Some(ref converted_path) = process_path {
            if let Some(ref raw_path) = raw_process_path {
                if converted_path != raw_path {
                    tracing::debug!("Converted path: {} -> {}", raw_path, converted_path);
                }
            }
        }
        
        let process_name = process_path
            .as_ref()
            .and_then(|p| std::path::Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());

        // Convert IP addresses (dual-stack). packed 结构的字段引用可能不对齐，
        // 先整体拷出再解析。
        // family = 4（或 0 = legacy）：首 4 字节是"主机序 u32"的 LE 表示。
        // WFP ALE fixed values hand the driver IPv4 addresses in HOST byte
        // order already (verified on a live system: 192.168.79.16 arrived as
        // a plain little-endian u32), so no byte reversal here.
        // family = 6：16 字节网络序，直接 Ipv6Addr::from。
        let local_addr_buf = self.local_addr;
        let remote_addr_buf = self.remote_addr;
        let (local_addr, remote_addr) = if self.address_family == CF_ADDR_FAMILY_V6 {
            (
                Ipv6Addr::from(local_addr_buf).to_string(),
                Ipv6Addr::from(remote_addr_buf).to_string(),
            )
        } else {
            (format_v4_bytes(&local_addr_buf), format_v4_bytes(&remote_addr_buf))
        };

        // Convert protocol
        let protocol = match self.protocol {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            58 => Protocol::Icmpv6,
            _ => Protocol::Any,
        };

        // Action：普通 ALE 连接事件按 allowed 转换；TCP flow 关闭报数（新驱动）
        // 统一转成 Close——它不代表新的授权决策，只携带连接终结时的字节总量，
        // processor 据此做连接收尾与差值落库。
        let action = match self.event_type {
            EVENT_TYPE_TCP_FLOW_CLOSE => EventAction::Close,
            _ => {
                if self.allowed != 0 {
                    EventAction::Allow
                } else {
                    EventAction::Block
                }
            }
        };

        // Direction: the driver stamps inbound (ALE_AUTH_RECV_ACCEPT) events
        // with 1 and outbound (ALE_AUTH_CONNECT) events with 2; 0 (legacy
        // drivers) is treated as outbound, the previously observed behavior.
        let direction = match self.direction {
            1 => Direction::Inbound,
            _ => Direction::Outbound,
        };

        // WFP ALE fixed values are already host byte order (verified live:
        // a connect to port 8001 arrived as 0x1F41 raw), so no swap.
        let local_port = self.local_port;
        let remote_port = self.remote_port;

        Ok(NetworkEvent {
            timestamp: chrono::Utc::now(),
            action,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            protocol,
            direction,
            process_id: Some(self.process_id),
            process_name,
            process_path,
            bytes_sent: if self.bytes_sent > 0 { Some(self.bytes_sent) } else { None },
            bytes_received: if self.bytes_received > 0 { Some(self.bytes_received) } else { None },
            packets_sent: None,
            packets_received: None,
            rule_id: if self.matched_rule_id != 0 {
                Some(self.matched_rule_id)
            } else {
                None
            },
        })
    }

    /// Convert WCHAR array to Rust String
    fn wchar_to_string(&self, wchars: &[u16]) -> Option<String> {
        // Find null terminator
        let len = wchars.iter().position(|&c| c == 0).unwrap_or(wchars.len());
        if len == 0 {
            return None;
        }

        // Convert UTF-16 to String
        String::from_utf16(&wchars[..len]).ok()
    }

    /// Convert NT device path to DOS path
    /// e.g., \Device\HarddiskVolume3\Program Files\... -> C:\Program Files\...
    fn convert_nt_path_to_dos(nt_path: &str) -> Option<String> {
        convert_nt_path_to_dos(nt_path)
    }

    /// Deserialize from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected_size = std::mem::size_of::<DriverEvent>();
        
        // Log structure layout info once
        static LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::info!(
                "DriverEvent layout: size={}, align={}, event_type@12, bytes_sent@582, bytes_received@590",
                std::mem::size_of::<DriverEvent>(),
                std::mem::align_of::<DriverEvent>()
            );
        }
        
        tracing::debug!(
            "Deserializing DriverEvent: buffer size = {}, expected size = {}",
            bytes.len(),
            expected_size
        );

        if bytes.len() < expected_size {
            return Err(ServiceError::Driver(format!(
                "Buffer too small: expected {}, got {}",
                expected_size,
                bytes.len()
            )));
        }

        // Safety: buffer length checked above; read_unaligned because the
        // byte buffer only guarantees 1-byte alignment while DriverEvent
        // requires 8-byte alignment.
        unsafe {
            let event_ptr = bytes.as_ptr() as *const DriverEvent;
            let event = event_ptr.read_unaligned();
            
            // Debug: print raw bytes at key offsets for events with traffic.
            // 跳过 Close 事件（EventType=1）：那是连接生命周期字节总量，5MB+
            // 完全合法（阈值是按 EStats 5 秒单次采样的量级定的），不适用于它。
            let (bytes_sent, bytes_received) = (event.bytes_sent, event.bytes_received);
            if event.event_type != EVENT_TYPE_TCP_FLOW_CLOSE
                && (bytes_sent > 1000000 || bytes_received > 1000000)
            {
                tracing::warn!(
                    "Suspicious large bytes detected! bytes_sent={}, bytes_received={}",
                    bytes_sent, bytes_received
                );
                tracing::warn!(
                    "Raw bytes at offset 582-589 (bytes_sent): {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                    bytes[582], bytes[583], bytes[584], bytes[585], bytes[586], bytes[587], bytes[588], bytes[589]
                );
                tracing::warn!(
                    "Raw bytes at offset 590-597 (bytes_received): {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                    bytes[590], bytes[591], bytes[592], bytes[593], bytes[594], bytes[595], bytes[596], bytes[597]
                );
            }
            
            let (pid, proto, laddr, lport, raddr, rport, allowed, family) = (
                event.process_id,
                event.protocol,
                event.local_addr,
                event.local_port,
                event.remote_addr,
                event.remote_port,
                event.allowed,
                event.address_family,
            );
            tracing::debug!(
                "Deserialized event: pid={}, protocol={}, family={}, local={:?}:({}, remote={:?}:{}), allowed={}, bytes_sent={}, bytes_received={}",
                pid,
                proto,
                family,
                laddr,
                lport,
                raddr,
                rport,
                allowed,
                bytes_sent,
                bytes_received
            );
            
            Ok(event)
        }
    }
}

/// Driver DNS event matching C DNS_EVENT (driver/inc/types.h).
/// C 侧为自然对齐（无 pack）：u64/u32/[u8;16]/u32/u16/[u8;512]，总大小
/// 552 字节（含尾部对齐垫到 8），与下方 repr(C) 布局逐字段一致。
/// RemoteAddr 为双栈形态（family=4 时首 4 字节 = 主机序 u32 的 LE 表示，
/// family=6 时 16 字节网络序），AddressFamily 区分。
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DriverDnsEvent {
    pub timestamp: u64,       // UINT64 Timestamp - offset 0
    pub process_id: u32,      // UINT32 ProcessId - offset 8
    pub remote_addr: [u8; 16],// BYTE RemoteAddr[16] - offset 12
    pub address_family: u32,  // UINT32 AddressFamily - offset 28
    pub data_length: u16,     // UINT16 DataLength - offset 32
    pub data: [u8; 512],      // BYTE Data[512] - offset 34
}

impl DriverDnsEvent {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected_size = std::mem::size_of::<DriverDnsEvent>();
        if bytes.len() < expected_size {
            return Err(ServiceError::Driver(format!(
                "DNS event buffer too small: {} < {}",
                expected_size,
                bytes.len()
            )));
        }

        let timestamp = u64::from_ne_bytes(bytes[0..8].try_into().expect("fixed-size slice, length checked above"));
        let process_id = u32::from_ne_bytes(bytes[8..12].try_into().expect("fixed-size slice, length checked above"));
        let mut remote_addr = [0u8; 16];
        remote_addr.copy_from_slice(&bytes[12..28]);
        let address_family = u32::from_ne_bytes(bytes[28..32].try_into().expect("fixed-size slice, length checked above"));
        let data_length = u16::from_ne_bytes(bytes[32..34].try_into().expect("fixed-size slice, length checked above"));
        let mut data = [0u8; 512];
        let copy_len = (data_length as usize).min(512);
        data[..copy_len].copy_from_slice(&bytes[34..34 + copy_len]);

        Ok(DriverDnsEvent {
            timestamp,
            process_id,
            remote_addr,
            address_family,
            data_length,
            data,
        })
    }
}

/// Convert a DOS drive path (C:ooar.exe) to its NT device form
/// (\Device\HarddiskVolumeXooar.exe) via QueryDosDeviceW.
/// Returns None when the path has no drive-letter prefix or the query fails.
#[cfg(target_os = "windows")]
fn convert_dos_path_to_nt(dos_path: &str) -> Option<String> {
    let bytes = dos_path.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        // 已经是 NT 路径或不是盘符路径，无需转换
        return Some(dos_path.to_string());
    }

    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    let drive_wide: Vec<u16> = dos_path[..2].encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = vec![0u16; 1024];
    let result = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buffer)) };
    if result == 0 {
        return None;
    }
    let end = buffer.iter().position(|&c| c == 0)?;
    let device = String::from_utf16(&buffer[..end]).ok()?;
    let rest = dos_path.get(2..)?;
    Some(format!("{}{}", device, rest))
}

#[cfg(not(target_os = "windows"))]
fn convert_dos_path_to_nt(dos_path: &str) -> Option<String> {
    Some(dos_path.to_string())
}

/// Convert NT device path to DOS path (\Device\HarddiskVolume3\... -> C:\...).
/// 公共入口：事件转换与通知侧共用。Windows 路径大小写不敏感，驱动上报的
/// NT 路径可能是 `\device\harddiskvolume3\...` 小写形态，前缀与设备名
/// 匹配必须忽略大小写，否则会把 NT 路径原样透传给上层显示。
pub fn convert_nt_path_to_dos(nt_path: &str) -> Option<String> {
    // Check if it's already a DOS path
    if nt_path.len() >= 2 && nt_path.chars().nth(1) == Some(':') {
        return Some(nt_path.to_string());
    }

    let lower = nt_path.to_ascii_lowercase();
    if !lower.starts_with("\\device\\") && !lower.starts_with("\\??\\") {
        return Some(nt_path.to_string());
    }

    // Try to use QueryDosDevice API to find the correct mapping
    #[cfg(target_os = "windows")]
    {
        if let Some(dos_path) = query_dos_device_path(nt_path) {
            return Some(dos_path);
        }
    }

    // Fallback: Try to extract volume number and guess the drive letter
    // This is less reliable but better than showing the NT path
    if let Some(volume_num) = extract_volume_number(&lower) {
        // Volume 1 and 3 are often C: (system volume)
        // Volume 2 and 4 are often D: (data volume)
        let drive_letter = match volume_num {
            1 | 3 => 'C',
            2 | 4 => 'D',
            5 => 'E',
            6 => 'F',
            _ => {
                // For higher volumes, just guess based on offset
                ((volume_num - 1) as u8 + b'C') as char
            }
        };

        let prefix = format!("\\device\\harddiskvolume{}", volume_num);
        if let Some(remaining) = lower.strip_prefix(&prefix) {
            let dos_path = format!("{}:{}", drive_letter, remaining);
            tracing::warn!(
                "Using fallback mapping for NT path '{}' -> '{}' (volume {} -> {}:)",
                nt_path, dos_path, volume_num, drive_letter
            );
            return Some(dos_path);
        }
    }

    // Last resort: return original path
    tracing::warn!("Could not convert NT path to DOS path: {}", nt_path);
    Some(nt_path.to_string())
}

/// Extract volume number from a lowercased NT path
/// e.g., \device\harddiskvolume3\... -> Some(3)
fn extract_volume_number(lower_nt_path: &str) -> Option<u32> {
    let rest = lower_nt_path.strip_prefix("\\device\\harddiskvolume")?;
    // Find the next backslash
    if let Some(pos) = rest.find('\\') {
        rest[..pos].parse::<u32>().ok()
    } else {
        rest.parse::<u32>().ok()
    }
}

/// Query DOS device path using Windows API
#[cfg(target_os = "windows")]
fn query_dos_device_path(nt_path: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{QueryDosDeviceW, GetLogicalDrives};

    // Get all available logical drives
    let drives_mask = unsafe { GetLogicalDrives() };

    // Try each drive letter
    for i in 0..26 {
        if (drives_mask & (1 << i)) == 0 {
            continue; // Drive doesn't exist
        }

        let drive_letter = (b'A' + i) as char;
        let drive = format!("{}:", drive_letter);
        let mut buffer = vec![0u16; 1024];

        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let result = QueryDosDeviceW(
                PCWSTR(drive_wide.as_ptr()),
                Some(&mut buffer),
            );

            if result > 0 {
                // QueryDosDeviceW can return multiple null-terminated strings
                // We need to parse them all
                let mut offset = 0;
                while offset < result as usize {
                    // Find the next null terminator
                    let end = buffer[offset..].iter()
                        .position(|&c| c == 0)
                        .map(|p| offset + p)
                        .unwrap_or(buffer.len());

                    if end > offset {
                        if let Ok(device_path) = String::from_utf16(&buffer[offset..end]) {
                            // Case-insensitive: the driver may report the NT
                            // path in lowercase while QueryDosDeviceW returns
                            // canonical \Device\HarddiskVolumeX casing.
                            let head_matches = nt_path
                                .get(..device_path.len())
                                .map(|head| head.eq_ignore_ascii_case(&device_path))
                                .unwrap_or(false);
                            if head_matches
                            {
                                let remaining = &nt_path[device_path.len()..];
                                let dos_path = format!("{}{}", drive, remaining);
                                tracing::debug!(
                                    "Successfully converted NT path '{}' to DOS path '{}' via device '{}'",
                                    nt_path, dos_path, device_path
                                );
                                return Some(dos_path);
                            }
                        }
                    }

                    offset = end + 1;
                    if offset >= result as usize {
                        break;
                    }
                }
            }
        }
    }

    tracing::debug!("QueryDosDeviceW failed to find mapping for NT path: {}", nt_path);
    None
}

#[cfg(test)]
mod tests {
    use super::convert_nt_path_to_dos;
    use super::*;
    use crate::models::{Rule, RuleAction};

    fn base_rule() -> Rule {
        Rule {
            id: Some(7),
            name: "t".into(),
            description: String::new(),
            enabled: true,
            priority: 100,
            action: RuleAction::Block,
            direction: Direction::Both,
            protocol: None,
            process_id: None,
            process_path: None,
            remote_addr: None,
            remote_addr_mask: None,
            remote_domain: None,
            remote_port: None,
            local_addr: None,
            local_addr_mask: None,
            local_port: None,
            network_zone: None,
            app_group_id: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn port_bounds_single() {
        let mut rule = base_rule();
        rule.remote_port = Some(PortRange::Single(53));
        let input = DriverRuleInput::from_rule(&rule).unwrap();
        assert_eq!(input.remote_port, 53);
        assert_eq!(input.remote_port_end, 53);
    }

    #[test]
    fn port_bounds_range() {
        let mut rule = base_rule();
        rule.local_port = Some(PortRange::Range(1000, 2000));
        let input = DriverRuleInput::from_rule(&rule).unwrap();
        assert_eq!(input.local_port, 1000);
        assert_eq!(input.local_port_end, 2000);
    }

    #[test]
    fn port_bounds_any() {
        let rule = base_rule();
        let input = DriverRuleInput::from_rule(&rule).unwrap();
        assert_eq!(input.remote_port, 0);
        assert_eq!(input.remote_port_end, 0);
        assert_eq!(input.local_port, 0);
        assert_eq!(input.local_port_end, 0);
    }

    #[test]
    fn dos_path_passthrough() {
        assert_eq!(
            convert_nt_path_to_dos(r"C:\Windows\System32\svchost.exe").as_deref(),
            Some(r"C:\Windows\System32\svchost.exe")
        );
    }

    #[test]
    fn lowercase_nt_prefix_still_converted() {
        // 驱动可能上报小写 NT 路径；此前大小写敏感匹配会原样透传。
        // QueryDosDeviceW 在真实卷上命中；测试机至少不能把 NT 形态当 DOS 直接返回。
        let out = convert_nt_path_to_dos(
            r"\device\harddiskvolume3\windows\system32\svchost.exe",
        )
        .expect("conversion must produce a path");
        assert!(
            out.contains(':'),
            "expected a DOS drive-letter path, got: {}",
            out
        );
    }
}
