//! Connection Statistics Collector - collects traffic stats from Windows API

use super::super::error::{Result, ServiceError};
use super::super::models::*;
use std::mem;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub process_id: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub struct StatsCollector;

/// 16 字节网络序地址 → 标准压缩写法（::1、fe80::…）
fn format_ipv6(bytes: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    let mut segs = [0u16; 8];
    for (i, seg) in segs.iter_mut().enumerate() {
        *seg = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }
    Ipv6Addr::new(
        segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
    ).to_string()
}

impl StatsCollector {
    pub fn new() -> Self {
        StatsCollector
    }

    /// Collect TCP connection statistics
    pub fn collect_tcp_stats(&self) -> Result<Vec<ConnectionStats>> {
        let mut stats = Vec::new();

        unsafe {
            // Get required buffer size
            let mut size: u32 = 0;
            GetTcpTable2(None, &mut size, false);

            // Allocate buffer
            let mut buffer = vec![0u8; size as usize];
            let table = buffer.as_mut_ptr() as *mut MIB_TCPTABLE2;

            // Get TCP table
            let result = GetTcpTable2(Some(table), &mut size, false);
            if result != 0 {
                return Err(ServiceError::Service(format!(
                    "GetTcpTable2 failed with error: {}",
                    result
                )));
            }

            let table_ref = &*table;
            let num_entries = table_ref.dwNumEntries as usize;

            // Parse entries using pointer arithmetic
            // The table field is declared as [1] but actually contains num_entries
            let entries_ptr = table_ref.table.as_ptr();

            for i in 0..num_entries {
                let entry = &*entries_ptr.add(i);

                // Convert addresses from network byte order
                let local_addr = format!(
                    "{}.{}.{}.{}",
                    entry.dwLocalAddr & 0xFF,
                    (entry.dwLocalAddr >> 8) & 0xFF,
                    (entry.dwLocalAddr >> 16) & 0xFF,
                    (entry.dwLocalAddr >> 24) & 0xFF
                );

                let remote_addr = format!(
                    "{}.{}.{}.{}",
                    entry.dwRemoteAddr & 0xFF,
                    (entry.dwRemoteAddr >> 8) & 0xFF,
                    (entry.dwRemoteAddr >> 16) & 0xFF,
                    (entry.dwRemoteAddr >> 24) & 0xFF
                );

                let local_port = u16::from_be(entry.dwLocalPort as u16);
                let remote_port = u16::from_be(entry.dwRemotePort as u16);

                // Only include established connections
                if entry.dwState == MIB_TCP_STATE_ESTAB.0 as u32 {
                    stats.push(ConnectionStats {
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        protocol: Protocol::Tcp,
                        process_id: entry.dwOwningPid,
                        bytes_sent: 0,      // TCP table doesn't provide byte counts
                        bytes_received: 0,  // We'll get these from GetPerTcpConnectionEStats
                    });
                }
            }
        }

        // IPv6 同构分支（GetTcp6Table2）。降级：v6 拉表失败只告警不返回 Err，
        // 不能拖垮已收集的 v4 统计。
        unsafe {
            let mut size: u32 = 0;
            GetTcp6Table2(std::ptr::null_mut(), &mut size, false);
            if size == 0 {
                tracing::debug!("GetTcp6Table2 size query returned 0 (no v6 TCP table)");
                return Ok(stats);
            }
            let mut buffer = vec![0u8; size as usize];
            let table = buffer.as_mut_ptr() as *mut MIB_TCP6TABLE2;
            let result = GetTcp6Table2(table, &mut size, false);
            if result != 0 {
                tracing::warn!("GetTcp6Table2 failed with error: {} (IPv6 stats degraded)", result);
                return Ok(stats);
            }

            let table_ref = &*table;
            let entries_ptr = table_ref.table.as_ptr();
            for i in 0..table_ref.dwNumEntries as usize {
                let entry = &*entries_ptr.add(i);
                if entry.State != MIB_TCP_STATE_ESTAB {
                    continue;
                }
                let local_bytes: [u8; 16] = entry.LocalAddr.u.Byte;
                let remote_bytes: [u8; 16] = entry.RemoteAddr.u.Byte;
                stats.push(ConnectionStats {
                    local_addr: format_ipv6(&local_bytes),
                    local_port: u16::from_be(entry.dwLocalPort as u16),
                    remote_addr: format_ipv6(&remote_bytes),
                    remote_port: u16::from_be(entry.dwRemotePort as u16),
                    protocol: Protocol::Tcp,
                    process_id: entry.dwOwningPid,
                    bytes_sent: 0,
                    bytes_received: 0,
                });
            }
        }

        Ok(stats)
    }

    /// Collect UDP connection statistics
    pub fn collect_udp_stats(&self) -> Result<Vec<ConnectionStats>> {
        let mut stats = Vec::new();

        unsafe {
            // Get required buffer size
            let mut size: u32 = 0;
            GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            // Allocate buffer
            let mut buffer = vec![0u8; size as usize];
            let table = buffer.as_mut_ptr() as *mut MIB_UDPTABLE_OWNER_PID;

            // Get UDP table
            let result = GetExtendedUdpTable(
                Some(table as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != 0 {
                return Err(ServiceError::Service(format!(
                    "GetExtendedUdpTable failed with error: {}",
                    result
                )));
            }

            let table_ref = &*table;
            let num_entries = table_ref.dwNumEntries as usize;

            // Parse entries using pointer arithmetic
            let entries_ptr = table_ref.table.as_ptr();

            for i in 0..num_entries {
                let entry = &*entries_ptr.add(i);

                let local_addr = format!(
                    "{}.{}.{}.{}",
                    entry.dwLocalAddr & 0xFF,
                    (entry.dwLocalAddr >> 8) & 0xFF,
                    (entry.dwLocalAddr >> 16) & 0xFF,
                    (entry.dwLocalAddr >> 24) & 0xFF
                );

                let local_port = u16::from_be(entry.dwLocalPort as u16);

                stats.push(ConnectionStats {
                    local_addr,
                    local_port,
                    remote_addr: "0.0.0.0".to_string(), // UDP is connectionless
                    remote_port: 0,
                    protocol: Protocol::Udp,
                    process_id: entry.dwOwningPid,
                    bytes_sent: 0,
                    bytes_received: 0,
                });
            }
        }

        // IPv6 同构分支（GetExtendedUdpTable AF_INET6）。降级：v6 失败只
        // 告警，保住已收集的 v4 结果。
        unsafe {
            let mut size: u32 = 0;
            GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if size == 0 {
                tracing::debug!("GetExtendedUdpTable(AF_INET6) size query returned 0");
                return Ok(stats);
            }
            let mut buffer = vec![0u8; size as usize];
            let table = buffer.as_mut_ptr() as *mut MIB_UDP6TABLE_OWNER_PID;
            let result = GetExtendedUdpTable(
                Some(table as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if result != 0 {
                tracing::warn!("GetExtendedUdpTable(AF_INET6) failed with error: {} (IPv6 stats degraded)", result);
                return Ok(stats);
            }

            let table_ref = &*table;
            let entries_ptr = table_ref.table.as_ptr();
            for i in 0..table_ref.dwNumEntries as usize {
                let entry = &*entries_ptr.add(i);
                let local_bytes: [u8; 16] = entry.ucLocalAddr;
                stats.push(ConnectionStats {
                    local_addr: format_ipv6(&local_bytes),
                    local_port: u16::from_be(entry.dwLocalPort as u16),
                    remote_addr: "::".to_string(), // UDP is connectionless
                    remote_port: 0,
                    protocol: Protocol::Udp,
                    process_id: entry.dwOwningPid,
                    bytes_sent: 0,
                    bytes_received: 0,
                });
            }
        }

        Ok(stats)
    }

    /// Get detailed TCP connection statistics including byte counts
    /// （按地址形态自动分派 v4/v6 EStats 路径）
    pub fn get_tcp_connection_stats(
        &self,
        local_addr: &str,
        local_port: u16,
        remote_addr: &str,
        remote_port: u16,
    ) -> Result<(u64, u64)> {
        if local_addr.contains(':') {
            self.get_tcp6_connection_stats(local_addr, local_port, remote_addr, remote_port)
        } else {
            self.get_tcp4_connection_stats(local_addr, local_port, remote_addr, remote_port)
        }
    }

    /// IPv4 EStats（原实现）
    fn get_tcp4_connection_stats(
        &self,
        local_addr: &str,
        local_port: u16,
        remote_addr: &str,
        remote_port: u16,
    ) -> Result<(u64, u64)> {
        unsafe {
            // Parse IP addresses
            let local_ip = Self::parse_ipv4(local_addr)?;
            let remote_ip = Self::parse_ipv4(remote_addr)?;

            // Create TCP row
            // 端口是 htons 语义：字节交换后的 16 位值零扩展到 u32，
            // 网络序端口落在低 16 位。(port as u32).to_be() 会把它放到
            // 高 16 位，行永远匹配不到连接，EStats 一直返回空
            let row = MIB_TCPROW_OWNER_PID {
                dwState: MIB_TCP_STATE_ESTAB.0 as u32,
                dwLocalAddr: local_ip,
                dwLocalPort: u32::from(local_port.to_be()),
                dwRemoteAddr: remote_ip,
                dwRemotePort: u32::from(remote_port.to_be()),
                dwOwningPid: 0,
            };

            // First, enable statistics collection for this connection
            let mut rw: TCP_ESTATS_DATA_RW_v0 = mem::zeroed();
            rw.EnableCollection = windows::Win32::Foundation::BOOLEAN(1); // TRUE
            
            let rw_size = mem::size_of::<TCP_ESTATS_DATA_RW_v0>() as u32;
            let mut rw_bytes = vec![0u8; rw_size as usize];
            std::ptr::copy_nonoverlapping(
                &rw as *const _ as *const u8,
                rw_bytes.as_mut_ptr(),
                rw_size as usize,
            );
            
            // 启用采集必须走 Set：Get 的 Rw 参数是输出缓冲，
            // 之前误用 Get 传预填值，EnableCollection 从未生效，字节数恒 0
            // (Set 失败容忍：连接可能刚断开)
            let _ = SetPerTcpConnectionEStats(
                &row as *const _ as *const _,
                TcpConnectionEstatsData,
                &rw_bytes,
                0,
                0,
            );

            // 读取字节数：Rw 槽传 1 字节输出缓冲（读回 EnableCollection），
            // Ros 槽对 Data 类型没有静态信息，必须 NULL/0，
            // Rod 槽传 TCP_ESTATS_DATA_ROD_v0（16 字节）。
            // 之前把 1 字节 rw 缓冲错放进 Ros 槽、Rod 传 NULL，
            // 触发 ERROR_INVALID_USER_BUFFER(1784)，字节数恒 0
            let rod_size = mem::size_of::<TCP_ESTATS_DATA_ROD_v0>();
            let mut rod_bytes = vec![0u8; rod_size];
            let mut rw_out = [0u8; 1];

            let result = GetPerTcpConnectionEStats(
                &row as *const _ as *const _,
                TcpConnectionEstatsData,
                Some(&mut rw_out),
                0,
                None,
                0,
                Some(rod_bytes.as_mut_slice()),
                0,
            );

            if result == 0 && rw_out[0] != 0 {
                let rod: TCP_ESTATS_DATA_ROD_v0 =
                    std::ptr::read(rod_bytes.as_ptr() as *const _);
                Ok((rod.DataBytesOut, rod.DataBytesIn))
            } else {
                // If we can't get detailed stats, return 0
                // This is normal for many connections
                Ok((0, 0))
            }
        }
    }

    /// Parse IPv4 address string to u32
    fn parse_ipv4(addr: &str) -> Result<u32> {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() != 4 {
            return Err(ServiceError::Service(format!("Invalid IPv4 address: {}", addr)));
        }

        let mut result: u32 = 0;
        for (i, part) in parts.iter().enumerate() {
            let byte: u8 = part.parse().map_err(|_| {
                ServiceError::Service(format!("Invalid IPv4 address: {}", addr))
            })?;
            result |= (byte as u32) << (i * 8);
        }

        Ok(result)
    }

    /// IPv6 EStats：与 v4 路径同构（Set 开采集 → Get 读 Rod），行结构换成
    /// MIB_TCP6ROW、API 换成 *PerTcp6ConnectionEStats。任何失败都返回 (0,0)
    /// 而非 Err（与 v4 的"连接可能刚断开"口径一致）。
    fn get_tcp6_connection_stats(
        &self,
        local_addr: &str,
        local_port: u16,
        remote_addr: &str,
        remote_port: u16,
    ) -> Result<(u64, u64)> {
        use std::str::FromStr;

        let local_ip = std::net::Ipv6Addr::from_str(local_addr)
            .map_err(|_| ServiceError::Service(format!("Invalid IPv6 address: {}", local_addr)))?;
        let remote_ip = std::net::Ipv6Addr::from_str(remote_addr)
            .map_err(|_| ServiceError::Service(format!("Invalid IPv6 address: {}", remote_addr)))?;

        unsafe {
            let local_in6 = IN6_ADDR { u: IN6_ADDR_0 { Byte: local_ip.octets() } };
            let remote_in6 = IN6_ADDR { u: IN6_ADDR_0 { Byte: remote_ip.octets() } };
            // 端口与 v4 同口径：网络序 16 位值零扩展到 DWORD 低 16 位
            let row = MIB_TCP6ROW {
                State: MIB_TCP_STATE_ESTAB,
                LocalAddr: local_in6,
                dwLocalScopeId: 0,
                dwLocalPort: u32::from(local_port.to_be()),
                RemoteAddr: remote_in6,
                dwRemoteScopeId: 0,
                dwRemotePort: u32::from(remote_port.to_be()),
            };

            let mut rw: TCP_ESTATS_DATA_RW_v0 = mem::zeroed();
            rw.EnableCollection = windows::Win32::Foundation::BOOLEAN(1);
            let rw_size = mem::size_of::<TCP_ESTATS_DATA_RW_v0>() as u32;
            let mut rw_bytes = vec![0u8; rw_size as usize];
            std::ptr::copy_nonoverlapping(
                &rw as *const _ as *const u8,
                rw_bytes.as_mut_ptr(),
                rw_size as usize,
            );
            let _ = SetPerTcp6ConnectionEStats(
                &row as *const _ as *const _,
                TcpConnectionEstatsData,
                &rw_bytes,
                0,
                0,
            );

            let rod_size = mem::size_of::<TCP_ESTATS_DATA_ROD_v0>();
            let mut rod_bytes = vec![0u8; rod_size];
            let mut rw_out = [0u8; 1];

            let result = GetPerTcp6ConnectionEStats(
                &row as *const _ as *const _,
                TcpConnectionEstatsData,
                Some(&mut rw_out),
                0,
                None,
                0,
                Some(rod_bytes.as_mut_slice()),
                0,
            );

            if result == 0 && rw_out[0] != 0 {
                let rod: TCP_ESTATS_DATA_ROD_v0 =
                    std::ptr::read(rod_bytes.as_ptr() as *const _);
                Ok((rod.DataBytesOut, rod.DataBytesIn))
            } else {
                Ok((0, 0))
            }
        }
    }

    /// Collect all connection statistics (TCP + UDP)
    pub fn collect_all_stats(&self) -> Result<Vec<ConnectionStats>> {
        let mut all_stats = Vec::new();

        // Collect TCP stats
        match self.collect_tcp_stats() {
            Ok(mut tcp_stats) => {
                tracing::trace!("Collected {} TCP connections", tcp_stats.len());
                
                // Try to get detailed byte counts for each TCP connection
                let mut stats_with_bytes = 0;
                for stat in &mut tcp_stats {
                    if let Ok((bytes_out, bytes_in)) = self.get_tcp_connection_stats(
                        &stat.local_addr,
                        stat.local_port,
                        &stat.remote_addr,
                        stat.remote_port,
                    ) {
                        if bytes_out > 0 || bytes_in > 0 {
                            stat.bytes_sent = bytes_out;
                            stat.bytes_received = bytes_in;
                            stats_with_bytes += 1;
                        }
                    }
                }
                
                if stats_with_bytes > 0 {
                    tracing::trace!("{} TCP connections have traffic data", stats_with_bytes);
                }
                
                all_stats.extend(tcp_stats);
            }
            Err(e) => {
                tracing::warn!("Failed to collect TCP stats: {}", e);
            }
        }

        // Collect UDP stats
        match self.collect_udp_stats() {
            Ok(udp_stats) => {
                tracing::trace!("Collected {} UDP connections", udp_stats.len());
                all_stats.extend(udp_stats);
            }
            Err(e) => {
                tracing::warn!("Failed to collect UDP stats: {}", e);
            }
        }

        Ok(all_stats)
    }
}
