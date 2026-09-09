//! Connection Tracker - tracks active network connections

use super::super::error::Result;
use super::super::models::*;
use super::stats_collector::StatsCollector;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use tokio::sync::RwLock;

pub struct ConnectionTracker {
    connections: Arc<RwLock<HashMap<ConnectionKey, ConnectionInfo>>>,
    blocked_count: Arc<AtomicU32>,
    allowed_count: Arc<AtomicU32>,
    suspicious_count: Arc<AtomicU32>,
    stats_collector: Arc<StatsCollector>,
    running: Arc<AtomicBool>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        ConnectionTracker {
            connections: Arc::new(RwLock::new(HashMap::new())),
            blocked_count: Arc::new(AtomicU32::new(0)),
            allowed_count: Arc::new(AtomicU32::new(0)),
            suspicious_count: Arc::new(AtomicU32::new(0)),
            stats_collector: Arc::new(StatsCollector::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the background stats collection task
    pub fn start_stats_collection(&self) {
        self.running.store(true, Ordering::SeqCst);
        
        let connections = self.connections.clone();
        let stats_collector = self.stats_collector.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            tracing::info!("Starting connection stats collection");
            
            while running.load(Ordering::SeqCst) {
                // Collect stats every 5 seconds
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                
                // GetTcpTable2/GetExtendedUdpTable/GetPerTcpConnectionEStats 是同步
                // IP Helper 调用，可能带几十毫秒延迟；丢到 blocking 线程池，
                // 避免卡住 tokio worker（IPC 卡顿/延迟尖刺）
                let collector = stats_collector.clone();
                let stats_result = tokio::task::spawn_blocking(move || collector.collect_all_stats()).await;
                match stats_result.unwrap_or_else(|e| {
                    Err(super::super::error::ServiceError::Service(format!(
                        "collect stats task join failed: {}", e
                    )))
                }) {
                    Ok(system_stats) => {
                        let mut conns = connections.write().await;
                        let mut updated_count = 0;
                        let mut total_bytes_sent = 0u64;
                        let mut total_bytes_received = 0u64;
                        
                        // Update existing connections with fresh stats
                        for sys_stat in system_stats {
                            let key = ConnectionKey {
                                local_addr: sys_stat.local_addr.clone(),
                                local_port: sys_stat.local_port,
                                remote_addr: sys_stat.remote_addr.clone(),
                                remote_port: sys_stat.remote_port,
                                protocol: sys_stat.protocol,
                            };
                            
                            if let Some(conn) = conns.get_mut(&key) {
                                // 系统统计的字节数不可用（0）时不覆盖驱动事件累计值，
                                // 否则 EStats 失败/未启用会把累计流量清零
                                if sys_stat.bytes_sent > 0 {
                                    conn.bytes_sent = sys_stat.bytes_sent;
                                }
                                if sys_stat.bytes_received > 0 {
                                    conn.bytes_received = sys_stat.bytes_received;
                                }
                                conn.last_seen = chrono::Utc::now().to_rfc3339();
                                updated_count += 1;
                                total_bytes_sent += conn.bytes_sent;
                                total_bytes_received += conn.bytes_received;
                            }
                        }
                        
                        if updated_count > 0 {
                            tracing::debug!(
                                "Updated stats for {} connections (total: {} sent, {} received)",
                                updated_count,
                                total_bytes_sent,
                                total_bytes_received
                            );
                        } else {
                            tracing::trace!("No connections to update stats for");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to collect connection stats: {}", e);
                    }
                }

                // 回收陈旧连接：Close 事件经常缺失，靠 last_seen 超时清理，防止连接表无限增长。
                // 其流量已由 network_history 的周期快照持久化，删除不影响历史统计。
                let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(300)).to_rfc3339();
                let mut conns = connections.write().await;
                let before = conns.len();
                conns.retain(|_, c| c.last_seen > cutoff);
                let removed = before - conns.len();
                drop(conns);
                if removed > 0 {
                    tracing::debug!("GC removed {} stale connections", removed);
                }
            }

            tracing::info!("Connection stats collection stopped");
        });
    }

    /// Stop the background stats collection
    pub fn stop_stats_collection(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub async fn update_connection(&self, event: &NetworkEvent) -> Result<()> {
        let key = ConnectionKey {
            local_addr: event.local_addr.clone(),
            local_port: event.local_port,
            remote_addr: event.remote_addr.clone(),
            remote_port: event.remote_port,
            protocol: event.protocol,
        };

        let mut connections = self.connections.write().await;

        match event.action {
            EventAction::Allow => {
                // Increment allowed counter
                self.allowed_count.fetch_add(1, Ordering::Relaxed);

                // 立刻对新连接启用 EStats 采集：等 5 秒轮询再启用的话，
                // 毫秒级完成的短连接（本机服务端应答、小下载）整个生命周期
                // 都在采集启用之前，字节数永远是 0。get_tcp_connection_stats
                // 内部先 Set 启用再读取，首读为 0 属预期。
                if event.protocol == Protocol::Tcp && event.direction == Direction::Outbound {
                    let collector = self.stats_collector.clone();
                    let local_addr = event.local_addr.clone();
                    let remote_addr = event.remote_addr.clone();
                    let local_port = event.local_port;
                    let remote_port = event.remote_port;
                    tokio::spawn(async move {
                        let _ = collector.get_tcp_connection_stats(
                            &local_addr,
                            local_port,
                            &remote_addr,
                            remote_port,
                        );
                    });
                }

                if let Some(conn) = connections.get_mut(&key) {
                    conn.bytes_sent = conn.bytes_sent.saturating_add(event.bytes_sent.unwrap_or(0));
                    conn.bytes_received = conn.bytes_received.saturating_add(event.bytes_received.unwrap_or(0));
                    conn.packets_sent = conn.packets_sent.saturating_add(event.packets_sent.unwrap_or(0));
                    conn.packets_received = conn.packets_received.saturating_add(event.packets_received.unwrap_or(0));
                    conn.last_seen = chrono::Utc::now().to_rfc3339();
                } else {
                    connections.insert(
                        key,
                        ConnectionInfo {
                            local_addr: event.local_addr.clone(),
                            local_port: event.local_port,
                            remote_addr: event.remote_addr.clone(),
                            remote_port: event.remote_port,
                            protocol: event.protocol,
                            process_id: event.process_id,
                            process_name: event.process_name.clone(),
                            process_path: event.process_path.clone(),
                            direction: event.direction,
                            bytes_sent: event.bytes_sent.unwrap_or(0),
                            bytes_received: event.bytes_received.unwrap_or(0),
                            packets_sent: event.packets_sent.unwrap_or(0),
                            packets_received: event.packets_received.unwrap_or(0),
                            state: ConnectionState::Established,
                            first_seen: chrono::Utc::now().to_rfc3339(),
                            last_seen: chrono::Utc::now().to_rfc3339(),
                        },
                    );
                }
            }
            EventAction::Block => {
                // Increment blocked counter
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
                
                // Still track blocked connections for statistics
                if let Some(conn) = connections.get_mut(&key) {
                    conn.bytes_sent = conn.bytes_sent.saturating_add(event.bytes_sent.unwrap_or(0));
                    conn.bytes_received = conn.bytes_received.saturating_add(event.bytes_received.unwrap_or(0));
                    conn.packets_sent = conn.packets_sent.saturating_add(event.packets_sent.unwrap_or(0));
                    conn.packets_received = conn.packets_received.saturating_add(event.packets_received.unwrap_or(0));
                    conn.last_seen = chrono::Utc::now().to_rfc3339();
                }
            }
            EventAction::Close => {
                connections.remove(&key);
            }
        }

        Ok(())
    }

    pub async fn get_active_connections(&self) -> Result<Vec<ConnectionInfo>> {
        let connections = self.connections.read().await;
        Ok(connections.values().cloned().collect())
    }

    pub async fn get_connection(&self, key: &ConnectionKey) -> Result<Option<ConnectionInfo>> {
        let connections = self.connections.read().await;
        Ok(connections.get(key).cloned())
    }

    pub async fn close_connection(&self, key: &ConnectionKey) -> Result<()> {
        let mut connections = self.connections.write().await;
        connections.remove(key);
        Ok(())
    }

    pub async fn get_process_connections(&self, pid: u32) -> Result<Vec<ConnectionInfo>> {
        let connections = self.connections.read().await;
        Ok(connections
            .values()
            .filter(|c| c.process_id == Some(pid))
            .cloned()
            .collect())
    }

    pub async fn get_global_stats(&self) -> Result<GlobalStats> {
        let connections = self.connections.read().await;

        let total_bytes_sent: u64 = connections.values().map(|c| c.bytes_sent).fold(0u64, |acc, x| acc.saturating_add(x));
        let total_bytes_received: u64 = connections.values().map(|c| c.bytes_received).fold(0u64, |acc, x| acc.saturating_add(x));
        let total_packets_sent: u64 = connections.values().map(|c| c.packets_sent).fold(0u64, |acc, x| acc.saturating_add(x));
        let total_packets_received: u64 = connections.values().map(|c| c.packets_received).fold(0u64, |acc, x| acc.saturating_add(x));

        Ok(GlobalStats {
            active_connections: connections.len() as u32,
            total_bytes_sent,
            total_bytes_received,
            total_packets_sent,
            total_packets_received,
            blocked_connections: self.blocked_count.load(Ordering::Relaxed),
            allowed_connections: self.allowed_count.load(Ordering::Relaxed),
            suspicious_connections: self.suspicious_count.load(Ordering::Relaxed),
        })
    }

    /// Mark a connection as suspicious
    pub fn mark_suspicious(&self) {
        self.suspicious_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Reset statistics counters
    pub fn reset_stats(&self) {
        self.blocked_count.store(0, Ordering::Relaxed);
        self.allowed_count.store(0, Ordering::Relaxed);
        self.suspicious_count.store(0, Ordering::Relaxed);
    }

    pub async fn get_process_stats(&self, pid: u32) -> Result<ProcessStats> {
        let connections = self.connections.read().await;
        let process_connections: Vec<_> = connections
            .values()
            .filter(|c| c.process_id == Some(pid))
            .collect();

        let total_bytes_sent: u64 = process_connections.iter().map(|c| c.bytes_sent).fold(0u64, |acc, x| acc.saturating_add(x));
        let total_bytes_received: u64 = process_connections.iter().map(|c| c.bytes_received).fold(0u64, |acc, x| acc.saturating_add(x));

        let process_name = process_connections
            .first()
            .and_then(|c| c.process_name.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        Ok(ProcessStats {
            process_id: pid,
            process_name,
            active_connections: process_connections.len() as u32,
            total_bytes_sent,
            total_bytes_received,
        })
    }
}