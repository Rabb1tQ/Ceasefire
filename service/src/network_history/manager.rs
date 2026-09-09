//! Network History Manager implementation

use super::super::error::Result;
use super::super::models::*;
use super::super::database::Database;
use super::super::connection::tracker::ConnectionTracker;
use super::super::geoip::GeoIpService;
use std::collections::HashMap;
use std::sync::Arc;

pub struct NetworkHistoryManager {
    db: Arc<Database>,
    geoip_service: Arc<GeoIpService>,
    // 周期快照的差值基线：连接键 -> 上次已落库的累计字节。与 Close 收尾
    // 落库共享，保证"驱动 flow 关闭报数 + 60 秒周期快照"两者不双计。
    //
    // 用 tokio Mutex（而非 std）：两条写路径都必须把"读基线 → 写差值行 →
    // 推进/移除基线"作为一个不可分割的事务执行，且中间包含异步 DB 写入。
    // 若两条路径交错（tick 刚按旧基线算出差值、Close 同时落库并清掉基线），
    // 同一批字节会被两边各记一次。持锁跨 await 是刻意为之——锁保护的正是
    // "DB 行与内存基线保持一致"这个不变量；两条路径都是单行小写入，
    // 临界区在毫秒级，不会阻塞对方多久。
    last_snapshot: Arc<tokio::sync::Mutex<HashMap<String, (u64, u64)>>>,
}

/// 连接键格式同时被周期快照与 Close 收尾使用，两处必须完全一致
fn connection_snapshot_key(
    local_addr: &str,
    local_port: u16,
    remote_addr: &str,
    remote_port: u16,
    protocol: Protocol,
) -> String {
    format!(
        "{}:{}->{}:{}:{}",
        local_addr, local_port, remote_addr, remote_port, protocol as u8
    )
}

impl NetworkHistoryManager {
    pub fn new(db: Arc<Database>, geoip_service: Arc<GeoIpService>) -> Self {
        NetworkHistoryManager {
            db,
            geoip_service,
            last_snapshot: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Start periodic snapshot of connection stats to history
    pub fn start_periodic_snapshot(
        &self,
        connection_tracker: Arc<ConnectionTracker>,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let db = self.db.clone();
        let last_snapshot = self.last_snapshot.clone();

        tokio::spawn(async move {
            tracing::info!("Starting periodic connection snapshot");

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                // Snapshot every 60 seconds
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

                match connection_tracker.get_active_connections().await {
                    Ok(connections) => {
                        let now = chrono::Utc::now();
                        let mut recorded_count = 0;

                        // 整轮快照持有基线锁（含 DB 写入），与 Close 收尾互斥：
                        // 任一时刻只有一条路径能推进某连接的已落库累计，保证
                        // 每字节只差值落库一次。
                        let mut baseline = last_snapshot.lock().await;
                        // 本轮差值行先收集、最后一个事务批量落库：
                        // 逐条 create_network_history 每条活跃连接一次
                        // spawn_blocking + 锁往返，一个周期一个事务即可。
                        let mut batch: Vec<NetworkHistoryRecord> = Vec::new();
                        for conn in &connections {
                            let conn_key = connection_snapshot_key(
                                &conn.local_addr,
                                conn.local_port,
                                &conn.remote_addr,
                                conn.remote_port,
                                conn.protocol,
                            );

                            // Calculate delta bytes since last snapshot
                            let (delta_sent, delta_received) = match baseline.get(&conn_key) {
                                Some((last_sent, last_received)) => (
                                    conn.bytes_sent.saturating_sub(*last_sent),
                                    conn.bytes_received.saturating_sub(*last_received),
                                ),
                                None => {
                                    // First time seeing this connection, record all bytes
                                    (conn.bytes_sent, conn.bytes_received)
                                }
                            };

                            // Only record if there's new traffic
                            if delta_sent > 0 || delta_received > 0 {
                                let record = NetworkHistoryRecord {
                                    id: None,
                                    timestamp: now.to_rfc3339(),
                                    action: RuleAction::Allow,
                                    local_addr: conn.local_addr.clone(),
                                    local_port: conn.local_port,
                                    remote_addr: conn.remote_addr.clone(),
                                    remote_port: conn.remote_port,
                                    protocol: conn.protocol,
                                    direction: conn.direction,
                                    process_id: conn.process_id,
                                    process_name: conn.process_name.clone(),
                                    process_path: conn.process_path.clone(),
                                    bytes_sent: delta_sent,
                                    bytes_received: delta_received,
                                    rule_id: None,
                                };

                                batch.push(record);
                            }

                            // Update last snapshot
                            baseline.insert(conn_key, (conn.bytes_sent, conn.bytes_received));
                        }

                        if !batch.is_empty() {
                            match db.create_network_history_batch(&batch).await {
                                Ok(()) => recorded_count += batch.len(),
                                Err(e) => {
                                    tracing::error!("Failed to record {} connection snapshots: {}", batch.len(), e);
                                }
                            }
                        }

                        // Clean up stale connections from last_snapshot
                        let current_keys: std::collections::HashSet<String> = connections.iter()
                            .map(|c| connection_snapshot_key(
                                &c.local_addr, c.local_port,
                                &c.remote_addr, c.remote_port,
                                c.protocol,
                            ))
                            .collect();

                        baseline.retain(|k, _| current_keys.contains(k));
                        drop(baseline);

                        if recorded_count > 0 {
                            tracing::debug!("Recorded {} connection snapshots with traffic", recorded_count);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to get active connections for snapshot: {}", e);
                    }
                }
            }
            
            tracing::info!("Periodic connection snapshot stopped");
        });
    }

    /// Add a network history record
    pub async fn add_record(&self, record: &NetworkHistoryRecord) -> Result<()> {
        self.db.create_network_history(record).await?;
        Ok(())
    }

    /// 连接收尾落库：驱动在 TCP flow 删除时上报该连接生命周期内的字节总量
    /// （NetworkEvent.bytes_sent/received）。此前各 tick 的增量已由周期快照
    /// 落库，这里与快照共用同一份差值基线，只补写最后一次快照之后的尾巴，
    /// 然后清掉基线。对生命周期短于一个快照周期的短连接（盲区目标场景），
    /// 基线不存在，总量即全部增量。
    pub async fn record_closed_connection(&self, event: &NetworkEvent) -> Result<()> {
        let total_sent = event.bytes_sent.unwrap_or(0);
        let total_received = event.bytes_received.unwrap_or(0);

        let conn_key = connection_snapshot_key(
            &event.local_addr,
            event.local_port,
            &event.remote_addr,
            event.remote_port,
            event.protocol,
        );

        // 与周期快照共用同一把基线锁，且持锁跨"移除基线 → 差值计算 → DB
        // 写入"整个过程：close 处理期间 60 秒 tick 不可能为同一连接再写差
        // 值行（反之亦然），极端时序下同一批字节不会重复计入。
        let mut baseline = self.last_snapshot.lock().await;
        let (last_sent, last_received) = baseline.remove(&conn_key).unwrap_or((0, 0));
        let delta_sent = total_sent.saturating_sub(last_sent);
        let delta_received = total_received.saturating_sub(last_received);

        if delta_sent == 0 && delta_received == 0 {
            return Ok(());
        }

        let record = NetworkHistoryRecord {
            id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: RuleAction::Allow, // Close 事件源自已放行的连接，按 Allow 计入统计
            local_addr: event.local_addr.clone(),
            local_port: event.local_port,
            remote_addr: event.remote_addr.clone(),
            remote_port: event.remote_port,
            protocol: event.protocol,
            direction: event.direction,
            process_id: event.process_id,
            process_name: event.process_name.clone(),
            process_path: event.process_path.clone(),
            bytes_sent: delta_sent,
            bytes_received: delta_received,
            rule_id: None,
        };

        tracing::debug!(
            "Connection closed with traffic: pid={:?}, {}:{} -> {}:{}, sent={}, received={} (delta)",
            event.process_id,
            event.local_addr,
            event.local_port,
            event.remote_addr,
            event.remote_port,
            delta_sent,
            delta_received
        );

        self.db.create_network_history(&record).await?;
        Ok(())
    }

    /// Get history records with filtering
    pub async fn get_history(&self, filters: &HistoryFilters) -> Result<Vec<NetworkHistoryRecord>> {
        self.db.get_network_history(filters).await
    }

    /// Get history statistics
    pub async fn get_statistics(&self, filters: &HistoryFilters) -> Result<NetworkStatistics> {
        let records = self.get_history(filters).await?;

        let mut stats = NetworkStatistics {
            total_connections: records.len(),
            bytes_sent: 0,
            bytes_received: 0,
            by_protocol: std::collections::HashMap::new(),
            by_app: std::collections::HashMap::new(),
            top_remote_addrs: std::collections::HashMap::new(),
            blocked_count: 0,
            allowed_count: 0,
        };

        for record in &records {
            // Count by action
            if record.action == RuleAction::Block {
                stats.blocked_count += 1;
            } else {
                stats.allowed_count += 1;
            }

            // Count by protocol
            *stats.by_protocol.entry(record.protocol).or_insert(0) += 1;

            // Count by app
            if let Some(ref process_name) = record.process_name {
                *stats.by_app.entry(process_name.clone()).or_insert(0) += 1;
            }

            // Count by remote address
            *stats.top_remote_addrs.entry(record.remote_addr.clone()).or_insert(0) += 1;
        }

        // Sort top remote addresses
        let mut addrs_vec: Vec<(String, usize)> = stats.top_remote_addrs.into_iter().collect();
        addrs_vec.sort_by(|a, b| b.1.cmp(&a.1));
        addrs_vec.truncate(10);
        stats.top_remote_addrs = addrs_vec.into_iter().collect();

        Ok(stats)
    }

    /// Clear old history records
    pub async fn clear_old_records(&self, days: u32) -> Result<u32> {
        self.db.clear_old_network_history(days).await
    }

    /// 窗口内历史流量字节总量（数据库侧 SUM，不受列表分页 limit 影响），
    /// 供全局统计（get_combined_global_stats）使用。
    pub async fn get_history_traffic_totals(&self, hours: u32) -> Result<(u64, u64)> {
        self.db.get_history_traffic_totals(hours).await
    }

    /// Clear old history records (alias for consistency)
    pub async fn clear_old_history(&self, days: u32) -> Result<u32> {
        self.clear_old_records(days).await
    }

    /// Get traffic statistics grouped by application
    /// 统计走数据库侧 SUM/GROUP BY（aggregate_app_traffic），不受列表分页
    /// limit(100) 限制；窗口过滤在 SQL 内完成。
    pub async fn get_app_traffic_stats(&self, hours: u32) -> Result<Vec<AppTrafficStats>> {
        let rows = self.db.aggregate_app_traffic(hours).await?;

        let mut result: Vec<AppTrafficStats> = rows
            .into_iter()
            .map(|(process_name, process_path, process_id, last_seen, sent, received, count)| {
                AppTrafficStats {
                    // 与旧行为一致：NULL 进程名归并为 "Unknown"
                    process_name: process_name.filter(|n| !n.is_empty()).unwrap_or_else(|| "Unknown".to_string()),
                    process_path: process_path.unwrap_or_else(|| "Unknown".to_string()),
                    bytes_sent: sent as u64,
                    bytes_received: received as u64,
                    connection_count: count as u32,
                    process_id: process_id.map(|p| p as u32),
                    last_seen,
                }
            })
            .collect();

        // Sort by total bytes descending
        result.sort_by(|a, b| (b.bytes_sent + b.bytes_received).cmp(&(a.bytes_sent + a.bytes_received)));

        Ok(result)
    }

    /// Get traffic statistics grouped by protocol
    /// 数据库侧 GROUP BY protocol，protocol 列存 JSON 字符串，此处还原枚举。
    pub async fn get_protocol_traffic_stats(&self, hours: u32) -> Result<Vec<ProtocolTrafficStats>> {
        let rows = self.db.aggregate_protocol_traffic(hours).await?;

        let mut result: Vec<ProtocolTrafficStats> = rows
            .into_iter()
            .map(|(protocol_json, sent, received, count)| {
                let protocol: Protocol = serde_json::from_str(&protocol_json).unwrap_or_default();
                let protocol_str = match protocol {
                    Protocol::Tcp => "TCP",
                    Protocol::Udp => "UDP",
                    Protocol::Icmp => "ICMP",
                    Protocol::Icmpv6 => "ICMPv6",
                    Protocol::Any => "Any",
                }.to_string();
                ProtocolTrafficStats {
                    protocol: protocol_str,
                    connection_count: count as u32,
                    bytes_sent: sent as u64,
                    bytes_received: received as u64,
                }
            })
            .collect();

        result.sort_by(|a, b| b.connection_count.cmp(&a.connection_count));

        Ok(result)
    }

    /// Get traffic statistics grouped by country
    /// 远端地址维度在数据库侧收敛成每地址一行（aggregate_remote_traffic），
    /// 再由 GeoIP 把地址映射到国家后汇总；明细行数不再受列表分页限制。
    pub async fn get_country_traffic_stats(&self, hours: u32) -> Result<Vec<CountryTrafficStats>> {
        let rows = self.db.aggregate_remote_traffic(hours).await?;

        let mut country_stats: std::collections::HashMap<String, CountryTrafficStats> = std::collections::HashMap::new();

        // Batch lookup GeoIP for all unique public IPs
        let unique_ips: Vec<String> = rows
            .iter()
            .map(|(addr, ..)| addr.clone())
            .filter(|addr| !Self::is_private_ip(addr))
            .collect();
        let ip_locations = if !unique_ips.is_empty() {
            self.geoip_service.lookup_batch(unique_ips).await.unwrap_or_default()
        } else {
            std::collections::HashMap::new()
        };

        for (remote_addr, sent, received, count) in rows {
            // Get country info from GeoIP lookup
            let (country_code, country_name) = if Self::is_private_ip(&remote_addr) {
                ("LOCAL".to_string(), "Local Network".to_string())
            } else if let Some(location) = ip_locations.get(&remote_addr) {
                (location.country_code.clone(), location.country_name.clone())
            } else {
                ("XX".to_string(), "Unknown".to_string())
            };

            let stats = country_stats.entry(country_code.clone()).or_insert(CountryTrafficStats {
                country_code: country_code.clone(),
                country_name: country_name.clone(),
                connection_count: 0,
                bytes_sent: 0,
                bytes_received: 0,
            });

            stats.connection_count = stats.connection_count.saturating_add(count as u32);
            stats.bytes_sent = stats.bytes_sent.saturating_add(sent as u64);
            stats.bytes_received = stats.bytes_received.saturating_add(received as u64);
        }

        let mut result: Vec<_> = country_stats.into_values().collect();
        result.sort_by(|a, b| (b.bytes_sent + b.bytes_received).cmp(&(a.bytes_sent + a.bytes_received)));

        Ok(result)
    }
    
    /// Check if an IP address is private/local
    fn is_private_ip(ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(ipv4) => {
                    ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
                }
                std::net::IpAddr::V6(ipv6) => {
                    ipv6.is_loopback() || ipv6.is_unicast_link_local()
                }
            }
        } else {
            false
        }
    }

    /// Get traffic trend over time
    /// 桶分组下推到 SQL（aggregate_trend_buckets），不受列表分页 limit 限制；
    /// 这里只负责按时间范围选桶宽并补齐空桶。
    pub async fn get_traffic_trend(&self, hours: u32) -> Result<Vec<TrafficTrendPoint>> {
        // Determine interval based on time range
        let now = chrono::Utc::now();

        let (interval_minutes, num_points) = if hours <= 1 {
            (5, 12)  // 5-minute intervals for 1 hour
        } else if hours <= 6 {
            (15, 24) // 15-minute intervals for 6 hours
        } else if hours <= 24 {
            (60, 24) // 1-hour intervals for 24 hours
        } else if hours <= 168 {
            (360, 28) // 6-hour intervals for 7 days
        } else {
            (1440, 30) // 1-day intervals for 30 days
        };

        // Create time buckets
        let mut trend_map: std::collections::BTreeMap<i64, TrafficTrendPoint> = std::collections::BTreeMap::new();

        for i in 0..num_points {
            let bucket_time = now - chrono::Duration::minutes((num_points - i - 1) * interval_minutes);
            let bucket_timestamp = bucket_time.timestamp() / (interval_minutes * 60) * (interval_minutes * 60);

            trend_map.entry(bucket_timestamp).or_insert(TrafficTrendPoint {
                timestamp: chrono::DateTime::from_timestamp(bucket_timestamp, 0)
                    .unwrap_or(now)
                    .to_rfc3339(),
                bytes_sent: 0,
                bytes_received: 0,
                connection_count: 0,
            });
        }

        // Aggregate DB-side buckets into the pre-filled zero buckets
        let interval_seconds = (interval_minutes * 60) as i64;
        for (bucket_timestamp, sent, received, count) in
            self.db.aggregate_trend_buckets(hours, interval_seconds).await?
        {
            if let Some(trend) = trend_map.get_mut(&bucket_timestamp) {
                trend.connection_count += count as u32;
                trend.bytes_sent = trend.bytes_sent.saturating_add(sent as u64);
                trend.bytes_received = trend.bytes_received.saturating_add(received as u64);
            }
        }

        let result: Vec<_> = trend_map.into_values().collect();

        Ok(result)
    }

    /// Dashboard 图表增强三件套共用的桶宽选择：1 小时视图 5 分钟桶，
    /// 24 小时视图 1 小时桶，7 天视图按天桶（页面会注明"按天聚合"）。
    /// 返回 (interval_seconds, 说明文案)
    pub fn timeline_bucket_seconds(hours: u32) -> i64 {
        if hours <= 1 {
            5 * 60
        } else if hours <= 24 {
            60 * 60
        } else {
            24 * 60 * 60
        }
    }

    /// 按应用堆叠流量时序（不做空桶填充；前端纯函数负责对齐时间轴）
    pub async fn get_app_traffic_timeline(&self, hours: u32) -> Result<Vec<AppTimelinePoint>> {
        let interval = Self::timeline_bucket_seconds(hours);
        let rows = self.db.aggregate_app_timeline(hours, interval).await?;
        Ok(rows
            .into_iter()
            .map(|(bucket, path, name, sent, received)| AppTimelinePoint {
                timestamp: chrono::DateTime::from_timestamp(bucket, 0)
                    .unwrap_or_else(chrono::Utc::now)
                    .to_rfc3339(),
                process_path: path,
                process_name: name,
                bytes_sent: sent.max(0) as u64,
                bytes_received: received.max(0) as u64,
            })
            .collect())
    }

    /// 放行/拦截趋势（按字节 + 连接数双指标）
    pub async fn get_action_trend(&self, hours: u32) -> Result<Vec<ActionTrendPoint>> {
        let interval = Self::timeline_bucket_seconds(hours);
        let rows = self.db.aggregate_action_trend(hours, interval).await?;
        let mut by_bucket: std::collections::BTreeMap<i64, ActionTrendPoint> =
            std::collections::BTreeMap::new();
        for (bucket, action, sent, received, count) in rows {
            let point = by_bucket.entry(bucket).or_insert(ActionTrendPoint {
                timestamp: chrono::DateTime::from_timestamp(bucket, 0)
                    .unwrap_or_else(chrono::Utc::now)
                    .to_rfc3339(),
                allowed_bytes: 0,
                blocked_bytes: 0,
                allowed_count: 0,
                blocked_count: 0,
            });
            let total = (sent.max(0) as u64).saturating_add(received.max(0) as u64);
            // action 列存 JSON 字符串（"Allow"/"Block"），宽松匹配避免编码耦合
            if action.contains("Block") {
                point.blocked_bytes = point.blocked_bytes.saturating_add(total);
                point.blocked_count += count.max(0) as u64;
            } else {
                point.allowed_bytes = point.allowed_bytes.saturating_add(total);
                point.allowed_count += count.max(0) as u64;
            }
        }
        Ok(by_bucket.into_values().collect())
    }

    /// 目标主机排行（domain 留空，由 IPC 层用 DNS 缓存反查填充）
    pub async fn get_top_hosts(&self, hours: u32, limit: u32) -> Result<Vec<TopHostStats>> {
        let rows = self.db.aggregate_top_hosts(hours, limit).await?;
        Ok(rows
            .into_iter()
            .map(|(addr, sent, received, count)| TopHostStats {
                remote_addr: addr,
                domain: None,
                bytes_sent: sent.max(0) as u64,
                bytes_received: received.max(0) as u64,
                connection_count: count.max(0) as u64,
            })
            .collect())
    }

    /// Get connection timeline for a specific process
    pub async fn get_process_timeline(&self, process_path: &str, hours: u32) -> Result<Vec<NetworkHistoryRecord>> {
        let filters = HistoryFilters {
            process_path: Some(process_path.to_string()),
            hours: Some(hours),
            ..Default::default()
        };
        self.get_history(&filters).await
    }

    /// Get remote address details
    /// 聚合（计数/字节/首末时间/协议与端口集合）走数据库侧
    /// aggregate_remote_address_details（SQL SUM/GROUP_CONCAT DISTINCT），
    /// 不再经 limit(100) 的列表路径求和——单地址连接数超过列表上限时
    /// 此前会总量少计。返回结构不变。
    pub async fn get_remote_address_details(&self, remote_addr: &str, hours: u32) -> Result<RemoteAddressDetails> {
        let (count, sent, received, first_seen, last_seen, protocols_csv, local_ports_csv, remote_ports_csv) =
            self.db.aggregate_remote_address_details(remote_addr, hours).await?;

        let protocol_display = |json: &str| -> String {
            let protocol: Protocol = serde_json::from_str(json).unwrap_or_default();
            match protocol {
                Protocol::Tcp => "TCP",
                Protocol::Udp => "UDP",
                Protocol::Icmp => "ICMP",
                Protocol::Icmpv6 => "ICMPv6",
                Protocol::Any => "Any",
            }
            .to_string()
        };

        // GROUP_CONCAT(DISTINCT ...) 已经去重；split_csv 对空/NULL 返回空集
        let split_csv = |csv: &Option<String>| -> Vec<String> {
            csv.as_deref()
                .map(|s| s.split(',').filter(|p| !p.is_empty()).map(str::to_string).collect())
                .unwrap_or_default()
        };

        Ok(RemoteAddressDetails {
            remote_addr: remote_addr.to_string(),
            connection_count: count as usize,
            bytes_sent: sent as u64,
            bytes_received: received as u64,
            first_seen,
            last_seen,
            protocols: split_csv(&protocols_csv)
                .iter()
                .map(|json| protocol_display(json))
                .collect(),
            local_ports: split_csv(&local_ports_csv)
                .iter()
                .filter_map(|p| p.parse::<u16>().ok())
                .collect(),
            remote_ports: split_csv(&remote_ports_csv)
                .iter()
                .filter_map(|p| p.parse::<u16>().ok())
                .collect(),
        })
    }
}