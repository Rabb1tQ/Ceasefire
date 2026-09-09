//! Event Processor - processes network events from driver

use super::super::error::Result;
use super::super::models::*;
use super::super::database::Database;
use super::super::connection::tracker::ConnectionTracker;
use super::super::notification::notifier::Notifier;
use super::super::network_history::manager::NetworkHistoryManager;
use super::super::driver::DriverHandle;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub struct EventProcessor {
    db: Arc<Database>,
    connection_tracker: Arc<ConnectionTracker>,
    notifier: Arc<Notifier>,
    history_manager: Arc<NetworkHistoryManager>,
    bandwidth_limiter: Arc<super::super::bandwidth::BandwidthLimiter>,
    kernel_throttle: Arc<super::super::bandwidth::KernelThrottleSync>,
    decision_manager: Arc<super::super::connection_decision::manager::ConnectionDecisionManager>,
    dns_cache: Arc<super::super::dns_cache::DnsCache>,
    log_buffer: Arc<tokio::sync::Mutex<super::buffer::LogBuffer>>,
}

impl EventProcessor {
    pub fn new(
        db: Arc<Database>,
        connection_tracker: Arc<ConnectionTracker>,
        notifier: Arc<Notifier>,
        history_manager: Arc<NetworkHistoryManager>,
        bandwidth_limiter: Arc<super::super::bandwidth::BandwidthLimiter>,
        kernel_throttle: Arc<super::super::bandwidth::KernelThrottleSync>,
        decision_manager: Arc<super::super::connection_decision::manager::ConnectionDecisionManager>,
        dns_cache: Arc<super::super::dns_cache::DnsCache>,
    ) -> Result<Self> {
        Ok(EventProcessor {
            db,
            connection_tracker,
            notifier,
            history_manager,
            bandwidth_limiter,
            kernel_throttle,
            decision_manager,
            dns_cache,
            log_buffer: Arc::new(tokio::sync::Mutex::new(super::buffer::LogBuffer::new())),
        })
    }

    /// Flush any buffered log entries to the database.
    /// Called from the FirewallService stop path so shutdown does not lose logs.
    pub async fn flush(&self) -> Result<()> {
        let logs: Vec<_> = self.log_buffer.lock().await.drain();
        if logs.is_empty() {
            return Ok(());
        }
        // 单事务批量插入：逐条 add_log 每条一次 spawn_blocking + 锁往返，
        // 100 条刷一次就是 100 个来回。批量失败整批回滚，日志留在调用方
        // 错误日志里（与此前逐条失败仅记 error 的语义一致，不再重试）。
        if let Err(e) = self.db.add_logs_batch(&logs).await {
            tracing::error!("Failed to add {} logs to database: {}", logs.len(), e);
        }
        Ok(())
    }

    /// 定时落库循环：日志缓冲除了 100 条满员触发外，每 10 秒也冲刷一次，
    /// 低流量时段的记录不会一直滞留在内存里。
    pub async fn start_log_flusher(self: &Arc<Self>, running: Arc<AtomicBool>) {
        loop {
            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            // The guard temporary of `if self.log_buffer.lock().await.len() > 0`
            // lives until the end of the whole `if` statement, so calling
            // flush() (which locks the mutex again) inside the block would
            // self-deadlock and freeze the event loop forever. Bind the length
            // to a variable so the guard is dropped at the semicolon.
            let pending = self.log_buffer.lock().await.len();
            if pending > 0 {
                if let Err(e) = self.flush().await {
                    tracing::error!("Periodic log flush failed: {}", e);
                }
            }
        }
    }

    pub async fn start(
        &self,
        driver: Arc<DriverHandle>,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        tracing::info!("Event processor started");

        loop {
            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            match driver.get_event().await {
                Ok(event) => {
                    if let Err(e) = self.process_event(&driver, event).await {
                        tracing::error!("Failed to process event: {}", e);
                    }
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    if err_msg.contains("not open") {
                        tracing::error!("Driver not open, stopping event processor");
                        break;
                    }
                    // Don't spam logs for "No event available" errors
                    if !err_msg.contains("No event available") &&
                       !err_msg.contains("函数不正确") &&
                       !err_msg.contains("Incorrect function") {
                        // 到达这里的都是真实错误（如 ABI 尺寸不匹配导致的解析失败），
                        // 必须 warn 级别可见——曾经用 debug 级别导致事件被静默丢弃数小时无感知
                        tracing::warn!("Failed to get event from driver: {}", e);
                    }
                    // Sleep a bit to avoid busy-waiting
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            }

            // 排空驱动 DNS 事件队列并解析域名→IP 映射（每轮最多 32 条防饿死）
            let mut drained = 0;
            while drained < 32 {
                match driver.get_dns_event().await {
                    Ok(Some(dns_event)) => {
                        self.process_dns_event(dns_event).await;
                        drained += 1;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let msg = e.to_string();
                        if !msg.contains("not open") {
                            tracing::debug!("Failed to get DNS event from driver: {}", msg);
                        }
                        break;
                    }
                }
            }
        }

        // Flush remaining buffered logs on exit
        if let Err(e) = self.flush().await {
            tracing::error!("Failed to flush logs on shutdown: {}", e);
        }

        tracing::info!("Event processor stopped");
        Ok(())
    }

    async fn process_event(&self, driver: &Arc<DriverHandle>, event: NetworkEvent) -> Result<()> {
        // 内核限速：借助事件的 PID+路径 把按路径配置的限速下发到驱动
        // （流层 callout 只有 PID，路径→PID 的映射由此事件流提供）
        if let Some(pid) = event.process_id {
            self.kernel_throttle
                .sync_event(driver, pid, event.process_path.as_deref())
                .await;
        }

        // Log event with byte statistics for debugging
        if event.bytes_sent.is_some() || event.bytes_received.is_some() {
            tracing::info!(
                "Event with traffic: PID={:?}, sent={:?}, received={:?}",
                event.process_id,
                event.bytes_sent,
                event.bytes_received
            );
        }

        // Update connection tracker
        self.connection_tracker.update_connection(&event).await?;

        // 带宽限流告警（统计路径）：真正的拦截在驱动流层令牌桶完成
        // （KernelThrottleSync 下发），这里仅对超限流量产生用户告警。
        let sent = event.bytes_sent.unwrap_or(0);
        let received = event.bytes_received.unwrap_or(0);
        if (sent > 0 || received > 0) && event.action == EventAction::Allow {
            if let Some(path) = event.process_path.clone() {
                if sent > 0 && !self.bandwidth_limiter.allow_upload(&path, sent).await {
                    let msg = format!("进程 {} 已超出上传带宽限制（{} 字节）", path, sent);
                    tracing::warn!("{}", msg);
                    if let Err(e) = self.notifier.notify_custom("带宽告警", &msg).await {
                        tracing::debug!("Bandwidth alert notification failed: {}", e);
                    }
                }
                if received > 0 && !self.bandwidth_limiter.allow_download(&path, received).await {
                    let msg = format!("进程 {} 已超出下载带宽限制（{} 字节）", path, received);
                    tracing::warn!("{}", msg);
                    if let Err(e) = self.notifier.notify_custom("带宽告警", &msg).await {
                        tracing::debug!("Bandwidth alert notification failed: {}", e);
                    }
                }
            }
        }

        // 记住的连接决策：驱动判完后在此核对。若已记住的决策为 Block 而连接实际被放行，
        // 记录日志并提醒用户（当前架构无法在事后强制拦截，需在测试机验证驱动层联动后才能完全生效）。
        if event.action == EventAction::Allow {
            let conn = ConnectionInfo {
                local_addr: event.local_addr.clone(),
                local_port: event.local_port,
                remote_addr: event.remote_addr.clone(),
                remote_port: event.remote_port,
                protocol: event.protocol,
                process_id: event.process_id,
                process_name: event.process_name.clone(),
                process_path: event.process_path.clone(),
                direction: event.direction,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                state: ConnectionState::Established,
                first_seen: chrono::Utc::now().to_rfc3339(),
                last_seen: chrono::Utc::now().to_rfc3339(),
            };
            match self.decision_manager.get_decision(&conn).await {
                Ok(Some(decision)) if decision.decision == DecisionAction::Block => {
                    let msg = format!(
                        "进程 {} 连接 {}:{} 已被放行，但存在记住的\"阻止\"决策",
                        decision.process_path, conn.remote_addr, conn.remote_port
                    );
                    tracing::warn!("{}", msg);
                    if let Err(e) = self.notifier.notify_custom("连接决策冲突", &msg).await {
                        tracing::debug!("Decision conflict notification failed: {}", e);
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to look up connection decisions: {}", e);
                }
                _ => {}
            }
        }


        // Add to log buffer and flush when full
        {
            let mut buf = self.log_buffer.lock().await;
            buf.add(self.event_to_log_entry(&event));
            if buf.len() >= 100 {
                drop(buf);
                self.flush().await?;
            }
        }

        // 记录网络历史。Close（新驱动 TCP flow 关闭字节上报）必须走差值路径：
        // 该连接此前各 tick 的增量已由周期快照落库，直接整段重记会双计，
        // 这里只把最后一次快照之后的尾巴补上，并清掉对应的快照基线。
        if event.action == EventAction::Close {
            if let Err(e) = self.history_manager.record_closed_connection(&event).await {
                tracing::error!("Failed to record closed-connection traffic: {}", e);
            }
        } else {
            let history_record = self.event_to_history_record(&event);
            if let Err(e) = self.history_manager.add_record(&history_record).await {
                tracing::error!("Failed to add network history record: {}", e);
            }
        }

        // Send notification for blocked connections
        if event.action == EventAction::Block {
            self.notifier.notify_blocked_connection(&event).await?;
        }

        Ok(())
    }

    /// 解析驱动上报的 DNS 响应报文，把 域名→IP 写入 DNS 缓存。
    /// 解析失败只记日志，不影响事件循环。
    async fn process_dns_event(&self, event: super::super::driver::converter::DriverDnsEvent) {
        let data_len = event.data_length as usize;
        if data_len == 0 || data_len > event.data.len() {
            return;
        }
        let payload = &event.data[..data_len];
        for (domain, ip, ttl) in super::super::dns_cache::parse_dns_response(payload) {
            self.dns_cache.add_entry(ip, domain, ttl).await;
        }
    }

    fn event_to_log_entry(&self, event: &NetworkEvent) -> LogEntry {
        LogEntry {
            id: None,
            timestamp: chrono::Utc::now(),
            action: event.action,
            local_addr: event.local_addr.clone(),
            local_port: event.local_port,
            remote_addr: event.remote_addr.clone(),
            remote_port: event.remote_port,
            protocol: event.protocol,
            direction: event.direction,
            process_id: event.process_id,
            process_name: event.process_name.clone(),
            bytes_sent: event.bytes_sent,
            bytes_received: event.bytes_received,
            rule_id: event.rule_id,
        }
    }

    fn event_to_history_record(&self, event: &NetworkEvent) -> NetworkHistoryRecord {
        NetworkHistoryRecord {
            id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: match event.action {
                EventAction::Allow => RuleAction::Allow,
                EventAction::Block => RuleAction::Block,
                EventAction::Close => RuleAction::Allow, // Treat close as allow for history
            },
            local_addr: event.local_addr.clone(),
            local_port: event.local_port,
            remote_addr: event.remote_addr.clone(),
            remote_port: event.remote_port,
            protocol: event.protocol,
            direction: event.direction,
            process_id: event.process_id,
            process_name: event.process_name.clone(),
            process_path: event.process_path.clone(),
            bytes_sent: event.bytes_sent.unwrap_or(0),
            bytes_received: event.bytes_received.unwrap_or(0),
            rule_id: event.rule_id,
        }
    }
}