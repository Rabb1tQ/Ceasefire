//! Notifier - 通知中心
//!
//! 两类消费路径：
//! 1. 服务端日志（原行为保留）；
//! 2. 待处理通知队列：GUI 通过 IPC PollNotifications 轮询取走，
//!    由 GUI 负责 Windows Toast 与"未知程序询问"弹窗（服务跑在
//!    Session 0，直接发 Toast 用户看不到）。

use super::super::error::Result;
use super::super::models::*;
use super::deduplicator::NotificationDeduplicator;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 队列上限：超过后丢弃最旧的通知（GUI 长时间未轮询时防内存膨胀）
const QUEUE_CAP: usize = 500;

pub struct Notifier {
    deduplicator: Arc<Mutex<NotificationDeduplicator>>,
    // 内部可变，便于通过 Arc<Notifier> 在运行时跟随设置开关
    enabled: std::sync::atomic::AtomicBool,
    /// 询问模式：默认拦截 + 未匹配规则的连接产生 Ask 通知（GUI 弹窗）
    ask_mode: std::sync::atomic::AtomicBool,
    queue: Mutex<VecDeque<NotificationItem>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl Notifier {
    pub fn new() -> Self {
        Notifier {
            deduplicator: Arc::new(Mutex::new(NotificationDeduplicator::new())),
            enabled: std::sync::atomic::AtomicBool::new(true),
            ask_mode: std::sync::atomic::AtomicBool::new(false),
            queue: Mutex::new(VecDeque::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_ask_mode(&self, enabled: bool) {
        self.ask_mode.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn ask_mode_enabled(&self) -> bool {
        self.ask_mode.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 把通知放入待处理队列（供 GUI 轮询）
    pub async fn enqueue(&self, item: NotificationItem) {
        let mut q = self.queue.lock().await;
        if q.len() >= QUEUE_CAP {
            q.pop_front();
        }
        q.push_back(item);
    }

    /// GUI 轮询：取走最多 max 条通知
    pub async fn drain(&self, max: usize) -> Vec<NotificationItem> {
        let mut q = self.queue.lock().await;
        let count = max.min(q.len());
        q.drain(..count).collect()
    }

    pub async fn pending_count(&self) -> usize {
        self.queue.lock().await.len()
    }

    fn make_item(&self, kind: NotificationKind, event: &NetworkEvent) -> NotificationItem {
        // 兜底转换：事件链路理应已完成 NT→DOS，但若驱动上报了非常规大小写
        // 形态导致上游转换失效，GUI 弹窗里会出现 \device\harddiskvolume3\...，
        // 这里再转一次，已是 DOS 路径时为 no-op
        let process_path = event.process_path.as_ref().and_then(|p| {
            crate::driver::converter::convert_nt_path_to_dos(p)
        });
        NotificationItem {
            id: self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            kind,
            timestamp: chrono::Utc::now().to_rfc3339(),
            process_path,
            process_name: event.process_name.clone(),
            remote_addr: event.remote_addr.clone(),
            remote_port: event.remote_port,
            protocol: event.protocol.to_string(),
            direction: event.direction.to_string(),
            rule_id: event.rule_id,
        }
    }

    pub async fn notify_blocked_connection(&self, event: &NetworkEvent) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        let key = format!(
            "{}:{}:{}:{}:{}",
            event.process_id.unwrap_or(0),
            event.remote_addr,
            event.remote_port,
            event.process_name.as_deref().unwrap_or(""),
            chrono::Utc::now().format("%Y%m%d%H")
        );

        if self
            .deduplicator
            .lock()
            .await
            .should_notify(&key, 60)
            .await
        {
            // 命中规则的拦截按规则意图处理，只作普通通知；
            // 询问模式下未命中任何规则（默认策略拦下）的连接升级为 Ask
            let kind = if self.ask_mode_enabled() && event.rule_id.is_none() {
                NotificationKind::Ask
            } else {
                NotificationKind::Blocked
            };
            let item = self.make_item(kind, event);
            tracing::info!("Notification ({}): {}", if kind == NotificationKind::Ask { "Ask" } else { "Blocked" }, self.format_message(event));
            self.enqueue(item).await;
        }

        Ok(())
    }

    pub async fn notify_custom(&self, title: &str, message: &str) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        tracing::info!("Notification: {} - {}", title, message);
        Ok(())
    }

    fn format_message(&self, event: &NetworkEvent) -> String {
        format!(
            "{}: {} (PID: {}) connected to {}:{}",
            event.protocol,
            event.process_name.as_deref().unwrap_or("Unknown"),
            event.process_id.unwrap_or(0),
            event.remote_addr,
            event.remote_port
        )
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}
