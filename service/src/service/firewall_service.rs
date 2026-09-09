//! Firewall Service implementation

use super::super::error::{Result, ServiceError};
use super::super::database::Database;
use super::super::driver::DriverHandle;
use super::super::rule::manager::RuleManager;
use super::super::event::processor::EventProcessor;
use super::super::ipc::server::IpcServer;
use super::super::connection::tracker::ConnectionTracker;
use super::super::notification::notifier::Notifier;
use super::super::app_group::manager::AppGroupManager;
use super::super::connection_decision::manager::ConnectionDecisionManager;
use super::super::network_history::manager::NetworkHistoryManager;
use super::super::bandwidth::{BandwidthLimiter, KernelThrottleSync};
use super::super::geoip::GeoIpService;
use super::super::wfp::{WfpEngine, WfpFilterManager};
use std::sync::Arc;

pub struct FirewallService {
    db: Arc<Database>,
    driver: Option<Arc<DriverHandle>>,
    rule_manager: Arc<RuleManager>,
    /// 启动时幂等同步预置分组成员需要；平时归 IPC handler 使用
    app_group_manager: Arc<AppGroupManager>,
    event_processor: Arc<EventProcessor>,
    ipc_server: Arc<IpcServer>,
    connection_tracker: Arc<ConnectionTracker>,
    notifier: Arc<Notifier>,
    history_manager: Arc<NetworkHistoryManager>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    kernel_throttle: Arc<KernelThrottleSync>,
    wfp_engine: Option<Arc<WfpEngine>>,
    /// IPC 处理器访问 WFP 引擎的共享槽（engine 在 start() 才创建）
    wfp_engine_slot: super::super::ipc::handler::WfpEngineSlot,
    wfp_filter_manager: Option<WfpFilterManager>,
    dns_cache: Arc<crate::dns_cache::DnsCache>,
    /// 域名规则展开引擎（DNS 命中 → 影子规则下发驱动）
    domain_engine: Arc<crate::rule::domain_expander::DomainRuleEngine>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl FirewallService {
    pub fn new(db: Arc<Database>) -> Result<Self> {
        let wfp_engine_slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let connection_tracker = Arc::new(ConnectionTracker::new());
        let driver = Arc::new(DriverHandle::new()?);
        let rule_manager = Arc::new(RuleManager::new(db.clone(), driver.clone())?);
        let notifier = Arc::new(Notifier::new());
        
        // Create new managers
        let app_group_manager = Arc::new(AppGroupManager::new(db.clone(), connection_tracker.clone()));
        let decision_manager = Arc::new(ConnectionDecisionManager::new(db.clone()));
        let bandwidth_limiter = Arc::new(BandwidthLimiter::new());
        let kernel_throttle = Arc::new(KernelThrottleSync::new());
        let geoip_service = Arc::new(GeoIpService::new(db.clone()));
        let history_manager = Arc::new(NetworkHistoryManager::new(db.clone(), geoip_service.clone()));
        let dns_cache = Arc::new(crate::dns_cache::DnsCache::new());

        // 域名规则展开引擎：db 查规则、driver 下发影子条目（RuleDriverOps
        // 由 Arc<DriverHandle> 实现），并注入 RuleManager 供删除/禁用/编辑
        // 时撤除影子条目
        let domain_engine = Arc::new(crate::rule::domain_expander::DomainRuleEngine::new(
            db.clone(),
            driver.clone() as Arc<dyn crate::rule::domain_expander::RuleDriverOps>,
        ));
        rule_manager.set_domain_engine(domain_engine.clone());

        let event_processor = Arc::new(EventProcessor::new(
            db.clone(),
            connection_tracker.clone(),
            notifier.clone(),
            history_manager.clone(),
            bandwidth_limiter.clone(),
            kernel_throttle.clone(),
            decision_manager.clone(),
            dns_cache.clone(),
        )?);

        let ipc_server = Arc::new(IpcServer::new(
            rule_manager.clone(),
            connection_tracker.clone(),
            db.clone(),
            app_group_manager.clone(),
            decision_manager.clone(),
            history_manager.clone(),
            bandwidth_limiter.clone(),
            kernel_throttle.clone(),
            geoip_service.clone(),
            dns_cache.clone(),
            notifier.clone(),
            driver.clone(),
            wfp_engine_slot.clone(),
        )?);

        Ok(FirewallService {
            db,
            driver: Some(driver),
            rule_manager,
            app_group_manager,
            event_processor,
            ipc_server,
            connection_tracker,
            notifier,
            history_manager,
            bandwidth_limiter,
            kernel_throttle,
            wfp_engine: None,
            wfp_engine_slot,
            wfp_filter_manager: None,
            dns_cache,
            domain_engine,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting Ceasefire Firewall Service");

        // Set running flag BEFORE starting background tasks
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        self.load_driver().await?;
        self.initialize_wfp().await?;
        // 服务重启而驱动未卸载时，驱动里还留着上次的规则；先清空再加载，
        // 否则每条 add 都会撞 RuleId 去重导致 start() 整体失败。
        // 驱动句柄缺失属于异常状态，直接报错而非静默跳过这一加载前置条件
        let driver = self.driver.as_ref().ok_or_else(|| {
            ServiceError::Service("驱动句柄未初始化，无法清空驱动侧规则".to_string())
        })?;
        // 按设置同步默认策略与系统豁免规则：create_rule 会同时下发驱动，
        // 但随后 clear_rules 会清掉，最终由 load_rules_to_driver 统一加载
        let (default_allow, system_rules_enabled, protect_when_not_running) = match self.db.get_settings().await {
            Ok(s) => (s.default_allow, s.system_rules_enabled, s.protect_when_not_running),
            Err(e) => {
                tracing::warn!("Failed to load settings, keeping default allow policy: {}", e);
                (true, true, false)
            }
        };
        if !default_allow && system_rules_enabled {
            if let Err(e) = crate::rule::system_rules::ensure_installed(&self.rule_manager).await {
                tracing::warn!("Failed to install system exemption rules: {}", e);
            }
        } else if !system_rules_enabled {
            let _ = crate::rule::system_rules::remove_all(&self.rule_manager).await;
        }
        driver.clear_rules().await?;
        driver.set_default_policy(default_allow).await?;
        self.rule_manager.load_rules_to_driver().await?;

        // 预置分组幂等同步（组成员 = 模板展开 ∩ 实际存在，清占位符死行）：
        // 必须在服务启动跑，否则无 GUI 的机器（同步此前只挂在 AppGroups 页
        // 打开的 IPC 上）占位符永不清理、新装程序永不入组。失败只告警——
        // 同步失败不该阻断防火墙启动
        if let Err(e) = self.app_group_manager.initialize_predefined().await {
            tracing::warn!("Failed to sync predefined app groups: {}", e);
        }

        // kill-switch 常驻过滤器按设置安装/移除（服务未运行期间兜底拦截）
        if let Some(engine) = self.wfp_engine.as_ref() {
            if protect_when_not_running {
                if let Err(e) = crate::wfp::add_persistent_block_filters(engine) {
                    tracing::warn!("Failed to install kill-switch filters: {}", e);
                }
            } else if let Err(e) = crate::wfp::remove_persistent_block_filters(engine) {
                tracing::warn!("Failed to remove kill-switch filters: {}", e);
            }
        }

        // 重启后恢复持久化的进程带宽限制（令牌桶内存状态 + 全局设置）
        match self.db.list_process_bandwidth_limits().await {
            Ok(limits) => {
                let count = limits.len();
                for limit in limits {
                    if limit.enabled {
                        self.bandwidth_limiter.set_limits(
                            &limit.process_path,
                            limit.upload_limit_kbps,
                            limit.download_limit_kbps,
                        ).await;
                        // 登记到内核限速同步表（条目在该路径的下一次连接事件时下发）
                        self.kernel_throttle.update_path_limit(
                            driver,
                            &limit.process_path,
                            limit.upload_limit_kbps,
                            limit.download_limit_kbps,
                        ).await;
                    }
                }
                tracing::info!("Restored {} persisted bandwidth limits", count);
            }
            Err(e) => tracing::warn!("Failed to restore persisted bandwidth limits: {}", e),
        }
        match self.db.get_settings().await {
            Ok(settings) => {
                // 与 IPC 入口同构的归一化：开关开但双限值均空/0 视作关闭，
                // 避免启动时装双 0 桶 + 残留旧内核全局条目
                let (enabled, up, down) = crate::bandwidth::kernel_sync::normalize_global_limit(
                    Some(settings.global_bandwidth_limit_enabled),
                    settings.global_upload_limit_kbps,
                    settings.global_download_limit_kbps,
                );
                // 无条件同步内核全局条目：enabled=false 时驱动侧 (0,0,0) 幂等
                // 删除 PID 0 条目，正好摘除上次崩溃退出（clear_kernel 未跑）
                // 残留的全局限速，否则它会继续限速到下一条连接事件覆盖。
                // 用户态桶仍仅在开启时装（与 IPC 入口同语义）。
                if enabled {
                    self.bandwidth_limiter.set_global_limits(up, down).await;
                }
                self.kernel_throttle.update_global(
                    driver,
                    enabled,
                    up.unwrap_or(0),
                    down.unwrap_or(0),
                ).await;
            }
            Err(e) => tracing::warn!("Failed to load global bandwidth settings: {}", e),
        }

        // 通知开关跟随服务端设置（D4：设置页的开关写入 settings，服务启动时生效）
        match self.db.get_settings().await {
            Ok(settings) => {
                self.notifier.set_enabled(settings.notifications_enabled);
                // 询问弹窗模式：默认拦截 + 开启"询问连接"时，未知程序联网产生 Ask 通知
                self.notifier.set_ask_mode(settings.ask_to_connect_enabled && !settings.default_allow);
            }
            Err(e) => tracing::warn!("Failed to load notification settings: {}", e),
        }



        // Start connection stats collection
        self.connection_tracker.start_stats_collection();
        tracing::info!("Connection stats collection started");

        // Start periodic snapshot of connections to history
        self.history_manager.start_periodic_snapshot(
            self.connection_tracker.clone(),
            self.running.clone(),
        );
        tracing::info!("Periodic connection snapshot started");

        // Start IPC server in background task
        let ipc_server = self.ipc_server.clone();
        tokio::spawn(async move {
            if let Err(e) = ipc_server.start().await {
                tracing::error!("IPC server error: {}", e);
            }
        });

        // Start domain rule expander in background task（影子条目不持久化，
        // 每次启动从空账本开始）
        {
            let domain_engine = self.domain_engine.clone();
            let dns_cache = self.dns_cache.clone();
            let running = self.running.clone();
            tokio::spawn(async move {
                domain_engine.run(dns_cache, running).await;
            });
        }

        // Start event processor in background task
        let driver = self.driver.clone().unwrap();
        let running = self.running.clone();
        let event_processor = self.event_processor.clone();
        tokio::spawn(async move {
            if let Err(e) = event_processor.start(driver, running).await {
                tracing::error!("Event processor error: {}", e);
            }
        });

        // Start periodic log flush (flush at least every 10s, not just when 100-entry buffer fills)
        {
            let event_processor = self.event_processor.clone();
            let running = self.running.clone();
            tokio::spawn(async move {
                event_processor.start_log_flusher(running).await;
            });
        }

        // DNS 缓存过期清理：cleanup_expired 此前没有任何调用点，缓存只增不减。
        // 每 5 分钟清一次过期项（过期阈值沿用 DnsCacheEntry::is_expired 的
        // TTL 定义）；清掉的条数打 debug 日志。
        {
            let dns_cache = self.dns_cache.clone();
            let running = self.running.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(5 * 60));
                loop {
                    interval.tick().await;
                    if !running.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    dns_cache.cleanup_expired().await;
                }
            });
        }

        // 每日数据库清理任务：清过期 network_history 与日志（两者目前都无
        // 其他调用方，VM 实测噪声事件约每秒 2 条，network_history 无界增长）。
        // interval 的首次 tick 立即返回，正好充当启动时的首次清理；之后每
        // 24 小时一次。保留天数每次执行时读取，改 log_retention_days 重启即生效
        {
            let db = self.db.clone();
            let running = self.running.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(24 * 60 * 60));
                loop {
                    interval.tick().await;
                    if !running.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let retention = match db.get_log_retention_days().await {
                        Ok(days) => days,
                        Err(e) => {
                            tracing::warn!("Failed to read log_retention_days, using default 30: {}", e);
                            30
                        }
                    };
                    if retention == 0 {
                        // retention 0 = 永不清理，读到后立即判断——任何
                        // DELETE 都不能发生在本判断之前
                        continue;
                    }
                    match db.clear_old_network_history(retention).await {
                        Ok(rows) => {
                            tracing::info!("Cleaned {} expired network_history rows (retention {} days)", rows, retention)
                        }
                        Err(e) => tracing::warn!("Failed to clean network_history: {}", e),
                    }
                    match db.cleanup_old_logs(retention).await {
                        Ok(rows) => {
                            tracing::info!("Cleaned {} expired log rows (retention {} days)", rows, retention)
                        }
                        Err(e) => tracing::warn!("Failed to clean logs: {}", e),
                    }
                    // 目录遍历 + 文件删除是同步 IO，丢到 blocking 线程池
                    let _ = tokio::task::spawn_blocking(move || {
                        clean_old_log_files(u64::from(retention))
                    })
                    .await;
                }
            });
        }
        
        tracing::info!("Service started successfully");
        
        // Keep service running
        while self.running.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping Ceasefire Firewall Service");
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);

        // Give the event processor a moment to exit its loop, then flush
        // any buffered log entries so shutdown does not lose them.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        if let Err(e) = self.event_processor.flush().await {
            tracing::error!("Failed to flush event logs during shutdown: {}", e);
        }

        // Stop IPC listening loop (P2-17: otherwise the accept loop never exits)
        self.ipc_server.stop();

        // Stop connection stats collection
        self.connection_tracker.stop_stats_collection();
        
        self.cleanup_wfp().await?;
        // 清空驱动内核限速表（否则条目会残留到驱动卸载）
        if let Some(driver) = self.driver.as_ref() {
            self.kernel_throttle.clear_kernel(driver).await;
        }
        self.unload_driver().await?;
        tracing::info!("Service stopped successfully");
        Ok(())
    }

    async fn load_driver(&mut self) -> Result<()> {
        tracing::info!("Loading WFP driver");
        if let Some(ref driver) = self.driver {
            driver.open().await?;
            // 启动即拉取驱动诊断：callout 注册失败（僵尸注册 =
            // FWP_E_ALREADY_EXISTS）此前只在内核 DbgPrint，用户态完全不可见
            match driver.get_diags().await {
                Ok(Some(raw)) => crate::driver::log_driver_diags(&raw),
                Ok(None) => tracing::warn!(
                    "driver predates IOCTL_GET_DIAGS: callout register status unavailable"
                ),
                Err(e) => tracing::warn!("failed to fetch driver diagnostics: {}", e),
            }
        }
        Ok(())
    }

    async fn unload_driver(&mut self) -> Result<()> {
        tracing::info!("Unloading WFP driver");
        if let Some(ref driver) = self.driver {
            driver.close().await?;
        }
        Ok(())
    }
    
    async fn initialize_wfp(&mut self) -> Result<()> {
        tracing::info!("Initializing WFP");
        
        // Create WFP engine
        let engine = Arc::new(WfpEngine::new()?);
        
        // Register provider and sublayer
        engine.register_provider()?;
        engine.register_sublayer()?;
        
        // Create filter manager
        let mut filter_manager = WfpFilterManager::new(engine.clone());
        
        // Register callouts
        filter_manager.register_callouts()?;
        
        // Add filters
        filter_manager.add_filters()?;
        
        self.wfp_engine = Some(engine.clone());
        if let Ok(mut slot) = self.wfp_engine_slot.lock() {
            *slot = Some(engine);
        }
        self.wfp_filter_manager = Some(filter_manager);
        
        tracing::info!("WFP initialized successfully");
        Ok(())
    }
    
    async fn cleanup_wfp(&mut self) -> Result<()> {
        tracing::info!("Cleaning up WFP");
        
        if let Some(ref mut filter_manager) = self.wfp_filter_manager {
            filter_manager.remove_filters()?;
            filter_manager.unregister_callouts()?;
        }
        
        if let Some(ref engine) = self.wfp_engine {
            engine.cleanup()?;
        }
        
        self.wfp_filter_manager = None;
        self.wfp_engine = None;
        if let Ok(mut slot) = self.wfp_engine_slot.lock() {
            *slot = None;
        }
        
        tracing::info!("WFP cleanup completed");
        Ok(())
    }
}
/// 清理日志目录里过期的滚动日志文件（ceasefire-service.log.YYYY-MM-DD）。
/// DB cleanup_old_logs 只清 logs 表，磁盘上的历史日志文件此前无人回收。
/// 逐文件容错：单个删除失败只 WARN 不中断。retention == 0 由调用方跳过。
fn clean_old_log_files(retention_days: u64) {
    let log_dir = std::path::Path::new(crate::LOG_DIR);
    let cutoff = std::time::SystemTime::now()
        - std::time::Duration::from_secs(retention_days * 24 * 60 * 60);

    let entries = match std::fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!("Failed to read log dir {:?}: {}", log_dir, e);
            return;
        }
    };

    let mut removed = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("ceasefire-service.log.") {
            continue;
        }
        let ok = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|modified| modified < cutoff)
            .unwrap_or(false);
        if !ok {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) => tracing::warn!("Failed to remove old log file {}: {}", entry.path().display(), e),
        }
    }
    tracing::info!("Cleaned {} old log files (retention {} days)", removed, retention_days);
}
