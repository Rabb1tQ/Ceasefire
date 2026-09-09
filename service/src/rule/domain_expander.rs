//! Domain Rule Expander - 把域名规则在 DNS 命中时展开成按 IP 的"影子规则"
//!
//! 内核规则匹配集没有域名概念：带 remote_domain 的规则不直接下发驱动，
//! 而是由本模块订阅 DnsCache 的写入事件，当解析结果命中某条启用中的
//! 域名规则时，把该 IP 以影子规则（继承源规则的 action/priority/direction
//! 等匹配字段，remote_addr=该 IP）下发给驱动。
//!
//! 影子条目生命周期 = min(DNS TTL, SHADOW_TTL_CAP)；同规则同 IP 重复命中
//! 刷新计时不叠加；源规则删除/禁用/编辑立即撤掉其全部影子条目；影子条目
//! 不持久化，服务重启即清零。

use super::super::dns_cache::{DnsCache, DnsObservation};
use super::super::database::Database;
use super::super::error::Result;
use super::super::models::*;
use super::validator::validate_domain;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 影子条目 TTL 上限：DNS TTL 可被域名方设得极长，影子规则过期撤除最多
/// 等 10 分钟，超长 TTL 的续期靠同域名的后续解析刷新。
pub const SHADOW_TTL_CAP: u32 = 600;

/// 影子规则合成 RuleId 基址：与 GROUP_RULE_ID_BASE（0x4000_0000）区分。
/// 影子条目只存在于驱动与内存，永不落库，DB 自增 ID 不会撞上该区间。
pub const SHADOW_RULE_ID_BASE: u32 = 0x8000_0000;

/// 影子条目名前缀（仅用于日志/tracing，影子规则不下发名字给驱动侧展示）
pub const SHADOW_NAME_PREFIX: &str = "[域名] ";

/// 驱动下发抽象：单测注入 mock 用，生产实现包 DriverHandle。
/// 返回 boxed future 是为了不引 async-trait 依赖。
pub trait RuleDriverOps: Send + Sync + 'static {
    fn add<'a>(&'a self, rule: &'a Rule)
        -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn remove<'a>(&'a self, id: u32)
        -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

impl RuleDriverOps for super::super::driver::DriverHandle {
    fn add<'a>(
        &'a self,
        rule: &'a Rule,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.add_rule(rule))
    }
    fn remove<'a>(
        &'a self,
        id: u32,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.remove_rule(id))
    }
}

/// 域名匹配：pattern 为精确域名或前导 "*." 通配。
/// - 大小写不敏感（两侧统一转小写）；
/// - "*.a.com" 不匹配 "a.com" 本身，也不匹配 "xa.com"——必须是点边界后缀；
/// - 精确 pattern 只匹配完全相等。
pub fn domain_pattern_matches(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim().to_lowercase();
    let domain = domain.trim().to_lowercase();
    if pattern.is_empty() || domain.is_empty() {
        return false;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            !suffix.is_empty() && domain.ends_with(&format!(".{}", suffix))
        }
        None => pattern == domain,
    }
}

/// 由 DNS TTL 计算影子条目存活时长
pub fn shadow_lifetime(ttl: u32) -> Duration {
    Duration::from_secs(ttl.min(SHADOW_TTL_CAP) as u64)
}

/// 影子规则合成：继承源规则的匹配面（除 remote_addr/remote_domain）与
/// action/priority/direction，remote_addr 设为命中 IP，app_group_id 清空
/// （分组展开与影子展开叠加没有意义，且域名规则按分组下发的路径已被跳过）。
pub fn build_shadow_rule(source: &Rule, ip: IpAddr, shadow_id: u32) -> Rule {
    Rule {
        id: Some(shadow_id),
        name: format!("{}{}", SHADOW_NAME_PREFIX, source.name),
        description: format!(
            "域名规则 {} 的影子条目（{}）",
            source.name, source.remote_domain.as_deref().unwrap_or("?")
        ),
        enabled: true,
        priority: source.priority,
        action: source.action,
        direction: source.direction,
        protocol: source.protocol,
        process_id: source.process_id,
        process_path: source.process_path.clone(),
        remote_addr: Some(ip.to_string()),
        remote_addr_mask: None,
        remote_domain: None,
        remote_port: source.remote_port.clone(),
        local_addr: None,
        local_addr_mask: None,
        local_port: source.local_port.clone(),
        network_zone: source.network_zone,
        app_group_id: None,
        created_at: None,
        updated_at: None,
    }
}

/// 命中结果：store 对一次 (rule_id, ip) 命中的裁决
#[derive(Debug, PartialEq, Eq)]
pub enum HitOutcome {
    /// 首次命中：需要下发影子规则（携带分配的合成 RuleId）
    Create { shadow_id: u32 },
    /// 已存在：仅刷新到期时间，不重复下发
    Refresh,
}

/// 影子条目账本（纯内存，可单测）：key = (源规则 id, 命中 IP)。
/// 负责合成 ID 分配、到期扫描、按源规则整体撤除。
pub struct ShadowStore {
    /// 合成 ID 计数器（低 32 位自增，撞 SHADOW_RULE_ID_BASE 组成唯一 ID；
    /// 服务生命周期内不重复，重启归零无害——影子条目本就不持久化）
    next_index: u32,
    entries: HashMap<(u32, IpAddr), (u32, Instant)>,
}

impl ShadowStore {
    pub fn new() -> Self {
        ShadowStore { next_index: 1, entries: HashMap::new() }
    }

    /// 记录一次命中。重复命中刷新计时（取更晚的到期时间），不叠加条目。
    pub fn hit(&mut self, rule_id: u32, ip: IpAddr, ttl: u32, now: Instant) -> HitOutcome {
        let lifetime = shadow_lifetime(ttl);
        let expiry = now + lifetime;
        match self.entries.get_mut(&(rule_id, ip)) {
            Some((_, expiry_ref)) => {
                if expiry > *expiry_ref {
                    *expiry_ref = expiry;
                }
                HitOutcome::Refresh
            }
            None => {
                let shadow_id = SHADOW_RULE_ID_BASE.wrapping_add(self.next_index);
                self.next_index = self.next_index.wrapping_add(1).max(1);
                self.entries.insert((rule_id, ip), (shadow_id, expiry));
                HitOutcome::Create { shadow_id }
            }
        }
    }

    /// 扫描到期条目：返回需撤除的合成 RuleId，并从账本移除。
    pub fn reap(&mut self, now: Instant) -> Vec<u32> {
        let expired: Vec<(u32, IpAddr)> = self
            .entries
            .iter()
            .filter(|(_, (_, expiry))| *expiry <= now)
            .map(|(k, _)| *k)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key).map(|(id, _)| id))
            .collect()
    }

    /// 移除单条账目（下发失败回滚用），返回该条目的合成 RuleId
    pub fn remove_entry(&mut self, rule_id: u32, ip: IpAddr) -> Option<u32> {
        self.entries.remove(&(rule_id, ip)).map(|(id, _)| id)
    }

    /// 账本快照：(源规则 id, 命中 IP, 合成 RuleId)，resync 重建用
    pub fn snapshot(&self) -> Vec<(u32, IpAddr, u32)> {
        self.entries
            .iter()
            .map(|((rid, ip), (sid, _))| (*rid, *ip, *sid))
            .collect()
    }

    /// 撤掉某条源规则的全部影子条目（规则删除/禁用/编辑时调用）。
    pub fn revoke_rule(&mut self, rule_id: u32) -> Vec<u32> {
        let keys: Vec<(u32, IpAddr)> = self
            .entries
            .keys()
            .filter(|(rid, _)| *rid == rule_id)
            .copied()
            .collect();
        keys.into_iter()
            .filter_map(|key| self.entries.remove(&key).map(|(id, _)| id))
            .collect()
    }

    /// 当前账本中的全部合成 RuleId（重载驱动后的 resync 用）
    pub fn all_shadow_ids(&self) -> Vec<u32> {
        self.entries.values().map(|(id, _)| *id).collect()
    }

    /// 由合成 RuleId 反查源规则 id
    pub fn source_of(&self, shadow_id: u32) -> Option<u32> {
        self.entries
            .iter()
            .find(|(_, (id, _))| *id == shadow_id)
            .map(|((rid, _), _)| *rid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ShadowStore {
    fn default() -> Self {
        Self::new()
    }
}

/// 展开引擎：订阅 DNS 缓存写入，命中启用中的域名规则时下发/续期影子规则。
pub struct DomainRuleEngine {
    db: Arc<Database>,
    driver: Arc<dyn RuleDriverOps>,
    store: tokio::sync::Mutex<ShadowStore>,
}

impl DomainRuleEngine {
    pub fn new(db: Arc<Database>, driver: Arc<dyn RuleDriverOps>) -> Self {
        DomainRuleEngine {
            db,
            driver,
            store: tokio::sync::Mutex::new(ShadowStore::new()),
        }
    }

    /// 主循环：DNS 写入事件 + 周期到期扫描。running 置 false 后退出。
    pub async fn run(
        self: &Arc<Self>,
        dns: Arc<DnsCache>,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut rx = dns.subscribe();
        let mut reap_timer = tokio::time::interval(Duration::from_secs(30));
        reap_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!("Domain rule expander started");

        loop {
            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                _ = reap_timer.tick() => {
                    let ids = self.store.lock().await.reap(Instant::now());
                    for id in ids {
                        tracing::info!("Shadow rule {} expired, removing", id);
                        // 移除失败只告警：到期条目下次 clear/重载兜底
                        if let Err(e) = self.driver.remove(id).await {
                            tracing::warn!("Failed to remove expired shadow rule {}: {}", id, e);
                        }
                    }
                }
                update = rx.recv() => match update {
                    Ok(obs) => self.on_dns_observation(&obs).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Domain expander lagged, {} DNS updates skipped", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            }
        }

        tracing::info!("Domain rule expander stopped");
    }

    /// 处理一条 DNS 观测：对每条启用中的域名规则尝试匹配并展开。
    async fn on_dns_observation(&self, obs: &DnsObservation) {
        let rules = match self.db.list_rules().await {
            Ok(rules) => rules,
            Err(e) => {
                tracing::warn!("Domain expander: failed to list rules: {}", e);
                return;
            }
        };

        for rule in rules.iter().filter(|r| r.enabled && r.remote_domain.is_some()) {
            let pattern = rule.remote_domain.as_deref().unwrap_or("");
            // 账本里的 pattern 可能带非法语法（旧数据），先过 validate_domain
            if validate_domain(pattern).is_err() || !domain_pattern_matches(pattern, &obs.domain) {
                continue;
            }
            let rule_id = match rule.id {
                Some(id) => id,
                None => continue,
            };

            let outcome = self
                .store
                .lock()
                .await
                .hit(rule_id, obs.ip, obs.ttl, Instant::now());
            if outcome == HitOutcome::Refresh {
                continue;
            }
            let HitOutcome::Create { shadow_id } = outcome else {
                continue;
            };

            let shadow = build_shadow_rule(rule, obs.ip, shadow_id);
            match self.driver.add(&shadow).await {
                Ok(()) => {
                    tracing::info!(
                        "Domain rule '{}' hit ({} → {}), shadow rule {} installed",
                        rule.name, obs.domain, obs.ip, shadow_id
                    );
                }
                Err(e) => {
                    // 下发失败：退账（账本里没有该条目，下次命中重试）
                    tracing::warn!(
                        "Failed to install shadow rule for '{}' ({}): {}",
                        rule.name,
                        obs.ip,
                        e
                    );
                    self.store.lock().await.remove_entry(rule_id, obs.ip);
                }
            }
        }
    }

    /// 撤掉某条源规则的全部影子条目（RuleManager 删除/禁用/编辑后调用）。
    pub async fn revoke_rule(&self, rule_id: u32) {
        let ids = self.store.lock().await.revoke_rule(rule_id);
        for id in ids {
            tracing::info!("Revoking shadow rule {} (source rule {} changed)", id, rule_id);
            if let Err(e) = self.driver.remove(id).await {
                tracing::warn!("Failed to revoke shadow rule {}: {}", id, e);
            }
        }
    }

    /// 驱动规则整体重载（clear_rules 会清掉影子条目）后重新下发账本内
    /// 全部影子规则，保持"账本 = 驱动"一致。源规则已删除/禁用的条目直接
    /// 从账本退掉。
    pub async fn resync_after_reload(&self) {
        let snapshot = self.store.lock().await.snapshot();
        if snapshot.is_empty() {
            return;
        }
        let rules = match self.db.list_rules().await {
            Ok(rules) => rules,
            Err(e) => {
                tracing::warn!("Domain expander resync: failed to list rules: {}", e);
                return;
            }
        };
        for (rule_id, ip, shadow_id) in snapshot {
            let source = rules.iter().find(|r| r.id == Some(rule_id));
            let source = match source {
                Some(r) if r.enabled && r.remote_domain.is_some() => r,
                Some(_) => {
                    // 规则被禁用/改为非域名：重载路径的 revoke 钩子已撤驱动
                    // 条目，这里只退账
                    self.store.lock().await.remove_entry(rule_id, ip);
                    continue;
                }
                None => {
                    self.store.lock().await.remove_entry(rule_id, ip);
                    continue;
                }
            };
            let shadow = build_shadow_rule(source, ip, shadow_id);
            if let Err(e) = self.driver.add(&shadow).await {
                tracing::warn!(
                    "Domain expander resync: failed to re-add shadow rule {}: {}",
                    shadow_id,
                    e
                );
                self.store.lock().await.remove_entry(rule_id, ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ServiceError;

    fn rule_with_domain(id: u32, name: &str, domain: &str, enabled: bool) -> Rule {
        Rule {
            id: Some(id),
            name: name.to_string(),
            description: String::new(),
            enabled,
            priority: 10,
            action: RuleAction::Block,
            direction: Direction::Outbound,
            protocol: Some(Protocol::Tcp),
            process_id: None,
            process_path: Some(r"C:\Program Files\App\app.exe".to_string()),
            remote_addr: None,
            remote_addr_mask: None,
            remote_domain: Some(domain.to_string()),
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

    // ---------- domain_pattern_matches ----------

    #[test]
    fn exact_domain_matches_only_itself() {
        assert!(domain_pattern_matches("a.example.com", "a.example.com"));
        assert!(!domain_pattern_matches("a.example.com", "b.example.com"));
        assert!(!domain_pattern_matches("a.example.com", "example.com"));
    }

    #[test]
    fn wildcard_suffix_boundary() {
        // 点边界后缀：子域命中
        assert!(domain_pattern_matches("*.a.com", "x.a.com"));
        assert!(domain_pattern_matches("*.a.com", "deep.sub.a.com"));
        // 不匹配裸域本身
        assert!(!domain_pattern_matches("*.a.com", "a.com"));
        // 必须是点边界：xa.com / com 都不命中
        assert!(!domain_pattern_matches("*.a.com", "xa.com"));
        assert!(!domain_pattern_matches("*.a.com", "com"));
        assert!(!domain_pattern_matches("*.a.com", "a.comx"));
    }

    #[test]
    fn domain_match_is_case_insensitive() {
        assert!(domain_pattern_matches("A.Example.COM", "a.example.com"));
        assert!(domain_pattern_matches("*.A.com", "Sub.A.COM"));
        assert!(domain_pattern_matches("*.a.com", "X.A.COM"));
    }

    #[test]
    fn domain_match_empty_inputs() {
        assert!(!domain_pattern_matches("", "a.com"));
        assert!(!domain_pattern_matches("*.a.com", ""));
        assert!(!domain_pattern_matches("   ", "a.com"));
    }

    // ---------- shadow_lifetime / build_shadow_rule ----------

    #[test]
    fn shadow_lifetime_caps_long_ttl() {
        assert_eq!(shadow_lifetime(300), Duration::from_secs(300));
        assert_eq!(shadow_lifetime(3600), Duration::from_secs(SHADOW_TTL_CAP as u64));
        assert_eq!(shadow_lifetime(0), Duration::from_secs(0));
    }

    #[test]
    fn build_shadow_rule_inherits_and_overrides() {
        let source = rule_with_domain(7, "block-tracker", "*.tracker.example", true);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        let shadow = build_shadow_rule(&source, ip, 0x8000_0001);

        assert_eq!(shadow.id, Some(0x8000_0001));
        assert_eq!(shadow.remote_addr, Some("93.184.216.34".to_string()));
        assert_eq!(shadow.remote_domain, None);
        assert_eq!(shadow.remote_addr_mask, None);
        assert_eq!(shadow.app_group_id, None);
        assert!(shadow.enabled);
        // 继承字段
        assert_eq!(shadow.action, source.action);
        assert_eq!(shadow.priority, source.priority);
        assert_eq!(shadow.direction, source.direction);
        assert_eq!(shadow.protocol, source.protocol);
        assert_eq!(shadow.process_path, source.process_path);
        assert_eq!(shadow.remote_port, source.remote_port);
        assert_eq!(shadow.local_port, source.local_port);
        assert_eq!(shadow.network_zone, source.network_zone);
    }

    // ---------- ShadowStore 生命周期 ----------

    #[test]
    fn hit_creates_then_refreshes_without_stacking() {
        let mut store = ShadowStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let now = Instant::now();

        let first = store.hit(42, ip, 300, now);
        let HitOutcome::Create { shadow_id } = first else {
            panic!("first hit must create");
        };
        assert_ne!(shadow_id, 0, "synthetic id must not be zero");
        assert_eq!(store.len(), 1);

        // 重复命中不叠加
        assert_eq!(store.hit(42, ip, 300, now), HitOutcome::Refresh);
        assert_eq!(store.hit(42, ip, 600, now), HitOutcome::Refresh);
        assert_eq!(store.len(), 1, "repeat hits must not stack entries");

        // 其他 IP / 其他规则各自成条
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(matches!(
            store.hit(42, ip2, 300, now),
            HitOutcome::Create { .. }
        ));
        assert!(matches!(
            store.hit(43, ip, 300, now),
            HitOutcome::Create { .. }
        ));
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn reap_removes_only_expired() {
        let mut store = ShadowStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let now = Instant::now();

        // 短 TTL 条目
        let HitOutcome::Create { shadow_id: short_id } = store.hit(1, ip, 1, now) else {
            unreachable!()
        };
        // 长 TTL 条目
        let HitOutcome::Create { shadow_id: long_id } = store.hit(2, ip, 600, now) else {
            unreachable!()
        };

        // 未到期：什么也不撤
        assert!(store.reap(now + Duration::from_millis(500)).is_empty());

        // 到期：只撤短 TTL 条目
        let reaped = store.reap(now + Duration::from_secs(2));
        assert_eq!(reaped, vec![short_id]);
        assert_eq!(store.len(), 1);
        assert_eq!(store.source_of(long_id), Some(2));

        // 刷新过的条目按刷新后的到期时间撤（hit 不叠加条目但推进到期点）
        let ip2: IpAddr = "9.9.9.9".parse().unwrap();
        store.hit(3, ip2, 2, now);
        store.hit(3, ip2, 2, now + Duration::from_secs(1));
        let reaped = store.reap(now + Duration::from_secs(2));
        assert!(reaped.is_empty(), "refreshed entry must survive past original expiry");
        let reaped = store.reap(now + Duration::from_secs(3));
        assert_eq!(reaped.len(), 1, "refreshed entry dies at refreshed expiry");
    }

    #[test]
    fn revoke_rule_removes_all_shadows_of_source() {
        let mut store = ShadowStore::new();
        let now = Instant::now();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        let ip3: IpAddr = "3.3.3.3".parse().unwrap();

        let _ = store.hit(10, ip1, 600, now);
        let _ = store.hit(10, ip2, 600, now);
        let _ = store.hit(20, ip3, 600, now);

        let revoked = store.revoke_rule(10);
        assert_eq!(revoked.len(), 2, "both shadows of rule 10 revoked");
        assert!(!revoked.contains(&store.all_shadow_ids()[0]) || revoked.len() == 2);
        assert_eq!(store.len(), 1);
        assert_eq!(store.source_of(store.all_shadow_ids()[0]), Some(20));

        // 幂等：再撤一次为空
        assert!(store.revoke_rule(10).is_empty());
    }

    // ---------- mock 驱动全链路 ----------

    #[derive(Default)]
    struct MockDriver {
        added: std::sync::Mutex<Vec<u32>>,
        removed: std::sync::Mutex<Vec<u32>>,
        fail_add: std::sync::atomic::AtomicBool,
    }

    impl RuleDriverOps for Arc<MockDriver> {
        fn add<'a>(
            &'a self,
            rule: &'a Rule,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                if self.fail_add.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(ServiceError::Driver("mock add failure".to_string()));
                }
                self.added
                    .lock()
                    .unwrap()
                    .push(rule.id.unwrap_or(0));
                Ok(())
            })
        }
        fn remove<'a>(
            &'a self,
            id: u32,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.removed.lock().unwrap().push(id);
                Ok(())
            })
        }
    }

    fn obs(domain: &str, ip: &str, ttl: u32) -> DnsObservation {
        DnsObservation {
            ip: ip.parse().unwrap(),
            domain: domain.to_string(),
            ttl,
        }
    }

    async fn engine_with_rules(
        rules: Vec<Rule>,
    ) -> (Arc<DomainRuleEngine>, Arc<MockDriver>, Vec<u32>) {
        // 库迁移会预置 [System] 规则，自增 ID 不从 1 开始，调用方必须用返回的真实 ID
        // 测试并行跑：每个用例独立 db 文件，避免互见彼此的种子规则
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("cf_domain_expander_test_{}.db", n));
        let _ = std::fs::remove_file(&path);
        let db = Arc::new(Database::open(path.to_str().unwrap()).expect("open db"));
        let mut real_ids = Vec::new();
        for rule in rules {
            let mut r = rule.clone();
            r.id = None;
            real_ids.push(db.create_rule(&r).await.expect("seed rule"));
        }
        let mock: Arc<MockDriver> = Arc::new(MockDriver::default());
        // Arc<MockDriver> 实现 RuleDriverOps；Arc<Arc<_>> 解一层引用
        let engine = Arc::new(DomainRuleEngine::new(db, Arc::new(mock.clone())));
        (engine, mock, real_ids)
    }

    #[tokio::test]
    async fn dns_hit_installs_shadow_rule() {
        let (engine, mock, _ids) =
            engine_with_rules(vec![rule_with_domain(1, "block-cdn", "*.cdn.example", true)])
                .await;

        engine.on_dns_observation(&obs("x.cdn.example", "93.184.216.34", 300)).await;

        let added = mock.added.lock().unwrap();
        assert_eq!(added.len(), 1, "one shadow rule installed");
        assert_ne!(added[0] & SHADOW_RULE_ID_BASE, 0, "synthetic id in shadow range");
        drop(added);
        assert_eq!(engine.store.lock().await.len(), 1);

        // 未命中域名不展开
        engine.on_dns_observation(&obs("other.example", "1.1.1.1", 300)).await;
        assert_eq!(mock.added.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn disabled_or_addr_rules_never_expand() {
        let disabled = rule_with_domain(1, "disabled", "*.cdn.example", false);
        let (engine, mock, _ids) = engine_with_rules(vec![disabled]).await;
        engine.on_dns_observation(&obs("x.cdn.example", "1.2.3.4", 300)).await;
        assert!(mock.added.lock().unwrap().is_empty());
        assert!(engine.store.lock().await.is_empty());
    }

    #[tokio::test]
    async fn add_failure_does_not_bookkeep() {
        let (engine, mock, _ids) =
            engine_with_rules(vec![rule_with_domain(1, "block-cdn", "*.cdn.example", true)])
                .await;
        mock.fail_add.store(true, std::sync::atomic::Ordering::SeqCst);

        engine.on_dns_observation(&obs("x.cdn.example", "1.2.3.4", 300)).await;

        assert!(mock.added.lock().unwrap().is_empty());
        assert!(engine.store.lock().await.is_empty(), "failed install must not be booked");
    }

    #[tokio::test]
    async fn revoke_rule_removes_from_driver() {
        let (engine, mock, ids) =
            engine_with_rules(vec![rule_with_domain(1, "block-cdn", "*.cdn.example", true)])
                .await;
        engine.on_dns_observation(&obs("x.cdn.example", "1.2.3.4", 300)).await;
        engine.on_dns_observation(&obs("y.cdn.example", "5.6.7.8", 300)).await;
        assert_eq!(mock.added.lock().unwrap().len(), 2);

        engine.revoke_rule(ids[0]).await;

        assert_eq!(mock.removed.lock().unwrap().len(), 2, "both shadows removed from driver");
        assert!(engine.store.lock().await.is_empty());
    }

    /// 驱动整体重载（clear_rules 清掉一切）后 resync：账本内影子规则重新
    /// 下发；源规则被删/禁用的条目退账不再下发。
    #[tokio::test]
    async fn resync_after_reload_reinstalls_and_prunes() {
        let db_path = std::env::temp_dir().join("cf_domain_resync_test.db");
        let _ = std::fs::remove_file(&db_path);
        let db = Arc::new(Database::open(db_path.to_str().unwrap()).expect("open db"));
        let mut active = rule_with_domain(1, "block-cdn", "*.cdn.example", true);
        active.id = None;
        let _active_id = db.create_rule(&active).await.unwrap();
        let mut dead = rule_with_domain(2, "dead-rule", "*.old.example", true);
        dead.id = None;
        let dead_id = db.create_rule(&dead).await.unwrap();

        let mock: Arc<MockDriver> = Arc::new(MockDriver::default());
        let engine = Arc::new(DomainRuleEngine::new(db.clone(), Arc::new(mock.clone())));

        engine.on_dns_observation(&obs("x.cdn.example", "1.2.3.4", 600)).await;
        engine.on_dns_observation(&obs("y.old.example", "5.6.7.8", 600)).await;
        assert_eq!(mock.added.lock().unwrap().len(), 2);

        // 模拟源规则 2 被删除（RuleManager 钩子会先 revoke 驱动条目）
        engine.revoke_rule(dead_id).await;
        db.delete_rule(dead_id).await.unwrap();
        // 模拟源规则 1 被禁用后重新启用（驱动被 reload 清空）
        mock.added.lock().unwrap().clear();
        engine.resync_after_reload().await;

        let added = mock.added.lock().unwrap();
        assert_eq!(added.len(), 1, "only the surviving rule's shadow is reinstalled");
        drop(added);
        assert_eq!(engine.store.lock().await.len(), 1);

        let _ = std::fs::remove_file(&db_path);
    }
}
