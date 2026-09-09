//! Rule Manager - manages firewall rules

use super::super::error::{Result, ServiceError};
use super::super::models::*;
use super::super::database::Database;
use super::super::driver::DriverHandle;
use std::sync::Arc;

/// 分组规则展开条目的合成 RuleId 基址：DB 自增规则 ID 从 1 开始且远小于
/// 0x4000_0000，两者不会冲突；每个规则最多展开 4096 个成员。
const GROUP_RULE_ID_BASE: u32 = 0x4000_0000;

fn expanded_rule_id(rule_id: u32, member_index: usize) -> u32 {
    GROUP_RULE_ID_BASE
        .wrapping_add(rule_id.wrapping_shl(12))
        .wrapping_add((member_index as u32) & 0xFFF)
}

/// 判断两条规则的匹配字段是否全部相等（create_rule 查重用）。
/// 只比较影响内核匹配行为的字段：direction/protocol/process_id/
/// process_path/地址与端口（含掩码）/network_zone/app_group_id（后两者与
/// matchset_covers 的 zone/group 口径对齐：仅 zone 或分组不同的规则不算
/// 重复，否则合并会把新值的 zone/分组静默丢成旧值）；action 不参与比较——参考
/// TinyWall/simplewall 的"每匹配集单条规则"设计，同一匹配集的
/// Allow/Block 并存靠优先级裁决容易堆积重复，改为命中后以本次决定
/// 为准就地合并（action/enabled/name/description 覆盖为传入值）。
/// PortRange 已实现 PartialEq，直接比较。
/// 内置规则的幂等安装（system_rules.rs）走按名字精确匹配，不经过
/// create_rule 的本查重路径；即使将来某条用户规则与系统规则字段全同，
/// 也不会影响 ensure_installed 的按名查找（名字不同则查不到、仍会按名
/// 新建，只会多一条用户规则，不破坏系统规则语义）。
fn same_effective_fields(a: &Rule, b: &Rule) -> bool {
    a.direction == b.direction
        && a.protocol == b.protocol
        && a.process_path == b.process_path
        && a.process_id == b.process_id
        && a.remote_addr == b.remote_addr
        && a.remote_addr_mask == b.remote_addr_mask
        && a.remote_domain == b.remote_domain
        && a.remote_port == b.remote_port
        && a.local_addr == b.local_addr
        && a.local_addr_mask == b.local_addr_mask
        && a.local_port == b.local_port
        && a.network_zone == b.network_zone
        && a.app_group_id == b.app_group_id
}

/// 地址字段（addr + 可选 mask / CIDR 字符串）的包含判定：broad 网段 ⊇ narrow
/// 网段时为真。口径与 manager::address_matches / validator::cidr_matches 一致：
/// mask=None 表示精确主机匹配（等价于满前缀）；/0 只匹配同族全部地址，异族不覆盖。
fn addr_field_covers(
    broad_addr: Option<&str>,
    broad_mask: Option<u8>,
    narrow_addr: Option<&str>,
    narrow_mask: Option<u8>,
) -> bool {
    let narrow_addr = match narrow_addr {
        None => return true,
        Some(a) => a,
    };
    let (broad_addr, broad_mask) = match broad_addr {
        None => return false,
        Some(a) => (a, broad_mask),
    };
    let parse_field = |addr: &str, mask: Option<u8>| -> Option<(std::net::IpAddr, u8)> {
        if addr.contains('/') {
            super::validator::validate_cidr(addr).ok()
        } else {
            let ip = addr.parse::<std::net::IpAddr>().ok()?;
            let host_bits = match ip {
                std::net::IpAddr::V4(_) => 32,
                std::net::IpAddr::V6(_) => 128,
            };
            Some((ip, mask.unwrap_or(host_bits)))
        }
    };
    let (Some((bip, bmask)), Some((nip, nmask))) = (
        parse_field(broad_addr, broad_mask),
        parse_field(narrow_addr, narrow_mask),
    ) else {
        // 解析失败按不覆盖处理（宁可不合并，也不错杀）
        return false;
    };
    if bmask > nmask {
        return false;
    }
    match (bip, nip) {
        (std::net::IpAddr::V4(b), std::net::IpAddr::V4(n)) => {
            let m = if bmask == 0 { 0u32 } else { !0u32 << (32 - bmask) };
            (u32::from(b) & m) == (u32::from(n) & m)
        }
        (std::net::IpAddr::V6(b), std::net::IpAddr::V6(n)) => {
            let m = if bmask == 0 {
                0u128
            } else if bmask >= 128 {
                !0u128
            } else {
                !0u128 << (128 - bmask)
            };
            (u128::from(b) & m) == (u128::from(n) & m)
        }
        // V4/V6 异族：驱动 MatchRules 对异族直接跳过，视为不覆盖
        _ => false,
    }
}

/// 端口字段的包含判定：None 覆盖任意；Single 只覆盖相等 Single；
/// Range 覆盖自身包含的 Range 与落在其中的 Single。
fn port_covers(broad: Option<&PortRange>, narrow: Option<&PortRange>) -> bool {
    match (broad, narrow) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(PortRange::Single(a)), Some(PortRange::Single(b))) => a == b,
        (Some(PortRange::Range(s, e)), Some(PortRange::Range(ns, ne))) => s <= ns && ne <= e,
        (Some(PortRange::Range(s, e)), Some(PortRange::Single(p))) => s <= p && p <= e,
        (Some(PortRange::Single(_)), Some(PortRange::Range(_, _))) => false,
    }
}

/// 判断 broad 的匹配集是否完全覆盖 narrow（shadowed/redundant rule 检测）。
/// broad 覆盖 narrow 意味着：任何被 narrow 命中的连接必然也被 broad 命中，
/// 两者 action 相同时 narrow 即为冗余规则。逐字段口径：
/// - direction：Both 覆盖 Inbound/Outbound，相等覆盖，其余不覆盖
/// - protocol：None（及 Any，语义同 matches_rule 的任意协议）覆盖任意，Some 相等覆盖
/// - process_path：对齐 driver/src/rules.c MatchRules 的真实匹配语义——
///   WcsEndsWithIgnoreCase(连接完整路径, 规则路径)，即规则路径是连接路径的
///   忽略大小写后缀。因此 broad 是 narrow 的（忽略大小写）后缀时覆盖
///   （narrow 命中的每个路径尾部都含 broad），反向不算
/// - process_id：None 覆盖，相等覆盖
/// - 地址/端口：见 addr_field_covers / port_covers
/// - network_zone/app_group_id：None 覆盖，相等覆盖。注意 create_rule 的
///   收敛合并路径额外要求两侧 zone/分组精确相等才允许合并（见该处注释），
///   本函数保持纯覆盖语义
fn matchset_covers(broad: &Rule, narrow: &Rule) -> bool {
    let direction_covers = broad.direction == Direction::Both
        || broad.direction == narrow.direction;
    let protocol_covers = match broad.protocol {
        None | Some(Protocol::Any) => true,
        Some(p) => Some(p) == narrow.protocol,
    };
    let path_covers = match (&broad.process_path, &narrow.process_path) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(b), Some(n)) => {
            // 驱动是后缀匹配：连接路径以规则路径结尾才算命中，
            // 故 broad 覆盖 narrow 当且仅当 narrow 路径以 broad 路径结尾
            let (b_lower, n_lower) = (b.to_lowercase(), n.to_lowercase());
            n_lower.ends_with(&b_lower)
        }
    };
    let pid_covers = match broad.process_id {
        None => true,
        Some(id) => narrow.process_id == Some(id),
    };
    let zone_covers = match broad.network_zone {
        None => true,
        Some(z) => narrow.network_zone == Some(z),
    };
    let group_covers = match broad.app_group_id {
        None => true,
        Some(g) => narrow.app_group_id == Some(g),
    };
    // 域名条件：不做包含推导（通配对精确的后缀覆盖关系不映射到 IP 命中面），
    // 两侧相等才视为覆盖；任一侧带域名而另一侧不带，一概不覆盖
    let domain_covers = broad.remote_domain == narrow.remote_domain;

    direction_covers
        && protocol_covers
        && path_covers
        && pid_covers
        && zone_covers
        && group_covers
        && domain_covers
        && addr_field_covers(
            broad.remote_addr.as_deref(),
            broad.remote_addr_mask,
            narrow.remote_addr.as_deref(),
            narrow.remote_addr_mask,
        )
        && addr_field_covers(
            broad.local_addr.as_deref(),
            broad.local_addr_mask,
            narrow.local_addr.as_deref(),
            narrow.local_addr_mask,
        )
        && port_covers(broad.remote_port.as_ref(), narrow.remote_port.as_ref())
        && port_covers(broad.local_port.as_ref(), narrow.local_port.as_ref())
}

pub struct RuleManager {
    pub(crate) db: Arc<Database>,
    driver: Arc<DriverHandle>,
    /// 域名规则展开引擎（firewall_service 组装后注入；None 时域名规则仅存 DB）
    domain_engine: std::sync::Mutex<Option<Arc<super::domain_expander::DomainRuleEngine>>>,
}

impl RuleManager {
    pub fn new(db: Arc<Database>, driver: Arc<DriverHandle>) -> Result<Self> {
        Ok(RuleManager {
            db,
            driver,
            domain_engine: std::sync::Mutex::new(None),
        })
    }

    /// 注入域名展开引擎（firewall_service::new 组装顺序：先建 RuleManager
    /// 再建引擎，故不能走构造参数）
    pub fn set_domain_engine(&self, engine: Arc<super::domain_expander::DomainRuleEngine>) {
        *self.domain_engine.lock().unwrap() = Some(engine);
    }

    fn domain_engine(&self) -> Option<Arc<super::domain_expander::DomainRuleEngine>> {
        self.domain_engine.lock().unwrap().clone()
    }

    pub async fn create_rule(&self, mut rule: Rule) -> Result<Rule> {
        super::validator::validate_rule(&rule)?;

        // 查重在落库与驱动下发之前：匹配字段全同的规则（不比 action）以本次
        // 决定为准，复用 update_rule 就地覆盖 action/enabled/name/description
        // （action 翻转时 update 路径内部会同步驱动条目），不重复插入 DB、
        // 不堆积同匹配集的 Allow/Block。
        //
        // [System] 前缀的内置规则**不参与任何合并**，两侧都豁免：
        // - 库里已有的 [System] 规则被 existing 过滤剔除——合并会覆盖其
        //   name，而 system_rules.rs 的幂等安装/卸载按名字精确匹配，改名后
        //   开关系统豁免时会再装一条同名新规则，合并反而制造重复；
        // - 传入规则本身带 [System] 前缀时（ensure_installed → create_rule）
        //   整体跳过下方三条合并路径——否则同动作、匹配集相同的用户规则会被
        //   就地改名成 [System] 前缀，之后关闭系统豁免时 remove_all 按前缀
        //   删除会无声清掉用户规则。传入 [System] 规则的同名幂等由
        //   ensure_installed 的按名查重保证，不依赖本查重路径。
        // 用户对系统程序的弹窗决策照常新建自己的 [弹窗] 规则，与其他
        // [弹窗] 规则之间仍正常去重。
        if !rule.name.starts_with(super::system_rules::SYSTEM_RULE_PREFIX) {
            let existing: Vec<Rule> = self
                .list_rules()
                .await?
                .into_iter()
                .filter(|r| !r.name.starts_with(super::system_rules::SYSTEM_RULE_PREFIX))
                .collect();
            if let Some(dup) = existing.iter().find(|r| same_effective_fields(r, &rule)) {
                let id = dup.id.unwrap_or(0);
                let mut merged = dup.clone();
                merged.action = rule.action;
                merged.enabled = rule.enabled;
                merged.name = rule.name.clone();
                merged.description = rule.description.clone();
                self.update_rule(id, merged.clone()).await?;
                tracing::info!(
                    "duplicate rule merged into existing id={} (action={:?})",
                    id,
                    merged.action
                );
                return Ok(merged);
            }

        // 包含关系收敛（shadowed/redundant rule）：action 不同时任何情况都不
        // 合并——不同 action 的遮蔽是意图冲突，不可自动处理。
        // zone/分组不同的两条规则即使匹配集覆盖也不合并：None 在覆盖语义上
        // 更宽，但用户显式指定 zone/分组代表独立意图，就地合并会把新值的
        // zone/分组静默丢成旧值（与 same_effective_fields 的精确相等口径
        // 一致，宁可不收敛）。
        // 顺序：先看新建规则是否更宽、吞并既有更窄规则；再判断新建规则是否
        // 被既有更宽规则覆盖。多条命中取列表第一条。
        if let Some(b) = existing
            .iter()
            .find(|r| r.action == rule.action
                && r.network_zone == rule.network_zone
                && r.app_group_id == rule.app_group_id
                && matchset_covers(&rule, r))
        {
                // 新建规则更宽：既有规则 b 的匹配字段整体替换为传入匹配字段，
                // 元信息（name/description/enabled）取传入值，action 已同，沿用
                // b 的 id/priority 等身份字段就地覆盖
                let id = b.id.unwrap_or(0);
                let mut merged = rule.clone();
                merged.id = Some(id);
                merged.action = b.action;
                merged.priority = b.priority;
                merged.created_at = b.created_at.clone();
                self.update_rule(id, merged.clone()).await?;
                tracing::info!("broader rule replaces narrower id={} (action={:?})", id, merged.action);
                return Ok(merged);
            }
        if let Some(a) = existing
            .iter()
            .find(|r| r.action == rule.action
                && r.network_zone == rule.network_zone
                && r.app_group_id == rule.app_group_id
                && matchset_covers(r, &rule))
        {
                // 已有更宽规则覆盖新建规则：新规则无增量，仅把元信息合并进 a
                let id = a.id.unwrap_or(0);
                let mut merged = a.clone();
                merged.name = rule.name.clone();
                merged.description = rule.description.clone();
                merged.enabled = rule.enabled;
                self.update_rule(id, merged.clone()).await?;
                tracing::info!("rule covered by broader rule id={} (action={:?})", id, merged.action);
                return Ok(merged);
            }
        }

        if rule.priority == 0 {
            rule.priority = self.get_next_priority().await?;
        }

        let id = self.db.create_rule(&rule).await?;
        rule.id = Some(id);

        if rule.enabled {
            // 域名规则不直接下发驱动（内核无域名匹配面，直发等于"任意远端
            // 地址"的全量规则）：由 domain_expander 在 DNS 命中时展开影子条目
            if rule.remote_domain.is_some() {
                tracing::info!(
                    "Created domain rule '{}' (expanded on DNS hits, not pushed to driver)",
                    rule.name
                );
                return Ok(rule);
            }
            // 分组规则在内核侧按成员展开成多条（合成 RuleId），直发单条会丢失分组语义，
            // 改为整体重载；普通规则保持增量下发
            let push = if rule.app_group_id.is_some() {
                self.reload_rules_to_driver().await
            } else {
                self.driver.add_rule(&rule).await
            };
            // 下发失败时删除刚插入的 DB 记录，避免"DB 有、驱动无"且重试重复插入
            if let Err(e) = push {
                if let Err(del) = self.db.delete_rule(id).await {
                    tracing::error!("Failed to roll back create_rule({}) after add_rule failure: {}", id, del);
                }
                return Err(e);
            }
        }

        tracing::info!("Created rule: {} - {}", rule.name, rule.description);
        Ok(rule)
    }

    pub async fn update_rule(&self, id: u32, rule: Rule) -> Result<()> {
        // [System] 前缀规则防护：改名会破坏 system_rules.rs 按名幂等安装，
        // 匹配字段被改会静默改变系统豁免面。IPC 只放行 enabled/description；
        // 系统内部迁移走 update_rule_internal（无前缀限制）。
        let old = self
            .db
            .get_rule(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Rule {} not found", id)))?;
        if old.name.starts_with(super::system_rules::SYSTEM_RULE_PREFIX) {
            let unchanged = rule.name == old.name
                && rule.direction == old.direction
                && rule.protocol == old.protocol
                && rule.process_id == old.process_id
                && rule.process_path == old.process_path
                && rule.remote_addr == old.remote_addr
                && rule.remote_addr_mask == old.remote_addr_mask
                && rule.remote_domain == old.remote_domain
                && rule.remote_port == old.remote_port
                && rule.local_addr == old.local_addr
                && rule.local_addr_mask == old.local_addr_mask
                && rule.local_port == old.local_port
                && rule.network_zone == old.network_zone
                && rule.app_group_id == old.app_group_id
                // action/priority 也属匹配面：改 Block 会把豁免规则变拦截
                // （VM 保命规则 #11 会被干掉），改 priority 会破坏系统规则的
                // 优先级布局，一并纳入守卫。
                && rule.action == old.action
                && rule.priority == old.priority;
            if !unchanged {
                return Err(ServiceError::Validation(
                    "系统规则（[System] 前缀）只允许修改启用状态与描述".to_string(),
                ));
            }
        }
        self.update_rule_internal(id, rule).await
    }

    pub(crate) async fn update_rule_internal(&self, id: u32, mut rule: Rule) -> Result<()> {
        super::validator::validate_rule(&rule)?;

        // Read the old state first so we can diff enabled transitions; the
        // database read-back after update would only return the new values.
        let old_rule = self
            .db
            .get_rule(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Rule {} not found", id)))?;

        self.db.update_rule(id, &rule).await?;

        // 域名规则与驱动无直接条目：编辑（含禁用）后先撤掉旧影子条目，
        // 仍有效的规则由下一次 DNS 命中按新条件重新展开。后续驱动分支全部跳过。
        if old_rule.remote_domain.is_some() || rule.remote_domain.is_some() {
            if let Some(engine) = self.domain_engine() {
                engine.revoke_rule(id).await;
            }
            tracing::info!("Updated domain rule: {}", rule.name);
            return Ok(());
        }

        // Driver updates need the rule id set (the caller's Rule may not carry it)
        rule.id = Some(id);

        if old_rule.app_group_id.is_some() || rule.app_group_id.is_some() {
            // 分组规则（或改成/改自分组规则）：成员展开可能变化，整体重载最稳妥。
            // 失败不回滚 DB：reload 幂等，服务重启/下次变更会再同步。
            if let Err(e) = self.reload_rules_to_driver().await {
                tracing::warn!("Failed to reload driver rules after group-rule update {}: {}", id, e);
            }
        } else if old_rule.enabled && !rule.enabled {
            // Rule transitioned to disabled: remove from driver. Symmetric rollback
            // with the enable path: restore DB enabled on failure so a retry takes
            // this branch again instead of skipping the driver removal.
            if let Err(e) = self.driver.remove_rule(id).await {
                let mut rollback = rule.clone();
                rollback.enabled = true;
                if let Err(rb) = self.db.update_rule(id, &rollback).await {
                    tracing::error!("Failed to roll back update_rule({}) disable transition: {}", id, rb);
                }
                return Err(e);
            }
        } else if !old_rule.enabled && rule.enabled {
            // Rule was created disabled and never downloaded to the driver;
            // driver.update_rule would return STATUS_NOT_FOUND for it, so add instead.
            // Same rollback as enable_rule: keep DB disabled on failure so a
            // retry takes this branch again instead of silently skipping.
            if let Err(e) = self.driver.add_rule(&rule).await {
                let mut rollback = rule.clone();
                rollback.enabled = false;
                if let Err(rb) = self.db.update_rule(id, &rollback).await {
                    tracing::error!("Failed to roll back update_rule({}) enable transition: {}", id, rb);
                }
                return Err(e);
            }
        } else if rule.enabled {
            // 已启用规则的参数变更（enable 状态不变）：驱动更新失败时 DB 已新、
            // 驱动仍旧，照抄上方 enable/disable 转移分支的回滚模式恢复 old_rule，
            // 保证重试仍走本分支而不是被"看似已同步"的状态跳过。
            if let Err(e) = self.driver.update_rule(&rule).await {
                let mut rollback = old_rule.clone();
                rollback.id = Some(id);
                if let Err(rb) = self.db.update_rule(id, &rollback).await {
                    tracing::error!("Failed to roll back update_rule({}) param change: {}", id, rb);
                }
                return Err(e);
            }
        }

        tracing::info!("Updated rule: {}", rule.name);
        Ok(())
    }

    pub async fn delete_rule(&self, id: u32) -> Result<()> {
        // [System] 前缀规则一律拒绝删除；系统内部清理走 delete_rule_internal。
        if let Some(old) = self.db.get_rule(id).await? {
            if old.name.starts_with(super::system_rules::SYSTEM_RULE_PREFIX) {
                return Err(ServiceError::Validation(
                    "系统规则（[System] 前缀）不能删除".to_string(),
                ));
            }
        }
        self.delete_rule_internal(id).await
    }

    pub(crate) async fn delete_rule_internal(&self, id: u32) -> Result<()> {
        let old_rule = self.db.get_rule(id).await?;
        self.db.delete_rule(id).await?;
        // 域名规则删除：先撤影子条目再返回（影子在驱动里按合成 ID 存在，
        // remove_rule(id) 删不掉它们）
        if old_rule.as_ref().map(|r| r.remote_domain.is_some()).unwrap_or(false) {
            if let Some(engine) = self.domain_engine() {
                engine.revoke_rule(id).await;
            }
            tracing::info!("Deleted rule: {}", id);
            return Ok(());
        }
        if old_rule.map(|r| r.app_group_id.is_some()).unwrap_or(false) {
            // 分组规则在驱动里是合成 ID 的展开条目，单删 id 删不掉，整体重载
            self.reload_rules_to_driver().await?;
        } else {
            self.driver.remove_rule(id).await?;
        }
        tracing::info!("Deleted rule: {}", id);
        Ok(())
    }

    pub async fn get_rule(&self, id: u32) -> Result<Option<Rule>> {
        self.db.get_rule(id).await
    }

    pub async fn list_rules(&self) -> Result<Vec<Rule>> {
        self.db.list_rules().await
    }

    /// 分页读取（GUI 规则管理页用；内部逻辑仍走全量 list_rules）
    pub async fn list_rules_page(&self, offset: u32, limit: u32, search: Option<String>) -> Result<RulePage> {
        self.db.list_rules_page(offset, limit, search).await
    }

    pub async fn enable_rule(&self, id: u32) -> Result<()> {
        let mut rule = self
            .db
            .get_rule(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Rule {} not found", id)))?;

        if rule.enabled {
            return Ok(());
        }

        rule.enabled = true;
        self.db.update_rule(id, &rule).await?;
        // 域名规则无直接驱动条目，启用即完成（影子条目由 DNS 命中展开）
        if rule.remote_domain.is_some() {
            tracing::info!("Enabled domain rule: {}", id);
            return Ok(());
        }
        // 此前 disabled 的规则从未下发到驱动，update 会命中 STATUS_NOT_FOUND，必须 add；
        // 下发失败时回滚 DB 的 enabled 状态，否则下次重试会因"已 enabled"早退 Ok(())
        // 而规则永远进不了驱动。分组规则走整体重载（内核侧是展开条目）。
        let push = if rule.app_group_id.is_some() {
            self.reload_rules_to_driver().await
        } else {
            self.driver.add_rule(&rule).await
        };
        if let Err(e) = push {
            rule.enabled = false;
            if let Err(rb) = self.db.update_rule(id, &rule).await {
                tracing::error!("Failed to roll back enable_rule({}): {}", id, rb);
            }
            return Err(e);
        }

        tracing::info!("Enabled rule: {}", id);
        Ok(())
    }

    pub async fn disable_rule(&self, id: u32) -> Result<()> {
        let mut rule = self
            .db
            .get_rule(id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Rule {} not found", id)))?;

        if !rule.enabled {
            return Ok(());
        }

        rule.enabled = false;
        self.db.update_rule(id, &rule).await?;
        // 域名规则禁用：撤掉其全部影子条目即完成（驱动里没有直接条目可删）
        if rule.remote_domain.is_some() {
            if let Some(engine) = self.domain_engine() {
                engine.revoke_rule(id).await;
            }
            tracing::info!("Disabled domain rule: {}", id);
            return Ok(());
        }
        // 与 enable_rule 对称：移除失败时回滚 DB 的 enabled，否则下次重试会因
        // "已 disabled"早退 Ok(()) 而规则永远留在驱动里。分组规则走整体重载。
        let remove = if rule.app_group_id.is_some() {
            self.reload_rules_to_driver().await
        } else {
            self.driver.remove_rule(id).await
        };
        if let Err(e) = remove {
            rule.enabled = true;
            if let Err(rb) = self.db.update_rule(id, &rule).await {
                tracing::error!("Failed to roll back disable_rule({}): {}", id, rb);
            }
            return Err(e);
        }

        tracing::info!("Disabled rule: {}", id);
        Ok(())
    }

    async fn get_next_priority(&self) -> Result<u32> {
        let rules = self.list_rules().await?;
        Ok(rules.len() as u32 + 1)
    }

    /// 清空并按当前 DB 状态整体重载驱动规则（分组规则变更后的同步方式）
    pub async fn reload_rules_to_driver(&self) -> Result<()> {
        self.driver.clear_rules().await?;
        self.load_rules_to_driver().await?;
        // clear_rules 把影子条目也清掉了：按账本重下发，保持账本与驱动一致
        if let Some(engine) = self.domain_engine() {
            engine.resync_after_reload().await;
        }
        Ok(())
    }

    pub async fn load_rules_to_driver(&self) -> Result<()> {
        let rules = self.list_rules().await?;
        // 内核没有分组概念：引用 app_group_id 的规则按分组成员展开成
        // 多条“进程路径规则”下发，合成 RuleId 与 DB 自增 ID 区分
        let group_paths = self.load_group_paths(&rules).await?;
        let mut loaded = 0usize;
        let mut failed = 0usize;

        for rule in &rules {
            if !rule.enabled {
                continue;
            }
            // 域名规则不直接下发（直发 = 无远端条件的全量规则），由
            // domain_expander 按 DNS 命中展开
            if rule.remote_domain.is_some() {
                continue;
            }
            match rule.app_group_id {
                Some(group_id) => {
                    let members = group_paths.get(&group_id);
                    if members.is_none() || members.map(|m| m.is_empty()).unwrap_or(true) {
                        tracing::warn!(
                            "Rule {} references empty/unknown group {}, skipped in driver",
                            rule.name, group_id
                        );
                        continue;
                    }
                    let rule_id = rule.id.unwrap_or(0);
                    for (i, path) in members.unwrap().iter().enumerate() {
                        let mut expanded = rule.clone();
                        expanded.app_group_id = None;
                        expanded.process_path = Some(path.clone());
                        expanded.id = Some(expanded_rule_id(rule_id, i));
                        // 单条失败只跳过该条，不中断整批：默认策略是 ALLOW，
                        // 中断会让后续规则（含 BLOCK）全部缺失，防火墙静默全放行
                        if let Err(e) = self.driver.add_rule(&expanded).await {
                            tracing::warn!(
                                "Failed to load rule '{}' (group member {}): {}, skipped",
                                rule.name, path, e
                            );
                            failed += 1;
                            continue;
                        }
                        loaded += 1;
                    }
                }
                None => {
                    if let Err(e) = self.driver.add_rule(rule).await {
                        tracing::warn!("Failed to load rule '{}': {}, skipped", rule.name, e);
                        failed += 1;
                        continue;
                    }
                    loaded += 1;
                }
            }
        }

        if failed > 0 {
            tracing::warn!("{} rules failed to load, skipped", failed);
        }
        tracing::info!("Loaded {} rules to driver ({} source rules, group rules expanded)", loaded, rules.len());
        Ok(())
    }

    /// Check if a connection matches a rule
    pub fn matches_rule(&self, rule: &Rule, connection: &ConnectionInfo) -> bool {
        // 域名规则的匹配经 domain_expander 展开后由驱动执行；本函数面向
        // 无域名上下文的连接匹配（服务侧核对），带域名条件的规则一律不命中，
        // 否则 remote_addr=None 会被误判为"匹配任意远端地址"
        if rule.remote_domain.is_some() {
            return false;
        }
        // Check protocol
        if let Some(rule_proto) = rule.protocol {
            if rule_proto != Protocol::Any && rule_proto != connection.protocol {
                return false;
            }
        }

        // Check direction
        if rule.direction != Direction::Both && rule.direction != connection.direction {
            return false;
        }

        // Check remote address
        if let Some(ref rule_addr) = rule.remote_addr {
            if !self.address_matches(rule_addr, rule.remote_addr_mask, &connection.remote_addr) {
                return false;
            }
        }

        // Check local address
        if let Some(ref rule_addr) = rule.local_addr {
            if !self.address_matches(rule_addr, rule.local_addr_mask, &connection.local_addr) {
                return false;
            }
        }

        // Check remote port
        if let Some(ref port_range) = rule.remote_port {
            if !port_range.matches(connection.remote_port) {
                return false;
            }
        }

        // Check local port
        if let Some(ref port_range) = rule.local_port {
            if !port_range.matches(connection.local_port) {
                return false;
            }
        }

        // Check process name (ConnectionInfo only has process_name)
        if let Some(ref rule_path) = rule.process_path {
            // Try to match process path with process name
            if connection.process_name.as_ref().map(|n| n.contains(rule_path)) != Some(true) {
                // For now, if no match, return false
                // In a real implementation, you'd want to get the full process path
                return false;
            }
        }

        // Check process ID
        if let Some(rule_pid) = rule.process_id {
            if connection.process_id != Some(rule_pid) {
                return false;
            }
        }

        // Check application group
        if let Some(group_id) = rule.app_group_id {
            // This would require async call to check group membership
            // For now, we skip this check and assume it's handled at a higher level
            let _ = group_id;
        }

        // Check network zone
        if let Some(zone) = rule.network_zone {
            if !self.network_zone_matches(zone, &connection.remote_addr) {
                return false;
            }
        }

        true
    }

    /// Check if an IP address matches a rule with optional subnet mask or CIDR notation
    /// 双栈：IPv4/IPv6 同族比较，异族不匹配
    fn address_matches(&self, rule_addr: &str, mask: Option<u8>, conn_addr: &str) -> bool {
        // Check for CIDR notation in rule_addr
        if rule_addr.contains('/') {
            // Use CIDR matching
            return super::validator::cidr_matches(rule_addr, conn_addr).unwrap_or(false);
        }

        // Traditional IP + mask matching
        let rule_ip = match rule_addr.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let conn_ip = match conn_addr.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        match (rule_ip, conn_ip) {
            (std::net::IpAddr::V4(rule), std::net::IpAddr::V4(conn)) => match mask {
                Some(mask_bits) => {
                    let mask_value = if mask_bits == 0 {
                        0u32
                    } else if mask_bits >= 32 {
                        !0u32
                    } else {
                        !0u32 << (32 - mask_bits)
                    };
                    (u32::from(rule) & mask_value) == (u32::from(conn) & mask_value)
                }
                None => rule == conn,
            },
            (std::net::IpAddr::V6(rule), std::net::IpAddr::V6(conn)) => match mask {
                Some(mask_bits) => {
                    let mask_value = if mask_bits == 0 {
                        0u128
                    } else if mask_bits >= 128 {
                        !0u128
                    } else {
                        !0u128 << (128 - mask_bits)
                    };
                    (u128::from(rule) & mask_value) == (u128::from(conn) & mask_value)
                }
                None => rule == conn,
            },
            // 异族不匹配（V4 规则不匹配 V6 连接，反之亦然）
            _ => false,
        }
    }

    /// Check if an address belongs to a network zone（双栈）
    fn network_zone_matches(&self, zone: NetworkZone, addr: &str) -> bool {
        let ip = match addr.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        // IPv6 唯一本地 fc00::/7 与链路本地 fe80::/10 的掩码判定
        let v6_is_lan = |seg: u128| {
            (seg & 0xfe00_0000_0000_0000_0000_0000_0000_0000)
                == 0xfc00_0000_0000_0000_0000_0000_0000_0000
                || (seg & 0xffc0_0000_0000_0000_0000_0000_0000_0000)
                    == 0xfe80_0000_0000_0000_0000_0000_0000_0000
        };

        match zone {
            NetworkZone::Localhost => ip.is_loopback(),
            NetworkZone::Lan => match ip {
                std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                std::net::IpAddr::V6(v6) => v6_is_lan(u128::from(v6)),
            },
            NetworkZone::Internet => match ip {
                std::net::IpAddr::V4(v4) => {
                    !(v4.is_loopback() || v4.is_private() || v4.is_link_local())
                }
                std::net::IpAddr::V6(v6) => {
                    let seg = u128::from(v6);
                    !(seg == 1 || v6_is_lan(seg))
                }
            },
        }
    }

    /// Get the highest priority matching rule for a connection
    pub async fn get_matching_rule(&self, connection: &ConnectionInfo) -> Result<Option<Rule>> {
        let rules = self.list_rules().await?;

        // 预取所有涉及分组规则的成员进程路径，使 app_group_id 匹配真正生效
        let group_paths = self.load_group_paths(&rules).await?;

        // Sort by priority (lower number = higher priority)
        let mut sorted_rules: Vec<_> = rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| r.priority);

        for rule in sorted_rules {
            if self.matches_rule_with_groups(rule, connection, &group_paths) {
                return Ok(Some(rule.clone()));
            }
        }

        Ok(None)
    }

    /// 加载所有被规则引用的应用分组的成员进程路径集合
    async fn load_group_paths(&self, rules: &[Rule]) -> Result<std::collections::HashMap<u32, Vec<String>>> {
        let mut group_paths: std::collections::HashMap<u32, Vec<String>> = std::collections::HashMap::new();
        for rule in rules {
            if let Some(group_id) = rule.app_group_id {
                let entry = group_paths.entry(group_id).or_default();
                if entry.is_empty() {
                    let members = self.db.get_group_members(group_id).await.unwrap_or_default();
                    *entry = members.into_iter().map(|m| m.process_path.to_lowercase()).collect();
                }
            }
        }
        Ok(group_paths)
    }

    /// matches_rule 的分组感知版本：按分组成员的进程路径匹配连接的进程路径
    fn matches_rule_with_groups(
        &self,
        rule: &Rule,
        connection: &ConnectionInfo,
        group_paths: &std::collections::HashMap<u32, Vec<String>>,
    ) -> bool {
        // 应用分组匹配：连接的进程路径必须属于分组任一成员（大小写不敏感）
        if let Some(group_id) = rule.app_group_id {
            let conn_path = connection
                .process_path
                .as_deref()
                .map(str::to_lowercase);
            let matches_group = match conn_path {
                Some(path) => group_paths
                    .get(&group_id)
                    .map(|members| members.contains(&path))
                    .unwrap_or(false),
                None => false,
            };
            if !matches_group {
                return false;
            }
        }

        // 其余条件复用原有同步匹配逻辑
        let mut rule_without_group = rule.clone();
        rule_without_group.app_group_id = None;
        self.matches_rule(&rule_without_group, connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// enabled=false：create/disable 路径不触驱动（DriverHandle 未 open 时
    /// add/remove 会报 "Driver not open" 并回滚），单测只覆盖 DB 与查重逻辑
    fn sample_rule(name: &str) -> Rule {
        Rule {
            id: None,
            name: name.to_string(),
            description: String::new(),
            enabled: false,
            priority: 0,
            action: RuleAction::Block,
            direction: Direction::Outbound,
            protocol: Some(Protocol::Tcp),
            process_id: None,
            process_path: Some(r"C:\Program Files\App\app.exe".to_string()),
            remote_addr: Some("10.0.0.0".to_string()),
            remote_addr_mask: Some(8),
            remote_domain: None,
            remote_port: Some(PortRange::Single(443)),
            local_addr: None,
            local_addr_mask: None,
            local_port: None,
            network_zone: None,
            app_group_id: None,
            created_at: None,
            updated_at: None,
        }
    }

    async fn test_manager(name: &str) -> (RuleManager, std::path::PathBuf) {
        // 每个测试独立 DB 文件：测试并行执行，共用文件会撞 WAL 锁
        let path = std::env::temp_dir().join(format!("cf_rule_dedup_test_{}.db", name));
        let _ = std::fs::remove_file(&path);
        let db = Arc::new(Database::open(path.to_str().unwrap()).expect("open db"));
        let driver = Arc::new(DriverHandle::new().expect("driver handle"));
        let mgr = RuleManager::new(db, driver).expect("manager");
        (mgr, path)
    }

    #[tokio::test]
    async fn duplicate_create_returns_same_id_and_list_does_not_grow() {
        let (mgr, path) = test_manager("same_id").await;

        let first = mgr.create_rule(sample_rule("rule-a")).await.unwrap();
        let first_id = first.id.expect("first rule gets an id");

        // 同匹配字段、不同 name/description/enabled/action 的二次创建：
        // 返回原 id，且字段被就地覆盖为本次传入值
        let mut dup = sample_rule("rule-b");
        dup.description = "different description".to_string();
        dup.action = RuleAction::Allow;
        let second = mgr.create_rule(dup).await.unwrap();
        assert_eq!(second.id, Some(first_id), "duplicate must reuse existing id");
        assert_eq!(second.name, "rule-b", "name merged from the new request");
        assert_eq!(second.description, "different description");
        assert_eq!(second.action, RuleAction::Allow);
        assert!(!second.enabled, "enabled merged from the new request (false)");

        let all = mgr.list_rules().await.unwrap();
        assert_eq!(all.len(), 1, "list must not grow on duplicate create");
        assert_eq!(all[0].name, "rule-b");
        assert_eq!(all[0].action, RuleAction::Allow);
        assert!(!all[0].enabled);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn action_flip_on_same_matchset_merges_into_one_rule() {
        let (mgr, path) = test_manager("action_flip").await;

        let mut allow = sample_rule("allow-rule");
        allow.action = RuleAction::Allow;
        let first = mgr.create_rule(allow).await.unwrap();

        // 先 Allow 后 Block 同一匹配集：仍是一条规则，action 变为 Block
        let block = sample_rule("block-rule");
        let second = mgr.create_rule(block).await.unwrap();
        assert_eq!(second.id, first.id, "same matchset must merge, not duplicate");
        assert_eq!(second.action, RuleAction::Block);
        assert_eq!(second.name, "block-rule");
        assert_eq!(mgr.list_rules().await.unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn differing_field_creates_new_rule() {
        let (mgr, path) = test_manager("differs").await;

        mgr.create_rule(sample_rule("rule-a")).await.unwrap();
        let mut other = sample_rule("rule-d");
        other.remote_port = Some(PortRange::Single(80));
        mgr.create_rule(other).await.unwrap();

        assert_eq!(mgr.list_rules().await.unwrap().len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    /// [System] 前缀规则不参与合并：用户对系统程序的弹窗决策新建独立规则，
    /// 系统规则的 name 不被覆盖（幂等安装按名字匹配，改名会引发重复安装）
    #[tokio::test]
    async fn system_rules_never_merged_or_renamed() {
        let (mgr, path) = test_manager("system_protect").await;

        // 模拟已安装的 [System] svchost.exe 豁免规则（宽路径 \svchost.exe）
        let mut sys = sample_rule("[System] svchost.exe");
        sys.direction = Direction::Both;
        sys.process_path = Some(r"\svchost.exe".to_string());
        sys.enabled = false;
        mgr.create_rule(sys).await.unwrap();

        // 用户弹窗决策：完整路径、更窄匹配集，理论上被系统规则覆盖——
        // 但系统规则不参与合并，必须新建独立规则
        let mut popup = sample_rule("[弹窗] svchost.exe");
        popup.process_path = Some(r"C:\Windows\System32\svchost.exe".to_string());
        popup.enabled = false;
        let created = mgr.create_rule(popup).await.unwrap();
        assert_ne!(
            created.name,
            "[System] svchost.exe",
            "must not merge into the system rule"
        );

        let all = mgr.list_rules().await.unwrap();
        assert_eq!(all.len(), 2, "system + user rule coexist");
        assert!(
            all.iter()
                .any(|r| r.name == "[System] svchost.exe"),
            "system rule keeps its name"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn inbound_new_covered_by_existing_both_merges() {
        let (mgr, path) = test_manager("both_covers_inbound").await;

        let mut both = sample_rule("both-rule");
        both.direction = Direction::Both;
        let first = mgr.create_rule(both).await.unwrap();

        // 新建更窄（Inbound）：被既有的 Both 覆盖，元信息合并进原规则
        let mut inbound = sample_rule("inbound-rule");
        inbound.direction = Direction::Inbound;
        let second = mgr.create_rule(inbound).await.unwrap();
        assert_eq!(second.id, first.id, "covered rule must merge into the broader one");
        assert_eq!(second.name, "inbound-rule");
        assert_eq!(second.direction, Direction::Both, "broader matchset unchanged");
        assert_eq!(mgr.list_rules().await.unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn broader_both_create_absorbs_existing_inbound() {
        let (mgr, path) = test_manager("both_absorbs_inbound").await;

        let mut inbound = sample_rule("inbound-rule");
        inbound.direction = Direction::Inbound;
        let first = mgr.create_rule(inbound).await.unwrap();

        // 新建更宽（Both）：吞并既有 Inbound 规则，匹配字段整体替换
        let mut both = sample_rule("both-rule");
        both.direction = Direction::Both;
        let second = mgr.create_rule(both).await.unwrap();
        assert_eq!(second.id, first.id, "broader rule replaces the narrower in place");
        assert_eq!(second.name, "both-rule");
        assert_eq!(second.direction, Direction::Both);
        assert_eq!(mgr.list_rules().await.unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn substring_process_path_merges() {
        let (mgr, path) = test_manager("path_substr").await;

        // 已有规则路径是连接路径的后缀（驱动 WcsEndsWithIgnoreCase 语义）→ 更宽
        let mut broad = sample_rule("svchost-broad");
        broad.process_path = Some(r"\svchost.exe".to_string());
        let first = mgr.create_rule(broad).await.unwrap();

        let mut full = sample_rule("svchost-full");
        full.process_path = Some(r"C:\Windows\System32\svchost.exe".to_string());
        let second = mgr.create_rule(full).await.unwrap();
        assert_eq!(second.id, first.id, "full path covered by substring rule");
        assert_eq!(second.name, "svchost-full");
        assert_eq!(mgr.list_rules().await.unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wider_subnet_create_merges() {
        let (mgr, path) = test_manager("subnet").await;

        // 已有 10.0.0.0/8 覆盖新建 10.1.2.3/32 → 合并进既有规则
        let mut subnet8 = sample_rule("subnet-8");
        subnet8.remote_port = None;
        let first = mgr.create_rule(subnet8).await.unwrap();

        let mut host = sample_rule("host-rule");
        host.remote_addr = Some("10.1.2.3".to_string());
        host.remote_addr_mask = Some(32);
        host.remote_port = None;
        let second = mgr.create_rule(host).await.unwrap();
        assert_eq!(second.id, first.id, "host rule covered by /8");
        assert_eq!(second.remote_addr.as_deref(), Some("10.0.0.0"));
        assert_eq!(second.remote_addr_mask, Some(8));
        assert_eq!(mgr.list_rules().await.unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn differing_action_never_merges() {
        let (mgr, path) = test_manager("action_diff").await;

        // 匹配集覆盖但 action 不同：两条并存（意图冲突不可自动合并）
        let mut block = sample_rule("block-rule");
        block.remote_port = None;
        block.action = RuleAction::Block;
        mgr.create_rule(block).await.unwrap();

        let mut allow = sample_rule("allow-rule");
        allow.remote_port = None;
        allow.remote_addr = Some("10.1.2.3".to_string());
        allow.remote_addr_mask = Some(32);
        allow.action = RuleAction::Allow;
        mgr.create_rule(allow).await.unwrap();

        assert_eq!(mgr.list_rules().await.unwrap().len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn port_range_covers_single() {
        let (mgr, path) = test_manager("port_range").await;

        let mut range = sample_rule("range-rule");
        range.remote_addr = None;
        range.remote_addr_mask = None;
        range.remote_port = Some(PortRange::Range(1, 100));
        let first = mgr.create_rule(range).await.unwrap();

        let mut single = sample_rule("single-rule");
        single.remote_addr = None;
        single.remote_addr_mask = None;
        single.remote_port = Some(PortRange::Single(80));
        let second = mgr.create_rule(single).await.unwrap();
        assert_eq!(second.id, first.id, "Single(80) covered by Range(1-100)");
        assert_eq!(second.remote_port, Some(PortRange::Range(1, 100)));
        assert_eq!(mgr.list_rules().await.unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    async fn create_distinct(mgr: &RuleManager, name: &str, port: u16) {
        // 每条规则匹配集必须互不相同，否则 create_rule 会合并成一条
        let mut rule = sample_rule(name);
        rule.remote_port = Some(PortRange::Single(port));
        mgr.create_rule(rule).await.unwrap();
    }

    #[tokio::test]
    async fn list_rules_page_slices_and_counts() {
        let (mgr, path) = test_manager("page_basic").await;

        for i in 0..5 {
            create_distinct(&mgr, &format!("rule-{}", i), 1000 + i as u16).await;
        }

        let page = mgr.list_rules_page(0, 2, None).await.unwrap();
        assert_eq!(page.total, 5);
        assert_eq!(page.rules.len(), 2);
        assert_eq!(page.rules[0].name, "rule-0");
        assert_eq!(page.rules[1].name, "rule-1");

        let middle = mgr.list_rules_page(2, 2, None).await.unwrap();
        assert_eq!(middle.total, 5);
        assert_eq!(middle.rules.len(), 2);
        assert_eq!(middle.rules[0].name, "rule-2");

        let last = mgr.list_rules_page(4, 2, None).await.unwrap();
        assert_eq!(last.rules.len(), 1);
        assert_eq!(last.rules[0].name, "rule-4");

        let _ = std::fs::remove_file(&path);
    }

    /// 同优先级多条规则跨页必须不重不漏（排序带 id 保证稳定）
    #[tokio::test]
    async fn list_rules_page_same_priority_no_gap_no_overlap() {
        let (mgr, path) = test_manager("page_same_priority").await;

        for i in 0..7 {
            create_distinct(&mgr, &format!("same-{}", i), 2000 + i as u16).await;
        }

        let mut seen: Vec<String> = Vec::new();
        let mut offset = 0;
        loop {
            let page = mgr.list_rules_page(offset, 3, None).await.unwrap();
            assert_eq!(page.total, 7);
            if page.rules.is_empty() {
                break;
            }
            seen.extend(page.rules.iter().map(|r| r.name.clone()));
            offset += 3;
        }

        let mut sorted = seen.clone();
        sorted.sort();
        let mut expected: Vec<String> = (0..7).map(|i| format!("same-{}", i)).collect();
        expected.sort();
        assert_eq!(sorted, expected, "paged scan must cover all rules exactly once");
        assert_eq!(seen.len(), 7, "no duplicates across pages");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn list_rules_page_offset_beyond_total() {
        let (mgr, path) = test_manager("page_overflow").await;

        create_distinct(&mgr, "only-rule", 3000).await;

        let page = mgr.list_rules_page(10, 5, None).await.unwrap();
        assert_eq!(page.total, 1, "total unaffected by offset");
        assert!(page.rules.is_empty(), "offset beyond total yields empty page");

        let _ = std::fs::remove_file(&path);
    }

    /// 服务端搜索：按 name 命中（SQLite LIKE 对 ASCII 不区分大小写），
    /// 不匹配的规则不得混入，total 与返回行数一致
    #[tokio::test]
    async fn list_rules_page_search_matches_by_name() {
        let (mgr, path) = test_manager("page_search_name").await;

        let mut hit = sample_rule("Chrome Blocker");
        hit.remote_port = Some(PortRange::Single(4000));
        mgr.create_rule(hit).await.unwrap();
        create_distinct(&mgr, "unrelated", 4001).await;

        let page = mgr.list_rules_page(0, 10, Some("chrome".to_string())).await.unwrap();
        assert_eq!(page.total, 1, "ASCII LIKE is case-insensitive: 'chrome' hits 'Chrome Blocker'");
        assert_eq!(page.rules.len(), 1);
        assert_eq!(page.rules[0].name, "Chrome Blocker");

        let _ = std::fs::remove_file(&path);
    }

    /// 服务端搜索：按 process_path 命中
    #[tokio::test]
    async fn list_rules_page_search_matches_by_process_path() {
        let (mgr, path) = test_manager("page_search_path").await;

        // sample_rule 的 process_path 为 C:\Program Files\App\app.exe
        create_distinct(&mgr, "rule-with-path", 4100).await;

        let page = mgr.list_rules_page(0, 10, Some(r"program files\app".to_string())).await.unwrap();
        assert_eq!(page.total, 1, "search hits process_path");
        assert_eq!(page.rules[0].name, "rule-with-path");

        let miss = mgr.list_rules_page(0, 10, Some(r"system32\nonexistent".to_string())).await.unwrap();
        assert_eq!(miss.total, 0);
        assert!(miss.rules.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    /// search 为 None / 空串时结果与无搜索链路完全一致（含 total 计数与行序）
    #[tokio::test]
    async fn list_rules_page_search_none_and_empty_match_baseline() {
        let (mgr, path) = test_manager("page_search_none").await;

        for i in 0..5 {
            create_distinct(&mgr, &format!("baseline-{}", i), 4200 + i as u16).await;
        }

        let baseline = mgr.list_rules_page(0, 3, None).await.unwrap();
        let empty = mgr.list_rules_page(0, 3, Some(String::new())).await.unwrap();
        let whitespace = mgr.list_rules_page(0, 3, Some("   ".to_string())).await.unwrap();

        assert_eq!(baseline.total, 5);
        assert_eq!(empty.total, baseline.total, "empty search must not filter");
        assert_eq!(whitespace.total, baseline.total, "whitespace search must not filter");
        let names = |p: &RulePage| -> Vec<String> { p.rules.iter().map(|r| r.name.clone()).collect() };
        assert_eq!(names(&baseline), names(&empty));
        assert_eq!(names(&baseline), names(&whitespace));

        let _ = std::fs::remove_file(&path);
    }

    /// 传入侧 [System] 豁免：ensure_installed 创建 [System] 规则（更宽匹配集、
    /// 同 action）时不得吞并/改名既有用户规则——否则关闭系统豁免时
    /// remove_all 按前缀删除会无声清掉用户规则
    #[tokio::test]
    async fn incoming_system_rule_does_not_absorb_user_rule() {
        let (mgr, path) = test_manager("system_incoming").await;

        // 用户规则：完整路径、Outbound、Allow
        let mut user = sample_rule("Allow C:\\Windows\\System32\\svchost.exe Outbound");
        user.action = RuleAction::Allow;
        user.process_path = Some(r"C:\Windows\System32\svchost.exe".to_string());
        let user_id = mgr.create_rule(user).await.unwrap().id.unwrap();

        // 传入 [System] 规则：Both、宽路径 \svchost.exe，理论上覆盖用户规则
        let mut sys = sample_rule("[System] svchost.exe");
        sys.action = RuleAction::Allow;
        sys.direction = Direction::Both;
        sys.process_path = Some(r"\svchost.exe".to_string());
        sys.enabled = false;
        let sys_created = mgr.create_rule(sys).await.unwrap();
        assert_ne!(
            sys_created.id,
            Some(user_id),
            "[System] rule must be an independent row, not an in-place rename"
        );

        let all = mgr.list_rules().await.unwrap();
        assert_eq!(all.len(), 2, "user rule and [System] rule coexist");
        let user_after = all.iter().find(|r| r.id == Some(user_id)).expect("user rule kept");
        assert_eq!(user_after.name, "Allow C:\\Windows\\System32\\svchost.exe Outbound");
        assert_eq!(user_after.direction, Direction::Outbound);
        assert_eq!(
            user_after.process_path.as_deref(),
            Some(r"C:\Windows\System32\svchost.exe")
        );
        assert_eq!(user_after.action, RuleAction::Allow);

        // remove_all 按前缀只删 [System] 那条（delete_rule 的驱动移除在未
        // open 的 DriverHandle 上报错被 remove_all 容忍，DB 行已删除）
        super::super::system_rules::remove_all(&mgr).await.unwrap();
        let after = mgr.list_rules().await.unwrap();
        assert_eq!(after.len(), 1, "only the [System] rule is removed");
        assert_eq!(after[0].id, Some(user_id), "user rule survives remove_all");

        let _ = std::fs::remove_file(&path);
    }

    /// 域名规则：enabled=true 创建也不触驱动（DriverHandle 未 open 时普通
    /// 规则会因 add_rule 失败回滚），删除同样不触驱动；带域名+IP 双条件被
    /// validator 拒绝。
    #[tokio::test]
    async fn domain_rules_bypass_driver_and_validate_exclusive() {
        let (mgr, path) = test_manager("domain_rule").await;

        let mut rule = sample_rule("block-evil-domain");
        rule.remote_addr = None;
        rule.remote_addr_mask = None;
        rule.remote_port = None;
        rule.remote_domain = Some("*.evil.example".to_string());
        rule.enabled = true;
        let created = mgr.create_rule(rule.clone()).await.expect("domain rule creates without driver");
        assert!(created.id.is_some());
        assert_eq!(mgr.list_rules().await.unwrap().len(), 1);

        // 互斥校验：再加 remote_addr 被拒
        let mut bad = rule.clone();
        bad.remote_addr = Some("10.0.0.1".to_string());
        let err = mgr.create_rule(bad).await.unwrap_err();
        assert!(matches!(err, ServiceError::Validation(_)));

        // 删除不触驱动（驱动未 open，remove_rule 会报错——域名规则路径必须跳过）
        mgr.delete_rule(created.id.unwrap()).await.expect("domain rule delete without driver");
        assert!(mgr.list_rules().await.unwrap().is_empty());

        let _ = std::fs::remove_file(&path);
    }

    /// same_effective_fields 必须比较 network_zone：仅 zone 不同的两条规则
    /// 不算重复，否则合并会把新值的 zone 静默丢成旧值（与 matchset_covers
    /// 的 zone_covers 口径对齐）
    #[tokio::test]
    async fn differing_network_zone_creates_new_rule() {
        let (mgr, path) = test_manager("zone_diff").await;

        let mut any_zone = sample_rule("block-chrome");
        any_zone.remote_addr = None;
        any_zone.remote_addr_mask = None;
        any_zone.remote_port = None;
        mgr.create_rule(any_zone).await.unwrap();

        let mut internet = sample_rule("block-chrome-internet");
        internet.remote_addr = None;
        internet.remote_addr_mask = None;
        internet.remote_port = None;
        internet.network_zone = Some(NetworkZone::Internet);
        mgr.create_rule(internet).await.unwrap();

        assert_eq!(
            mgr.list_rules().await.unwrap().len(),
            2,
            "zone-only difference must not merge"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// [System] 前缀规则防护：IPC 可达的 update_rule 拒绝改名/改匹配字段、
    /// 放行 enabled/description；delete_rule 一律拒绝；remove_all 走
    /// delete_rule_internal 仍能删除。
    #[tokio::test]
    async fn system_rule_update_delete_guard() {
        let (mgr, path) = test_manager("system_guard").await;

        let mut sys = sample_rule("[System] svchost.exe");
        sys.action = RuleAction::Allow;
        sys.direction = Direction::Both;
        sys.process_path = Some(r"C:\Windows\System32\svchost.exe".to_string());
        let sys_id = mgr.create_rule(sys).await.unwrap().id.unwrap();

        // a) 改名被拒绝，DB 未动
        let mut renamed = mgr.get_rule(sys_id).await.unwrap().unwrap();
        renamed.name = "user-rule".to_string();
        let err = mgr.update_rule(sys_id, renamed).await.unwrap_err();
        assert!(matches!(err, ServiceError::Validation(_)), "rename must be Validation error, got {:?}", err);
        assert_eq!(mgr.get_rule(sys_id).await.unwrap().unwrap().name, "[System] svchost.exe");

        // 改匹配字段同样被拒绝
        let mut rematched = mgr.get_rule(sys_id).await.unwrap().unwrap();
        rematched.process_path = Some(r"C:\evil.exe".to_string());
        assert!(mgr.update_rule(sys_id, rematched).await.is_err());

        // 改 action（豁免规则变拦截）被拒绝，DB 未动
        let mut blocked = mgr.get_rule(sys_id).await.unwrap().unwrap();
        blocked.action = RuleAction::Block;
        let err = mgr.update_rule(sys_id, blocked).await.unwrap_err();
        assert!(matches!(err, ServiceError::Validation(_)), "action change must be Validation error, got {:?}", err);
        assert_eq!(mgr.get_rule(sys_id).await.unwrap().unwrap().action, RuleAction::Allow);

        // 改 priority（破坏系统规则优先级布局）被拒绝
        let mut repri = mgr.get_rule(sys_id).await.unwrap().unwrap();
        repri.priority += 100;
        let err = mgr.update_rule(sys_id, repri).await.unwrap_err();
        assert!(matches!(err, ServiceError::Validation(_)), "priority change must be Validation error, got {:?}", err);

        // b) 改 description 成功；翻转 enabled 被放行（单测里 DriverHandle 未
        // open，失败是 Driver 错误而非 Validation——证明防护没有拦截 enabled）
        let before = mgr.get_rule(sys_id).await.unwrap().unwrap();
        let mut note = before.clone();
        note.description = "user note".to_string();
        mgr.update_rule(sys_id, note).await.unwrap();
        assert_eq!(mgr.get_rule(sys_id).await.unwrap().unwrap().description, "user note");

        let mut flip = before;
        flip.enabled = !flip.enabled;
        let err = mgr.update_rule(sys_id, flip).await.unwrap_err();
        assert!(
            matches!(err, ServiceError::Driver(_)),
            "enabled flip must pass the guard (Driver error expected), got {:?}",
            err
        );

        // c) 删除被拒绝
        let err = mgr.delete_rule(sys_id).await.unwrap_err();
        assert!(matches!(err, ServiceError::Validation(_)));
        assert!(mgr.get_rule(sys_id).await.unwrap().is_some());

        // d) remove_all（内部路径）仍能删除。单测 DriverHandle 未 open，
        // delete_rule_internal 的驱动移除报错被 remove_all 容忍（与既有
        // incoming_system_rule 测试同口径），但 DB 行已删除
        let _ = super::super::system_rules::remove_all(&mgr).await.unwrap();
        assert!(mgr.get_rule(sys_id).await.unwrap().is_none());

        let _ = std::fs::remove_file(&path);
    }
}
