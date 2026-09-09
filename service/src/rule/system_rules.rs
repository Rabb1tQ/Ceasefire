//! 内置系统豁免规则集（参考 simplewall System rules）。
//!
//! 默认拦截（default_allow=false）模式下，若没有系统进程豁免，Windows
//! 自身的网络探测（NCSI）、DNS、激活、Windows Update 等会全部被拦，
//! 用户会看到"断网"假象。此模块在服务启动 / 设置切换时按需安装或移除
//! 一组 [System] 前缀的放行规则；它们是普通规则，可在 GUI 规则页查看、
//! 停用或删除。按规则名做幂等。
//!
//! 规则路径一律是运行时解析出的系统目录下、存在性检查通过的**完整路径**
//! （盘符开头）。历史上用 `\svchost.exe` 这类短路径配合驱动的"包含"语义
//! 可命中任意目录同名 exe，已废弃。

use super::manager::RuleManager;
use super::super::error::Result;
use super::super::models::*;

/// 系统规则统一名称前缀；按名称匹配实现幂等安装/卸载
pub const SYSTEM_RULE_PREFIX: &str = "[System] ";

fn system_rule(name: &str, description: &str, priority: u32, m: RuleMatch) -> Rule {
    Rule {
        id: None,
        name: format!("{}{}", SYSTEM_RULE_PREFIX, name),
        description: description.to_string(),
        enabled: true,
        priority,
        action: RuleAction::Allow,
        direction: m.direction,
        protocol: m.protocol,
        process_id: m.process_id,
        process_path: m.process_path,
        remote_addr: None,
        remote_addr_mask: None,
        remote_domain: None,
        remote_port: m.remote_port,
        local_addr: None,
        local_addr_mask: None,
        local_port: m.local_port,
        network_zone: None,
        app_group_id: None,
        created_at: None,
        updated_at: None,
    }
}

struct RuleMatch {
    direction: Direction,
    protocol: Option<Protocol>,
    process_id: Option<u32>,
    process_path: Option<String>,
    remote_port: Option<PortRange>,
    local_port: Option<PortRange>,
}

fn path_only(direction: Direction, path: &str) -> RuleMatch {
    RuleMatch { direction, protocol: None, process_id: None, process_path: Some(path.to_string()), remote_port: None, local_port: None }
}

fn dhcp_match() -> RuleMatch {
    RuleMatch { direction: Direction::Both, protocol: Some(Protocol::Udp), process_id: None, process_path: None, remote_port: None, local_port: Some(PortRange::Single(68)) }
}

/// 系统目录（SYSTEMROOT，失败回退 C:\Windows）
fn system_root() -> String {
    std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".to_string())
}

/// 系统进程定义：name 是规则名主体；wow64=true 时 System32 与 SysWOW64
/// 两个变体都按存在性安装（SysWOW64 变体命名为 `{name} (SysWOW64)`），
/// wow64=false（lsass/services 不可能跑 WOW64）只装 System32 变体。
struct ProcessDef<'a> {
    name: &'a str,
    description: &'a str,
    priority: u32,
    direction: Direction,
    wow64: bool,
}

const PROCESS_DEFS: &[ProcessDef] = &[
    // svchost.exe：承载 NCSI、DNS 客户端、WU 等绝大多数系统服务
    ProcessDef { name: "svchost.exe", description: "Windows 服务宿主（NCSI/DNS/WU 等）", priority: 2, direction: Direction::Outbound, wow64: true },
    ProcessDef { name: "lsass.exe", description: "本地安全机构子系统", priority: 3, direction: Direction::Both, wow64: false },
    ProcessDef { name: "services.exe", description: "服务控制管理器", priority: 4, direction: Direction::Both, wow64: false },
    ProcessDef { name: "dllhost.exe", description: "COM Surrogate", priority: 5, direction: Direction::Outbound, wow64: true },
    ProcessDef { name: "wuauclt.exe", description: "Windows Update 客户端", priority: 6, direction: Direction::Outbound, wow64: true },
    ProcessDef { name: "backgroundTaskHost.exe", description: "UWP 后台任务宿主", priority: 7, direction: Direction::Outbound, wow64: true },
];

/// 系统豁免规则定义（priority 越小越先匹配）。root 传入 SYSTEMROOT
/// （如 C:\Windows），便于测试注入临时目录。
pub fn definitions_with_root(root: &str) -> Vec<Rule> {
    let mut defs = vec![
        // 内核 System 进程（PID 4）：DHCP/ICMP 等内核态网络
        system_rule("System", "内核系统进程（PID 4）", 1, RuleMatch {
            direction: Direction::Both,
            protocol: None,
            process_id: Some(4),
            process_path: None,
            remote_port: None,
            local_port: None,
        }),
    ];
    for p in PROCESS_DEFS {
        // System32 变体无条件生成：迁移按定义名匹配旧短路径行，若被存在性
        // 跳过（如未来版本移除 wuauclt.exe 的机器升级旧库），旧 \wuauclt.exe
        // 任意目录命中行将永远无人迁移；不存在的完整路径规则只是永不匹配的
        // Allow 行，无害。仅 SysWOW64 变体保留存在性门控（32 位系统无此目录）。
        let mut variants: Vec<(&str, String)> = vec![("", format!(r"{}\System32\{}", root, p.name))];
        if p.wow64 {
            let wow_path = format!(r"{}\SysWOW64\{}", root, p.name);
            if std::path::Path::is_file(std::path::Path::new(&wow_path)) {
                variants.push((" (SysWOW64)", wow_path));
            }
        }
        for (suffix, full_path) in variants {
            defs.push(system_rule(
                &format!("{}{}", p.name, suffix),
                &format!("{}。实际路径: {}", p.description, full_path),
                p.priority,
                path_only(p.direction, &full_path),
            ));
        }
    }
    // 任意进程的 DNS（UDP/53）放行：否则默认拦截下域名解析全挂。
    // 仅 UDP：驱动规则结构按协议精确匹配，TCP/53 回退查询罕见，
    // 如确有需要可由用户自行加规则。
    defs.push(system_rule("DNS", "DNS 查询（UDP 53，任意进程）", 8, RuleMatch {
        direction: Direction::Both,
        protocol: Some(Protocol::Udp),
        process_id: None,
        process_path: None,
        remote_port: Some(PortRange::Single(53)),
        local_port: None,
    }));
    // DHCP：本地 68 端口
    defs.push(system_rule("DHCP", "DHCP 客户端（UDP 68）", 9, dhcp_match()));
    defs
}

pub fn definitions() -> Vec<Rule> {
    definitions_with_root(&system_root())
}

/// 安装缺失的系统规则（按名称幂等），并对同名但匹配路径已过时的旧规则
/// （如历史版本写入的 `\svchost.exe` 短路径）做原地迁移。返回新增条数。
pub async fn ensure_installed(rule_manager: &RuleManager) -> Result<usize> {
    ensure_installed_with_root(rule_manager, &system_root()).await
}

pub async fn ensure_installed_with_root(rule_manager: &RuleManager, root: &str) -> Result<usize> {
    let existing = rule_manager.list_rules().await?;
    let mut added = 0;
    let mut migrated = 0;
    for def in definitions_with_root(root) {
        match existing.iter().find(|r| r.name == def.name) {
            None => {
                match rule_manager.create_rule(def).await {
                    Ok(_) => added += 1,
                    Err(e) => tracing::warn!("Failed to install system rule: {}", e),
                }
            }
            Some(old) => {
                // 原地迁移：匹配路径与当前定义不一致（旧版短路径 / 系统
                // 目录变更）时走 update_rule 更新匹配字段，但保留该行现有
                // 的 enabled/priority/id/created_at——用户停用过的不许被
                // 重置为 enabled，用户调过的优先级也不动。
                if old.process_path == def.process_path {
                    continue;
                }
                let def_name = def.name.clone();
                let mut updated = def;
                updated.id = old.id;
                updated.enabled = old.enabled;
                updated.priority = old.priority;
                updated.created_at = old.created_at.clone();
                match rule_manager.update_rule_internal(old.id.unwrap_or(0), updated).await {
                    Ok(()) => migrated += 1,
                    Err(e) => tracing::warn!("Failed to migrate system rule {}: {}", def_name, e),
                }
            }
        }
    }
    if added > 0 {
        tracing::info!("Installed {} system exemption rules", added);
    }
    if migrated > 0 {
        tracing::info!("Migrated {} system exemption rules to full paths", migrated);
    }
    Ok(added)
}

/// 移除全部系统规则（按前缀）。
pub async fn remove_all(rule_manager: &RuleManager) -> Result<usize> {
    let existing = rule_manager.list_rules().await?;
    let mut removed = 0;
    for r in existing {
        if r.name.starts_with(SYSTEM_RULE_PREFIX) {
            if let Some(id) = r.id {
                match rule_manager.delete_rule_internal(id).await {
                    Ok(()) => removed += 1,
                    Err(e) => tracing::warn!("Failed to remove system rule {}: {}", r.name, e),
                }
            }
        }
    }
    if removed > 0 {
        tracing::info!("Removed {} system exemption rules", removed);
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::manager::RuleManager;
    use crate::driver::DriverHandle;
    use crate::database::Database;
    use std::sync::Arc;

    async fn test_manager(name: &str) -> (RuleManager, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("cf_sys_rules_test_{}.db", name));
        let _ = std::fs::remove_file(&path);
        let db = Arc::new(Database::open(path.to_str().unwrap()).expect("open db"));
        let driver = Arc::new(DriverHandle::new().expect("driver handle"));
        let mgr = RuleManager::new(db, driver).expect("manager");
        (mgr, path)
    }

    fn seed_rule(name: &str, path: &str, priority: u32) -> Rule {
        Rule {
            id: None,
            name: name.to_string(),
            description: "old".to_string(),
            enabled: false,
            priority,
            action: RuleAction::Allow,
            direction: Direction::Outbound,
            protocol: None,
            process_id: None,
            process_path: Some(path.to_string()),
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

    /// 携带进程路径的定义必须是盘符开头的完整路径（System/DNS/DHCP 等无路径定义跳过）
    #[test]
    fn definitions_use_full_paths() {
        for def in definitions_with_root(r"C:\Windows") {
            if let Some(path) = def.process_path.as_deref() {
                assert!(
                    path.as_bytes().get(1) == Some(&b':'),
                    "path must start with a drive letter: {} ({})",
                    def.name,
                    path
                );
                assert!(
                    path.matches('\\').count() >= 2,
                    "path must be fully qualified: {} ({})",
                    def.name,
                    path
                );
            }
        }
    }

    /// SysWOW64 变体按文件存在性生成
    #[test]
    fn wow64_variant_gated_by_existence() {
        let root = std::env::temp_dir().join(format!("cf_sys_root_gate_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("System32")).unwrap();
        std::fs::create_dir_all(root.join("SysWOW64")).unwrap();
        std::fs::write(root.join("System32").join("svchost.exe"), b"fake").unwrap();
        let root_str = root.to_str().unwrap().to_string();

        // SysWOW64 下没有文件：只有 System32 变体
        let names: Vec<String> = definitions_with_root(&root_str).into_iter().map(|d| d.name).collect();
        assert!(names.contains(&format!("{}svchost.exe", SYSTEM_RULE_PREFIX)));
        assert!(!names.contains(&format!("{}svchost.exe (SysWOW64)", SYSTEM_RULE_PREFIX)));

        // 文件出现后变体随之生成
        std::fs::write(root.join("SysWOW64").join("svchost.exe"), b"fake").unwrap();
        let names: Vec<String> = definitions_with_root(&root_str).into_iter().map(|d| d.name).collect();
        assert!(names.contains(&format!("{}svchost.exe (SysWOW64)", SYSTEM_RULE_PREFIX)));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 迁移：旧 \svchost.exe 短路径行被原地更新为完整路径，enabled/priority
    /// 保留；SysWOW64 变体的路径解析同样正确。（enabled 行的新增/更新会直发
    /// 驱动，单测里 DriverHandle 未 open 会报错回滚，故统一用 disabled 行；
    /// enabled 行为在 VM 全量验收覆盖。）
    #[tokio::test]
    async fn migration_updates_stale_paths_and_keeps_enabled() {
        let (mgr, db_path) = test_manager("migrate").await;

        let root = std::env::temp_dir().join(format!("cf_sys_root_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for sub in ["System32", "SysWOW64"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
            std::fs::write(root.join(sub).join("svchost.exe"), b"fake").unwrap();
        }
        let root_str = root.to_str().unwrap().to_string();

        let old_id = mgr.create_rule(seed_rule(&format!("{}svchost.exe", SYSTEM_RULE_PREFIX), r"\svchost.exe", 42))
            .await.unwrap().id.unwrap();
        let wow_id = mgr.create_rule(seed_rule(&format!("{}svchost.exe (SysWOW64)", SYSTEM_RULE_PREFIX), r"\svchost.exe", 43))
            .await.unwrap().id.unwrap();

        ensure_installed_with_root(&mgr, &root_str).await.unwrap();

        let all = mgr.list_rules().await.unwrap();
        let migrated = all.iter().find(|r| r.id == Some(old_id)).expect("migrated row keeps its id");
        assert_eq!(
            migrated.process_path.as_deref(),
            Some(root.join("System32").join("svchost.exe").to_str().unwrap()),
            "stale short path must be replaced with the full System32 path"
        );
        assert!(!migrated.enabled, "user-disabled rule must not be re-enabled");
        assert_eq!(migrated.priority, 42, "user-adjusted priority must be kept");

        let wow = all.iter().find(|r| r.id == Some(wow_id)).expect("wow64 row kept");
        assert_eq!(
            wow.process_path.as_deref(),
            Some(root.join("SysWOW64").join("svchost.exe").to_str().unwrap()),
            "SysWOW64 variant resolves to the SysWOW64 directory"
        );
        assert!(!wow.enabled);

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&db_path);
    }

    /// remove_all 语义不变：新命名的 (SysWOW64) 行同样按前缀删除，用户规则保留
    #[tokio::test]
    async fn remove_all_covers_wow64_variant() {
        let (mgr, db_path) = test_manager("remove_all").await;
        let sys_id = mgr.create_rule(seed_rule(&format!("{}svchost.exe", SYSTEM_RULE_PREFIX), r"C:\Windows\System32\svchost.exe", 2))
            .await.unwrap().id.unwrap();
        let wow_id = mgr.create_rule(seed_rule(&format!("{}svchost.exe (SysWOW64)", SYSTEM_RULE_PREFIX), r"C:\Windows\SysWOW64\svchost.exe", 2))
            .await.unwrap().id.unwrap();
        mgr.create_rule(seed_rule("user rule", r"C:\Program Files\App\app.exe", 100)).await.unwrap();

        // DriverHandle 未 open 时 delete_rule 的驱动移除会报错（DB 行已删），
        // 单测只验证 DB 侧前缀删除语义；计数在 VM 验收覆盖
        let _ = remove_all(&mgr).await;
        let after = mgr.list_rules().await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].name, "user rule", "user rule survives remove_all");
        assert_ne!(after[0].id, Some(sys_id));
        assert_ne!(after[0].id, Some(wow_id));

        let _ = std::fs::remove_file(&db_path);
    }
}
