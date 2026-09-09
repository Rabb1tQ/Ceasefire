//! cfctl - small admin/test client for the running Ceasefire service.
//! Usage:
//!   cfctl.exe settings                          print current settings
//!   cfctl.exe policy allow|block                set default policy (default_allow)
//!   cfctl.exe ask on|off                        toggle ask_to_connect_enabled
//!   cfctl.exe systemrules on|off                toggle system_rules_enabled
//!   cfctl.exe killswitch on|off                 toggle protect_when_not_running
//!   cfctl.exe poll [n]                          drain up to n notifications
//!   cfctl.exe throttle-path <path> <up_kbps> <down_kbps>   0 0 = remove
//!   cfctl.exe throttle-global <up_kbps> <down_kbps> [on|off]  0 0 = disable; on/off = 显式开关（off 保留限值）
//!   cfctl.exe inbound <local_port> <secs>       Block rule (Inbound) on local port, hold, remove
//!   cfctl.exe outbound [ip] [port] [secs]       Block rule (Outbound) to ip:port, hold, remove
//!   cfctl.exe outbound-range <ip> <start> <end> [secs]  Block rule (Outbound) to ip:start..end
//!                                                 (端口区间 ABI 实测用；优先级 10 先于 [弹窗] 规则)
//!   cfctl.exe rules                             list rules (id/name/enabled/action/direction)
//!   cfctl.exe export <file>                     导出用户规则 JSON 到文件（schema 1）
//!   cfctl.exe import <file> [merge|replace]     从文件导入规则（默认 merge）
//!   cfctl.exe dash <hours>                      Dashboard 图表四端点数据概览（时序/趋势/主机）
//!   cfctl.exe groups                            分组页验收：list/create/rename/enable/delete/init-predef
//!                                                 groups                          列出全部分组
//!                                                 groups create <name> [desc]     新建自定义分组
//!                                                 groups rename <id> <name>       重命名
//!                                                 groups enable <id> on|off       启停
//!                                                 groups delete <id>              删除（级联清成员）
//!                                                 groups members <id>             列成员
//!                                                 groups addmember <id> <path>    加成员
//!                                                 groups init-predef              初始化预定义分组
//!   cfctl.exe diags                             driver diagnostics (callout register status + counters)

use ceasefire_service::models::{Direction, IpcRequest, IpcResponse, PortRange, Rule, RuleAction};
use std::io::{Read, Write};

const PIPE: &str = r"\\.\pipe\CeasefireFirewall";

fn send(req: &IpcRequest) -> Result<IpcResponse, String> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE)
        .map_err(|e| format!("open pipe: {}", e))?;
    let data = bincode::serialize(req).map_err(|e| format!("serialize: {}", e))?;
    f.write_all(&(data.len() as u32).to_le_bytes()).map_err(|e| format!("write len: {}", e))?;
    f.write_all(&data).map_err(|e| format!("write body: {}", e))?;
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).map_err(|e| format!("read len: {}", e))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    f.read_exact(&mut body).map_err(|e| format!("read body: {}", e))?;
    bincode::deserialize(&body).map_err(|e| format!("deserialize: {}", e))
}

fn get_settings() -> Result<ceasefire_service::models::Settings, String> {
    match send(&IpcRequest::GetSettings)? {
        IpcResponse::Settings(s) => Ok(s),
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn put_settings(s: ceasefire_service::models::Settings) -> Result<(), String> {
    match send(&IpcRequest::UpdateSettings(s))? {
        IpcResponse::Success => Ok(()),
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("settings");
    match cmd {
        "settings" => {
            match get_settings() {
                Ok(s) => {
                    println!("{:#?}", s);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        "policy" => {
            let allow = args.get(1).map(String::as_str) == Some("allow");
            let mut s = get_settings()?;
            s.default_allow = allow;
            put_settings(s).map(|_| println!("default_allow = {}", allow))
        }
        "ask" => {
            let on = args.get(1).map(String::as_str) == Some("on");
            let mut s = get_settings()?;
            s.ask_to_connect_enabled = on;
            put_settings(s).map(|_| println!("ask_to_connect_enabled = {}", on))
        }
        "systemrules" => {
            let on = args.get(1).map(String::as_str) == Some("on");
            let mut s = get_settings()?;
            s.system_rules_enabled = on;
            put_settings(s).map(|_| println!("system_rules_enabled = {}", on))
        }
        "killswitch" => {
            let on = args.get(1).map(String::as_str) == Some("on");
            let mut s = get_settings()?;
            s.protect_when_not_running = on;
            put_settings(s).map(|_| println!("protect_when_not_running = {}", on))
        }
        "poll" => {
            let n: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
            match send(&IpcRequest::PollNotifications(n)) {
                Ok(IpcResponse::Notifications(items)) => {
                    println!("{} notification(s)", items.len());
                    for it in items {
                        println!(
                            "  [{:?}] {} {} -> {}:{} proto={} dir={} rule={:?}",
                            it.kind, it.process_name.unwrap_or_default(), it.process_path.unwrap_or_default(),
                            it.remote_addr, it.remote_port, it.protocol, it.direction, it.rule_id
                        );
                    }
                    Ok(())
                }
                other => Err(format!("unexpected response: {:?}", other)),
            }
        }
        "throttle-path" => {
            let path = args.get(1).cloned().unwrap_or_default();
            let up: Option<u32> = args.get(2).and_then(|s| s.parse().ok());
            let down: Option<u32> = args.get(3).and_then(|s| s.parse().ok());
            let limit = ceasefire_service::models::ProcessBandwidthLimit {
                id: None,
                enabled: true,
                process_path: path.clone(),
                process_name: None,
                upload_limit_kbps: up,
                download_limit_kbps: down,
                created_at: None,
                updated_at: None,
            };
            // up/down 均为 None（"throttle-path X"）或 Some(0) 时是删除语义，
            // 服务端已把"没删到行"映射为 Error，因此这里 Error 直接透传报错。
            let is_remove = up.map(|v| v == 0).unwrap_or(true)
                && down.map(|v| v == 0).unwrap_or(true);
            match send(&IpcRequest::SetProcessBandwidthLimit(limit)) {
                Ok(IpcResponse::Success) => {
                    if is_remove {
                        Ok(println!("throttle-path removed: {}", path))
                    } else {
                        Ok(println!("throttle-path set: {} {:?}/{:?}", path, up, down))
                    }
                }
                Ok(IpcResponse::Error(e)) => Err(e),
                other => Err(format!("unexpected response: {:?}", other)),
            }
        }
        "throttle-global" => {
            // 走与 GUI 相同的 SetGlobalBandwidthLimit IPC（含内核条目同步），
            // 不再经 update_settings 整份写（那条路不触发 kernel_throttle）。
            // 第三参数 on/off 显式控制开关：off 时限值照旧持久化、仅摘除
            // 内核全局条目（enabled=Some(false) 语义）；不传则 enabled=None
            // 走服务端按限值推断的旧语义。
            // 0 与缺省都归一化为 None（与 GUI 客户端同口径）：服务端 enabled=None
            // 时按 is_some() 推断开关，Some(0) 会被误判为"启用且限值 0"。
            // （set_throttle(0,0,0) 的驱动语义自第二十二轮起仅为"删除 PID 0
            // 全局条目"；清全表是 IOCTL_CLEAR_THROTTLE 的职责，仅服务停止使用。）
            let up: Option<u32> = args
                .get(1)
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|v| *v > 0);
            let down: Option<u32> = args
                .get(2)
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|v| *v > 0);
            let enabled = match args.get(3).map(|s| s.to_ascii_lowercase()) {
                Some(ref t) if t == "on" || t == "true" || t == "1" => Some(true),
                Some(ref t) if t == "off" || t == "false" || t == "0" => Some(false),
                _ => None,
            };
            match send(&IpcRequest::SetGlobalBandwidthLimit {
                upload_limit_kbps: up,
                download_limit_kbps: down,
                enabled,
            })? {
                IpcResponse::Success => {
                    println!("global throttle {:?}/{:?} enabled={:?}", up, down, enabled);
                    Ok(())
                }
                IpcResponse::Error(e) => Err(e),
                other => Err(format!("unexpected response: {:?}", other)),
            }
        }
        "inbound" => {
            let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8001);
            let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15);
            let rule = Rule {
                id: None,
                name: "cfctl-inbound-block".into(),
                description: String::new(),
                enabled: true,
                priority: 100,
                action: RuleAction::Block,
                direction: Direction::Inbound,
                protocol: None,
                process_id: None,
                process_path: None,
                remote_addr: None,
                remote_addr_mask: None,
                remote_domain: None,
                remote_port: None,
                local_addr: None,
                local_addr_mask: None,
                local_port: Some(PortRange::Single(port)),
                network_zone: None,
                app_group_id: None,
                created_at: None,
                updated_at: None,
            };
            match send(&IpcRequest::CreateRule(rule)) {
                Ok(IpcResponse::Rule(r)) => {
                    let id = r.id.unwrap_or(0);
                    println!("inbound Block rule on local port {} installed (id={}); holding {}s", port, id, secs);
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                    match send(&IpcRequest::DeleteRule(id)) {
                        Ok(IpcResponse::Success) => Ok(println!("rule removed")),
                        other => Err(format!("remove failed: {:?}", other)),
                    }
                }
                other => Err(format!("create failed: {:?}", other)),
            }
        }
        "outbound-range" => {
            // Port-range outbound-block test: exercises the RULE_INPUT port-end
            // fields end to end (driver must block start..port..end, not just start).
            // Priority 10 so the Block wins over [弹窗] Allow rules at priority 50.
            let ip: String = args.get(1).cloned().unwrap_or_else(|| "192.168.79.23".into());
            let start: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
            let end: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2000);
            let secs: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(15);
            let rule = Rule {
                id: None,
                name: "cfctl-outbound-range-block".into(),
                description: String::new(),
                enabled: true,
                priority: 10,
                action: RuleAction::Block,
                direction: Direction::Outbound,
                protocol: Some(ceasefire_service::models::Protocol::Tcp),
                process_id: None,
                process_path: None,
                remote_addr: Some(ip.clone()),
                remote_addr_mask: Some(32),
                remote_domain: None,
                remote_port: Some(PortRange::Range(start, end)),
                local_addr: None,
                local_addr_mask: None,
                local_port: None,
                network_zone: None,
                app_group_id: None,
                created_at: None,
                updated_at: None,
            };
            match send(&IpcRequest::CreateRule(rule)) {
                Ok(IpcResponse::Rule(r)) => {
                    let id = r.id.unwrap_or(0);
                    println!("outbound Block rule to {}:{}-{} installed (id={}); holding {}s", ip, start, end, id, secs);
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                    match send(&IpcRequest::DeleteRule(id)) {
                        Ok(IpcResponse::Success) => Ok(println!("rule removed")),
                        other => Err(format!("remove failed: {:?}", other)),
                    }
                }
                other => Err(format!("create failed: {:?}", other)),
            }
        }
        "outbound" => {
            // Honest outbound-block test: Block Outbound to remote ip:port,
            // hold, then remove. Default target is the dev-host test server.
            let ip: String = args.get(1).cloned().unwrap_or_else(|| "192.168.79.23".into());
            let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8010);
            let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15);
            // optional mask override; default exact match for the family (v4=32, v6=128)
            let default_mask: u8 = if ip.contains(':') { 128 } else { 32 };
            let mask: u8 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(default_mask);
            let rule = Rule {
                id: None,
                name: "cfctl-outbound-block".into(),
                description: String::new(),
                enabled: true,
                priority: 100,
                action: RuleAction::Block,
                direction: Direction::Outbound,
                protocol: Some(ceasefire_service::models::Protocol::Tcp),
                process_id: None,
                process_path: None,
                remote_addr: Some(ip.clone()),
                remote_addr_mask: Some(mask),
                remote_domain: None,
                remote_port: Some(PortRange::Single(port)),
                local_addr: None,
                local_addr_mask: None,
                local_port: None,
                network_zone: None,
                app_group_id: None,
                created_at: None,
                updated_at: None,
            };
            match send(&IpcRequest::CreateRule(rule)) {
                Ok(IpcResponse::Rule(r)) => {
                    let id = r.id.unwrap_or(0);
                    println!("outbound Block rule to {}:{} installed (id={}); holding {}s", ip, port, id, secs);
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                    match send(&IpcRequest::DeleteRule(id)) {
                        Ok(IpcResponse::Success) => Ok(println!("rule removed")),
                        other => Err(format!("remove failed: {:?}", other)),
                    }
                }
                other => Err(format!("create failed: {:?}", other)),
            }
        }
        "inbound-allow" => {
            // Persistent Inbound Allow rule on a local port (lifeline for the
            // vmctl agent before switching default policy to block).
            let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8080);
            let rule = Rule {
                id: None,
                name: format!("cfctl-inbound-allow-{}", port),
                description: String::new(),
                enabled: true,
                priority: 50,
                action: RuleAction::Allow,
                direction: Direction::Inbound,
                protocol: None,
                process_id: None,
                process_path: None,
                remote_addr: None,
                remote_addr_mask: None,
                remote_domain: None,
                remote_port: None,
                local_addr: None,
                local_addr_mask: None,
                local_port: Some(PortRange::Single(port)),
                network_zone: None,
                app_group_id: None,
                created_at: None,
                updated_at: None,
            };
            match send(&IpcRequest::CreateRule(rule)) {
                Ok(IpcResponse::Rule(r)) => Ok(println!("inbound Allow rule on port {} created (id={:?})", port, r.id)),
                other => Err(format!("create failed: {:?}", other)),
            }
        }
        "delrule" => {
            let id: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            match send(&IpcRequest::DeleteRule(id)) {
                Ok(IpcResponse::Success) => Ok(println!("rule {} deleted", id)),
                other => Err(format!("delete failed: {:?}", other)),
            }
        }
        "rules" => {
            match send(&IpcRequest::ListRules { offset: 0, limit: u32::MAX, search: None }) {
                Ok(IpcResponse::RulePage(page)) => {
                    for r in page.rules {
                        println!(
                            "  #{:<3} {:<6} {:<7} dir={:<8} enabled={} path={:?} raddr={:?}/{} rport={:?} lport={:?} group={:?}",
                            r.id.unwrap_or(0), r.name, format!("{:?}", r.action), format!("{:?}", r.direction),
                            r.enabled, r.process_path, r.remote_addr, r.remote_addr_mask.unwrap_or(0),
                            r.remote_port, r.local_port, r.app_group_id
                        );
                    }
                    Ok(())
                }
                other => Err(format!("unexpected response: {:?}", other)),
            }
        }
        // 导入/导出端到端测试口（与 GUI 相同 IPC）：export 拿 JSON 字节落盘；
        // import 读盘、解析 schema、按 merge/replace 走整批导入。
        "export" => {
            let path = args.get(1).cloned().unwrap_or_else(|| "rules_export.json".to_string());
            match send(&IpcRequest::ExportRules) {
                Ok(IpcResponse::ExportData(data)) => {
                    std::fs::write(&path, data).map_err(|e| format!("write {}: {}", path, e))?;
                    Ok(println!("exported to {}", path))
                }
                Ok(IpcResponse::Error(e)) => Err(e),
                other => Err(format!("unexpected response: {:?}", other)),
            }
        }
        "import" => {
            let path = args.get(1).cloned().unwrap_or_else(|| "rules_export.json".to_string());
            let mode = match args.get(2).map(String::as_str) {
                Some("replace") | Some("Replace") => {
                    ceasefire_service::models::ImportMode::Replace
                }
                _ => ceasefire_service::models::ImportMode::Merge,
            };
            let text = std::fs::read_to_string(&path).map_err(|e| format!("read {}: {}", path, e))?;
            let parsed: ceasefire_service::models::RuleExportFile = serde_json::from_str(&text)
                .map_err(|e| format!("parse {}: {}", path, e))?;
            if parsed.schema != ceasefire_service::models::RULE_EXPORT_SCHEMA {
                return Err(format!("unsupported schema {}", parsed.schema));
            }
            match send(&IpcRequest::ImportRules { rules: parsed.rules, mode }) {
                Ok(IpcResponse::ImportStats(s)) => Ok(println!(
                    "imported={} skipped={} groups_created={}",
                    s.imported, s.skipped, s.groups_created
                )),
                Ok(IpcResponse::Error(e)) => Err(e),
                other => Err(format!("unexpected response: {:?}", other)),
            }
        }
        // Dashboard 图表数据端点概览（1/24/168 三档）
        "dash" => {
            let hours: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);
            let tl = match send(&IpcRequest::GetAppTrafficTimeline { hours }) {
                Ok(IpcResponse::AppTrafficTimeline(v)) => v,
                Ok(IpcResponse::Error(e)) => return Err(e),
                other => return Err(format!("timeline: {:?}", other)),
            };
            let at = match send(&IpcRequest::GetActionTrend { hours }) {
                Ok(IpcResponse::ActionTrend(v)) => v,
                Ok(IpcResponse::Error(e)) => return Err(e),
                other => return Err(format!("trend: {:?}", other)),
            };
            let th = match send(&IpcRequest::GetTopHosts { hours, limit: 10 }) {
                Ok(IpcResponse::TopHosts(v)) => v,
                Ok(IpcResponse::Error(e)) => return Err(e),
                other => return Err(format!("hosts: {:?}", other)),
            };
            println!("app timeline: {} point(s)", tl.len());
            for p in tl.iter().take(3) {
                println!("  {} {} up={} down={}", p.timestamp, p.process_path, p.bytes_sent, p.bytes_received);
            }
            println!("action trend: {} bucket(s)", at.len());
            for p in at.iter().take(3) {
                println!("  {} allowed={} blocked={}", p.timestamp, p.allowed_bytes, p.blocked_bytes);
            }
            println!("top hosts: {} host(s)", th.len());
            for h in th.iter().take(5) {
                println!("  {} {:?} up={} down={} n={}", h.remote_addr, h.domain, h.bytes_sent, h.bytes_received, h.connection_count);
            }
            Ok(())
        }
        // 分组页验收：自定义分组 CRUD + 预置初始化（走与 GUI 相同的 IPC 变体）
        "groups" => {
            use ceasefire_service::models::AppGroup;
            let sub = args.get(1).map(String::as_str).unwrap_or("list");
            match sub {
                "list" => {
                    let groups = match send(&IpcRequest::ListAppGroups) {
                        Ok(IpcResponse::AppGroups(v)) => v,
                        Ok(IpcResponse::Error(e)) => return Err(e),
                        other => return Err(format!("list: {:?}", other)),
                    };
                    for g in &groups {
                        println!("#{} {} [{}] enabled={} predefined={}", g.id.unwrap_or(0), g.name, g.description, g.enabled, g.is_predefined);
                    }
                    println!("{} group(s)", groups.len());
                    Ok(())
                }
                "create" => {
                    let name = args.get(2).ok_or("usage: groups create <name> [desc]")?.clone();
                    let desc = args.get(3).cloned().unwrap_or_default();
                    let group = AppGroup {
                        id: None,
                        name,
                        description: desc,
                        enabled: true,
                        is_predefined: false,
                        created_at: None,
                        updated_at: None,
                    };
                    match send(&IpcRequest::CreateAppGroup { group }) {
                        Ok(IpcResponse::AppGroupCreated(g)) => {
                            println!("created #{} {}", g.id.unwrap_or(0), g.name);
                            Ok(())
                        }
                        Ok(IpcResponse::Error(e)) => Err(e),
                        other => Err(format!("create: {:?}", other)),
                    }
                }
                "rename" => {
                    let id: u32 = args.get(2).and_then(|s| s.parse().ok()).ok_or("usage: groups rename <id> <name>")?;
                    let name = args.get(3).ok_or("usage: groups rename <id> <name>")?.clone();
                    // 先取现值只改名字段，其余原样回传
                    let groups = match send(&IpcRequest::ListAppGroups) {
                        Ok(IpcResponse::AppGroups(v)) => v,
                        Ok(IpcResponse::Error(e)) => return Err(e),
                        other => return Err(format!("list: {:?}", other)),
                    };
                    let mut g = groups.into_iter().find(|g| g.id == Some(id))
                        .ok_or_else(|| format!("group #{} not found", id))?;
                    g.name = name;
                    match send(&IpcRequest::UpdateAppGroup { id, group: g }) {
                        Ok(IpcResponse::Success) => {
                            println!("renamed #{}", id);
                            Ok(())
                        }
                        Ok(IpcResponse::Error(e)) => Err(e),
                        other => Err(format!("rename: {:?}", other)),
                    }
                }
                "enable" => {
                    let id: u32 = args.get(2).and_then(|s| s.parse().ok()).ok_or("usage: groups enable <id> on|off")?;
                    let enabled = args.get(3).map(String::as_str) != Some("off");
                    match send(&IpcRequest::SetAppGroupEnabled { id, enabled }) {
                        Ok(IpcResponse::Success) => {
                            println!("group #{} enabled={}", id, enabled);
                            Ok(())
                        }
                        Ok(IpcResponse::Error(e)) => Err(e),
                        other => Err(format!("enable: {:?}", other)),
                    }
                }
                "delete" => {
                    let id: u32 = args.get(2).and_then(|s| s.parse().ok()).ok_or("usage: groups delete <id>")?;
                    match send(&IpcRequest::DeleteAppGroup { id }) {
                        Ok(IpcResponse::Success) => {
                            println!("deleted #{}", id);
                            Ok(())
                        }
                        Ok(IpcResponse::Error(e)) => Err(e),
                        other => Err(format!("delete: {:?}", other)),
                    }
                }
                "members" => {
                    let id: u32 = args.get(2).and_then(|s| s.parse().ok()).ok_or("usage: groups members <id>")?;
                    let members = match send(&IpcRequest::GetAppGroupMembers(id)) {
                        Ok(IpcResponse::AppGroupMembers(v)) => v,
                        Ok(IpcResponse::Error(e)) => return Err(e),
                        other => return Err(format!("members: {:?}", other)),
                    };
                    for m in &members {
                        println!("  {}", m.process_path);
                    }
                    println!("{} member(s)", members.len());
                    Ok(())
                }
                "addmember" => {
                    let id: u32 = args.get(2).and_then(|s| s.parse().ok()).ok_or("usage: groups addmember <id> <path>")?;
                    let path = args.get(3).ok_or("usage: groups addmember <id> <path>")?.clone();
                    match send(&IpcRequest::AddAppGroupMember { group_id: id, process_path: path, process_name: None }) {
                        Ok(IpcResponse::Success) => {
                            println!("member added to #{}", id);
                            Ok(())
                        }
                        Ok(IpcResponse::Error(e)) => Err(e),
                        other => Err(format!("addmember: {:?}", other)),
                    }
                }
                "init-predef" => {
                    match send(&IpcRequest::InitializePredefinedGroups) {
                        Ok(IpcResponse::Success) => {
                            println!("predefined groups initialized");
                            Ok(())
                        }
                        Ok(IpcResponse::Error(e)) => Err(e),
                        other => Err(format!("init-predef: {:?}", other)),
                    }
                }
                other => Err(format!("unknown groups subcommand: {}", other)),
            }
        }
        // Reproduce the GUI drawer query exactly: server-side paged history
        // (args: history [path] [limit] [action] [sort_by] [sort_order])
        "history" => {
            use ceasefire_service::models::HistoryFilters;
            let filters = HistoryFilters {
                limit: Some(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(51)),
                offset: Some(0),
                hours: Some(24),
                action: args.get(3).cloned(),
                protocol: None,
                process_path: args.get(1).and_then(|s| (s != "-").then(|| s.to_string())),
                remote_addr: None,
                direction: None,
                sort_by: args.get(4).cloned(),
                sort_order: args.get(5).cloned(),
            };
            match send(&IpcRequest::GetNetworkHistory(filters)) {
                Ok(IpcResponse::NetworkHistoryRecords(records)) => {
                    println!("got {} records", records.len());
                    for r in records.iter().take(3) {
                        println!("  {} {} {} {}:{} dir={}", r.timestamp, format!("{:?}", r.action),
                            format!("{:?}", r.protocol), r.remote_addr, r.remote_port, format!("{:?}", r.direction));
                    }
                    Ok(())
                }
                Ok(other) => Err(format!("unexpected response variant: {:?}", other)),
                Err(e) => Err(format!("IPC failed: {}", e)),
            }
        }
        // Driver diagnostics: callout FwpsCalloutRegister status/calloutId and
        // per-family runtime counters. Explains "layer DEAD" (0x80320009 =
        // stale registration) vs "classify not invoked" (0 classify count).
        "diags" => {
            match send(&IpcRequest::GetDriverDiags) {
                Ok(IpcResponse::DriverDiags(Some(d))) => {
                    println!("callout registration (reg 0=OK, 0x80320009=stale/zombie; unreg 0=OK, only diag v2+ drivers report):");
                    for c in &d.callouts {
                        println!(
                            "  {:<24} status=0x{:08X} calloutId={} unreg=0x{:08X} unregRetries={}",
                            c.name, c.reg_status, c.callout_id, c.unreg_status, c.unreg_retries
                        );
                    }
                    println!("counters ([0]=V4 [1]=V6):");
                    println!(
                        "  stream classify:      V4={:>6}  V6={:>6}",
                        d.classify_stream[0], d.classify_stream[1]
                    );
                    println!(
                        "  flow-est classify:    V4={:>6}  V6={:>6}",
                        d.classify_flow_est[0], d.classify_flow_est[1]
                    );
                    println!(
                        "  assoc ok/fail:        V4={}/{}  V6={}/{}",
                        d.assoc_ok[0], d.assoc_fail[0], d.assoc_ok[1], d.assoc_fail[1]
                    );
                    println!(
                        "  flow-delete (Close events): V4={:>6}  V6={:>6}",
                        d.flow_delete[0], d.flow_delete[1]
                    );
                    println!(
                        "  stream bytes counted: V4={}  V6={}",
                        d.stream_bytes_counted[0], d.stream_bytes_counted[1]
                    );
                    // diag v3 尾部：限速表进程生命周期清理（服务侧已按版本门控）
                    if d.diag_version >= 3 {
                        println!(
                            "  throttle: active={} notify-removes={}",
                            d.throttle_active_entries, d.throttle_notify_removes
                        );
                    } else {
                        println!("  throttle: (driver too old)");
                    }
                    // diag v4 尾部：下载限速 classify/verdict（第 19 轮起执行点在
                    // INBOUND_IPPACKET 层，计数器字段名保持 in_transport 沿用 v5 布局）
                    if d.diag_version >= 4 {
                        println!(
                            "  download classify:      V4={:>6}  V6={:>6}",
                            d.in_transport_classify[0], d.in_transport_classify[1]
                        );
                        println!(
                            "  download permit:       V4={:>6}  V6={:>6}",
                            d.in_transport_permit[0], d.in_transport_permit[1]
                        );
                        println!(
                            "  download block:        V4={:>6}  V6={:>6}",
                            d.in_transport_block[0], d.in_transport_block[1]
                        );
                        println!(
                            "  download reg:          V4=0x{:08X} id={}  V6=0x{:08X} id={}",
                            d.in_transport_reg_status[0], d.in_transport_callout_id[0],
                            d.in_transport_reg_status[1], d.in_transport_callout_id[1]
                        );
                    } else {
                        println!("  in-transport: (driver too old)");
                    }
                    // diag v5 尾部：kernel pacing（克隆-扣留-定时注入）。
                    // 恒等式：held = injected + injectFail + 当前队列深度
                    //（queueDrop 在入队前发生，不计入 held）
                    if d.diag_version >= 5 {
                        println!("pacing (clone-hold-timed-inject):");
                        println!(
                            "  held={} injected={} injectFail={} queueDrop={}",
                            d.pacing_held, d.pacing_injected, d.pacing_inject_fail, d.pacing_queue_drop
                        );
                        println!(
                            "  queueDepthMax={}B timerTicks={}",
                            d.pacing_queue_depth_max, d.pacing_timer_ticks
                        );
                    } else {
                        println!("  pacing: (driver too old)");
                    }
                    Ok(())
                }
                Ok(IpcResponse::DriverDiags(None)) => {
                    Err("driver does not support diagnostics IOCTL (old build)".into())
                }
                Ok(other) => Err(format!("unexpected response: {:?}", other)),
                Err(e) => Err(format!("IPC failed: {}", e)),
            }
        }
        other => Err(format!("unknown command: {}", other)),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {}", e);
        std::process::exit(1);
    }
}
