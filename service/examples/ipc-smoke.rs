//! IPC smoke test: simulates the GUI client against the running service.
//! Usage: ipc-smoke.exe [pipe_name]   (default \\.\pipe\CeasefireFirewall)
//! Exercises read-only requests plus a create/delete rule round-trip.
//! One pipe connection per request (server accepts one client per instance).

use ceasefire_service::models::{Direction, IpcRequest, IpcResponse, PortRange, Rule, RuleAction};
use std::io::{Read, Write};

fn main() {
    let pipe = std::env::args()
        .nth(1)
        .filter(|a| a.contains("pipe"))
        .unwrap_or_else(|| r"\\.\pipe\CeasefireFirewall".to_string());

    // "block <pid> <seconds>": install a Block rule for a process, hold, remove.
    let args: Vec<String> = std::env::args().collect();
    // "block pid <pid> <secs>" or "block addr <ip> <port> <secs>"
    if let Some(i) = args.iter().position(|a| a == "block") {
        let mode = args.get(i + 1).cloned().unwrap_or_default();
        let mut rule = test_rule();
        rule.name = "smoke-block-test".into();
        let secs: u64;
        if mode == "addr" {
            rule.process_id = None;
            rule.remote_addr = args.get(i + 2).cloned();
            rule.remote_addr_mask = Some(32);
            rule.remote_port = args.get(i + 3).and_then(|s| s.parse().ok()).map(PortRange::Single);
            secs = args.get(i + 4).and_then(|s| s.parse().ok()).unwrap_or(30);
        } else {
            let pid: u32 = args.get(i + 2).and_then(|s| s.parse().ok()).unwrap_or(0);
            rule.process_id = Some(pid);
            rule.remote_addr = None;
            rule.remote_addr_mask = None;
            rule.remote_port = None;
            secs = args.get(i + 3).and_then(|s| s.parse().ok()).unwrap_or(30);
        }
        match send(&pipe, &IpcRequest::CreateRule(rule)) {
            Ok(IpcResponse::Rule(r)) => {
                println!("Block rule installed (id={:?}); holding {}s", r.id, secs);
                std::thread::sleep(std::time::Duration::from_secs(secs));
                match send(&pipe, &IpcRequest::DeleteRule(r.id.unwrap_or(0))) {
                    Ok(IpcResponse::Success) => println!("Block rule removed"),
                    o => println!("remove failed: {:?}", o),
                }
            }
            o => println!("install failed: {:?}", o),
        }
        return;
    }

    let mut reqs = read_requests();
    for (i, req) in reqs.iter().enumerate() {
        match send(&pipe, req) {
            Ok(resp) => println!("[{:02}] {:<26} => {}", i, name_of(req), summarize(&resp)),
            Err(e) => println!("[{:02}] {:<26} => TRANSPORT ERROR: {}", i, name_of(req), e),
        }
    }

    // create -> capture id -> delete (cleanup), verifies mutations too
    match send(&pipe, &IpcRequest::CreateRule(test_rule())) {
        Ok(IpcResponse::Rule(r)) => {
            let id = r.id;
            println!("[--] CreateRule                => Rule id={:?} name={}", id, r.name);
            match send(&pipe, &IpcRequest::DeleteRule(id.unwrap_or(0))) {
                Ok(IpcResponse::Success) => println!("[--] DeleteRule(id)            => Success (cleanup ok)"),
                other => println!("[--] DeleteRule(id)            => {:?} (LEAKED RULE!)", other),
            }
        }
        other => println!("[--] CreateRule                => {:?} (mutation FAILED)", other),
    }
}

fn send(pipe: &str, req: &IpcRequest) -> Result<IpcResponse, String> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe)
        .map_err(|e| format!("open pipe: {}", e))?;
    let data = bincode::serialize(req).map_err(|e| format!("serialize: {}", e))?;
    f.write_all(&(data.len() as u32).to_le_bytes())
        .map_err(|e| format!("write len: {}", e))?;
    f.write_all(&data).map_err(|e| format!("write body: {}", e))?;
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).map_err(|e| format!("read len: {}", e))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(format!("response too large: {}", len));
    }
    let mut body = vec![0u8; len];
    f.read_exact(&mut body).map_err(|e| format!("read body: {}", e))?;
    bincode::deserialize(&body).map_err(|e| format!("deserialize: {}", e))
}

fn test_rule() -> Rule {
    Rule {
        id: None,
        name: "smoke-test-rule".into(),
        description: String::new(),
        enabled: true,
        priority: 5000,
        action: RuleAction::Block,
        direction: Direction::Outbound,
        protocol: None,
        process_id: None,
        process_path: None,
        remote_addr: Some("192.0.2.1".into()),
        remote_addr_mask: Some(32),
                remote_domain: None,
        remote_port: Some(PortRange::Single(80)),
        local_addr: None,
        local_addr_mask: None,
        local_port: None,
        network_zone: None,
        app_group_id: None,
        created_at: None,
        updated_at: None,
    }
}

fn read_requests() -> Vec<IpcRequest> {
    let filters = ceasefire_service::models::HistoryFilters {
        limit: Some(10),
        offset: None,
        hours: Some(1),
        action: None,
        protocol: None,
        process_path: None,
        remote_addr: None,
        direction: None,
        sort_by: None,
        sort_order: None,
    };
    vec![
        IpcRequest::ListRules { offset: 0, limit: u32::MAX, search: None },
        IpcRequest::GetActiveConnections,
        IpcRequest::GetGlobalStats,
        IpcRequest::GetSettings,
        IpcRequest::ListAppGroups,
        IpcRequest::ListConnectionDecisions,
        IpcRequest::GetNetworkHistory(filters),
        IpcRequest::ListProcessBandwidthLimits,
        IpcRequest::GetTrafficTrend { hours: 1 },
        IpcRequest::LookupDomain("192.168.79.23".into()),
        IpcRequest::GetGeoCacheStats,
    ]
}

fn name_of(r: &IpcRequest) -> String {
    let s = format!("{:?}", r);
    s.split('(').next().unwrap_or(&s).split('{').next().unwrap_or(&s).to_string()
}

fn summarize(r: &IpcResponse) -> String {
    use IpcResponse::*;
    match r {
        Success => "Success".into(),
        Rule(r) => format!("Rule id={:?} name={}", r.id, r.name),
        RulePage(p) => format!("RulePage total={} rules x{}", p.total, p.rules.len()),
        Connections(v) => format!("Connections x{}", v.len()),
        GlobalStats(s) => format!(
            "GlobalStats active={} blocked={} allowed={}",
            s.active_connections, s.blocked_connections, s.allowed_connections
        ),
        Settings(s) => format!(
            "Settings notify={} ask_to_connect={}",
            s.notifications_enabled, s.ask_to_connect_enabled
        ),
        AppGroups(v) => format!("AppGroups x{}", v.len()),
        AppGroupMembers(v) => format!("AppGroupMembers x{}", v.len()),
        ConnectionDecisions(v) => format!("ConnectionDecisions x{}", v.len()),
        DeletedCount(n) => format!("DeletedCount {}", n),
        NetworkHistoryRecords(v) => format!("NetworkHistoryRecords x{}", v.len()),
        ProcessBandwidthLimit(o) => format!("ProcessBandwidthLimit present={}", o.is_some()),
        ProcessBandwidthLimits(v) => format!("ProcessBandwidthLimits x{}", v.len()),
        TrafficTrend(v) => format!("TrafficTrend x{}", v.len()),
        Domain(d) => format!("Domain {:?}", d),
        GeoLocationBatch(m) => format!("GeoLocationBatch x{}", m.len()),
        GeoCacheStats(s) => format!(
            "GeoCacheStats mem={} db_loaded={}",
            s.memory_cache_size, s.database_loaded
        ),
        Error(e) => format!("ERROR: {}", e),
        other => format!("{:?}", std::mem::discriminant(other)),
    }
}
