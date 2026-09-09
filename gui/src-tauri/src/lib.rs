// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ipc;
mod tray;

use tauri::{Manager, State};

// IPC 载荷类型复用 service crate（经 ipc 模块 re-export），与前端 JSON 字段名保持不变的部分仍为 snake_case
use ipc::{ConnectionInfo, GlobalStats, Rule, RulePage, Settings};

struct AppState {
    ipc_client: ipc::IpcClient,
}

#[tauri::command]
async fn create_rule(state: State<'_, AppState>, rule: Rule) -> Result<i64, String> {
    state.ipc_client.create_rule(rule).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_rule(state: State<'_, AppState>, id: u32, rule: Rule) -> Result<(), String> {
    state.ipc_client.update_rule(id, rule).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_rule(state: State<'_, AppState>, id: u32) -> Result<(), String> {
    state.ipc_client.delete_rule(id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_rules(state: State<'_, AppState>, offset: u32, limit: u32, search: Option<String>) -> Result<RulePage, String> {
    state.ipc_client.list_rules(offset, limit, search).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn toggle_rule(state: State<'_, AppState>, id: u32) -> Result<(), String> {
    // 服务端没有原子 toggle，这里读取当前规则后翻转 enabled 再写回
    let page = state.ipc_client.list_rules(0, u32::MAX, None).await.map_err(|e| e.to_string())?;
    let mut rule = page
        .rules
        .into_iter()
        .find(|r| r.id == Some(id))
        .ok_or_else(|| format!("规则 {} 不存在", id))?;
    rule.enabled = !rule.enabled;
    state.ipc_client.update_rule(id, rule).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_connections(state: State<'_, AppState>) -> Result<Vec<ConnectionInfo>, String> {
    state.ipc_client.get_connections().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_global_stats(state: State<'_, AppState>) -> Result<GlobalStats, String> {
    state.ipc_client.get_global_stats().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    state.ipc_client.get_settings().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    state.ipc_client.update_settings(settings).await
        .map_err(|e| e.to_string())
}

// Application Groups
#[tauri::command]
async fn list_app_groups(state: State<'_, AppState>) -> Result<Vec<ipc::AppGroup>, String> {
    state.ipc_client.list_app_groups().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_app_group_members(state: State<'_, AppState>, group_id: u32) -> Result<Vec<ipc::AppGroupMember>, String> {
    state.ipc_client.get_app_group_members(group_id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn initialize_predefined_groups(state: State<'_, AppState>) -> Result<(), String> {
    state.ipc_client.initialize_predefined_groups().await
        .map_err(|e| e.to_string())
}

// 自定义分组管理
#[tauri::command]
async fn create_app_group(state: State<'_, AppState>, group: ipc::AppGroup) -> Result<ipc::AppGroup, String> {
    state.ipc_client.create_app_group(group).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_app_group(state: State<'_, AppState>, id: u32, group: ipc::AppGroup) -> Result<(), String> {
    state.ipc_client.update_app_group(id, group).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_app_group(state: State<'_, AppState>, id: u32) -> Result<(), String> {
    state.ipc_client.delete_app_group(id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_app_group_enabled(state: State<'_, AppState>, id: u32, enabled: bool) -> Result<(), String> {
    state.ipc_client.set_app_group_enabled(id, enabled).await
        .map_err(|e| e.to_string())
}

// Connection Decisions
#[tauri::command]
async fn list_connection_decisions(state: State<'_, AppState>) -> Result<Vec<ipc::ConnectionDecision>, String> {
    state.ipc_client.list_connection_decisions().await
        .map_err(|e| e.to_string())
}

// Network History
#[tauri::command]
async fn get_network_history(state: State<'_, AppState>, filters: Option<ipc::HistoryFilters>) -> Result<Vec<ipc::NetworkHistoryRecord>, String> {
    state.ipc_client.get_network_history(filters).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_network_history_count(state: State<'_, AppState>, filters: Option<ipc::HistoryFilters>) -> Result<u64, String> {
    state.ipc_client.get_network_history_count(filters).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_app_group_member(state: State<'_, AppState>, group_id: u32, process_path: String, process_name: Option<String>) -> Result<(), String> {
    state.ipc_client.add_app_group_member(group_id, process_path, process_name).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn remove_app_group_member(state: State<'_, AppState>, group_id: u32, process_path: String) -> Result<(), String> {
    state.ipc_client.remove_app_group_member(group_id, process_path).await
        .map_err(|e| e.to_string())
}

// Connection Decision Management
#[tauri::command]
async fn record_connection_decision(state: State<'_, AppState>, decision: ipc::ConnectionDecision) -> Result<ipc::ConnectionDecision, String> {
    state.ipc_client.record_connection_decision(decision).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_connection_decision(state: State<'_, AppState>, id: u32) -> Result<(), String> {
    state.ipc_client.delete_connection_decision(id).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn clear_expired_decisions(state: State<'_, AppState>) -> Result<u32, String> {
    state.ipc_client.clear_expired_decisions().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn export_network_history(state: State<'_, AppState>, filters: Option<ipc::HistoryFilters>, format: String) -> Result<Vec<u8>, String> {
    let filters = filters.unwrap_or_default();
    state.ipc_client.export_network_history(filters, format).await
        .map_err(|e| e.to_string())
}

// Bandwidth Management
#[tauri::command]
async fn set_process_bandwidth_limit(state: State<'_, AppState>, limit: ipc::ProcessBandwidthLimit) -> Result<(), String> {
    state.ipc_client.set_process_bandwidth_limit(limit).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_process_bandwidth_limits(state: State<'_, AppState>) -> Result<Vec<ipc::ProcessBandwidthLimit>, String> {
    state.ipc_client.list_process_bandwidth_limits().await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_global_bandwidth_limit(state: State<'_, AppState>, upload_limit_kbps: Option<u32>, download_limit_kbps: Option<u32>, enabled: Option<bool>) -> Result<(), String> {
    state.ipc_client.set_global_bandwidth_limit(upload_limit_kbps, download_limit_kbps, enabled).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_process_bandwidth_limit(state: State<'_, AppState>, process_path: String) -> Result<(), String> {
    state.ipc_client.delete_process_bandwidth_limit(process_path).await
        .map_err(|e| e.to_string())
}

// App Traffic Stats
#[tauri::command]
async fn get_app_traffic_stats(state: State<'_, AppState>, hours: u32) -> Result<Vec<ipc::AppTrafficStats>, String> {
    state.ipc_client.get_app_traffic_stats(hours).await
        .map_err(|e| e.to_string())
}

// Protocol Traffic Stats
#[tauri::command]
async fn get_protocol_traffic_stats(state: State<'_, AppState>, hours: u32) -> Result<Vec<ipc::ProtocolTrafficStats>, String> {
    state.ipc_client.get_protocol_traffic_stats(hours).await
        .map_err(|e| e.to_string())
}

// Country Traffic Stats
#[tauri::command]
async fn get_country_traffic_stats(state: State<'_, AppState>, hours: u32) -> Result<Vec<ipc::CountryTrafficStats>, String> {
    state.ipc_client.get_country_traffic_stats(hours).await
        .map_err(|e| e.to_string())
}

// Rule import/export
#[tauri::command]
async fn export_rules(state: State<'_, AppState>) -> Result<String, String> {
    state
        .ipc_client
        .export_rules()
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn import_rules(
    state: State<'_, AppState>,
    rules: Vec<ipc::ExportedRule>,
    mode: String,
) -> Result<ipc::ImportStats, String> {
    let mode = match mode.as_str() {
        "Replace" => ipc::ImportMode::Replace,
        _ => ipc::ImportMode::Merge,
    };
    state
        .ipc_client
        .import_rules(rules, mode)
        .await
        .map_err(|e| e.to_string())
}

// Dashboard chart enhancements
#[tauri::command]
async fn get_app_traffic_timeline(
    state: State<'_, AppState>,
    hours: u32,
) -> Result<Vec<ipc::AppTimelinePoint>, String> {
    state
        .ipc_client
        .get_app_traffic_timeline(hours)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_action_trend(
    state: State<'_, AppState>,
    hours: u32,
) -> Result<Vec<ipc::ActionTrendPoint>, String> {
    state
        .ipc_client
        .get_action_trend(hours)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_top_hosts(
    state: State<'_, AppState>,
    hours: u32,
    limit: u32,
) -> Result<Vec<ipc::TopHostStats>, String> {
    state
        .ipc_client
        .get_top_hosts(hours, limit)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_remote_host_details(
    state: State<'_, AppState>,
    remote_addr: String,
    hours: u32,
) -> Result<Option<ipc::RemoteAddressDetails>, String> {
    state
        .ipc_client
        .get_remote_host_details(remote_addr, hours)
        .await
        .map_err(|e| e.to_string())
}

// Traffic Trend
#[tauri::command]
async fn get_traffic_trend(state: State<'_, AppState>, hours: i64) -> Result<Vec<ipc::TrafficTrendPoint>, String> {
    state.ipc_client.get_traffic_trend(hours as u32).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn lookup_domain(state: State<'_, AppState>, ip: String) -> Result<Option<String>, String> {
    state.ipc_client.lookup_domain(ip).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn lookup_geo_location_batch(state: State<'_, AppState>, ips: Vec<String>) -> Result<std::collections::HashMap<String, ipc::GeoLocation>, String> {
    state.ipc_client.lookup_geo_location_batch(ips).await
        .map_err(|e| e.to_string())
}

// Process Management
#[tauri::command]
async fn kill_process(state: State<'_, AppState>, pid: u32) -> Result<(), String> {
    state.ipc_client.kill_process(pid).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn open_process_folder(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("explorer")
            .args(&["/select,", &path])
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("Not supported on this platform".to_string())
    }
}

#[tauri::command]
async fn poll_notifications(state: State<'_, AppState>, max: u32) -> Result<Vec<ipc::NotificationItem>, String> {
    state.ipc_client.poll_notifications(max).await
        .map_err(|e| e.to_string())
}

// 驱动诊断快照（设置页「驱动诊断」分区，手动刷新；旧驱动返回 None）
#[tauri::command]
async fn get_driver_diags(state: State<'_, AppState>) -> Result<Option<ipc::DriverDiagnostics>, String> {
    state.ipc_client.get_driver_diags().await
        .map_err(|e| e.to_string())
}

/// 首次 Ask 弹出时提示一次"在询问窗口处理"，之后 Ask 不再弹 Toast（窗口自带置顶弹窗）
static ASK_HINT_SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 后台轮询服务端通知：拦截事件弹 Windows Toast；
/// 询问模式（Ask）的未知程序事件额外发 firewall-ask 事件给前端弹窗。
/// 轮询失败静默退避（服务未启动时每 5 秒重试一次）。
fn spawn_notification_poller(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let client = match ipc::IpcClient::new(r"\\.\pipe\CeasefireFirewall") {
            Ok(c) => c,
            Err(_) => return,
        };
        loop {
            // Box<dyn Error> 非 Send：先转成 String 错误再跨 await 存活
            let res = client.poll_notifications(50).await.map_err(|e| e.to_string());
            let items = match res {
                Ok(items) => items,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };
            for item in items {
                let name = item.process_name.clone()
                    .unwrap_or_else(|| item.process_path.clone().unwrap_or_else(|| "未知程序".into()));
                match item.kind {
                    ceasefire_service::models::NotificationKind::Ask => {
                        if !ASK_HINT_SHOWN.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            tray::show_notification(
                                &app,
                                "未知程序尝试联网",
                                &format!("{} 尝试连接 {}:{}，请在弹出的询问窗口中处理", name, item.remote_addr, item.remote_port),
                            );
                        }
                        // 事件为全局 emit，ask 小窗（独立 webview）自行监听并弹出
                        let _ = tauri::Emitter::emit(&app, "firewall-ask", &item);
                    }
                    _ => {
                        tray::show_notification(
                            &app,
                            "连接已阻止",
                            &format!("已阻止 {} 连接 {}:{}", name, item.remote_addr, item.remote_port),
                        );
                        let _ = tauri::Emitter::emit(&app, "firewall-notification", &item);
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });
}

/// 首次隐藏到托盘时提示一次"仍在后台运行"，之后不再弹
static TRAY_HINT_SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Ask 询问小窗：预创建并隐藏，首次 Ask 到达时秒开（无白屏等待）。
/// 已存在则直接复用。
fn ensure_ask_window(app: &tauri::AppHandle) -> Option<tauri::WebviewWindow> {
    if let Some(w) = app.get_webview_window("ask") {
        return Some(w);
    }
    tauri::WebviewWindowBuilder::new(
        app,
        "ask",
        tauri::WebviewUrl::App("index.html#/ask".into()),
    )
    .title("未知程序询问")
    .inner_size(480.0, 320.0)
    .resizable(false)
    .always_on_top(true)
    .skip_taskbar(false)
    .visible(false)
    .build()
    .map_err(|e| {
        eprintln!("Failed to create ask window: {}", e);
        e
    })
    .ok()
}

#[tauri::command]
async fn show_ask_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(w) = ensure_ask_window(&app) {
        // 每次弹出都重新置顶，防止被其他 always-on-top 窗口压住
        let _ = w.set_always_on_top(true);
        let _ = w.show();
        let _ = w.set_focus();
    }
    Ok(())
}

#[tauri::command]
async fn hide_ask_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("ask") {
        let _ = w.hide();
    }
    Ok(())
}

fn hide_to_tray(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
        if !TRAY_HINT_SHOWN.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tray::show_notification(app, "Ceasefire 仍在后台运行", "程序已最小化到托盘，可从托盘图标重新打开或退出。");
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .on_window_event(|window, event| {
            // ask 小窗点 X = 跳过当前这条（保持拦截），不是退出程序
            if window.label() == "ask" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                    let _ = tauri::Emitter::emit_to(window.app_handle(), "ask", "firewall-ask-skip", ());
                }
                return;
            }
            if window.label() != "main" {
                return;
            }
            match event {
                // 点 X 隐藏到托盘，不退出；唯一退出路径是托盘菜单"退出"
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    hide_to_tray(window.app_handle());
                }
                // Tauri 直至 2.11.5 的 WindowEvent 都没有 Minimized 变体（已核对
                // 源码枚举）；Windows 上最小化会触发一次 Resized，此时
                // is_minimized() 为真，借机隐藏到托盘。
                // 这里只 hide、不 unminimize：最小化动画进行中还原窗口会重绘
                // 一帧导致白屏闪烁。窗口保持在 minimized 态隐藏，从托盘恢复时
                // 由 tray.rs 的显示分支统一纠正（show → unminimize → set_focus）。
                tauri::WindowEvent::Resized(_) => {
                    if window.is_minimized().unwrap_or(false) {
                        hide_to_tray(window.app_handle());
                    }
                }
                _ => {}
            }
        })
        .setup(|app| {
            // Initialize IPC client - use named pipe to connect to service
            let ipc_client = ipc::IpcClient::new(r"\\.\pipe\CeasefireFirewall")
                .map_err(|e| format!("Failed to create IPC client: {}", e))?;

            // Store IPC client in app state
            app.manage(AppState { ipc_client });

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Setup tray icon
            tray::setup_tray(app.handle());

            // 预创建 Ask 询问小窗（隐藏），首次 Ask 到达时秒开
            ensure_ask_window(app.handle());

            // 通知轮询（service→GUI 事件通道 + Toast）
            spawn_notification_poller(app.handle().clone());

            Ok(())
        })
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            create_rule,
            update_rule,
            delete_rule,
            list_rules,
            toggle_rule,
            get_connections,
            get_global_stats,
            get_settings,
            update_settings,
            list_app_groups,
            get_app_group_members,
            initialize_predefined_groups,
            create_app_group,
            update_app_group,
            delete_app_group,
            set_app_group_enabled,
            list_connection_decisions,
            get_network_history,
            get_network_history_count,
            get_app_traffic_stats,
            get_protocol_traffic_stats,
            get_country_traffic_stats,
            get_traffic_trend,
            lookup_domain,
            export_rules,
            get_app_traffic_timeline,
            get_action_trend,
            get_top_hosts,
            get_remote_host_details,
            import_rules,
            lookup_geo_location_batch,
            kill_process,
            poll_notifications,
            open_process_folder,
            tray::show_connection_blocked_notification,
            tray::show_suspicious_connection_notification,
            tray::show_bandwidth_warning_notification,
            tray::show_firewall_status_notification,
            add_app_group_member,
            remove_app_group_member,
            record_connection_decision,
            delete_connection_decision,
            clear_expired_decisions,
            export_network_history,
            set_process_bandwidth_limit,
            list_process_bandwidth_limits,
            set_global_bandwidth_limit,
            delete_process_bandwidth_limit,
            get_driver_diags,
            show_ask_window,
            hide_ask_window,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
