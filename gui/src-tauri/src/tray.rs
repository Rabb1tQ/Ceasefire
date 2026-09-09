use tauri::AppHandle;
use tauri_plugin_notification::NotificationExt;

use tauri::Manager;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

/// 最小可用托盘：图标 + 菜单（显示/隐藏主窗口、退出），左键点击切换窗口显示。
/// 使用 Tauri v2 内置 tray 能力（tauri crate 的 "tray-icon" feature）。
pub fn setup_tray(app: &AppHandle) {
    let show = MenuItem::with_id(app, "show", "显示 / 隐藏主窗口", true, None::<&str>)
        .expect("tray menu item creation cannot fail with valid id");
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)
        .expect("tray menu item creation cannot fail with valid id");
    let menu = Menu::with_items(app, &[&show, &quit])
        .expect("tray menu creation cannot fail with valid items");

    let mut builder = TrayIconBuilder::with_id("ceasefire-tray")
        .menu(&menu)
        .tooltip("Ceasefire 防火墙")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => toggle_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    if let Err(e) = builder.build(app) {
        eprintln!("Failed to setup tray icon: {}", e);
    }
}

fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
        } else {
            // 窗口隐藏时可能仍处于最小化态（最小化到托盘时只 hide 不还原），
            // 先 show 再 unminimize，保证恢复时不会停留在最小化；
            // 窗口隐藏期间 unminimize 不触发重绘，不会有闪烁。
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
    }
}

pub fn show_notification(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification()
        .builder()
        .title(title)
        .body(body)
        .show();
}

#[tauri::command]
pub fn show_connection_blocked_notification(app: AppHandle, process_name: String, remote_ip: String, port: u16) {
    show_notification(
        &app,
        "连接已阻止",
        &format!("已阻止 {} 连接到 {}:{}", process_name, remote_ip, port)
    );
}

#[tauri::command]
pub fn show_suspicious_connection_notification(app: AppHandle, process_name: String, remote_ip: String, reason: String) {
    show_notification(
        &app,
        "检测到可疑连接",
        &format!("{} 尝试连接 {} ({})", process_name, remote_ip, reason)
    );
}

#[tauri::command]
pub fn show_bandwidth_warning_notification(app: AppHandle, process_name: String, current_speed: String, limit: String) {
    show_notification(
        &app,
        "带宽警告",
        &format!("{} 当前带宽 {} 已超过限制 {}", process_name, current_speed, limit)
    );
}

#[tauri::command]
pub fn show_firewall_status_notification(app: AppHandle, status: String) {
    show_notification(
        &app,
        "防火墙状态变更",
        &format!("防火墙现在处于 {} 状态", status)
    );
}