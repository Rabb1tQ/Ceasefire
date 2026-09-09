//! Ceasefire Firewall Service
//! 
//! Windows Service implementation for the Ceasefire local firewall system.

/// 服务日志目录（main.rs 的滚动日志/panic.log 与 firewall_service 的过期
/// 文件清理共用同一来源，勿在其他处硬编码重复路径）
pub const LOG_DIR: &str = "C:\\ProgramData\\Ceasefire\\logs";

pub mod models;
pub mod database;
pub mod error;
pub mod dns_cache;

// Module subdirectories
pub mod service;
pub mod rule;
pub mod connection;
pub mod event;
pub mod ipc;
pub mod notification;
pub mod driver;
pub mod app_group;
pub mod connection_decision;
pub mod network_history;
pub mod bandwidth;
pub mod geoip;
pub mod wfp;

// Re-export commonly used types
pub use models::*;
pub use error::{Result, ServiceError};
pub use database::Database;
pub use service::FirewallService;

// Re-export submodules as legacy aliases
pub use rule as rule_manager;
pub use connection as connection_tracker;
pub use event as event_processor;
pub use ipc as ipc_server;