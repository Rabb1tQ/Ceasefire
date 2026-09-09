//! Windows Service Manager module

pub mod firewall_service;
pub mod service_handler;

pub use firewall_service::FirewallService;
pub use service_handler::{install_service, run_as_service, uninstall_service};
