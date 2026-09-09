//! Ceasefire Firewall Service - Main Entry Point

use ceasefire_service::*;
use ceasefire_service::LOG_DIR;
use ceasefire_service::service::{install_service, run_as_service, uninstall_service};
use std::sync::Arc;

fn main() -> Result<()> {
    // Initialize logging. The WorkerGuard must stay alive for the whole
    // process lifetime; storing it in main keeps file logging active and
    // flushes buffered entries when main returns (instead of leaking it).
    let _log_guard = init_logging();

    // Panics in SCM context print to stderr, which nobody sees, leaving exit
    // code 1067 with no clue. Route panic info into the log file (direct
    // append, not the non_blocking writer, so it survives an abort).
    std::panic::set_hook(Box::new(|info| {
        let msg = format!(
            "PANIC in {}:{}: {}",
            info.location().map(|l| l.file().to_string()).unwrap_or_default(),
            info.location().map(|l| l.line().to_string()).unwrap_or_default(),
            info
        );
        tracing::error!("{}", msg);
        let path = std::path::Path::new(crate::LOG_DIR).join("panic.log");
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"), msg);
            let _ = f.flush();
        }
    }));

    tracing::info!("Ceasefire Firewall Service starting...");

    // Log structure sizes for debugging
    tracing::info!(
        "DriverEvent: size={}, align={}",
        std::mem::size_of::<driver::converter::DriverEvent>(),
        std::mem::align_of::<driver::converter::DriverEvent>()
    );

    // Console mode is forced via --console or CEASEFIRE_CONSOLE=1.
    // Otherwise we attempt SCM dispatch; if the process was not started by
    // the Service Control Manager the dispatcher fails and we fall back to
    // console mode (the SCM never sets environment variables for services).
    let args: Vec<String> = std::env::args().collect();

    // 服务管理子命令（需管理员）：install / uninstall
    match args.get(1).map(String::as_str) {
        Some("install") => {
            return install_service();
        }
        Some("uninstall") => {
            return uninstall_service();
        }
        _ => {}
    }

    let console_forced = args.iter().any(|a| a == "--console")
        || std::env::var("CEASEFIRE_CONSOLE").map(|v| v == "1").unwrap_or(false);

    if !console_forced {
        match run_as_service() {
            Ok(()) => {
                tracing::info!("Ceasefire Firewall Service stopped");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    "Service dispatch failed ({}); falling back to console mode",
                    e
                );
            }
        }
    }

    // Run as console application (for debugging)
    tracing::info!("Running in console mode");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ServiceError::Service(format!("Failed to create runtime: {}", e)))?;

    runtime.block_on(async {
        // Get database path from args or use default
        let db_path = std::env::var("CEASEFIRE_DB")
            .unwrap_or_else(|_| "C:\\ProgramData\\Ceasefire\\ceasefire.db".to_string());

        // Open database
        let db = Arc::new(Database::open(&db_path)?);

        // Create service
        let mut firewall_service = FirewallService::new(db)?;

        // Start service
        firewall_service.start().await?;

        // Wait for Ctrl+C
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received Ctrl+C, shutting down...");
            }
            _ = terminate => {
                tracing::info!("Received terminate signal, shutting down...");
            }
        }

        // Stop service
        firewall_service.stop().await?;

        tracing::info!("Ceasefire Firewall Service stopped");
        Ok(())
    })
}

/// Initialize logging, returning the WorkerGuard that keeps the
/// non-blocking file writer running.
fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_appender::rolling;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let log_dir = std::path::Path::new(LOG_DIR);
    std::fs::create_dir_all(log_dir).ok();

    let file_appender = rolling::daily(&log_dir, "ceasefire-service.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ceasefire_service=info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(false)
        )
        .with(
            fmt::layer()
                .with_target(false)
                .with_span_events(fmt::format::FmtSpan::CLOSE)
        )
        .init();

    guard
}
