//! IPC Server - handles client connections via named pipes

use super::super::error::{Result, ServiceError};
use super::super::models::*;
use super::super::database::Database;
use super::super::rule::manager::RuleManager;
use super::super::connection::tracker::ConnectionTracker;
use super::super::app_group::manager::AppGroupManager;
use super::super::connection_decision::manager::ConnectionDecisionManager;
use super::super::network_history::manager::NetworkHistoryManager;
use super::super::bandwidth::{BandwidthLimiter, KernelThrottleSync};
use super::super::geoip::GeoIpService;
use super::super::driver::DriverHandle;
use super::handler::{RequestHandler, WfpEngineSlot};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

const PIPE_NAME: &str = r"\\.\pipe\CeasefireFirewall";

pub struct IpcServer {
    rule_manager: Arc<RuleManager>,
    connection_tracker: Arc<ConnectionTracker>,
    db: Arc<Database>,
    app_group_manager: Arc<AppGroupManager>,
    decision_manager: Arc<ConnectionDecisionManager>,
    history_manager: Arc<NetworkHistoryManager>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    kernel_throttle: Arc<KernelThrottleSync>,
    geoip_service: Arc<GeoIpService>,
    dns_cache: Arc<crate::dns_cache::DnsCache>,
    notifier: Arc<crate::notification::notifier::Notifier>,
    driver: Arc<DriverHandle>,
    wfp_engine: WfpEngineSlot,
    running: Arc<std::sync::atomic::AtomicBool>,
    shutdown: Arc<tokio::sync::Notify>,
}

impl IpcServer {
    pub fn new(
        rule_manager: Arc<RuleManager>,
        connection_tracker: Arc<ConnectionTracker>,
        db: Arc<Database>,
        app_group_manager: Arc<AppGroupManager>,
        decision_manager: Arc<ConnectionDecisionManager>,
        history_manager: Arc<NetworkHistoryManager>,
        bandwidth_limiter: Arc<BandwidthLimiter>,
        kernel_throttle: Arc<KernelThrottleSync>,
        geoip_service: Arc<GeoIpService>,
        dns_cache: Arc<crate::dns_cache::DnsCache>,
        notifier: Arc<crate::notification::notifier::Notifier>,
        driver: Arc<DriverHandle>,
        wfp_engine: WfpEngineSlot,
    ) -> Result<Self> {
        Ok(IpcServer {
            rule_manager,
            connection_tracker,
            db,
            app_group_manager,
            decision_manager,
            history_manager,
            bandwidth_limiter,
            kernel_throttle,
            geoip_service,
            dns_cache,
            notifier,
            driver,
            wfp_engine,
            running: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// 停止 IPC 监听：服务 stop 时调用，否则监听循环永不退出
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        self.shutdown.notify_waiters();
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!("IPC server starting on {}", PIPE_NAME);

        while self.running.load(std::sync::atomic::Ordering::SeqCst) {
            let pipe_stream = match create_named_pipe().await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::error!("Failed to create named pipe: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            tracing::info!("Named pipe created, waiting for client connection...");

            // 等待客户端连接时可被 stop() 打断，否则 connect 会永远阻塞
            let connected = tokio::select! {
                r = pipe_stream.connect() => r,
                _ = self.shutdown.notified() => {
                    tracing::info!("IPC server shutting down, aborting pending connect");
                    break;
                }
            };

            match connected {
                Ok(_) => {
                    tracing::info!("Client connected to IPC server");
                    let handler_clone = RequestHandler::new(
                        self.rule_manager.clone(),
                        self.connection_tracker.clone(),
                        self.db.clone(),
                        self.app_group_manager.clone(),
                        self.decision_manager.clone(),
                        self.history_manager.clone(),
                        self.bandwidth_limiter.clone(),
                        self.kernel_throttle.clone(),
                        self.geoip_service.clone(),
                        self.dns_cache.clone(),
                        self.notifier.clone(),
                        self.driver.clone(),
                        self.wfp_engine.clone(),
                    );
                    
                    // Spawn a task to handle this client
                    tokio::spawn(async move {
                        if let Err(e) = handle_client_connection(pipe_stream, handler_clone).await {
                            tracing::error!("Client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept client connection: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }

        tracing::info!("IPC server stopped");
        Ok(())
    }
}

async fn handle_client_connection(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    handler: RequestHandler,
) -> Result<()> {
    // Stream is already connected by the caller
    loop {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                tracing::info!("Client disconnected");
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::info!("Client disconnected (EOF)");
                break;
            }
            Err(e) => {
                tracing::error!("Read length error: {}", e);
                return Err(ServiceError::Ipc(format!("Read error: {}", e)));
            }
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        tracing::debug!("Received request length: {}", len);
        if len == 0 || len > 10_000_000 {
            tracing::warn!("Invalid message length: {}", len);
            break;
        }

        let mut data = vec![0u8; len];

        if let Err(e) = stream.read_exact(&mut data).await {
            tracing::warn!("Failed to read message data: {}", e);
            break;
        }

        tracing::debug!("Received {} bytes of data", data.len());

        let request: IpcRequest = match bincode::deserialize(&data) {
            Ok(req) => {
                tracing::debug!("Deserialized request successfully");
                req
            }
            Err(e) => {
                tracing::warn!("Failed to deserialize request: {}", e);
                break;
            }
        };

        let response = handler.handle_request(request).await;

        let response_data = match bincode::serialize(&response) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to serialize response: {}", e);
                break;
            }
        };

        let len = response_data.len() as u32;
        tracing::debug!("Sending response length: {}", len);
        if let Err(e) = stream.write_all(&len.to_le_bytes()).await {
            tracing::warn!("Failed to write response length: {}", e);
            break;
        }
        if let Err(e) = stream.write_all(&response_data).await {
            tracing::warn!("Failed to write response data: {}", e);
            break;
        }
        if let Err(e) = stream.flush().await {
            tracing::warn!("Failed to flush stream: {}", e);
            break;
        }
        tracing::debug!("Response sent successfully");
    }

    Ok(())
}

async fn create_named_pipe() -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;

    // Restrict the pipe to SYSTEM and Administrators only: the pipe server
    // runs as SYSTEM and exposes commands like KillProcess, so a default
    // (NULL) DACL would let any local user issue privileged commands.
    let mut security_descriptor = windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let sa_result = unsafe {
        windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(sddl.as_ptr()),
            windows::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut security_descriptor,
            None,
        )
    };
    if sa_result.is_err() {
        return Err(ServiceError::Ipc(
            "Failed to build pipe security descriptor".to_string(),
        ));
    }

    let mut sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor.0 as *mut std::ffi::c_void,
        bInheritHandle: false.into(),
    };

    let server = unsafe {
        ServerOptions::new()
            .access_inbound(true)
            .access_outbound(true)
            .in_buffer_size(65536)
            .out_buffer_size(65536)
            .create_with_security_attributes_raw(PIPE_NAME, &mut sa as *mut _ as *mut std::ffi::c_void)
    };

    // CreateNamedPipeW copies the security descriptor, so free ours now.
    unsafe {
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            security_descriptor.0 as *mut std::ffi::c_void,
        ));
    }

    let server = server
        .map_err(|e| ServiceError::Ipc(format!("Failed to create named pipe: {}", e)))?;

    tracing::info!("Named pipe created (admin-only DACL): {}", PIPE_NAME);
    Ok(server)
}