//! Windows Service Handler

use windows_service::{
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use std::sync::mpsc;
use std::time::Duration;

const SERVICE_NAME: &str = "CeasefireFirewall";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

pub fn run_as_service() -> super::super::Result<()> {
    service_dispatcher::start(SERVICE_NAME, service_main)
        .map_err(|e| super::super::ServiceError::Service(e.to_string()))
}

/// 注册 SCM 服务（`ceasefire-service.exe install`）。
/// binPath 使用当前 exe 的绝对路径，不依赖调用方 CWD。
pub fn install_service() -> super::super::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| super::super::ServiceError::Service(e.to_string()))?;

    let exe_path = std::env::current_exe()
        .map_err(|e| super::super::ServiceError::Service(e.to_string()))?;

    let info = windows_service::service::ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "Ceasefire Firewall Service".into(),
        service_type: SERVICE_TYPE,
        // 开机自启：服务未运行期间由持久 kill-switch 过滤器兜底（见 wfp::filter）
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| super::super::ServiceError::Service(e.to_string()))?;
    drop(service);

    // 实测（Win10 19045）：ChangeServiceConfig2(FAILURE_ACTIONS) 对仅含
    // CHANGE_CONFIG 的句柄一律 ERROR_ACCESS_DENIED(5)——哪怕句柄来自
    // CreateServiceW 本身、且同一句柄写描述符成功；sc.exe 能配是因为它
    // 用 ALL_ACCESS 打开服务。故以 ALL_ACCESS 重开句柄再做两项配置。
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::ALL_ACCESS)
        .map_err(|e| super::super::ServiceError::Service(format!("安装后以 ALL_ACCESS 重开服务失败: {}", e)))?;
    let _ = service.set_description("Ceasefire 防火墙服务（驱动通信、规则库与 IPC 管道）");

    // 崩溃自恢复：失败动作配置为重启。若服务开着 kill-switch
    // （protect_when_not_running 持久过滤器）时崩溃，无此配置 = 整机断网且
    // 无自愈。1/2/3 次失败均 5 秒后重启（延迟避免崩溃循环打满 CPU），
    // 86400 秒无失败后清零失败计数。
    let restart_action = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_millis(5000),
    };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                restart_action.clone(),
                restart_action.clone(),
                restart_action,
            ]),
        })
        .map_err(|e| super::super::ServiceError::Service(format!("配置失败动作(自动重启)失败: {}", e)))?;

    println!(
        "服务 [{}] 安装成功（启动类型: 自动，崩溃自动重启: 3 次，延迟 5 秒）",
        SERVICE_NAME
    );
    Ok(())
}

/// 注销 SCM 服务（`ceasefire-service.exe uninstall`）。先尝试停止运行中的服务。
pub fn uninstall_service() -> super::super::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| super::super::ServiceError::Service(e.to_string()))?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| super::super::ServiceError::Service(e.to_string()))?;

    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            // 等待 SCM 完成停止，最多约 10 秒
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Ok(s) = service.query_status() {
                    if s.current_state == ServiceState::Stopped {
                        break;
                    }
                }
            }
        }
    }

    service
        .delete()
        .map_err(|e| super::super::ServiceError::Service(e.to_string()))?;

    // 注销前移除持久 kill-switch 过滤器，否则服务删除后全机网络仍被拦
    if let Err(e) = super::super::wfp::remove_persistent_block_filters_standalone() {
        println!("警告：移除持久过滤器失败（如开启过“服务未运行时拦截”请手动检查 WFP）：{}", e);
    }

    println!("服务 [{}] 已注销", SERVICE_NAME);
    Ok(())
}

extern "system" fn service_main(_arguments: u32, _argv: *mut *mut u16) {
    let args: Vec<String> = (0.._arguments)
        .map(|i| {
            let ptr = unsafe { *_argv.add(i as usize) };
            let len = (0..).take_while(|&i| unsafe { *ptr.add(i) } != 0).count();
            let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
            String::from_utf16_lossy(slice)
        })
        .collect();

    if let Err(e) = run_service(args) {
        tracing::error!("Service failed: {}", e);
    }
}

fn run_service(_arguments: Vec<String>) -> super::super::Result<()> {
    // Channel used to wake this thread when SCM sends Stop
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    let event_handler = {
        let stop_tx = stop_tx.clone();
        move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop => {
                    let _ = stop_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| super::super::ServiceError::Service(e.to_string()))?;

    // Start the firewall on a tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| super::super::ServiceError::Service(format!("Failed to create runtime: {}", e)))?;

    let service_result = {
        let stop_rx = stop_rx;
        let report_running = || {
            status_handle
                .set_service_status(ServiceStatus {
                    service_type: SERVICE_TYPE,
                    current_state: ServiceState::Running,
                    controls_accepted: ServiceControlAccept::STOP,
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 0,
                    wait_hint: std::time::Duration::default(),
                    process_id: None,
                })
                .map_err(|e| super::super::ServiceError::Service(e.to_string()))
        };
        let report_stopping = || {
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::StopPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: std::time::Duration::from_secs(10),
                process_id: None,
            });
        };

        // 防火墙启动失败：记录下来，最终以服务特定错误码报告 STOPPED，
        // 让 SCM 计为失败并触发失败动作（自动重启）。SCM Stop 不置位。
        let mut start_error: Option<super::super::ServiceError> = None;

        (|| -> super::super::Result<()> {
            report_running()?;

            let db_path = std::env::var("CEASEFIRE_DB")
                .unwrap_or_else(|_| "C:\\ProgramData\\Ceasefire\\ceasefire.db".to_string());
            let db = std::sync::Arc::new(super::super::Database::open(&db_path)?);
            let mut firewall_service = super::FirewallService::new(db)?;

            // Wait for either the service task to fail or SCM Stop.
            // std mpsc::recv is blocking, so run it on a blocking thread.
            // Must use Runtime::spawn_blocking (not tokio::task::spawn_blocking):
            // we are on the SCM service thread, outside any block_on, and the
            // free function panics without reactor context (service exit 1067).
            let stop_wait = runtime.spawn_blocking(move || stop_rx.recv().is_ok());
            tokio::pin!(stop_wait);

            runtime.block_on(async {
                tokio::select! {
                    r = firewall_service.start() => {
                        if let Err(e) = r {
                            tracing::error!("Firewall service start failed: {}", e);
                            start_error = Some(e);
                        }
                    }
                    _ = &mut stop_wait => {
                        tracing::info!("Stop requested by SCM");
                    }
                }
            });

            report_stopping();

            // Graceful shutdown on the runtime
            runtime.block_on(async {
                if let Err(e) = firewall_service.stop().await {
                    tracing::error!("Error during service shutdown: {}", e);
                }
            });

            if let Some(e) = start_error {
                return Err(e);
            }

            Ok(())
        })()
    };

    // 启动失败必须以非零服务特定错误码报告 STOPPED，SCM 才会计为失败并触发
    // 失败动作（自动重启）；用户主动 net stop 走 Win32(0) 正常停止，不被重启。
    let exit_code = match &service_result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => ServiceExitCode::ServiceSpecific(classify_start_failure(e)),
    };

    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    });

    runtime.shutdown_timeout(std::time::Duration::from_secs(15));
    service_result
}

/// 服务特定错误码：1 = 驱动初始化/通信失败，2 = IPC 管道失败，3 = 其他启动
/// 失败（DB/WFP 等）。数值写入 SCM 事件日志便于区分失败原因；非零本身即触发
/// 失败动作重启。
fn classify_start_failure(e: &super::super::ServiceError) -> u32 {
    match e {
        super::super::ServiceError::Driver(_) => 1,
        super::super::ServiceError::Ipc(_) => 2,
        _ => 3,
    }
}
