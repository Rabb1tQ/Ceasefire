//! Kernel throttle table synchronization.
//!
//! The driver's stream-layer callout attributes TCP data to a PID; the
//! bandwidth limits configured in the GUI/service are keyed by process path.
//! This component keeps the mapping: whenever a connection event reveals
//! that a PID belongs to a limited path, the corresponding kernel throttle
//! entry is (re)pushed via IOCTL_SET_THROTTLE. A global limit is installed
//! as the PID-0 entry and applies to every stream without a per-process
//! entry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::driver::DriverHandle;

/// 锁卫生：本模块的四个 std::sync::Mutex 一律用
/// `lock().unwrap_or_else(|e| e.into_inner())` 而非 `lock().unwrap()`。
/// 这些调用大多发生在 spawn 出去的 tokio task（周期同步、事件驱动同步）里，
/// 一旦某线程在临界区 panic 导致锁中毒，`unwrap()` 会级联 panic 并静默杀死
/// 整个带宽同步任务（限速从此完全失效且无日志）。选择 into_inner 而不是
/// map_err 上报：中断一个已 panic 的临界区、带着（可能部分失效的）表数据
/// 继续运行，比让整个同步任务消失安全得多——表内容的错误最多导致限速值
/// 旧一拍，任务消失则永远不再同步。

pub struct KernelThrottleSync {
    /// path -> (upload kbps, download kbps); kbps 0 = that direction unlimited
    path_limits: Mutex<HashMap<String, (u32, u32)>>,
    /// (enabled, upload kbps, download kbps)
    global: Mutex<(bool, u32, u32)>,
    /// pid -> path of entries already pushed to the driver
    pushed: Mutex<HashMap<u32, String>>,
    /// whether the global (pid 0) entry has been pushed
    global_pushed: Mutex<bool>,
}

fn kbps_to_bps(kbps: u32) -> u32 {
    kbps.saturating_mul(128) // kbps * 1024 / 8
}

use crate::models::normalize_path;

/// pushed 表超过该条数时触发一次死 PID 清扫。正常 pushed 远小于此值，
/// 清扫频率极低；阈值以下容忍少量死 PID 残留（驱动进程退出回调会清内核侧）。
const PUSHED_SWEEP_THRESHOLD: usize = 512;

/// STILL_ACTIVE（NTSTATUS STATUS_PENDING 作为进程退出码的值）
const STILL_ACTIVE: u32 = 259;

/// OpenProcess + GetExitCodeProcess 判断 PID 是否存活。OpenProcess 失败
/// （进程已退出/无权限）一律按已死处理：漏清扫比误清扫代价高（误清扫只
/// 导致限速在下一次连接事件重新下发，漏清扫则死 PID 永久占位）。
fn pid_is_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return true; // 全局条目（pid 0）不参与清扫
    }
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut exit_code = 0u32;
        let alive = GetExitCodeProcess(handle, &mut exit_code).is_ok()
            && exit_code == STILL_ACTIVE;
        let _ = CloseHandle(handle);
        alive
    }
}

impl KernelThrottleSync {
    pub fn new() -> Self {
        KernelThrottleSync {
            path_limits: Mutex::new(HashMap::new()),
            global: Mutex::new((false, 0, 0)),
            pushed: Mutex::new(HashMap::new()),
            global_pushed: Mutex::new(false),
        }
    }

    /// pushed 表膨胀时的死 PID 清扫：对每个已推送 PID 查存活，死进程的条目
    /// 直接从 pushed 移除——内核侧条目已由驱动进程退出通知回调清理，这里
    /// 绝不再对死 PID 下发 IOCTL 撤回（会刷 STATUS_SUCCESS 噪声且无意义）。
    /// 由 update_path_limit / update_global 两个显式触发点调用。
    fn sweep_dead_pids(&self) {
        let dead: Vec<u32> = {
            let pushed = self.pushed.lock().unwrap_or_else(|e| e.into_inner());
            if pushed.len() <= PUSHED_SWEEP_THRESHOLD {
                return;
            }
            pushed
                .keys()
                .copied()
                .filter(|pid| !pid_is_alive(*pid))
                .collect()
        };
        if dead.is_empty() {
            return;
        }
        {
            let mut pushed = self.pushed.lock().unwrap_or_else(|e| e.into_inner());
            for pid in &dead {
                pushed.remove(pid);
            }
        }
        tracing::info!("Swept {} dead-PID entries from pushed throttle table", dead.len());
    }

    /// Update (or remove, when both limits are None/zero) a per-path limit and
    /// immediately retract any kernel entries previously pushed for it.
    /// 零值归一：Some(0) 视作未设置——历史遗留的 0/0 条目会让 sync_event 对
    /// 每个连接事件下发 set_throttle(pid,0,0)，而驱动 ThrottleSetEntry 对
    /// 不存在的 PID 返回 STATUS_INSUFFICIENT_RESOURCES，刷屏 WARN。
    pub async fn update_path_limit(
        &self,
        driver: &Arc<DriverHandle>,
        path: &str,
        upload_kbps: Option<u32>,
        download_kbps: Option<u32>,
    ) {
        // Windows 路径大小写不敏感且分隔符可能为 / 或 \：配置侧与事件侧统一
        // 经 normalize_path 后再进表。事件里的 process_path 由系统进程查询返回
        // （如 C:\windows\system32\curl.exe），与 GUI/cfctl 配置的写法可能不同，
        // 不归一会导致查表 miss，限速静默不下发。
        let path = normalize_path(path);
        let upload_kbps = upload_kbps.filter(|v| *v > 0);
        let download_kbps = download_kbps.filter(|v| *v > 0);
        self.sweep_dead_pids();
        let changed = {
            let mut limits = self.path_limits.lock().unwrap_or_else(|e| e.into_inner());
            match (upload_kbps, download_kbps) {
                (None, None) => limits.remove(&path).is_some(),
                (up, down) => {
                    limits.insert(path.to_string(), (up.unwrap_or(0), down.unwrap_or(0)));
                    true
                }
            }
        };
        if !changed {
            return;
        }

        // Retract stale entries for this path so a removed/lowered limit does
        // not keep throttling until the next connection event.
        let pids: Vec<u32> = {
            let pushed = self.pushed.lock().unwrap_or_else(|e| e.into_inner());
            pushed
                .iter()
                // 比较双方都过同一归一化函数：pushed 表的值由 sync_event 写入时
                // 已归一，这里再过一次属于防御性兜底，防止将来写入点漏归一。
                .filter(|(_, p)| normalize_path(p) == path)
                .map(|(pid, _)| *pid)
                .collect()
        };
        for pid in pids {
            if let Err(e) = driver.set_throttle(pid, 0, 0).await {
                tracing::warn!("Failed to retract throttle entry for PID {}: {}", pid, e);
            }
            self.pushed.lock().unwrap_or_else(|e| e.into_inner()).remove(&pid);
        }

        // If a limit still exists, re-push lazily on the next event for the
        // path (the process may already be running with connections).
        if let Some(_entry) = self.path_limits.lock().unwrap_or_else(|e| e.into_inner()).get(&path) {
            // Nothing to do here without a known PID; sync_event covers it.
        }
    }

    /// Update the global limit and push the kernel pid-0 entry right away.
    /// When the global limit is disabled or zeroed, also retract per-PID
    /// entries that were pushed as the global fallback.
    pub async fn update_global(
        &self,
        driver: &Arc<DriverHandle>,
        enabled: bool,
        upload_kbps: u32,
        download_kbps: u32,
    ) {
        self.sweep_dead_pids();
        {
            let mut global = self.global.lock().unwrap_or_else(|e| e.into_inner());
            *global = (enabled, upload_kbps, download_kbps);
        }
        self.push_global(driver).await;

        if !enabled || (upload_kbps == 0 && download_kbps == 0) {
            // 全局兜底失效后，这些条目失去存在依据且不会再有事件来覆盖它们
            // （sync_event 只推不撤），必须在显式触发点回收。按 path 记录
            // 区分来源：path 为空的条目才是全局兜底下的。
            let pids: Vec<u32> = {
                let pushed = self.pushed.lock().unwrap_or_else(|e| e.into_inner());
                pushed
                    .iter()
                    .filter(|(_, p)| p.is_empty())
                    .map(|(pid, _)| *pid)
                    .collect()
            };
            for pid in pids {
                if let Err(e) = driver.set_throttle(pid, 0, 0).await {
                    tracing::warn!("Failed to retract global-fallback throttle entry for PID {}: {}", pid, e);
                }
                self.pushed.lock().unwrap_or_else(|e| e.into_inner()).remove(&pid);
            }
        }
    }

    /// Push the global entry (called at service start and on changes).
    pub async fn push_global(&self, driver: &Arc<DriverHandle>) {
        let (enabled, up, down) = *self.global.lock().unwrap_or_else(|e| e.into_inner());
        // "开关开但上下行限值均为 0"视作未配置：不下发任何 ioctl，现状条目
        // 原样保留；全局兜底的摘除由 update_global 的显式回撤分支处理（只撤
        // global-fallback 条目）。注意 (0,0,0) 在驱动侧语义是"仅删 PID 0
        // 全局条目"，与按进程条目删除对齐——绝不会误清其它条目。
        if enabled && up == 0 && down == 0 {
            tracing::info!("Global bandwidth limit enabled but both limits are 0 - treating as unconfigured, kernel table untouched");
            return;
        }
        let (up_bps, down_bps) = if enabled {
            (kbps_to_bps(up), kbps_to_bps(down))
        } else {
            // 关闭：删除 PID 0 全局条目（驱动对不存在的条目幂等成功）。
            // 按进程条目不受影响——清全表必须走 clear_kernel。
            (0, 0)
        };
        match driver.set_throttle(0, up_bps, down_bps).await {
            Ok(()) => {
                *self.global_pushed.lock().unwrap_or_else(|e| e.into_inner()) = enabled;
            }
            Err(e) => tracing::warn!("Failed to push global throttle entry: {}", e),
        }
    }

    /// Clear the whole kernel throttle table (service stop).
    pub async fn clear_kernel(&self, driver: &Arc<DriverHandle>) {
        // 必须走专用 IOCTL：set_throttle(0,0,0) 现在只删 PID 0 全局条目。
        if let Err(e) = driver.clear_throttle_table().await {
            tracing::warn!("Failed to clear kernel throttle table: {}", e);
        }
        self.pushed.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *self.global_pushed.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }

    /// Called for every driver connection event: pushes the kernel entry for
    /// this PID when a limit applies. Push-only：本方法绝不撤销已下发的限速
    /// 条目——事件流里大量样本不带进程路径（Close 事件、惰性关联的流层连
    /// 接），按"查不到配置就撤"会把刚下发的限速在 1ms 内撤销（已在 VM 上
    /// 观测到 PUSH→RETRACT）。撤销只能由 update_path_limit / update_global /
    /// clear_kernel 这三个显式触发点执行；代价是 PID 退出后条目会保留到下
    /// 一次配置变更或服务停止，由内核表的自然覆盖兜住。
    pub async fn sync_event(&self, driver: &Arc<DriverHandle>, pid: u32, path: Option<&str>) {
        if pid == 0 {
            return;
        }
        // 与 update_path_limit 的入口规范化对齐（小写 + 分隔符），否则事件
        // 路径写法与配置不同时查不到条目。
        let lookup = path.map(normalize_path);
        let desired = {
            let limits = self.path_limits.lock().unwrap_or_else(|e| e.into_inner());
            match lookup.as_deref().and_then(|p| limits.get(p).copied()) {
                // 双重保险：即使 (0,0) 条目混进来（老版本落库的遗留行）也不
                // 向驱动下发空条目——驱动对不存在的 PID 返回错误，日志刷屏。
                Some(kbps) if kbps.0 > 0 || kbps.1 > 0 => {
                    (kbps_to_bps(kbps.0), kbps_to_bps(kbps.1))
                }
                _ => {
                    let (enabled, up, down) = *self.global.lock().unwrap_or_else(|e| e.into_inner());
                    if enabled && (up > 0 || down > 0) {
                        (kbps_to_bps(up), kbps_to_bps(down))
                    } else {
                        // 本事件对该 PID 无适用限速：不写不动，绝不撤回。
                        return;
                    }
                }
            }
        };

        if let Err(e) = driver.set_throttle(pid, desired.0, desired.1).await {
            tracing::warn!("Failed to sync throttle entry for PID {}: {}", pid, e);
            return;
        }
        self.pushed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pid, lookup.unwrap_or_default());
    }
}

/// 全局限速 IPC 入参归一化（纯函数，便于单测）。
///
/// 返回 (生效开关, 上行 kbps, 下行 kbps)，限值 None = 该方向未设置：
/// * 开关缺省时按限值有无推断（旧调用方兼容）；
/// * Some(0) 限值归一为 None（未设置）；
/// * "开关开但双限值均空/0" 归一为关闭——否则内核旧全局条目残留继续限速、
///   用户态装双 0 桶产生假告警，两条路径都错。
pub fn normalize_global_limit(
    enabled_flag: Option<bool>,
    upload: Option<u32>,
    download: Option<u32>,
) -> (bool, Option<u32>, Option<u32>) {
    let mut enabled = enabled_flag.unwrap_or(upload.is_some() || download.is_some());
    let up = upload.filter(|v| *v > 0);
    let down = download.filter(|v| *v > 0);
    if enabled && up.is_none() && down.is_none() {
        enabled = false;
    }
    (enabled, up, down)
}

#[cfg(test)]
mod tests {
    use super::normalize_global_limit;

    #[test]
    fn test_normalize_global_limit_explicit_on() {
        // 显式开启 + 有效限值：原样保留
        assert_eq!(normalize_global_limit(Some(true), Some(1024), Some(2048)), (true, Some(1024), Some(2048)));
    }

    #[test]
    fn test_normalize_global_limit_explicit_off_keeps_values() {
        // 显式关闭：限值照旧透传（持久化用），开关为 false
        assert_eq!(normalize_global_limit(Some(false), Some(1024), Some(2048)), (false, Some(1024), Some(2048)));
    }

    #[test]
    fn test_normalize_global_limit_inferred_from_values() {
        // 旧调用方（无开关字段）：按限值有无推断
        assert_eq!(normalize_global_limit(None, Some(512), None), (true, Some(512), None));
        assert_eq!(normalize_global_limit(None, None, None), (false, None, None));
    }

    #[test]
    fn test_normalize_global_limit_zero_means_unset() {
        // Some(0) = 未设置
        assert_eq!(normalize_global_limit(Some(true), Some(0), Some(1024)), (true, None, Some(1024)));
    }

    #[test]
    fn test_normalize_global_limit_on_with_both_zero_normalized_off() {
        // 开关开但双限值均空/0：归一为关闭，避免旧内核条目残留 + 双 0 假告警桶
        assert_eq!(normalize_global_limit(Some(true), None, None), (false, None, None));
        assert_eq!(normalize_global_limit(Some(true), Some(0), Some(0)), (false, None, None));
    }
}
