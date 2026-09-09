//! Bandwidth limiting module for process and global bandwidth control

mod token_bucket;
pub mod kernel_sync;

pub use kernel_sync::KernelThrottleSync;

pub use token_bucket::TokenBucket;
pub use token_bucket::SharedTokenBucket;

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::models::normalize_path;

/// Bandwidth limiter for controlling process and global bandwidth
///
/// 内存表的 key 一律是 normalize_path 之后的写法（小写 + /→\），与 DB 层、
/// kernel_sync 保持一致：DB 恢复的键是小写归一化路径，而驱动事件回报的是
/// 系统原始大小写（C:\Windows\...），GUI 又可能传 C:/ 正斜杠写法——任何一端
/// 不归一，超限判断就会查不中同一进程的限速桶。
pub struct BandwidthLimiter {
    upload_limits: Arc<RwLock<HashMap<String, Arc<SharedTokenBucket>>>>,
    download_limits: Arc<RwLock<HashMap<String, Arc<SharedTokenBucket>>>>,
    global_upload_limit: Arc<RwLock<Option<Arc<SharedTokenBucket>>>>,
    global_download_limit: Arc<RwLock<Option<Arc<SharedTokenBucket>>>>,
}

impl BandwidthLimiter {
    pub fn new() -> Self {
        BandwidthLimiter {
            upload_limits: Arc::new(RwLock::new(HashMap::new())),
            download_limits: Arc::new(RwLock::new(HashMap::new())),
            global_upload_limit: Arc::new(RwLock::new(None)),
            global_download_limit: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if upload is allowed for a process
    pub async fn allow_upload(&self, process_path: &str, bytes: u64) -> bool {
        let mut allowed = true;

        // Check per-process upload limit
        {
            let limits = self.upload_limits.read().await;
            if let Some(bucket) = limits.get(&normalize_path(process_path)) {
                allowed = bucket.consume(bytes).await;
            }
        }

        // Check global upload limit
        if allowed {
            let global_limit = self.global_upload_limit.read().await;
            if let Some(bucket) = global_limit.as_ref() {
                allowed = bucket.consume(bytes).await;
            }
        }

        allowed
    }

    /// Check if download is allowed for a process
    pub async fn allow_download(&self, process_path: &str, bytes: u64) -> bool {
        let mut allowed = true;

        // Check per-process download limit
        {
            let limits = self.download_limits.read().await;
            if let Some(bucket) = limits.get(&normalize_path(process_path)) {
                allowed = bucket.consume(bytes).await;
            }
        }

        // Check global download limit
        if allowed {
            let global_limit = self.global_download_limit.read().await;
            if let Some(bucket) = global_limit.as_ref() {
                allowed = bucket.consume(bytes).await;
            }
        }

        allowed
    }

    /// Set bandwidth limits for a process
    pub async fn set_limits(&self, process_path: &str, upload_limit_kbps: Option<u32>, download_limit_kbps: Option<u32>) {
        let key = normalize_path(process_path);

        // Set upload limit
        if let Some(kbps) = upload_limit_kbps {
            let bytes_per_sec = (kbps as u64) * 1024 / 8;
            let bucket = Arc::new(SharedTokenBucket::new(bytes_per_sec, bytes_per_sec));
            let mut limits = self.upload_limits.write().await;
            limits.insert(key.clone(), bucket);
        } else {
            let mut limits = self.upload_limits.write().await;
            limits.remove(&key);
        }

        // Set download limit
        if let Some(kbps) = download_limit_kbps {
            let bytes_per_sec = (kbps as u64) * 1024 / 8;
            let bucket = Arc::new(SharedTokenBucket::new(bytes_per_sec, bytes_per_sec));
            let mut limits = self.download_limits.write().await;
            limits.insert(key.clone(), bucket);
        } else {
            let mut limits = self.download_limits.write().await;
            limits.remove(&key);
        }
    }

    /// Set global bandwidth limits
    pub async fn set_global_limits(&self, upload_limit_kbps: Option<u32>, download_limit_kbps: Option<u32>) {
        if let Some(kbps) = upload_limit_kbps {
            let bytes_per_sec = (kbps as u64) * 1024 / 8;
            let bucket = Arc::new(SharedTokenBucket::new(bytes_per_sec, bytes_per_sec));
            *self.global_upload_limit.write().await = Some(bucket);
        } else {
            *self.global_upload_limit.write().await = None;
        }

        if let Some(kbps) = download_limit_kbps {
            let bytes_per_sec = (kbps as u64) * 1024 / 8;
            let bucket = Arc::new(SharedTokenBucket::new(bytes_per_sec, bytes_per_sec));
            *self.global_download_limit.write().await = Some(bucket);
        } else {
            *self.global_download_limit.write().await = None;
        }
    }

    /// Get upload limit for a process (in kbps)
    pub async fn get_upload_limit(&self, process_path: &str) -> Option<u32> {
        let limits = self.upload_limits.read().await;
        if let Some(bucket) = limits.get(&normalize_path(process_path)) {
            let rate = bucket.get_rate().await;
            Some((rate / 1024 * 8) as u32)
        } else {
            None
        }
    }

    /// Get download limit for a process (in kbps)
    pub async fn get_download_limit(&self, process_path: &str) -> Option<u32> {
        let limits = self.download_limits.read().await;
        if let Some(bucket) = limits.get(&normalize_path(process_path)) {
            let rate = bucket.get_rate().await;
            Some((rate / 1024 * 8) as u32)
        } else {
            None
        }
    }

    /// Get bandwidth statistics for all processes
    pub async fn get_bandwidth_stats(&self) -> Vec<BandwidthStats> {
        let mut stats = Vec::new();

        let upload_limits = self.upload_limits.read().await;
        let download_limits = self.download_limits.read().await;

        // Collect all unique process paths
        let mut all_processes: Vec<String> = upload_limits.keys().cloned().collect();
        for process in download_limits.keys() {
            if !all_processes.contains(process) {
                all_processes.push(process.clone());
            }
        }

        for process_path in all_processes {
            let upload_limit_kbps = if let Some(bucket) = upload_limits.get(&process_path) {
                let rate = bucket.get_rate().await;
                Some((rate / 1024 * 8) as u32)
            } else {
                None
            };
            let download_limit_kbps = if let Some(bucket) = download_limits.get(&process_path) {
                let rate = bucket.get_rate().await;
                Some((rate / 1024 * 8) as u32)
            } else {
                None
            };

            stats.push(BandwidthStats {
                process_path: process_path.clone(),
                upload_limit_kbps,
                download_limit_kbps,
            });
        }

        stats
    }
}

/// Bandwidth statistics for a process
#[derive(Debug, Clone)]
pub struct BandwidthStats {
    pub process_path: String,
    pub upload_limit_kbps: Option<u32>,
    pub download_limit_kbps: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 写入用正斜杠 + 混合大小写，查询用小写反斜杠原样写法（驱动事件形态）：
    /// 必须命中同一个限速桶。这是服务重启后 DB 归一化键能对上事件路径的前提。
    #[tokio::test]
    async fn bandwidth_keys_match_across_spellings_and_case() {
        let limiter = BandwidthLimiter::new();
        limiter
            .set_limits("C:/Program Files/App/APP.exe", Some(200), Some(200))
            .await;

        let event_path = r"c:\program files\app\app.exe";

        // allow_upload / allow_download 命中同一桶（桶容量 200KB，消费 1 字节必然允许）
        assert!(
            limiter.allow_upload(event_path, 1).await,
            "upload query with normalized spelling must hit the bucket"
        );
        assert!(
            limiter.allow_download(event_path, 1).await,
            "download query with normalized spelling must hit the bucket"
        );

        // get_upload_limit / get_download_limit：kbps*1024/8/1024*8 回读等于原 kbps
        assert_eq!(limiter.get_upload_limit(event_path).await, Some(200));
        assert_eq!(limiter.get_download_limit(event_path).await, Some(200));

        // 未设置的进程查不到
        assert_eq!(limiter.get_upload_limit(r"C:\Other\App.exe").await, None);
    }

    /// SetProcessBandwidthLimit enabled=false 的撤销语义（handler 与重启恢复
    /// 路径统一走 set_limits(path, None, None)）：既有桶必须被移除，
    /// allow_upload/allow_download 恢复不受限。IpcHandler 本身无单测基建
    /// （需完整 DB/驱动/内核同步依赖），此处覆盖该语义在限流器层面的保证。
    #[tokio::test]
    async fn clearing_limits_removes_existing_buckets() {
        let limiter = BandwidthLimiter::new();
        let path = r"C:\Program Files\App\app.exe";
        limiter.set_limits(path, Some(100), Some(100)).await;
        assert!(
            limiter.get_upload_limit(path).await.is_some(),
            "bucket installed before clearing"
        );

        // 关闭：撤销当前生效条目
        limiter.set_limits(path, None, None).await;
        assert_eq!(limiter.get_upload_limit(path).await, None, "upload bucket removed");
        assert_eq!(limiter.get_download_limit(path).await, None, "download bucket removed");
        assert!(
            limiter.allow_upload(path, u64::MAX).await,
            "no bucket left, upload unrestricted"
        );
        assert!(
            limiter.allow_download(path, u64::MAX).await,
            "no bucket left, download unrestricted"
        );
    }
}