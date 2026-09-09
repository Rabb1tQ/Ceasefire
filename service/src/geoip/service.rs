//! GeoIP 服务实现 - 使用本地MaxMind GeoIP数据库

use super::super::error::Result;
use super::super::models::GeoLocation;
use super::super::database::Database;
use std::sync::Arc;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use tokio::sync::RwLock;
use chrono::Utc;

/// 内存缓存容量上限：插入超限时按 FIFO 淘汰最旧条目（命中不刷新顺序），
/// 防止长期运行下每个查过的 IP 都常驻内存。不引第三方 LRU 依赖。
const CACHE_MAX_ENTRIES: usize = 10_000;

/// HashMap + 插入序队列的组合：map 负责查找，order 记录插入先后用于
/// FIFO 淘汰。重复 insert 已有 key 时只覆盖值，不动队列位置。
#[derive(Default)]
struct GeoCache {
    map: HashMap<String, GeoLocation>,
    order: VecDeque<String>,
}

impl GeoCache {
    fn insert(&mut self, ip: String, location: GeoLocation) {
        if !self.map.contains_key(&ip) {
            if self.map.len() >= CACHE_MAX_ENTRIES {
                if let Some(oldest) = self.order.pop_front() {
                    self.map.remove(&oldest);
                }
            }
            self.order.push_back(ip.clone());
        }
        self.map.insert(ip, location);
    }

    /// 删除单个条目（map 与 order 同步），供过期清理使用；返回是否存在
    fn remove(&mut self, ip: &str) -> bool {
        if self.map.remove(ip).is_some() {
            if let Some(pos) = self.order.iter().position(|k| k == ip) {
                self.order.remove(pos);
            }
            true
        } else {
            false
        }
    }
}

/// GeoIP 服务 - 使用本地MaxMind数据库
pub struct GeoIpService {
    db: Arc<Database>,
    cache: Arc<RwLock<GeoCache>>,
    cache_ttl_hours: i64,
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoIpService {
    /// 创建新的 GeoIP 服务
    pub fn new(db: Arc<Database>) -> Self {
        // 尝试从多个可能的位置加载GeoIP数据库
        let reader = Self::load_geoip_database();

        GeoIpService {
            db,
            cache: Arc::new(RwLock::new(GeoCache::default())),
            cache_ttl_hours: 24 * 7, // 7天缓存
            reader,
        }
    }

    /// 从可能的路径加载GeoIP数据库
    fn load_geoip_database() -> Option<Arc<maxminddb::Reader<Vec<u8>>>> {
        // 候选路径。前两个基于 exe 所在目录解析：Windows 服务的 CWD 是
        // System32，相对路径候选在服务模式下无法命中，必须以 current_exe 为锚点。
        let mut possible_paths: Vec<String> = Vec::new();
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                for rel in ["GeoLite2-City.mmdb", "data/GeoLite2-City.mmdb"] {
                    possible_paths.push(exe_dir.join(rel).to_string_lossy().into_owned());
                }
            }
        }
        possible_paths.extend([
            "data/GeoLite2-City.mmdb".to_string(),
            "GeoLite2-City.mmdb".to_string(),
            "../data/GeoLite2-City.mmdb".to_string(),
            "service/data/GeoLite2-City.mmdb".to_string(),
            "service/GeoLite2-City.mmdb".to_string(),
            "C:/ProgramData/Ceasefire/GeoLite2-City.mmdb".to_string(),
        ]);

        for path in possible_paths {
            if Path::new(&path).exists() {
                match std::fs::read(&path) {
                    Ok(data) => {
                        match maxminddb::Reader::from_source(data) {
                            Ok(reader) => {
                                tracing::info!("成功加载GeoIP数据库: {}", path);
                                return Some(Arc::new(reader));
                            }
                            Err(e) => {
                                tracing::error!("无法解析GeoIP数据库 {}: {}", path, e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("无法读取GeoIP数据库 {}: {}", path, e);
                    }
                }
            } else {
                tracing::debug!("GeoIP数据库文件不存在: {}", path);
            }
        }

        tracing::warn!("警告: 未找到GeoIP数据库文件，IP地理查询将返回未知位置");
        None
    }

    /// 查询单个 IP 的地理位置
    pub async fn lookup_location(&self, ip: &str) -> Result<GeoLocation> {
        // 检查缓存
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.map.get(ip) {
                // 检查缓存是否过期
                if let Some(cached_at) = cached.cached_at {
                    let age = Utc::now() - cached_at;
                    if age.num_hours() < self.cache_ttl_hours {
                        return Ok(cached.clone());
                    }
                }
            }
        }

        // 检查数据库缓存
        if let Some(db_cached) = self.db.get_geo_location(ip).await? {
            if let Some(cached_at) = db_cached.cached_at {
                let age = Utc::now() - cached_at;
                if age.num_hours() < self.cache_ttl_hours {
                    // 更新内存缓存
                    {
                        let mut cache = self.cache.write().await;
                        cache.insert(ip.to_string(), db_cached.clone());
                    }
                    return Ok(db_cached);
                }
            }
        }

        // 从本地数据库获取
        let location = self.lookup_from_database(ip).await?;

        // 保存到缓存
        {
            let mut cache = self.cache.write().await;
            cache.insert(ip.to_string(), location.clone());
        }

        // 保存到数据库
        let _ = self.db.save_geo_location(&location).await;

        Ok(location)
    }

    /// 从本地MaxMind数据库查询
    async fn lookup_from_database(&self, ip: &str) -> Result<GeoLocation> {
        if let Some(ref reader) = self.reader {
            // 解析IP地址
            let parsed_ip: std::net::IpAddr = ip.parse()
                .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

            match reader.lookup::<maxminddb::geoip2::City>(parsed_ip) {
                Ok(city) => {
                    let country_code = city.country.as_ref().and_then(|c| c.iso_code).unwrap_or("XX").to_string();
                    let country_name = city.country
                        .as_ref()
                        .and_then(|c| c.names.as_ref())
                        .and_then(|names| names.get("en").cloned())
                        .unwrap_or_else(|| {
                            city.registered_country
                                .as_ref()
                                .and_then(|c| c.names.as_ref())
                                .and_then(|names| names.get("en").cloned())
                                .unwrap_or_else(|| "Unknown")
                        });

                    let region = city.subdivisions
                        .as_ref()
                        .and_then(|subs| subs.first())
                        .and_then(|sub| sub.names.as_ref())
                        .and_then(|names| names.get("en").cloned());

                    let city_name = city.city.as_ref().and_then(|c| c.names.as_ref()).and_then(|names| names.get("en").cloned());

                    let (latitude, longitude) = city.location
                        .as_ref()
                        .map(|loc| (loc.latitude, loc.longitude))
                        .unwrap_or((None, None));

                    Ok(GeoLocation {
                        ip: ip.to_string(),
                        country_code: country_code.to_string(),
                        country_name: country_name.to_string(),
                        region: region.map(|s| s.to_string()),
                        city: city_name.map(|s| s.to_string()),
                        latitude,
                        longitude,
                        cached_at: Some(Utc::now()),
                    })
                }
                Err(_) => {
                    // 查询失败，返回未知位置
                    Ok(self.unknown_location(ip))
                }
            }
        } else {
            // 没有数据库文件，返回未知位置
            Ok(self.unknown_location(ip))
        }
    }

    /// 返回未知位置的GeoLocation
    fn unknown_location(&self, ip: &str) -> GeoLocation {
        GeoLocation {
            ip: ip.to_string(),
            country_code: "XX".to_string(),
            country_name: "Unknown".to_string(),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            cached_at: Some(Utc::now()),
        }
    }

    /// 批量查询 IP 地理位置
    pub async fn lookup_batch(&self, ips: Vec<String>) -> Result<HashMap<String, GeoLocation>> {
        let mut results = HashMap::new();
        let mut uncached_ips = Vec::new();

        // 首先检查缓存
        {
            let cache = self.cache.read().await;
            for ip in &ips {
                if let Some(cached) = cache.map.get(ip) {
                    if let Some(cached_at) = cached.cached_at {
                        let age = Utc::now() - cached_at;
                        if age.num_hours() < self.cache_ttl_hours {
                            results.insert(ip.clone(), cached.clone());
                            continue;
                        }
                    }
                }
                uncached_ips.push(ip.clone());
            }
        }

        // 查询未缓存的 IP
        for ip in uncached_ips {
            match self.lookup_location(&ip).await {
                Ok(location) => {
                    results.insert(ip, location);
                }
                Err(e) => {
                    eprintln!("Failed to lookup IP {}: {}", ip, e);
                }
            }
        }

        Ok(results)
    }

    /// 清理过期缓存
    pub async fn cleanup_cache(&self) -> Result<u32> {
        let mut count = 0;
        let cutoff = Utc::now() - chrono::Duration::hours(self.cache_ttl_hours);

        {
            let mut cache = self.cache.write().await;
            let mut to_remove = Vec::new();
            
            for (ip, location) in cache.map.iter() {
                if let Some(cached_at) = location.cached_at {
                    if cached_at < cutoff {
                        to_remove.push(ip.clone());
                    }
                }
            }

            for ip in to_remove {
                if cache.remove(&ip) {
                    count += 1;
                }
            }
        }

        // 清理数据库缓存
        let db_count = self.db.cleanup_old_geo_locations(self.cache_ttl_hours).await?;
        Ok(count + db_count)
    }

    /// 获取缓存统计信息
    pub async fn get_cache_stats(&self) -> Result<GeoIpCacheStats> {
        let cache = self.cache.read().await;
        let db_count = self.db.get_geo_location_count().await?;

        Ok(GeoIpCacheStats {
            memory_cache_size: cache.map.len(),
            database_cache_size: db_count,
            cache_ttl_hours: self.cache_ttl_hours,
            database_loaded: self.reader.is_some(),
        })
    }

    /// 检查GeoIP数据库是否已加载
    pub fn is_database_loaded(&self) -> bool {
        self.reader.is_some()
    }
}

/// GeoIP 缓存统计
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoIpCacheStats {
    pub memory_cache_size: usize,
    pub database_cache_size: u32,
    pub cache_ttl_hours: i64,
    pub database_loaded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lookup_localhost() {
        let db = Arc::new(Database::open(":memory:").unwrap());
        let service = GeoIpService::new(db);
        
        // 本地地址应该返回未知
        let result = service.lookup_location("127.0.0.1").await;
        assert!(result.is_ok());
        let location = result.unwrap();
        assert_eq!(location.country_code, "XX");
        assert_eq!(location.country_name, "Unknown");
    }

    #[tokio::test]
    async fn test_cache() {
        let db = Arc::new(Database::open(":memory:").unwrap());
        let service = GeoIpService::new(db);
        
        // 第一次查询
        let result1 = service.lookup_location("127.0.0.1").await;
        assert!(result1.is_ok());
        
        // 第二次查询应该从缓存获取
        let result2 = service.lookup_location("127.0.0.1").await;
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap().country_code, result2.unwrap().country_code);
    }

    #[tokio::test]
    async fn test_batch_lookup() {
        let db = Arc::new(Database::open(":memory:").unwrap());
        let service = GeoIpService::new(db);
        
        let ips = vec![
            "127.0.0.1".to_string(),
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
        ];
        
        let results = service.lookup_batch(ips).await;
        assert!(results.is_ok());
        let map = results.unwrap();
        assert_eq!(map.len(), 3);
    }

    /// 容量上限：插入 10001 个不同 key 后 size == 10000，且淘汰的是最旧的
    /// （FIFO，命中不刷新顺序）。
    #[test]
    fn cache_fifo_eviction_caps_at_limit() {
        let mut cache = GeoCache::default();
        for i in 0..(CACHE_MAX_ENTRIES as u32 + 1) {
            let mut loc = service_unknown_for_test(&i.to_string());
            loc.ip = i.to_string();
            cache.insert(i.to_string(), loc);
        }
        assert_eq!(cache.map.len(), CACHE_MAX_ENTRIES);
        // 最旧的 "0" 被淘汰；次旧的 "1" 仍在
        assert!(!cache.map.contains_key("0"));
        assert!(cache.map.contains_key("1"));
        assert!(cache.map.contains_key(&(CACHE_MAX_ENTRIES as u32).to_string()));

        // 覆盖已有 key 不改变容量、不挤掉别的条目
        let before = cache.map.len();
        cache.insert("1".to_string(), service_unknown_for_test("1"));
        assert_eq!(cache.map.len(), before);
        assert!(cache.order.len() == CACHE_MAX_ENTRIES);
    }

    fn service_unknown_for_test(ip: &str) -> GeoLocation {
        GeoLocation {
            ip: ip.to_string(),
            country_code: "XX".to_string(),
            country_name: "Unknown".to_string(),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            cached_at: Some(Utc::now()),
        }
    }
}
