//! DNS Cache - maps IP addresses to domain names
//! 
//! Captures DNS responses from FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 layer

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use std::time::{Duration, Instant};

/// DNS cache entry
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub domain: String,
    pub ip: IpAddr,
    pub ttl: u32,
    pub timestamp: Instant,
}

/// DNS 观测事件（add_entry 成功写入后向订阅者广播）。
/// 订阅者（domain_expander）据此把命中域名规则的 IP 展开成影子规则。
#[derive(Debug, Clone)]
pub struct DnsObservation {
    pub ip: IpAddr,
    pub domain: String,
    pub ttl: u32,
}

impl DnsCacheEntry {
    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > Duration::from_secs(self.ttl as u64)
    }
}

/// DNS cache manager
pub struct DnsCache {
    // IP → domain name mapping
    cache: Arc<RwLock<HashMap<IpAddr, DnsCacheEntry>>>,
    // 写入广播：domain_expander 订阅后做域名规则展开。容量覆盖一轮排空
    // （事件循环每轮最多 32 条）的突发即可，慢订阅者丢帧只影响影子规则
    // 展开时机（下次同域名 DNS 响应会再触发）。
    updates: broadcast::Sender<DnsObservation>,
}

impl DnsCache {
    /// Create a new DNS cache
    pub fn new() -> Self {
        let (updates, _) = broadcast::channel(256);
        DnsCache {
            cache: Arc::new(RwLock::new(HashMap::new())),
            updates,
        }
    }

    /// 订阅缓存写入事件（domain_expander 用）
    pub fn subscribe(&self) -> broadcast::Receiver<DnsObservation> {
        self.updates.subscribe()
    }

    /// Add a DNS entry to cache
    pub async fn add_entry(&self, ip: IpAddr, domain: String, ttl: u32) {
        let entry = DnsCacheEntry {
            domain: domain.clone(),
            ip,
            ttl,
            timestamp: Instant::now(),
        };

        let mut cache = self.cache.write().await;
        cache.insert(ip, entry);
        drop(cache);

        // 无订阅者时 send 返回 Err，属正常空操作
        let _ = self.updates.send(DnsObservation { ip, domain: domain.clone(), ttl });

        tracing::debug!("DNS cache: {} → {}", domain, ip);
    }

    /// Lookup domain name by IP address
    pub async fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let cache = self.cache.read().await;
        
        if let Some(entry) = cache.get(ip) {
            if !entry.is_expired() {
                return Some(entry.domain.clone());
            }
        }
        
        None
    }

    /// Clean expired entries（过期阈值沿用 DnsCacheEntry::is_expired 的 TTL 定义）。
    /// 返回清理条数；由防火墙服务的周期任务每 5 分钟调用一次。
    pub async fn cleanup_expired(&self) -> usize {
        let mut cache = self.cache.write().await;
        let before = cache.len();
        cache.retain(|_, entry| !entry.is_expired());
        let removed = before - cache.len();

        if removed > 0 {
            tracing::debug!("DNS cache: removed {} expired entries, {} remaining", removed, cache.len());
        }
        removed
    }

    /// Get cache size
    pub async fn size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Clear all entries
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        tracing::info!("DNS cache cleared");
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse DNS response packet and extract domain → IP mappings
pub fn parse_dns_response(data: &[u8]) -> Vec<(String, IpAddr, u32)> {
    let mut results = Vec::new();

    // DNS header is 12 bytes minimum
    if data.len() < 12 {
        return results;
    }

    // Check if it's a response (QR bit = 1)
    if (data[2] & 0x80) == 0 {
        return results;
    }

    // Get answer count (bytes 6-7)
    let answer_count = u16::from_be_bytes([data[6], data[7]]);
    if answer_count == 0 {
        return results;
    }

    // Skip header (12 bytes) and question section
    let mut offset = 12;

    // Skip question section
    // Read QNAME (domain name)
    while offset < data.len() {
        let len = data[offset] as usize;
        if len == 0 {
            offset += 1; // Skip null terminator
            break;
        }
        if len > 63 || offset + len >= data.len() {
            return results; // Invalid
        }
        offset += len + 1;
    }

    // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
    offset += 4;

    // Parse answer section
    for _ in 0..answer_count {
        if offset >= data.len() {
            break;
        }

        // Parse NAME (can be compressed with pointer)
        let domain = match parse_dns_name(data, &mut offset) {
            Some(d) => d,
            None => break,
        };

        // Check remaining space for TYPE, CLASS, TTL, RDLENGTH
        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let _rclass = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let ttl = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + rdlength > data.len() {
            break;
        }

        // Parse A record (IPv4)
        if rtype == 1 && rdlength == 4 {
            let ip = IpAddr::from([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            results.push((domain.clone(), ip, ttl));
        }
        // Parse AAAA record (IPv6)
        else if rtype == 28 && rdlength == 16 {
            let mut ipv6_bytes = [0u8; 16];
            ipv6_bytes.copy_from_slice(&data[offset..offset + 16]);
            let ip = IpAddr::from(ipv6_bytes);
            results.push((domain.clone(), ip, ttl));
        }

        offset += rdlength;
    }

    results
}

/// Parse DNS name from packet (handles compression)
fn parse_dns_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut name = String::new();
    let mut jumped = false;
    let mut jump_offset = *offset;
    let max_jumps = 5; // Prevent infinite loops
    let mut jumps = 0;

    loop {
        if jump_offset >= data.len() {
            return None;
        }

        let len = data[jump_offset];

        // Check for compression pointer (top 2 bits set)
        if (len & 0xC0) == 0xC0 {
            if jump_offset + 1 >= data.len() {
                return None;
            }

            // Get pointer offset
            let pointer = u16::from_be_bytes([len & 0x3F, data[jump_offset + 1]]) as usize;

            if !jumped {
                *offset = jump_offset + 2;
            }

            jump_offset = pointer;
            jumped = true;
            jumps += 1;

            if jumps > max_jumps {
                return None; // Too many jumps
            }

            continue;
        }

        // End of name
        if len == 0 {
            if !jumped {
                *offset = jump_offset + 1;
            }
            break;
        }

        // Read label
        if len > 63 || jump_offset + (len as usize) >= data.len() {
            return None;
        }

        jump_offset += 1;

        if !name.is_empty() {
            name.push('.');
        }

        for i in 0..len {
            let ch = data[jump_offset + i as usize];
            // Only allow printable ASCII
            if ch < 32 || ch > 126 {
                return None;
            }
            name.push(ch as char);
        }

        jump_offset += len as usize;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_cache() {
        let cache = DnsCache::new();
        let ip = "1.1.1.1".parse().unwrap();

        cache.add_entry(ip, "example.com".to_string(), 300).await;

        let domain = cache.lookup(&ip).await;
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_dns_name() {
        // Simple name: "example.com" = 7 "example" 3 "com" 0
        let data = vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let mut offset = 0;
        let name = parse_dns_name(&data, &mut offset);
        assert_eq!(name, Some("example.com".to_string()));
        assert_eq!(offset, 13);
    }
}
