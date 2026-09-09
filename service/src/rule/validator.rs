//! Rule Validator - validates firewall rules

use super::super::error::{Result, ServiceError};
use super::super::models::*;

/// Validate CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/32")
/// 双栈：IPv4 prefix 0-32，IPv6 prefix 0-128
pub fn validate_cidr(cidr: &str) -> Result<(std::net::IpAddr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(ServiceError::Validation(format!(
            "Invalid CIDR format: {}. Expected format: IP/MASK",
            cidr
        )));
    }

    let ip = parts[0].parse::<std::net::IpAddr>()
        .map_err(|_| ServiceError::Validation(format!("Invalid IP address: {}", parts[0])))?;

    let mask = parts[1].parse::<u8>()
        .map_err(|_| ServiceError::Validation(format!("Invalid subnet mask: {}", parts[1])))?;

    let max = match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    if mask > max {
        return Err(ServiceError::Validation(format!(
            "Subnet mask must be between 0 and {}, got: {}",
            max, mask
        )));
    }

    Ok((ip, mask))
}

/// Parse CIDR notation and extract IP and mask
pub fn parse_cidr(cidr: &str) -> Result<(String, u8)> {
    let (ip, mask) = validate_cidr(cidr)?;
    Ok((ip.to_string(), mask))
}

/// Check if an IP address matches a CIDR range（双栈，异族视为不匹配）
pub fn cidr_matches(cidr: &str, addr: &str) -> Result<bool> {
    let (cidr_ip, mask_bits) = validate_cidr(cidr)?;
    let target_ip = addr.parse::<std::net::IpAddr>()
        .map_err(|_| ServiceError::Validation(format!("Invalid target IP address: {}", addr)))?;

    // 注意：/0 不能提前视为"匹配一切"——0.0.0.0/0 只匹配 IPv4，
    // ::/0 只匹配 IPv6，与驱动侧 MatchRules 的异族跳过语义一致。
    match (cidr_ip, target_ip) {
        (std::net::IpAddr::V4(cidr), std::net::IpAddr::V4(target)) => {
            let mask_value = if mask_bits == 0 {
                0u32
            } else {
                !0u32 << (32 - mask_bits)
            };
            Ok((u32::from(cidr) & mask_value) == (u32::from(target) & mask_value))
        }
        (std::net::IpAddr::V6(cidr), std::net::IpAddr::V6(target)) => {
            let mask_value = if mask_bits == 0 {
                0u128
            } else if mask_bits >= 128 {
                !0u128
            } else {
                !0u128 << (128 - mask_bits)
            };
            Ok((u128::from(cidr) & mask_value) == (u128::from(target) & mask_value))
        }
        _ => Ok(false),
    }
}

pub fn validate_rule(rule: &Rule) -> Result<()> {
    if rule.name.trim().is_empty() {
        return Err(ServiceError::Validation("Rule name cannot be empty".to_string()));
    }

    // Validate IP address format if specified (supports CIDR notation, IPv4/IPv6)
    if let Some(ref addr) = rule.remote_addr {
        if addr.contains('/') {
            // CIDR notation
            validate_cidr(addr)?;
        } else if addr.parse::<std::net::IpAddr>().is_err() {
            return Err(ServiceError::Validation(format!(
                "Invalid IP address: {}",
                addr
            )));
        }
    }

    // 域名条件与 IP 地址互斥：两者同时设置的规则语义含糊（且驱动单条条目
    // 只有一个远端地址槽），创建/更新入口直接拒绝
    if rule.remote_domain.is_some() && rule.remote_addr.is_some() {
        return Err(ServiceError::Validation(
            "远程域名与远程地址互斥，同一条规则只能设置其中一个".to_string(),
        ));
    }

    // Validate remote domain format if specified
    if let Some(ref domain) = rule.remote_domain {
        if let Err(reason) = validate_domain(domain) {
            return Err(ServiceError::Validation(format!(
                "Invalid remote domain '{}': {}",
                domain, reason
            )));
        }
    }

    // Validate port range
    if let Some(ref port_range) = rule.remote_port {
        match port_range {
            // u16 本身就限制了端口上限，无需再与 65535 比较
            PortRange::Single(_) => {}
            PortRange::Range(start, end) => {
                if *start > *end {
                    return Err(ServiceError::Validation(format!(
                        "Invalid port range: {}-{}",
                        start, end
                    )));
                }
            }
        }
    }

    if let Some(ref port_range) = rule.local_port {
        match port_range {
            // u16 本身就限制了端口上限，无需再与 65535 比较
            PortRange::Single(_) => {}
            PortRange::Range(start, end) => {
                if *start > *end {
                    return Err(ServiceError::Validation(format!(
                        "Invalid port range: {}-{}",
                        start, end
                    )));
                }
            }
        }
    }

    // Validate subnet mask（前缀位数）：能解析出地址族时按族收紧上限
    // （IPv4 → 32，IPv6 → 128）。此前统一放宽到 128，IPv4 规则携带 mask>32
    // 能入库，但下发时 converter 按族校验失败，一条坏规则会拖垮整批加载。
    // CIDR 形式的 prefix 已由 validate_cidr 按族校验，这里只管显式 mask；
    // remote_addr 为空/不可解析时无族信息，保持 128 宽松上限（无地址不会
    // 生成掩码下发，converter 侧到不了）
    if let Some(mask) = rule.remote_addr_mask {
        let max = rule
            .remote_addr
            .as_deref()
            .map(|addr| addr.split('/').next().unwrap_or(addr))
            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
            .map(|ip| match ip {
                std::net::IpAddr::V4(_) => 32u8,
                std::net::IpAddr::V6(_) => 128u8,
            })
            .unwrap_or(128u8);
        if mask > max {
            return Err(ServiceError::Validation(format!(
                "Subnet mask out of range: {} (max {} for this address family)",
                mask, max
            )));
        }
    }

    // Validate process path if specified
    if let Some(ref path) = rule.process_path {
        if !is_valid_path(path) {
            return Err(ServiceError::Validation(format!(
                "Invalid process path: {}",
                path
            )));
        }
        // 驱动侧 MAX_PATH_LENGTH=260（含结尾 NUL）：converter 下发超过 259 个
        // UTF-16 字符的路径会被截断，截断后的后缀匹配 needle 永不命中——
        // Block 规则对超长路径进程静默失效。创建/更新入口直接拒绝。
        if path.encode_utf16().count() >= 260 {
            return Err(ServiceError::Validation(format!(
                "进程路径过长：{} 个 UTF-16 字符（上限 259，超出会被驱动截断导致规则永不匹配）",
                path.encode_utf16().count()
            )));
        }
    }

    // local_addr/local_addr_mask 复用 remote 侧同样的 IP/CIDR 格式校验（坏值
    // 给出与 remote 一致的错误），随后一律拒绝：驱动 ABI（DriverRuleInput）
    // 没有本地地址字段，带值规则到不了内核、实际按"任意本地地址"匹配，
    // 属静默放大放行面。DB 里的历史行不走本校验，不受影响。
    if let Some(ref addr) = rule.local_addr {
        if addr.contains('/') {
            validate_cidr(addr)?;
        } else if addr.parse::<std::net::IpAddr>().is_err() {
            return Err(ServiceError::Validation(format!(
                "Invalid local IP address: {}",
                addr
            )));
        }
    }
    if let Some(mask) = rule.local_addr_mask {
        let max = rule
            .local_addr
            .as_deref()
            .map(|addr| addr.split('/').next().unwrap_or(addr))
            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
            .map(|ip| match ip {
                std::net::IpAddr::V4(_) => 32u8,
                std::net::IpAddr::V6(_) => 128u8,
            })
            .unwrap_or(128u8);
        if mask > max {
            return Err(ServiceError::Validation(format!(
                "Local subnet mask out of range: {} (max {} for this address family)",
                mask, max
            )));
        }
    }
    if rule.local_addr.is_some() || rule.local_addr_mask.is_some() {
        return Err(ServiceError::Validation(
            "本地地址匹配暂不支持，请使用远程地址条件".to_string(),
        ));
    }

    Ok(())
}

fn is_valid_path(path: &str) -> bool {
    // Basic path validation
    !path.trim().is_empty()
        && (path.contains('\\') || path.contains('/') || path.starts_with(".\\"))
}

/// 校验域名匹配条件的格式：精确域名或前导 "*." 通配（仅此一种通配形式）。
/// 大小写不敏感（匹配侧统一转小写比较），这里只做语法检查。
/// 返回 Err(reason) 表示非法，原因供 IPC 错误信息拼接。
pub fn validate_domain(domain: &str) -> std::result::Result<(), String> {
    let d = domain.trim();
    if d.is_empty() {
        return Err("域名为空".to_string());
    }
    if d != domain {
        return Err("域名首尾不能有空白".to_string());
    }
    if d.len() > 253 {
        return Err("域名超过 253 字符上限".to_string());
    }

    // 仅支持前导 "*." 通配：剥掉后按普通域名校验；单独 "*"、"a*"、"*.a.*" 一律非法
    let host = match d.strip_prefix("*.").and_then(|rest| {
        // "*" 只能整体作为首标签："*a.com"、"*."（rest 为空）都不合法
        if rest.is_empty() || rest.contains('*') {
            None
        } else {
            Some(rest)
        }
    }) {
        Some(rest) => rest,
        None => {
            if d.contains('*') {
                return Err("通配只支持前导 \"*.\" 一种写法".to_string());
            }
            d
        }
    };

    for label in host.split('.') {
        if label.is_empty() {
            return Err("出现空标签（连续点或首尾点）".to_string());
        }
        if label.len() > 63 {
            return Err(format!("标签 '{}' 超过 63 字符", label));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!("标签 '{}' 含非法字符（仅允许字母/数字/连字符）", label));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("标签 '{}' 不能以连字符开头或结尾", label));
        }
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule() -> Rule {
        Rule {
            id: None,
            name: "test".to_string(),
            description: String::new(),
            enabled: true,
            priority: 100,
            action: RuleAction::Block,
            direction: Direction::Outbound,
            protocol: None,
            process_id: None,
            process_path: None,
            remote_addr: None,
            remote_addr_mask: None,
            remote_domain: None,
            remote_port: None,
            local_addr: None,
            local_addr_mask: None,
            local_port: None,
            network_zone: None,
            app_group_id: None,
            created_at: None,
            updated_at: None,
        }
    }

    /// remote_domain 与 remote_addr 互斥；域名格式非法（通配位置/字符/标签）被拒
    #[test]
    fn remote_domain_validation() {
        let mut r = base_rule();

        // 合法：精确域名 / 前导通配 / 大写输入
        r.remote_domain = Some("a.example.com".to_string());
        assert!(validate_rule(&r).is_ok());
        r.remote_domain = Some("*.example.com".to_string());
        assert!(validate_rule(&r).is_ok());
        r.remote_domain = Some("Example.COM".to_string());
        assert!(validate_rule(&r).is_ok());
        r.remote_domain = Some("localhost".to_string());
        assert!(validate_rule(&r).is_ok(), "single-label exact match is allowed");

        // 互斥：与 remote_addr 同时设置被拒
        r.remote_addr = Some("10.0.0.1".to_string());
        r.remote_domain = Some("a.example.com".to_string());
        assert!(validate_rule(&r).is_err());
        r.remote_addr = None;

        // 通配只支持前导 "*."
        for bad in ["*", "a*.com", "a.*.com", "*example.com", "*.", "a.b*"] {
            r.remote_domain = Some(bad.to_string());
            assert!(validate_rule(&r).is_err(), "'{}' must be rejected", bad);
        }

        // 字符/标签非法
        for bad in ["a b.com", "a..b", ".a.com", "a.com.", "-a.com", "a-.com", "a_b.com"] {
            r.remote_domain = Some(bad.to_string());
            assert!(validate_rule(&r).is_err(), "'{}' must be rejected", bad);
        }

        // 空白 / 超长
        r.remote_domain = Some("  ".to_string());
        assert!(validate_rule(&r).is_err());
        r.remote_domain = Some(format!("{}.com", "a".repeat(260)));
        assert!(validate_rule(&r).is_err());

        // 清空后恢复正常
        r.remote_domain = None;
        assert!(validate_rule(&r).is_ok());
    }

    /// local_addr 三项（addr/mask）带值即拒绝：驱动 ABI 无该字段，历史行为
    /// 是静默按"任意本地地址"匹配。校验顺序保证坏 IP 值同样报 Validation。
    #[test]
    fn local_addr_fields_are_rejected() {
        let mut r = base_rule();
        r.local_addr = Some("10.0.0.5".to_string());
        assert!(validate_rule(&r).is_err());

        r.local_addr = Some("not-an-ip".to_string());
        assert!(validate_rule(&r).is_err());

        r.local_addr = Some("10.0.0.5".to_string());
        r.local_addr_mask = Some(24);
        assert!(validate_rule(&r).is_err());

        r.local_addr = None;
        r.local_addr_mask = Some(24);
        assert!(validate_rule(&r).is_err());

        // 只有 remote 侧条件时正常通过
        r.local_addr_mask = None;
        r.remote_addr = Some("192.168.1.0/24".to_string());
        assert!(validate_rule(&r).is_ok());
    }

    /// 进程路径超过驱动 MAX_PATH_LENGTH-1（259 个 UTF-16 字符）时拒绝：
    /// converter 下发会截断，截断 needle 使后缀匹配永不命中（Block 静默失效）
    #[test]
    fn overlong_process_path_is_rejected() {
        let mut r = base_rule();
        r.process_path = Some(format!(r"C:\{}", "a".repeat(256)));
        assert_eq!(r.process_path.as_ref().unwrap().encode_utf16().count(), 259);
        assert!(validate_rule(&r).is_ok(), "259 chars (the max) must pass");

        r.process_path = Some(format!(r"C:\{}", "a".repeat(257)));
        assert!(validate_rule(&r).is_err(), "260 chars must be rejected");
    }
}
