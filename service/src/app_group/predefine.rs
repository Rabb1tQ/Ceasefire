//! Predefined Application Groups

use super::super::models::*;
use std::path::{Path, PathBuf};

/// 预置分组（6 组）。历史上还有 Chromium Browsers / File Sharing / Streaming
/// 三组，已裁撤：Chromium 成员本就是 Browsers 的子集并入后者；后两者成员
/// 各只有 2 个，需要的用户自建即可。旧库里已初始化的裁撤组不做迁移删除
///（预置组允许用户在 UI 里删除，删掉 initialize_predefined 也不会再补回）。
pub fn get_predefined_groups() -> Vec<AppGroup> {
    vec![
        AppGroup {
            id: None,
            name: "Browsers".to_string(),
            description: "All web browsers (Firefox, IE, Chrome, Edge, Opera, Vivaldi)".to_string(),
            enabled: true,
            is_predefined: true,
            created_at: None,
            updated_at: None,
        },
        AppGroup {
            id: None,
            name: "IM Clients".to_string(),
            description: "Instant messaging and chat applications".to_string(),
            enabled: true,
            is_predefined: true,
            created_at: None,
            updated_at: None,
        },
        AppGroup {
            id: None,
            name: "Email Clients".to_string(),
            description: "Email and messaging clients".to_string(),
            enabled: true,
            is_predefined: true,
            created_at: None,
            updated_at: None,
        },
        AppGroup {
            id: None,
            name: "Gaming".to_string(),
            description: "Gaming platforms and launchers".to_string(),
            enabled: true,
            is_predefined: true,
            created_at: None,
            updated_at: None,
        },
        AppGroup {
            id: None,
            name: "Development".to_string(),
            description: "Development tools and IDEs".to_string(),
            enabled: true,
            is_predefined: true,
            created_at: None,
            updated_at: None,
        },
        AppGroup {
            id: None,
            name: "System Services".to_string(),
            description: "Windows system services and background processes".to_string(),
            enabled: true,
            is_predefined: true,
            created_at: None,
            updated_at: None,
        },
    ]
}

/// Get predefined members for a group name
pub fn get_predefined_members(group_name: &str) -> Option<Vec<(String, String)>> {
    match group_name {
        "Browsers" => Some(vec![
            ("C:\\Program Files\\Mozilla Firefox\\firefox.exe".to_string(), "Firefox".to_string()),
            ("C:\\Program Files\\Internet Explorer\\iexplore.exe".to_string(), "Internet Explorer".to_string()),
            ("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe".to_string(), "Internet Explorer".to_string()),
            ("C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe".to_string(), "Microsoft Edge".to_string()),
            ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe".to_string(), "Microsoft Edge".to_string()),
            ("C:\\Users\\%USERNAME%\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe".to_string(), "Google Chrome".to_string()),
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string(), "Google Chrome".to_string()),
            ("C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe".to_string(), "Google Chrome".to_string()),
            ("C:\\Program Files\\Opera\\launcher.exe".to_string(), "Opera".to_string()),
            ("C:\\Program Files (x86)\\Opera\\launcher.exe".to_string(), "Opera".to_string()),
            ("C:\\Program Files\\Vivaldi\\Application\\vivaldi.exe".to_string(), "Vivaldi".to_string()),
        ]),
        "Email Clients" => Some(vec![
            ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE".to_string(), "Microsoft Outlook".to_string()),
            ("C:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe".to_string(), "Thunderbird".to_string()),
            ("C:\\Program Files (x86)\\Mozilla Thunderbird\\thunderbird.exe".to_string(), "Thunderbird".to_string()),
        ]),
        "IM Clients" => Some(vec![
            // Discord 实际安装布局是 %LOCALAPPDATA%\Discord\app-<版本>\Discord.exe
            // 两级目录，通配段由 expand_member_paths 在启动时按实际目录展开
            ("C:\\Users\\%USERNAME%\\AppData\\Local\\Discord\\app-*\\Discord.exe".to_string(), "Discord".to_string()),
            ("C:\\Program Files\\Telegram Desktop\\Telegram.exe".to_string(), "Telegram".to_string()),
            ("C:\\Program Files\\WhatsApp\\WhatsApp.exe".to_string(), "WhatsApp".to_string()),
            ("C:\\Program Files\\Slack\\slack.exe".to_string(), "Slack".to_string()),
            ("C:\\Program Files\\Zoom\\bin\\Zoom.exe".to_string(), "Zoom".to_string()),
            // 国内常见 IM：微信（新旧两种安装名）+ QQ（NT 版）
            ("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe".to_string(), "WeChat".to_string()),
            ("C:\\Program Files\\Tencent\\Weixin\\Weixin.exe".to_string(), "Weixin".to_string()),
            ("C:\\Program Files\\Tencent\\QQNT\\QQ.exe".to_string(), "QQ".to_string()),
        ]),
        "Gaming" => Some(vec![
            ("C:\\Program Files\\Epic Games\\Launcher\\Portal\\Binaries\\Win32\\EpicGamesLauncher.exe".to_string(), "Epic Games Launcher".to_string()),
            ("C:\\Program Files (x86)\\GOG Galaxy\\GalaxyClient.exe".to_string(), "GOG Galaxy".to_string()),
            ("C:\\Program Files (x86)\\Steam\\steam.exe".to_string(), "Steam".to_string()),
        ]),
        "Development" => Some(vec![
            ("C:\\Program Files\\Microsoft VS Code\\Code.exe".to_string(), "Visual Studio Code".to_string()),
            ("C:\\Program Files\\JetBrains\\IntelliJ IDEA Community Edition\\bin\\idea64.exe".to_string(), "IntelliJ IDEA".to_string()),
        ]),
        "System Services" => Some(vec![
            ("C:\\Windows\\System32\\svchost.exe".to_string(), "Service Host".to_string()),
            ("C:\\Windows\\System32\\services.exe".to_string(), "Services".to_string()),
        ]),
        _ => None,
    }
}

/// 展开模板路径中的两个动态段（read_dir 仅碰调用方给的目录）：
/// * `%USERNAME%` 段：枚举该位置前缀目录（如 C:\Users）下的实际用户目录
///   逐个替换——服务以 SYSTEM 运行读不到用户级 env，环境变量展开永远得到
///   SYSTEM 账号，用户级安装的程序因此永不匹配；
/// * 含 `*` 的段：read_dir 前缀目录，按星号前后缀匹配子项展开（单级通配，
///   覆盖 Discord `app-<版本>` 这类带版本号的目录）。
///
/// 返回全部候选（不做存在性过滤，调用方用 exists() 区分"应装未装"）。
pub fn expand_member_paths(template: &str) -> Vec<PathBuf> {
    use std::path::Component;

    // 通配段匹配：单个 '*'，前后缀精确比较（大小写不敏感，Windows 路径惯例）
    fn wildcard_match(name: &str, pattern: &str) -> bool {
        match pattern.split_once('*') {
            None => name.eq_ignore_ascii_case(pattern),
            Some((prefix, suffix)) => {
                if name.len() < prefix.len() + suffix.len() {
                    return false;
                }
                name.get(..prefix.len()).map(|s| s.eq_ignore_ascii_case(prefix)).unwrap_or(false)
                    && name.get(name.len() - suffix.len()..).map(|s| s.eq_ignore_ascii_case(suffix)).unwrap_or(false)
            }
        }
    }

    let mut current: Vec<PathBuf> = Vec::new();
    for comp in Path::new(template).components() {
        match comp {
            Component::Prefix(p) => {
                let prefix: PathBuf = p.as_os_str().into();
                if current.is_empty() {
                    current.push(prefix);
                } else {
                    for base in &mut current {
                        base.push(&prefix);
                    }
                }
            }
            Component::RootDir => {
                for base in &mut current {
                    base.push(std::path::MAIN_SEPARATOR.to_string());
                }
            }
            Component::Normal(seg) => {
                let seg = seg.to_string_lossy().to_string();
                let mut next: Vec<PathBuf> = Vec::new();
                if seg == "%USERNAME%" {
                    // 枚举前缀目录下的实际用户目录（只取目录，跳过打不开的）
                    for base in &current {
                        if let Ok(entries) = std::fs::read_dir(base) {
                            for entry in entries.flatten() {
                                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                    next.push(entry.path());
                                }
                            }
                        }
                    }
                } else if seg.contains('*') {
                    for base in &current {
                        if let Ok(entries) = std::fs::read_dir(base) {
                            for entry in entries.flatten() {
                                if wildcard_match(&entry.file_name().to_string_lossy(), &seg) {
                                    next.push(entry.path());
                                }
                            }
                        }
                    }
                } else {
                    for base in &current {
                        next.push(base.join(&seg));
                    }
                }
                current = next;
                if current.is_empty() {
                    return Vec::new();
                }
            }
            _ => {}
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tempdir 造假安装布局：建目录/写空文件
    fn mkdir(p: &Path) {
        std::fs::create_dir_all(p).unwrap();
    }
    fn touch_file(p: &Path) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, b"").unwrap();
    }

    #[test]
    fn username_segment_enumerates_actual_user_dirs() {
        let tmp = std::env::temp_dir().join(format!(
            "cf_predef_u_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        // 两个用户目录 + 一个同名文件（不是目录，必须被跳过）+ SYSTEM 式干扰
        mkdir(&tmp.join("Alice"));
        mkdir(&tmp.join("Bob"));
        touch_file(&tmp.join("NotAUser"));

        let template = format!(
            "{}\\%USERNAME%\\AppData\\Local\\Tool\\tool.exe",
            tmp.to_str().unwrap()
        );
        touch_file(&tmp.join("Alice\\AppData\\Local\\Tool\\tool.exe"));
        touch_file(&tmp.join("Bob\\AppData\\Local\\Tool\\tool.exe"));

        let mut got = expand_member_paths(&template);
        got.sort();
        assert_eq!(got.len(), 2, "one candidate per real user dir, got {:?}", got);
        assert!(got.iter().any(|p| p.to_string_lossy().contains("Alice")));
        assert!(got.iter().any(|p| p.to_string_lossy().contains("Bob")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn wildcard_segment_expands_versioned_dirs() {
        let tmp = std::env::temp_dir().join(format!(
            "cf_predef_w_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        // Discord 真实布局：app-<版本>\Discord.exe 两级目录
        touch_file(&tmp.join("app-1.0.1\\Discord.exe"));
        touch_file(&tmp.join("app-2.5.9\\Discord.exe"));
        // 不匹配通配的同级目录/文件
        touch_file(&tmp.join("other\\Discord.exe"));
        touch_file(&tmp.join("app-9.9\\Unrelated.exe"));

        let template = format!("{}\\app-*\\Discord.exe", tmp.to_str().unwrap());
        let mut got = expand_member_paths(&template);
        got.sort();
        // 通配按目录名匹配（app-1.0.1/2.5.9/9.9 命中，other 排除）；展开是
        // 纯候选集，最终文件是否存在由调用方 exists() 过滤（app-9.9 下实际
        // 是 Unrelated.exe，会在过滤阶段被剔除）
        assert_eq!(got.len(), 3, "wildcard matches by dir name, got {:?}", got);
        assert!(got.iter().all(|p| {
            let s = p.to_string_lossy();
            s.contains("app-1.0.1") || s.contains("app-2.5.9") || s.contains("app-9.9")
        }));
        assert!(got.iter().all(|p| p.ends_with("Discord.exe")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn plain_template_yields_single_candidate() {
        let got = expand_member_paths(r"C:\Program Files\App\tool.exe");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].to_string_lossy(), r"C:\Program Files\App\tool.exe");
    }

    #[test]
    fn unmatched_dynamic_segment_yields_empty() {
        // 前缀目录不存在时（read_dir 失败）候选为空而不是 panic
        let got = expand_member_paths(r"Z:\NoSuchVolume\%USERNAME%\app.exe");
        assert!(got.is_empty());
        let got = expand_member_paths(r"Z:\NoSuchVolume\app-*\app.exe");
        assert!(got.is_empty());
    }

    #[test]
    fn discord_template_now_two_level() {
        // 模板必须是 app-*\Discord.exe 两级结构（旧的单级 app-*.exe 永不命中）
        let members = get_predefined_members("IM Clients").unwrap();
        let discord = members.iter().find(|(p, _)| p.contains("Discord")).unwrap();
        assert!(discord.0.contains("app-*\\Discord.exe"), "got {}", discord.0);
    }
}
