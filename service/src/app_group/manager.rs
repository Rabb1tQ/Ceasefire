//! Application Group Manager implementation

use super::super::error::{Result, ServiceError};
use super::super::models::*;
use super::super::database::Database;
use super::super::connection::tracker::ConnectionTracker;
use std::sync::Arc;

pub struct AppGroupManager {
    db: Arc<Database>,
    tracker: Arc<ConnectionTracker>,
}

impl AppGroupManager {
    pub fn new(db: Arc<Database>, tracker: Arc<ConnectionTracker>) -> Self {
        AppGroupManager { db, tracker }
    }

    /// Create a new application group
    pub async fn create_group(&self, group: &AppGroup) -> Result<AppGroup> {
        let id = self.db.create_app_group(group).await?;
        let mut created_group = group.clone();
        created_group.id = Some(id);
        
        tracing::info!("Created application group: {}", group.name);
        Ok(created_group)
    }

    /// Update an application group
    pub async fn update_group(&self, id: u32, group: &AppGroup) -> Result<()> {
        self.db.update_app_group(id, group).await?;
        tracing::info!("Updated application group: {}", group.name);
        Ok(())
    }

    /// Delete an application group
    pub async fn delete_group(&self, id: u32) -> Result<()> {
        self.db.delete_app_group(id).await?;
        tracing::info!("Deleted application group: {}", id);
        Ok(())
    }

    /// Get an application group by ID
    pub async fn get_group(&self, id: u32) -> Result<Option<AppGroup>> {
        self.db.get_app_group(id).await
    }

    /// List all application groups
    pub async fn list_groups(&self) -> Result<Vec<AppGroup>> {
        self.db.list_app_groups().await
    }

    /// Add a process to an application group
    pub async fn add_member(&self, group_id: u32, process_path: &str, process_name: Option<String>) -> Result<()> {
        // 入口归一化（小写 + /→\，与带宽模块同口径）：不同拼写的同一路径
        // 必须落成同一行，is_member 也按同一口径比较
        let process_path = normalize_path(process_path);
        // Check if group exists
        let group = self.db.get_app_group(group_id).await?
            .ok_or_else(|| ServiceError::NotFound(format!("Application group {} not found", group_id)))?;

        if !group.enabled {
            return Err(ServiceError::Validation("Cannot add member to disabled group".to_string()));
        }

        self.db.add_group_member(group_id, &process_path, process_name).await?;
        tracing::info!("Added process {} to group {}", process_path, group_id);
        Ok(())
    }

    /// Remove a process from an application group
    pub async fn remove_member(&self, group_id: u32, process_path: &str) -> Result<()> {
        let process_path = normalize_path(process_path);
        self.db.remove_group_member(group_id, &process_path).await?;
        tracing::info!("Removed process {} from group {}", process_path, group_id);
        Ok(())
    }

    /// Get all members of an application group
    pub async fn get_members(&self, group_id: u32) -> Result<Vec<AppGroupMember>> {
        self.db.get_group_members(group_id).await
    }

    /// Check if a process belongs to an application group
    pub async fn is_member(&self, group_id: u32, process_path: &str) -> Result<bool> {
        let process_path = normalize_path(process_path);
        let members = self.get_members(group_id).await?;
        Ok(members.iter().any(|m| normalize_path(&m.process_path) == process_path))
    }

    /// Enable an application group
    pub async fn enable_group(&self, id: u32) -> Result<()> {
        let mut group = self.db.get_app_group(id).await?
            .ok_or_else(|| ServiceError::NotFound(format!("Application group {} not found", id)))?;

        if group.enabled {
            return Ok(());
        }

        group.enabled = true;
        self.db.update_app_group(id, &group).await?;
        tracing::info!("Enabled application group: {}", id);
        Ok(())
    }

    /// Disable an application group
    pub async fn disable_group(&self, id: u32) -> Result<()> {
        let mut group = self.db.get_app_group(id).await?
            .ok_or_else(|| ServiceError::NotFound(format!("Application group {} not found", id)))?;

        if !group.enabled {
            return Ok(());
        }

        group.enabled = false;
        self.db.update_app_group(id, &group).await?;
        tracing::info!("Disabled application group: {}", id);
        Ok(())
    }

    /// Get group statistics with actual traffic data
    pub async fn get_group_stats(&self, group_id: u32) -> Result<AppGroupStats> {
        let group = self.db.get_app_group(group_id).await?
            .ok_or_else(|| ServiceError::NotFound(format!("Application group {} not found", group_id)))?;

        let members = self.get_members(group_id).await?;
        
        // Get all active connections
        let connections = self.tracker.get_active_connections().await?;
        
        // Filter connections belonging to group members
        let group_connections: Vec<_> = connections.iter()
            .filter(|conn| {
                if let Some(process_name) = &conn.process_name {
                    members.iter().any(|m| {
                        if let Some(ref m_name) = m.process_name {
                            process_name.contains(m_name)
                        } else {
                            m.process_path.contains(process_name)
                        }
                    })
                } else {
                    false
                }
            })
            .collect();
        
        let active_connections = group_connections.len() as u32;
        let total_bytes_sent: u64 = group_connections.iter().map(|c| c.bytes_sent).sum();
        let total_bytes_received: u64 = group_connections.iter().map(|c| c.bytes_received).sum();
        
        Ok(AppGroupStats {
            group_id,
            group_name: group.name.clone(),
            active_connections,
            total_bytes_sent,
            total_bytes_received,
        })
    }

    /// Get all enabled groups
    pub async fn list_enabled_groups(&self) -> Result<Vec<AppGroup>> {
        let groups = self.list_groups().await?;
        Ok(groups.into_iter().filter(|g| g.enabled).collect())
    }

    /// Get groups for a process
    pub async fn get_groups_for_process(&self, process_path: &str) -> Result<Vec<AppGroup>> {
        let all_groups = self.list_groups().await?;
        let mut result = Vec::new();

        for group in all_groups {
            if group.enabled && self.is_member(group.id.unwrap_or(0), process_path).await? {
                result.push(group);
            }
        }

        Ok(result)
    }

    /// Initialize predefined application groups (async wrapper)
    ///
    /// 幂等同步：每次启动执行。组不存在才创建（绝不删组——规则可能引用
    /// group_id）；组成员同步为"模板展开 ∩ 实际存在"，并清理历史版本残留的
    /// 占位符垃圾成员（含 % 或 * 的路径）。GUI 允许向预置组手动加成员，
    /// 不在模板候选集里的成员一律不动，只管理模板来源的成员。
    pub async fn initialize_predefined(&self) -> Result<()> {
        let predefined = super::predefine::get_predefined_groups();
        let existing_groups = self.list_groups().await?;

        for group in predefined {
            let group_id = match existing_groups.iter().find(|g| g.name == group.name) {
                Some(existing) => existing.id,
                None => {
                    let mut new_group = group.clone();
                    new_group.is_predefined = true;
                    // create_group 返回带 id 的副本
                    self.create_group(&new_group).await?.id
                }
            };
            if let Some(group_id) = group_id {
                self.sync_predefined_members(group_id, &group.name).await;
            }
        }

        tracing::info!("Initialized predefined application groups");
        Ok(())
    }

    /// 把预置组成员同步为：模板展开 ∩ 存在。只动模板来源的成员：
    /// * 补齐：展开后真实存在但 DB 缺失的候选（新装程序）；
    /// * 移除：DB 里属于模板候选集但已不存在（卸载/模板改版）的成员，
    ///   以及历史版本直接落库的占位符路径（含 %USERNAME% 或 *，永不可能
    ///   匹配事件路径的死行）；
    /// * 手动成员（不在模板候选集）原样保留。
    async fn sync_predefined_members(&self, group_id: u32, group_name: &str) {
        use std::collections::HashSet;

        let templates = match super::predefine::get_predefined_members(group_name) {
            Some(t) => t,
            None => return,
        };

        // 展开（含不存在候选，作为"模板来源"判定集）+ 存在性过滤出期望集
        let mut candidates: HashSet<String> = HashSet::new();
        let mut desired: Vec<(String, String)> = Vec::new();
        for (template, name) in &templates {
            for path in super::predefine::expand_member_paths(template) {
                let normalized = normalize_path(&path.to_string_lossy());
                candidates.insert(normalized.clone());
                if path.exists() {
                    desired.push((normalized, name.clone()));
                }
            }
        }

        let members = match self.get_members(group_id).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Failed to list members of predefined group {}: {}", group_name, e);
                return;
            }
        };

        let mut removed = 0usize;
        for member in &members {
            let normalized = normalize_path(&member.process_path);
            let is_placeholder = member.process_path.contains('%') || member.process_path.contains('*');
            let is_stale_template = candidates.contains(&normalized)
                && !desired.iter().any(|(p, _)| *p == normalized);
            if is_placeholder || is_stale_template {
                if let Err(e) = self.db.remove_group_member(group_id, &normalized).await {
                    tracing::warn!("Failed to remove stale predefined member {} from {}: {}", normalized, group_name, e);
                    continue;
                }
                removed += 1;
            }
        }

        let mut added = 0usize;
        let member_paths: HashSet<String> = members
            .iter()
            .map(|m| normalize_path(&m.process_path))
            .collect();
        for (path, name) in &desired {
            // 移除循环里刚删掉的行不会出现在 member_paths 的原始快照里，
            // 但 desired 与 candidates 同源，被删行必然不在 desired（仅当
            // 同一路径既在快照又在 desired 时才可能重复 add，db 侧幂等兜底）
            if member_paths.contains(path) {
                continue;
            }
            if self.db.add_group_member(group_id, path, Some(name.clone())).await.is_ok() {
                added += 1;
            }
        }

        if removed > 0 || added > 0 {
            tracing::info!("Synced predefined group {}: +{} / -{} members", group_name, added, removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_manager(name: &str) -> (AppGroupManager, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("cf_app_group_test_{}.db", name));
        let _ = std::fs::remove_file(&path);
        let db = Arc::new(Database::open(path.to_str().unwrap()).expect("open db"));
        let tracker = Arc::new(ConnectionTracker::new());
        let mgr = AppGroupManager::new(db.clone(), tracker);
        (mgr, path)
    }

    fn test_group() -> AppGroup {
        AppGroup {
            id: None,
            name: "browsers".to_string(),
            description: String::new(),
            enabled: true,
            is_predefined: false,
            created_at: None,
            updated_at: None,
        }
    }

    /// 同一程序的两种路径拼法 add 后只落一行；is_member 大小写/斜杠方向
    /// 不敏感；remove 任一拼法都能删中归一化行。
    #[tokio::test]
    async fn member_paths_normalize_to_one_row() {
        let (mgr, path) = test_manager("norm").await;
        let group = mgr.create_group(&test_group()).await.unwrap();
        let gid = group.id.unwrap();

        mgr.add_member(gid, r"C:\A\b.exe", Some("b.exe".to_string())).await.unwrap();
        mgr.add_member(gid, "c:/a/B.exe", Some("b.exe".to_string())).await.unwrap();

        let members = mgr.get_members(gid).await.unwrap();
        assert_eq!(members.len(), 1, "two spellings must collapse to one row");
        assert_eq!(members[0].process_path, r"c:\a\b.exe", "stored normalized");

        assert!(mgr.is_member(gid, r"C:\A\B.EXE").await.unwrap());
        assert!(mgr.is_member(gid, "c:/a/b.exe").await.unwrap());
        assert!(!mgr.is_member(gid, r"C:\A\c.exe").await.unwrap());

        mgr.remove_member(gid, "C:/A/B.exe").await.unwrap();
        assert!(!mgr.is_member(gid, r"c:\a\b.exe").await.unwrap());

        let _ = std::fs::remove_file(&path);
    }

    /// 自定义分组全链路：create 落库带 id、update 改名/描述、enable/disable
    /// 翻转状态（幂等，重复设置不报错）。
    #[tokio::test]
    async fn create_update_enable_disable_roundtrip() {
        let (mgr, path) = test_manager("crud").await;

        let mut group = test_group();
        group.name = "My Tools".to_string();
        group.description = "user created".to_string();
        let created = mgr.create_group(&group).await.unwrap();
        let gid = created.id.expect("create returns id");
        assert!(!created.is_predefined);

        let mut fetched = mgr.get_group(gid).await.unwrap().unwrap();
        assert_eq!(fetched.name, "My Tools");

        fetched.name = "My Tools Renamed".to_string();
        fetched.description = "renamed".to_string();
        mgr.update_group(gid, &fetched).await.unwrap();
        let fetched = mgr.get_group(gid).await.unwrap().unwrap();
        assert_eq!(fetched.name, "My Tools Renamed");
        assert_eq!(fetched.description, "renamed");

        mgr.disable_group(gid).await.unwrap();
        assert!(!mgr.get_group(gid).await.unwrap().unwrap().enabled);
        // 幂等：重复 disable 不报错
        mgr.disable_group(gid).await.unwrap();
        mgr.enable_group(gid).await.unwrap();
        assert!(mgr.get_group(gid).await.unwrap().unwrap().enabled);
        mgr.enable_group(gid).await.unwrap();

        let _ = std::fs::remove_file(&path);
    }

    /// 删组必须级联清掉成员行（DB 未开 PRAGMA foreign_keys，
    /// 表上的 ON DELETE CASCADE 不生效，靠 delete_app_group 事务内显式删）。
    #[tokio::test]
    async fn delete_group_cascades_members() {
        let (mgr, path) = test_manager("cascade").await;
        let group = mgr.create_group(&test_group()).await.unwrap();
        let gid = group.id.unwrap();

        mgr.add_member(gid, r"C:\Tools\a.exe", Some("a.exe".to_string())).await.unwrap();
        mgr.add_member(gid, r"C:\Tools\b.exe", None).await.unwrap();
        assert_eq!(mgr.get_members(gid).await.unwrap().len(), 2);

        mgr.delete_group(gid).await.unwrap();
        assert!(mgr.get_group(gid).await.unwrap().is_none());
        assert!(mgr.get_members(gid).await.unwrap().is_empty(), "members must be cascade-deleted");

        let _ = std::fs::remove_file(&path);
    }

    /// 预置组初始化语义：只按名补缺失、不重复添加；用户删掉的预置组再跑
    /// 初始化能找回；裁撤组不再出现。
    #[tokio::test]
    async fn initialize_predefined_is_additive_and_recovers_deleted() {
        let (mgr, path) = test_manager("predef").await;

        mgr.initialize_predefined().await.unwrap();
        mgr.initialize_predefined().await.unwrap();
        let groups = mgr.list_groups().await.unwrap();
        let predefined: Vec<_> = super::super::predefine::get_predefined_groups();
        assert_eq!(groups.len(), predefined.len(), "no duplicates on re-init");
        for p in &predefined {
            assert!(groups.iter().any(|g| g.name == p.name && g.is_predefined), "{} missing", p.name);
        }
        assert!(!groups.iter().any(|g| g.name == "Chromium Browsers"));
        assert!(!groups.iter().any(|g| g.name == "File Sharing"));
        assert!(!groups.iter().any(|g| g.name == "Streaming"));

        // 用户删除预置组 → 初始化找回（只补缺失）
        let browsers = groups.iter().find(|g| g.name == "Browsers").unwrap();
        mgr.delete_group(browsers.id.unwrap()).await.unwrap();
        mgr.initialize_predefined().await.unwrap();
        let groups = mgr.list_groups().await.unwrap();
        assert!(groups.iter().any(|g| g.name == "Browsers" && g.is_predefined));
        assert_eq!(groups.len(), predefined.len());

        let _ = std::fs::remove_file(&path);
    }
}
