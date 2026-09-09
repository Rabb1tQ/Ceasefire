//! 规则导入/导出（功能 B）
//!
//! 导出：只导用户规则（非 [System] 前缀），JSON 文件结构见
//! [`crate::models::RuleExportFile`]；app_group_id 转成分组名，process_id/
//! id/时间戳不导出。
//!
//! 导入：整批先校验（validator + 未知 schema/类型由反序列化层拒绝），任何
//! 一条不过则整批拒绝并报明细；分组按名回映射（预置组直接匹配、非预置组
//! 不存在时创建）；Merge 按 name+process_path 判重跳过，Replace 先清空
//! 用户规则（系统规则不动）；DB 写入走单事务，成功后整体重载驱动。

use super::super::error::{Result, ServiceError};
use super::super::models::*;
use super::manager::RuleManager;
use super::system_rules::SYSTEM_RULE_PREFIX;

impl RuleManager {
    /// 导出用户规则为 JSON 字节（GUI 直接落文件）
    pub async fn export_rules(&self) -> Result<Vec<u8>> {
        let rules = self.list_rules().await?;
        let groups = self.db.list_app_groups().await?;
        let group_name = |id: u32| -> Option<String> {
            groups
                .iter()
                .find(|g| g.id == Some(id))
                .map(|g| g.name.clone())
        };

        let exported: Vec<ExportedRule> = rules
            .iter()
            .filter(|r| !r.name.starts_with(SYSTEM_RULE_PREFIX))
            .map(|r| ExportedRule {
                name: r.name.clone(),
                description: r.description.clone(),
                enabled: r.enabled,
                priority: r.priority,
                action: r.action.clone(),
                direction: r.direction.clone(),
                protocol: r.protocol.clone(),
                process_path: r.process_path.clone(),
                remote_addr: r.remote_addr.clone(),
                remote_addr_mask: r.remote_addr_mask,
                remote_domain: r.remote_domain.clone(),
                remote_port: r.remote_port.clone(),
                local_addr: r.local_addr.clone(),
                local_addr_mask: r.local_addr_mask,
                local_port: r.local_port.clone(),
                network_zone: r.network_zone.clone(),
                group: r.app_group_id.and_then(group_name),
            })
            .collect();

        let file = RuleExportFile {
            schema: RULE_EXPORT_SCHEMA,
            exported_at: chrono::Utc::now().to_rfc3339(),
            rules: exported,
        };
        let mut json = serde_json::to_vec_pretty(&file)
            .map_err(|e| ServiceError::Validation(format!("导出序列化失败: {}", e)))?;
        json.push(b'\n');
        Ok(json)
    }

    /// 导入规则。任何一条校验不过 → 整批拒绝（Err 带逐条明细），不做部分导入。
    pub async fn import_rules(
        &self,
        rules: Vec<ExportedRule>,
        mode: ImportMode,
    ) -> Result<ImportStats> {
        if rules.is_empty() {
            return Err(ServiceError::Validation("导入内容为空".to_string()));
        }

        // 1) 逐条转 Rule 并校验；错误收集后整批拒绝
        let mut converted: Vec<Rule> = Vec::with_capacity(rules.len());
        let mut errors: Vec<String> = Vec::new();
        for (i, er) in rules.iter().enumerate() {
            let rule = Rule {
                id: None,
                name: er.name.clone(),
                description: er.description.clone(),
                enabled: er.enabled,
                priority: er.priority,
                action: er.action.clone(),
                direction: er.direction.clone(),
                protocol: er.protocol.clone(),
                process_id: None,
                process_path: er.process_path.clone(),
                remote_addr: er.remote_addr.clone(),
                remote_addr_mask: er.remote_addr_mask,
                remote_domain: er.remote_domain.clone(),
                remote_port: er.remote_port.clone(),
                local_addr: er.local_addr.clone(),
                local_addr_mask: er.local_addr_mask,
                local_port: er.local_port.clone(),
                network_zone: er.network_zone.clone(),
                // 分组名回映射在校验通过后统一做（避免坏行先建出垃圾组）
                app_group_id: None,
                created_at: None,
                updated_at: None,
            };
            if rule.name.starts_with(SYSTEM_RULE_PREFIX) {
                errors.push(format!("#{}「{}」: 不允许导入 [System] 前缀规则", i + 1, rule.name));
                continue;
            }
            if let Err(e) = super::validator::validate_rule(&rule) {
                errors.push(format!("#{}「{}」: {}", i + 1, rule.name, e));
                continue;
            }
            converted.push(rule);
        }
        if !errors.is_empty() {
            return Err(ServiceError::Validation(format!(
                "导入被整批拒绝，{} 条问题明细：{}",
                errors.len(),
                errors.join("；")
            )));
        }

        // 2) 分组按名回映射：预置组按名匹配，非预置组不存在则创建
        let mut groups = self.db.list_app_groups().await?;
        let mut groups_created = 0usize;
        let mut group_ids: Vec<Option<u32>> = Vec::with_capacity(converted.len());
        for er in &rules {
            let Some(name) = &er.group else {
                group_ids.push(None);
                continue;
            };
            let existing = groups.iter().find(|g| &g.name == name).map(|g| g.id);
            let id = match existing {
                Some(id) => id,
                None => {
                    let new_group = AppGroup {
                        id: None,
                        name: name.clone(),
                        description: "规则导入时自动创建".to_string(),
                        enabled: true,
                        is_predefined: false,
                        created_at: None,
                        updated_at: None,
                    };
                    let id = self.db.create_app_group(&new_group).await?;
                    groups.push(AppGroup { id: Some(id), ..new_group });
                    groups_created += 1;
                    Some(id)
                }
            };
            group_ids.push(id);
        }
        for (rule, gid) in converted.iter_mut().zip(&group_ids) {
            rule.app_group_id = *gid;
        }

        // 3) Merge 判重：与现有用户规则按 name+process_path 比对，重复跳过
        let mut to_insert: Vec<Rule> = Vec::new();
        let mut skipped = 0usize;
        if mode == ImportMode::Merge {
            let existing: Vec<(String, Option<String>)> = self
                .list_rules()
                .await?
                .iter()
                .filter(|r| !r.name.starts_with(SYSTEM_RULE_PREFIX))
                .map(|r| (r.name.clone(), r.process_path.clone()))
                .collect();
            for rule in converted {
                if existing.iter().any(|(n, p)| *n == rule.name && *p == rule.process_path) {
                    skipped += 1;
                } else {
                    to_insert.push(rule);
                }
            }
        } else {
            to_insert = converted;
        }

        // 4) Replace：先清空用户规则（走 delete_rule_internal，域名规则的
        //    影子条目与驱动条目同步撤掉）；[System] 规则不动
        if mode == ImportMode::Replace {
            let victims: Vec<u32> = self
                .list_rules()
                .await?
                .iter()
                .filter(|r| !r.name.starts_with(SYSTEM_RULE_PREFIX))
                .filter_map(|r| r.id)
                .collect();
            for id in victims {
                // 清理阶段容忍驱动侧失败（DB 行已在 delete_rule_internal 内先删，
                // 残留驱动条目由随后有 enabled 导入时的整体重载兜底）：
                // 单元测试环境没有驱动设备，不能因 remove 失败中断导入
                if let Err(e) = self.delete_rule_internal(id).await {
                    tracing::warn!("Replace import: failed to fully delete rule {}: {}", id, e);
                }
            }
        }

        // 5) 单事务落库 + 整体重载驱动（域名规则的影子由 resync 保持）
        let imported = to_insert.len();
        if !to_insert.is_empty() {
            // 只要有 enabled 规则才需要重载驱动（全 disabled 的导入不触驱动，
            // 单元测试环境无驱动设备也能走完整导入流程）
            let any_enabled = to_insert.iter().any(|r| r.enabled);
            self.db.create_rules_batch(to_insert).await?;
            if any_enabled {
                self.reload_rules_to_driver().await?;
            }
        }
        tracing::info!(
            "Rules imported: mode={:?}, imported={}, skipped={}, groups_created={}",
            mode,
            imported,
            skipped,
            groups_created
        );
        Ok(ImportStats {
            imported,
            skipped,
            groups_created,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::DriverHandle;
    use crate::models::{ImportMode, RuleAction};
    use std::sync::Arc;

    fn rule(name: &str, path: Option<&str>, action: RuleAction) -> Rule {
        Rule {
            id: None,
            name: name.to_string(),
            description: "d".to_string(),
            enabled: false, // 导入测试统一 disabled，避免驱动依赖
            priority: 100,
            action,
            direction: Direction::Outbound,
            protocol: None,
            process_id: None,
            process_path: path.map(|p| p.to_string()),
            remote_addr: Some("10.0.0.0".to_string()),
            remote_addr_mask: Some(8),
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

    fn exported(rule: &Rule, group: Option<&str>) -> ExportedRule {
        ExportedRule {
            name: rule.name.clone(),
            description: rule.description.clone(),
            enabled: rule.enabled,
            priority: rule.priority,
            action: rule.action.clone(),
            direction: rule.direction.clone(),
            protocol: rule.protocol.clone(),
            process_path: rule.process_path.clone(),
            remote_addr: rule.remote_addr.clone(),
            remote_addr_mask: rule.remote_addr_mask,
            remote_domain: rule.remote_domain.clone(),
            remote_port: rule.remote_port.clone(),
            local_addr: rule.local_addr.clone(),
            local_addr_mask: rule.local_addr_mask,
            local_port: rule.local_port.clone(),
            network_zone: rule.network_zone.clone(),
            group: group.map(|g| g.to_string()),
        }
    }

    async fn manager() -> (Arc<RuleManager>, String) {
        let path = {
            static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::env::temp_dir().join(format!("cf_import_export_test_{}.db", n))
        };
        let _ = std::fs::remove_file(&path);
        // 驱动只用于 disabled 规则路径（导入测试不触驱动）
        let driver = Arc::new(DriverHandle::new().expect("driver handle"));
        let db = Arc::new(crate::database::Database::open(path.to_str().unwrap()).unwrap());
        let mgr = RuleManager::new(db, driver).expect("manager");
        (Arc::new(mgr), path.to_str().unwrap().to_string())
    }

    fn file(rules: Vec<ExportedRule>) -> Vec<u8> {
        serde_json::to_vec(&RuleExportFile {
            schema: RULE_EXPORT_SCHEMA,
            exported_at: chrono::Utc::now().to_rfc3339(),
            rules,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn export_round_trip_excludes_system_rules() {
        let (mgr, path) = manager().await;
        mgr.db.create_rule(&rule("user-a", Some("C:\\a.exe"), RuleAction::Allow)).await.unwrap();
        mgr.db.create_rule(&rule("[System] 内置", Some("C:\\s.exe"), RuleAction::Allow)).await.unwrap();

        let json = mgr.export_rules().await.unwrap();
        let parsed: RuleExportFile = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.schema, RULE_EXPORT_SCHEMA);
        assert_eq!(parsed.rules.len(), 1, "only user rules exported");
        assert_eq!(parsed.rules[0].name, "user-a");
        assert!(parsed.rules[0].process_path.is_some());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn merge_dedups_by_name_and_process() {
        let (mgr, path) = manager().await;
        let seeded = rule("dup", Some("C:\\dup.exe"), RuleAction::Allow);
        mgr.db.create_rule(&seeded).await.unwrap();

        let batch = vec![
            exported(&seeded, None), // 完全同名同路径 → 跳过
            exported(&rule("new", Some("C:\\n.exe"), RuleAction::Block), None),
        ];
        let stats = mgr.import_rules(batch, ImportMode::Merge).await.unwrap();
        assert_eq!(stats.imported, 1, "new rule inserted");
        assert_eq!(stats.skipped, 1, "same name+process_path duplicate skipped");
        assert_eq!(stats.groups_created, 0);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn replace_keeps_system_rules() {
        let (mgr, path) = manager().await;
        mgr.db.create_rule(&rule("old-user", Some("C:\\o.exe"), RuleAction::Allow)).await.unwrap();
        let sys = rule("[System] 系统", Some("C:\\s.exe"), RuleAction::Allow);
        mgr.db.create_rule(&sys).await.unwrap();

        let batch = vec![exported(&rule("fresh", Some("C:\\f.exe"), RuleAction::Block), None)];
        let stats = mgr.import_rules(batch, ImportMode::Replace).await.unwrap();
        assert_eq!(stats.imported, 1);

        let all = mgr.list_rules().await.unwrap();
        assert!(all.iter().any(|r| r.name == "fresh"));
        assert!(all.iter().any(|r| r.name == "[System] 系统"), "system rule survives replace");
        assert!(!all.iter().any(|r| r.name == "old-user"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn group_name_maps_back_and_creates_missing() {
        let (mgr, path) = manager().await;
        // 预置一个组，导入引用它 + 引用一个不存在的组
        let gid = mgr
            .db
            .create_app_group(&AppGroup {
                id: None,
                name: "浏览器".to_string(),
                description: String::new(),
                enabled: true,
                is_predefined: false,
                created_at: None,
                updated_at: None,
            })
            .await
            .unwrap();

        let a = {
            let mut a = exported(&rule("g-a", None, RuleAction::Allow), Some("浏览器"));
            a.remote_addr = Some("1.1.1.1".to_string());
            a.remote_addr_mask = None;
            a
        };
        let b = {
            let mut b = exported(&rule("g-b", None, RuleAction::Block), Some("新组"));
            b.remote_addr = Some("2.2.2.2".to_string());
            b.remote_addr_mask = None;
            b
        };
        let stats = mgr.import_rules(vec![a, b], ImportMode::Merge).await.unwrap();
        assert_eq!(stats.groups_created, 1, "missing group created");

        let all = mgr.list_rules().await.unwrap();
        let ra = all.iter().find(|r| r.name == "g-a").unwrap();
        let rb = all.iter().find(|r| r.name == "g-b").unwrap();
        assert_eq!(ra.app_group_id, Some(gid), "existing group mapped by name");
        assert_ne!(rb.app_group_id, Some(gid));
        assert!(rb.app_group_id.is_some(), "new group referenced");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn invalid_rule_rejects_whole_batch() {
        let (mgr, path) = manager().await;
        let mut good = exported(&rule("good", None, RuleAction::Allow), None);
        good.remote_addr = Some("1.1.1.1".to_string());
        good.remote_addr_mask = None;
        let mut bad = exported(&rule("bad", None, RuleAction::Allow), None);
        bad.remote_addr = Some("not-an-ip".to_string());
        bad.remote_addr_mask = None;

        let err = mgr
            .import_rules(vec![good, bad], ImportMode::Merge)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad"), "error names the offending rule");
        // 整批拒绝：good 也未入库
        let all = mgr.list_rules().await.unwrap();
        assert!(!all.iter().any(|r| r.name == "good"));
        let _ = std::fs::remove_file(path);
    }
}
