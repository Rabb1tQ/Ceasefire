//! Connection Decision Manager implementation

use super::super::error::Result;
use super::super::models::*;
use super::super::database::Database;
use std::sync::Arc;

pub struct ConnectionDecisionManager {
    db: Arc<Database>,
}

impl ConnectionDecisionManager {
    pub fn new(db: Arc<Database>) -> Self {
        ConnectionDecisionManager { db }
    }

    /// Record a connection decision
    pub async fn record_decision(&self, decision: &ConnectionDecision) -> Result<()> {
        self.db.create_connection_decision(decision).await?;
        tracing::info!("Recorded connection decision: {:?} for process {}", 
            decision.decision, decision.process_path);
        Ok(())
    }

    /// Get a decision for a specific connection
    /// 事件热路径：走 DB 侧带 WHERE 的精确查询（remote_addr + remote_port +
    /// process_name，过期行已在 SQL 里排除，走 idx_decisions_conn_match 索引），
    /// 不再拉全表在 Rust 里逐条过滤。matches_connection / is_expired 保留为
    /// 防御性核对（语义与 SQL 完全一致）。
    pub async fn get_decision(&self, connection: &ConnectionInfo) -> Result<Option<ConnectionDecision>> {
        let decisions = self.db
            .find_connection_decisions(
                &connection.remote_addr,
                connection.remote_port,
                connection.process_name.as_deref(),
            )
            .await?;

        for decision in decisions {
            if decision.is_expired() {
                continue;
            }

            if self.matches_connection(&decision, connection) {
                return Ok(Some(decision));
            }
        }

        Ok(None)
    }

    /// Check if a decision matches a connection
    fn matches_connection(&self, decision: &ConnectionDecision, connection: &ConnectionInfo) -> bool {
        // Check process name (ConnectionInfo only has process_name)
        if let Some(ref rule_name) = decision.process_name {
            if connection.process_name.as_ref().map(|n| n.as_str()) != Some(rule_name.as_str()) {
                return false;
            }
        }

        // Check remote address
        let rule_addr = &decision.remote_addr;
        if connection.remote_addr != *rule_addr {
            return false;
        }

        // Check remote port
        if connection.remote_port != decision.remote_port {
            return false;
        }

        true
    }

    /// List all decisions
    pub async fn list_decisions(&self) -> Result<Vec<ConnectionDecision>> {
        self.db.list_connection_decisions().await
    }

    /// Delete a decision
    pub async fn delete_decision(&self, id: u32) -> Result<()> {
        self.db.delete_connection_decision(id).await?;
        tracing::info!("Deleted connection decision: {}", id);
        Ok(())
    }

    /// Clear expired decisions
    /// 单条 SQL DELETE（created_at 为 NULL 或超过一天的行），不再拉全表逐条删。
    pub async fn clear_expired_decisions(&self) -> Result<u32> {
        let deleted_count = self.db.delete_expired_connection_decisions().await?;

        if deleted_count > 0 {
            tracing::info!("Cleared {} expired connection decisions", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Clear all decisions for a process
    /// 单条 SQL DELETE WHERE process_path，不再拉全表逐条删。
    pub async fn clear_process_decisions(&self, process_path: &str) -> Result<u32> {
        let deleted_count = self.db.delete_process_decisions(process_path).await?;

        if deleted_count > 0 {
            tracing::info!("Cleared {} decisions for process {}", deleted_count, process_path);
        }

        Ok(deleted_count)
    }
}