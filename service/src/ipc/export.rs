//! Network history export (CSV / JSON).
//!
//! 只保留网络历史导出；旧的日志导出（export_to_csv/export_to_json，
//! 基于 LogQuery/query_logs）没有任何调用者，已随死代码一并删除。

use super::super::database::Database;
use super::super::error::Result;
use super::super::models::{ExportFormat, HistoryFilters, RuleAction};

/// 最简 CSV 字段转义：含逗号/引号/换行/回车的字段整体加引号，内部引号翻倍。
fn csv_field(field: impl std::fmt::Display) -> String {
    let s = field.to_string();
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Export network history records matching the filters.
pub async fn export_network_history(
    db: &Database,
    filters: &HistoryFilters,
    format: ExportFormat,
) -> Result<Vec<u8>> {
    let records = db.get_network_history(filters).await?;

    match format {
        ExportFormat::Csv => {
            let mut out = String::from(
                "timestamp,action,local_addr,local_port,remote_addr,remote_port,protocol,direction,process_id,process_name,bytes_sent,bytes_received\r\n",
            );
            for r in &records {
                // process_name 等字符串列可能含逗号/引号/换行，需按 csv_field 转义；
                // 地址/协议/方向等列内容受校验器约束，但一并转义无害且防御性更好。
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\r\n",
                    csv_field(&r.timestamp),
                    csv_field(match r.action { RuleAction::Allow => "Allow", RuleAction::Block => "Block" }),
                    csv_field(&r.local_addr),
                    csv_field(r.local_port),
                    csv_field(&r.remote_addr),
                    csv_field(r.remote_port),
                    csv_field(&r.protocol),
                    csv_field(&r.direction),
                    csv_field(r.process_id.map(|p| p.to_string()).unwrap_or_default()),
                    csv_field(r.process_name.as_deref().unwrap_or("")),
                    csv_field(r.bytes_sent),
                    csv_field(r.bytes_received),
                ));
            }
            Ok(out.into_bytes())
        }
        ExportFormat::Json => {
            let json = serde_json::to_vec_pretty(&records)
                .map_err(|e| super::super::error::ServiceError::Service(format!("JSON 序列化失败: {}", e)))?;
            Ok(json)
        }
    }
}
