//! Database - SQLite database management for Ceasefire Firewall Service

use super::error::{Result, ServiceError};
use super::models::*;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let db_dir = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(db_dir).map_err(|e| ServiceError::Database(e.to_string()))?;

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|e| ServiceError::Database(format!("Failed to open database: {}", e)))?;

        // Serialize access across threads and enable WAL so concurrent
        // readers and the writer do not immediately fail with SQLITE_BUSY.
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| ServiceError::Database(format!("Failed to set busy timeout: {}", e)))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| ServiceError::Database(format!("Failed to enable WAL: {}", e)))?;

        let db = Database { conn: Arc::new(Mutex::new(conn)) };
        db.init_schema()?;

        Ok(db)
    }

    /// 在 blocking 线程池上执行同步 SQLite 操作。rusqlite 连接由 std Mutex
    /// 包裹，WAL checkpoint / 迁移 / 批量写入可能占用连接数十毫秒以上，
    /// 直接在 async 上下文调用会卡住 tokio worker（多 worker 时表现为周期
    /// 性延迟尖刺）。所有 pub 查询/写入方法都经此包装；对外 async 签名不变。
    /// 锁竞争顺序不变：仍旧只有这一把 conn 锁。
    async fn run_blocking<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        match tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(|e| ServiceError::Database(e.to_string()))?;
            f(&conn)
        })
        .await
        {
            Ok(res) => res,
            Err(e) => Err(ServiceError::Database(format!("spawn_blocking join failed: {}", e))),
        }
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| ServiceError::Database(e.to_string()))?;
        conn.execute(
                "CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    priority INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    protocol TEXT,
                    process_id INTEGER,
                    process_path TEXT,
                    remote_addr TEXT,
                    remote_addr_mask INTEGER,
                    remote_port_start INTEGER,
                    remote_port_end INTEGER,
                    local_addr TEXT,
                    local_addr_mask INTEGER,
                    local_port_start INTEGER,
                    local_port_end INTEGER,
                    network_zone TEXT,
                    app_group_id INTEGER,
                    upload_limit INTEGER,
                    download_limit INTEGER,
                    bandwidth_enabled INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    remote_domain TEXT
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    local_addr TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    remote_addr TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    process_id INTEGER,
                    process_name TEXT,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    rule_id INTEGER
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    notifications_enabled INTEGER NOT NULL DEFAULT 1,
                    notification_level TEXT NOT NULL DEFAULT '\"BlockedOnly\"',
                    log_retention_days INTEGER NOT NULL DEFAULT 30,
                    auto_block_suspicious INTEGER NOT NULL DEFAULT 0,
                    ask_to_connect_enabled INTEGER NOT NULL DEFAULT 1,
                    remember_decisions INTEGER NOT NULL DEFAULT 1,
                    suspicious_alerts_enabled INTEGER NOT NULL DEFAULT 1,
                    global_bandwidth_limit_enabled INTEGER NOT NULL DEFAULT 0,
                    global_upload_limit_kbps INTEGER,
                    global_download_limit_kbps INTEGER
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "INSERT OR IGNORE INTO settings (id, notifications_enabled, notification_level, log_retention_days, 
                                                auto_block_suspicious, ask_to_connect_enabled, remember_decisions, 
                                                suspicious_alerts_enabled, global_bandwidth_limit_enabled) 
                 VALUES (1, 1, '\"BlockedOnly\"', 30, 0, 1, 1, 1, 0)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Migrate old notification_level values to JSON format
        conn.execute(
                "UPDATE settings SET notification_level = '\"' || notification_level || '\"' 
                 WHERE id = 1 AND notification_level NOT LIKE '\"%\"'",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // 默认策略 / 系统豁免规则开关：ALTER ADD COLUMN 幂等（重复列错误忽略）
        for col in ["default_allow INTEGER NOT NULL DEFAULT 1", "system_rules_enabled INTEGER NOT NULL DEFAULT 1", "protect_when_not_running INTEGER NOT NULL DEFAULT 0"] {
            let sql = format!("ALTER TABLE settings ADD COLUMN {}", col);
            if let Err(e) = conn.execute(&sql, []) {
                let msg = e.to_string();
                if !msg.contains("duplicate column") {
                    return Err(ServiceError::Database(msg));
                }
            }
        }


        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Migrate NULL bytes_sent and bytes_received to 0 for existing records
        conn.execute(
                "UPDATE logs SET bytes_sent = 0 WHERE bytes_sent IS NULL",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "UPDATE logs SET bytes_received = 0 WHERE bytes_received IS NULL",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Application groups table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS app_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    is_predefined INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // App group members table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS app_group_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER NOT NULL,
                    process_path TEXT NOT NULL,
                    process_name TEXT,
                    added_at TEXT NOT NULL,
                    FOREIGN KEY (group_id) REFERENCES app_groups(id) ON DELETE CASCADE,
                    UNIQUE(group_id, process_path)
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_group_members_path ON app_group_members(process_path)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Connection decisions table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS connection_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_path TEXT NOT NULL,
                    process_name TEXT,
                    remote_addr TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    decision TEXT NOT NULL CHECK(decision IN ('allow', 'block')),
                    remember INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_decisions_process ON connection_decisions(process_path)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_decisions_addr ON connection_decisions(remote_addr)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Suspicious rules table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS suspicious_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    conditions TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Process bandwidth limits table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS process_bandwidth_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_path TEXT NOT NULL,
                    process_name TEXT,
                    upload_limit_kbps INTEGER,
                    download_limit_kbps INTEGER,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(process_path)
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Traffic aggregations table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS traffic_aggregations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time_bucket TEXT NOT NULL,
                    granularity TEXT NOT NULL CHECK(granularity IN ('hour', 'day', 'week', 'month')),
                    process_name TEXT,
                    protocol TEXT,
                    country_code TEXT,
                    bytes_sent INTEGER NOT NULL,
                    bytes_received INTEGER NOT NULL,
                    connection_count INTEGER NOT NULL
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // Network history table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS network_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    local_addr TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    remote_addr TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    process_id INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    bytes_sent INTEGER NOT NULL DEFAULT 0,
                    bytes_received INTEGER NOT NULL DEFAULT 0,
                    rule_id INTEGER
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_network_history_timestamp ON network_history(timestamp)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_network_history_process_path ON network_history(process_path)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agg_time ON traffic_aggregations(time_bucket, granularity)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agg_process ON traffic_aggregations(process_name)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agg_country ON traffic_aggregations(country_code)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // GeoIP cache table
        conn.execute(
                "CREATE TABLE IF NOT EXISTS geo_cache (
                    ip TEXT PRIMARY KEY,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    region TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    cached_at TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_geo_country ON geo_cache(country_code)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        self.run_migrations(&conn)?;

        Ok(())
    }

    /// Schema/data migrations, gated by PRAGMA user_version.
    /// 新迁移按版本号递增追加：先比较版本，再在事务里改数据，最后写版本。
    fn run_migrations(&self, conn: &Connection) -> Result<()> {
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        if version < 1 {
            // v1: process_bandwidth_limits 主键路径归一化（小写 + /→\）。
            // 旧库里同一进程的多种写法可能存成多行；归并后重写，旧行删除。
            self.migrate_normalize_bandwidth_paths(conn)?;
        }

        if version < 2 {
            // v2: 热路径查询索引。
            // - connection_decisions：事件路径按 (remote_addr, remote_port, process_name)
            //   精确匹配（find_connection_decisions），此前的 idx_decisions_addr 单列
            //   索引对多列等值查询只能收敛第一列。
            // - network_history：get_remote_address_details / get_network_history 的
            //   remote_addr 等值过滤此前全表扫。
            // CREATE INDEX IF NOT EXISTS 天然幂等，重跑无害。
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_decisions_conn_match
                 ON connection_decisions(remote_addr, remote_port, process_name)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_network_history_remote_addr ON network_history(remote_addr)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;
        }

        if version < 3 {
            // v3: app_group_members 成员路径归一化（小写 + /→\）。旧库里同一
            // 程序的多种写法是两行；归并去重后重写，同组同 key 保留 added_at
            // 最新的一行。
            self.migrate_normalize_group_member_paths(conn)?;
        }

        if version < 3 {
            conn.pragma_update(None, "user_version", 3)
                .map_err(|e| ServiceError::Database(e.to_string()))?;
        }

        if version < 4 {
            // v4: rules 表加 remote_domain 列（域名规则，服务侧展开为影子
            // 规则下发，不持久化展开条目）。新库建表时已带该列，ALTER 报
            // duplicate column 属预期，静默忽略（与 settings 列迁移同口径）。
            if let Err(e) = conn.execute("ALTER TABLE rules ADD COLUMN remote_domain TEXT", []) {
                let msg = e.to_string();
                if !msg.contains("duplicate column") {
                    return Err(ServiceError::Database(msg));
                }
            }
            // Dashboard 图表聚合的热路径索引：时间+进程 复合（按应用堆叠
            // 时序按时间桶+进程分组）；remote_addr 单列索引 v2 已建。
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_network_history_ts_process
                 ON network_history(timestamp, process_path)",
                [],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;
            conn.pragma_update(None, "user_version", 4)
                .map_err(|e| ServiceError::Database(e.to_string()))?;
        }

        Ok(())
    }

    fn migrate_normalize_group_member_paths(&self, conn: &Connection) -> Result<()> {
        let rows: Vec<(i32, String, Option<String>, String)> = conn
            .prepare("SELECT group_id, process_path, process_name, added_at FROM app_group_members")
            .and_then(|mut stmt| {
                let mut rows = Vec::new();
                let mut it = stmt.query([])?;
                while let Some(row) = it.next()? {
                    rows.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
                }
                Ok(rows)
            })
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        // 归并到 (group_id, 归一化路径) key；同 key 多行时保留 added_at 最新的一条。
        let mut merged: std::collections::HashMap<(i32, String), (Option<String>, String)> =
            std::collections::HashMap::new();
        for (group_id, path, name, added_at) in rows {
            let key = (group_id, normalize_path(&path));
            let replace = merged
                .get(&key)
                .map(|prev| prev.1 <= added_at)
                .unwrap_or(true);
            if replace {
                merged.insert(key, (name, added_at));
            }
        }

        // 空表或全部已是规范写法也重写一遍（幂等），统一走同一代码路径。
        conn.execute_batch("BEGIN IMMEDIATE; DELETE FROM app_group_members;")
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        for ((group_id, key), (name, added_at)) in &merged {
            if let Err(e) = conn.execute(
                "INSERT INTO app_group_members (group_id, process_path, process_name, added_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![group_id, key, name, added_at],
            ) {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(ServiceError::Database(e.to_string()));
            }
        }

        conn.execute_batch("COMMIT;")
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        Ok(())
    }

    fn migrate_normalize_bandwidth_paths(&self, conn: &Connection) -> Result<()> {
        let rows: Vec<(String, Option<String>, Option<i64>, Option<i64>, i32, String, String)> =
            conn.prepare("SELECT process_path, process_name, upload_limit_kbps, download_limit_kbps, enabled, created_at, updated_at FROM process_bandwidth_limits")
                .and_then(|mut stmt| {
                    let mut rows = Vec::new();
                    let mut it = stmt.query([])?;
                    while let Some(row) = it.next()? {
                        rows.push((
                            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                            row.get::<_, String>(5)?, row.get::<_, String>(6)?,
                        ));
                    }
                    Ok(rows)
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?;

        // 归并到归一化 key；同 key 多行时保留 updated_at 最新的一条。
        let mut merged: std::collections::HashMap<String, (String, Option<String>, Option<i64>, Option<i64>, i32, String, String)> =
            std::collections::HashMap::new();
        for row in rows {
            let key = normalize_path(&row.0);
            let replace = merged
                .get(&key)
                .map(|prev| prev.6 <= row.6)
                .unwrap_or(true);
            if replace {
                merged.insert(key, row);
            }
        }

        // 空表或全部已是规范写法也重写一遍（幂等），统一走同一代码路径。
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             DELETE FROM process_bandwidth_limits;",
        )
        .map_err(|e| ServiceError::Database(e.to_string()))?;

        for (key, row) in &merged {
            if let Err(e) = conn.execute(
                "INSERT INTO process_bandwidth_limits
                 (process_path, process_name, upload_limit_kbps, download_limit_kbps, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![key, row.1, row.2, row.3, row.4, row.5, row.6],
            ) {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(ServiceError::Database(e.to_string()));
            }
        }

        conn.execute_batch("COMMIT;")
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn create_rule(&self, rule: &Rule) -> Result<u32> {
        let rule = rule.clone();
        let now = chrono::Utc::now().to_rfc3339();

        // Convert PortRange to start/end for storage
        let (remote_port_start, remote_port_end) = match &rule.remote_port {
            Some(PortRange::Single(p)) => (Some(*p as i32), None),
            Some(PortRange::Range(s, e)) => (Some(*s as i32), Some(*e as i32)),
            None => (None, None),
        };

        let (local_port_start, local_port_end) = match &rule.local_port {
            Some(PortRange::Single(p)) => (Some(*p as i32), None),
            Some(PortRange::Range(s, e)) => (Some(*s as i32), Some(*e as i32)),
            None => (None, None),
        };

        let network_zone_str = rule.network_zone.map(|nz| json_to_string(&nz));

        // 规则级带宽限速（DB 列保留但已死）：限速活功能走
        // process_bandwidth_limits（按进程），不再从 Rule 读取
        let upload_limit: Option<i64> = None;
        let download_limit: Option<i64> = None;
        let bandwidth_enabled: i32 = 0;

        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO rules (name, description, enabled, priority, action, direction, protocol,
                                   process_id, process_path, remote_addr, remote_addr_mask,
                                   remote_port_start, remote_port_end, local_addr, local_addr_mask,
                                   local_port_start, local_port_end, network_zone, app_group_id,
                                   upload_limit, download_limit, bandwidth_enabled, created_at, updated_at,
                                   remote_domain)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                         ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
                params![
                    rule.name,
                    rule.description,
                    rule.enabled as i32,
                    rule.priority,
                    json_to_string(&rule.action),
                    json_to_string(&rule.direction),
                    rule.protocol.as_ref().map(|p| json_to_string(&p)),
                    rule.process_id.map(|p| p as i32),
                    rule.process_path,
                    rule.remote_addr,
                    rule.remote_addr_mask.map(|m| m as i32),
                    remote_port_start,
                    remote_port_end,
                    rule.local_addr,
                    rule.local_addr_mask.map(|m| m as i32),
                    local_port_start,
                    local_port_end,
                    network_zone_str,
                    rule.app_group_id.map(|id| id as i32),
                    upload_limit,
                    download_limit,
                    bandwidth_enabled,
                    now,
                    now,
                    rule.remote_domain,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid() as u32)
        })
        .await
    }

    /// 批量插入规则：单事务完成（规则导入用），任一条失败整体回滚。
    /// 插入语义与 create_rule 完全一致（同列、同编码）。
    pub async fn create_rules_batch(&self, rules: Vec<Rule>) -> Result<Vec<u32>> {
        self.run_blocking(move |conn| {
            let now = chrono::Utc::now().to_rfc3339();
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let mut ids = Vec::with_capacity(rules.len());
            for rule in &rules {
                let (remote_port_start, remote_port_end) = match &rule.remote_port {
                    Some(PortRange::Single(p)) => (Some(*p as i32), None),
                    Some(PortRange::Range(s, e)) => (Some(*s as i32), Some(*e as i32)),
                    None => (None, None),
                };
                let (local_port_start, local_port_end) = match &rule.local_port {
                    Some(PortRange::Single(p)) => (Some(*p as i32), None),
                    Some(PortRange::Range(s, e)) => (Some(*s as i32), Some(*e as i32)),
                    None => (None, None),
                };
                let network_zone_str = rule.network_zone.map(|nz| json_to_string(&nz));
                tx.execute(
                    "INSERT INTO rules (name, description, enabled, priority, action, direction, protocol,
                                       process_id, process_path, remote_addr, remote_addr_mask,
                                       remote_port_start, remote_port_end, local_addr, local_addr_mask,
                                       local_port_start, local_port_end, network_zone, app_group_id,
                                       upload_limit, download_limit, bandwidth_enabled, created_at, updated_at,
                                       remote_domain)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                             ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
                    params![
                        rule.name,
                        rule.description,
                        rule.enabled as i32,
                        rule.priority,
                        json_to_string(&rule.action),
                        json_to_string(&rule.direction),
                        rule.protocol.as_ref().map(|p| json_to_string(&p)),
                        rule.process_id.map(|p| p as i32),
                        rule.process_path,
                        rule.remote_addr,
                        rule.remote_addr_mask.map(|m| m as i32),
                        remote_port_start,
                        remote_port_end,
                        rule.local_addr,
                        rule.local_addr_mask.map(|m| m as i32),
                        local_port_start,
                        local_port_end,
                        network_zone_str,
                        rule.app_group_id.map(|id| id as i32),
                        None::<i64>,
                        None::<i64>,
                        0,
                        now,
                        now,
                        rule.remote_domain,
                    ],
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
                ids.push(tx.last_insert_rowid() as u32);
            }
            tx.commit().map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(ids)
        })
        .await
    }

    pub async fn update_rule(&self, id: u32, rule: &Rule) -> Result<()> {
        let rule = rule.clone();
        let now = chrono::Utc::now().to_rfc3339();

        let (remote_port_start, remote_port_end) = match &rule.remote_port {
            Some(PortRange::Single(p)) => (Some(*p as i32), None),
            Some(PortRange::Range(s, e)) => (Some(*s as i32), Some(*e as i32)),
            None => (None, None),
        };

        let (local_port_start, local_port_end) = match &rule.local_port {
            Some(PortRange::Single(p)) => (Some(*p as i32), None),
            Some(PortRange::Range(s, e)) => (Some(*s as i32), Some(*e as i32)),
            None => (None, None),
        };

        let network_zone_str = rule.network_zone.map(|nz| json_to_string(&nz));

        // 规则级带宽限速（DB 列保留但已死）：限速活功能走
        // process_bandwidth_limits（按进程），不再从 Rule 读取
        let upload_limit: Option<i64> = None;
        let download_limit: Option<i64> = None;
        let bandwidth_enabled: i32 = 0;

        self.run_blocking(move |conn| {
            conn.execute(
                "UPDATE rules SET name = ?1, description = ?2, enabled = ?3, priority = ?4,
                                  action = ?5, direction = ?6, protocol = ?7, process_id = ?8,
                                  process_path = ?9, remote_addr = ?10, remote_addr_mask = ?11,
                                  remote_port_start = ?12, remote_port_end = ?13, local_addr = ?14,
                                  local_addr_mask = ?15, local_port_start = ?16, local_port_end = ?17,
                                  network_zone = ?18, app_group_id = ?19, upload_limit = ?20,
                                  download_limit = ?21, bandwidth_enabled = ?22, updated_at = ?23,
                                  remote_domain = ?24
                 WHERE id = ?25",
                params![
                    rule.name,
                    rule.description,
                    rule.enabled as i32,
                    rule.priority,
                    json_to_string(&rule.action),
                    json_to_string(&rule.direction),
                    rule.protocol.as_ref().map(|p| json_to_string(&p)),
                    rule.process_id.map(|p| p as i32),
                    rule.process_path,
                    rule.remote_addr,
                    rule.remote_addr_mask.map(|m| m as i32),
                    remote_port_start,
                    remote_port_end,
                    rule.local_addr,
                    rule.local_addr_mask.map(|m| m as i32),
                    local_port_start,
                    local_port_end,
                    network_zone_str,
                    rule.app_group_id.map(|id| id as i32),
                    upload_limit,
                    download_limit,
                    bandwidth_enabled,
                    now,
                    rule.remote_domain,
                    id,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    pub async fn delete_rule(&self, id: u32) -> Result<()> {
        self.run_blocking(move |conn| {
            conn.execute("DELETE FROM rules WHERE id = ?1", params![id])
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn get_rule(&self, id: u32) -> Result<Option<Rule>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM rules WHERE id = ?1")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let rule = stmt
                .query_row(params![id], rule_from_row)
                .optional()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(rule)
        })
        .await
    }

    pub async fn list_rules(&self) -> Result<Vec<Rule>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM rules ORDER BY priority, id")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let rules = stmt
                .query_map([], rule_from_row)
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(rules)
        })
        .await
    }

    /// 分页读取规则。secondary sort 必须带 id，否则同优先级行序不稳定、翻页会重复/漏行。
    /// search 非空时对 name / description / process_path 做 LIKE 模糊匹配：
    /// 依赖 SQLite LIKE 的默认语义——对 ASCII 字符不区分大小写
    /// （case_sensitive_like 编译选项默认 off），进程路径大小写写法差异不影响命中。
    pub async fn list_rules_page(&self, offset: u32, limit: u32, search: Option<String>) -> Result<RulePage> {
        self.run_blocking(move |conn| {
            let pattern = search
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| format!("%{s}%"));
            let (total, rules) = match &pattern {
                Some(p) => {
                    let cond = " WHERE (name LIKE ?1 OR description LIKE ?1 OR process_path LIKE ?1)";
                    let total: u64 = conn
                        .query_row(
                            &format!("SELECT COUNT(*) FROM rules{cond}"),
                            params![p],
                            |row| row.get(0),
                        )
                        .map_err(|e| ServiceError::Database(e.to_string()))?;
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT * FROM rules{cond} ORDER BY priority, id LIMIT ?2 OFFSET ?3"
                        ))
                        .map_err(|e| ServiceError::Database(e.to_string()))?;
                    let rules = stmt
                        .query_map(params![p, limit, offset], rule_from_row)
                        .map_err(|e| ServiceError::Database(e.to_string()))?
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(|e| ServiceError::Database(e.to_string()))?;
                    (total, rules)
                }
                None => {
                    let total: u64 = conn
                        .query_row("SELECT COUNT(*) FROM rules", [], |row| row.get(0))
                        .map_err(|e| ServiceError::Database(e.to_string()))?;
                    let mut stmt = conn
                        .prepare("SELECT * FROM rules ORDER BY priority, id LIMIT ?1 OFFSET ?2")
                        .map_err(|e| ServiceError::Database(e.to_string()))?;
                    let rules = stmt
                        .query_map(params![limit, offset], rule_from_row)
                        .map_err(|e| ServiceError::Database(e.to_string()))?
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(|e| ServiceError::Database(e.to_string()))?;
                    (total, rules)
                }
            };
            Ok(RulePage { total, rules })
        })
        .await
    }

    pub async fn add_log(&self, log: &LogEntry) -> Result<()> {
        let log = log.clone();
        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO logs (timestamp, action, local_addr, local_port, remote_addr, remote_port,
                                   protocol, direction, process_id, process_name, bytes_sent, 
                                   bytes_received, rule_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    log.timestamp.to_rfc3339(),
                    json_to_string(&log.action),
                    log.local_addr,
                    log.local_port,
                    log.remote_addr,
                    log.remote_port,
                    json_to_string(&log.protocol),
                    json_to_string(&log.direction),
                    log.process_id.map(|p| p as i32),
                    log.process_name,
                    log.bytes_sent.map(|b| b as i64),
                    log.bytes_received.map(|b| b as i64),
                    log.rule_id.map(|r| r as i32),
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    /// 批量落库：单事务插入一批日志。flush 路径每 100 条才触发一次，
    /// 逐条 add_log 意味着 100 次 spawn_blocking + 锁往返 + 独立 INSERT；
    /// 这里一个事务一次往返完成，顺序语义与逐条写入一致（事务内按顺序插入，
    /// 任一条失败整体回滚并向上报错，由调用方记录失败日志）。
    pub async fn add_logs_batch(&self, logs: &[LogEntry]) -> Result<()> {
        let logs = logs.to_vec();
        self.run_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            for log in &logs {
                tx.execute(
                    "INSERT INTO logs (timestamp, action, local_addr, local_port, remote_addr, remote_port,
                                       protocol, direction, process_id, process_name, bytes_sent,
                                       bytes_received, rule_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        log.timestamp.to_rfc3339(),
                        json_to_string(&log.action),
                        log.local_addr,
                        log.local_port,
                        log.remote_addr,
                        log.remote_port,
                        json_to_string(&log.protocol),
                        json_to_string(&log.direction),
                        log.process_id.map(|p| p as i32),
                        log.process_name,
                        log.bytes_sent.map(|b| b as i64),
                        log.bytes_received.map(|b| b as i64),
                        log.rule_id.map(|r| r as i32),
                    ],
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            }
            tx.commit().map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn get_settings(&self) -> Result<Settings> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM settings WHERE id = 1")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let settings = stmt
                .query_row([], |row| {
                    // 按列名读取：历史遗留列（notification_level/log_retention_days/
                    // auto_block_suspicious/suspicious_alerts_enabled）已从模型移除，不再读取
                    Ok(Settings {
                        notifications_enabled: row.get::<_, i32>("notifications_enabled")? != 0,
                        ask_to_connect_enabled: row.get::<_, Option<i32>>("ask_to_connect_enabled")?.unwrap_or(1) != 0,
                        remember_decisions: row.get::<_, Option<i32>>("remember_decisions")?.unwrap_or(1) != 0,
                        global_bandwidth_limit_enabled: row.get::<_, Option<i32>>("global_bandwidth_limit_enabled")?.unwrap_or(0) != 0,
                        global_upload_limit_kbps: row.get::<_, Option<i64>>("global_upload_limit_kbps")?.map(|l| l as u32),
                        global_download_limit_kbps: row.get::<_, Option<i64>>("global_download_limit_kbps")?.map(|l| l as u32),
                        default_allow: row.get::<_, Option<i32>>("default_allow")?.unwrap_or(1) != 0,
                        system_rules_enabled: row.get::<_, Option<i32>>("system_rules_enabled")?.unwrap_or(1) != 0,
                        protect_when_not_running: row.get::<_, Option<i32>>("protect_when_not_running")?.unwrap_or(0) != 0,
                    })
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(settings)
        })
        .await
    }

    pub async fn update_settings(&self, settings: &Settings) -> Result<()> {
        let settings = settings.clone();
        self.run_blocking(move |conn| {
            conn.execute(
                "UPDATE settings SET notifications_enabled = ?1,
                                      ask_to_connect_enabled = ?2, remember_decisions = ?3,
                                      global_bandwidth_limit_enabled = ?4,
                                      global_upload_limit_kbps = ?5, global_download_limit_kbps = ?6,
                                      default_allow = ?7, system_rules_enabled = ?8,
                                      protect_when_not_running = ?9
                 WHERE id = 1",
                params![
                    settings.notifications_enabled as i32,
                    settings.ask_to_connect_enabled as i32,
                    settings.remember_decisions as i32,
                    settings.global_bandwidth_limit_enabled as i32,
                    settings.global_upload_limit_kbps.map(|l| l as i64),
                    settings.global_download_limit_kbps.map(|l| l as i64),
                    settings.default_allow as i32,
                    settings.system_rules_enabled as i32,
                    settings.protect_when_not_running as i32,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    /// 读取日志保留天数。settings 表有 log_retention_days 列（默认 30），但
    /// Settings 模型已移除该字段，仅数据库清理任务使用，故单独按列读取。
    /// 0 = 永不清理，原样返回不做钳制；列不存在/未设置时由调用方按默认 30
    /// 处理（settings 建行时写默认 30）。
    pub async fn get_log_retention_days(&self) -> Result<u32> {
        self.run_blocking(move |conn| {
            let days: i64 = conn
                .query_row(
                    "SELECT log_retention_days FROM settings WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(if days < 0 { 0 } else { days as u32 })
        })
        .await
    }

    pub async fn cleanup_old_logs(&self, days: u32) -> Result<u32> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);

        self.run_blocking(move |conn| {
            let rows = conn.execute(
                "DELETE FROM logs WHERE timestamp < ?1",
                params![cutoff.to_rfc3339()],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(rows as u32)
        })
        .await
    }

    // ==================== Application Groups ====================

    pub async fn create_app_group(&self, group: &AppGroup) -> Result<u32> {
        let group = group.clone();
        let now = chrono::Utc::now().to_rfc3339();

        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO app_groups (name, description, enabled, is_predefined, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    group.name,
                    group.description,
                    group.enabled as i32,
                    group.is_predefined as i32,
                    now,
                    now,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid() as u32)
        })
        .await
    }

    pub async fn update_app_group(&self, id: u32, group: &AppGroup) -> Result<()> {
        let group = group.clone();
        let now = chrono::Utc::now().to_rfc3339();

        self.run_blocking(move |conn| {
            conn.execute(
                "UPDATE app_groups SET name = ?1, description = ?2, enabled = ?3, 
                                  is_predefined = ?4, updated_at = ?5 WHERE id = ?6",
                params![
                    group.name,
                    group.description,
                    group.enabled as i32,
                    group.is_predefined as i32,
                    now,
                    id,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    pub async fn delete_app_group(&self, id: u32) -> Result<()> {
        self.run_blocking(move |conn| {
            // 连接未开 PRAGMA foreign_keys，表上的 ON DELETE CASCADE 不生效，
            // 成员行必须显式清理；同事务内先删成员再删组，避免留下孤儿行
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let result = (|| -> std::result::Result<(), ServiceError> {
                conn.execute(
                    "DELETE FROM app_group_members WHERE group_id = ?1",
                    params![id],
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
                conn.execute("DELETE FROM app_groups WHERE id = ?1", params![id])
                    .map_err(|e| ServiceError::Database(e.to_string()))?;
                Ok(())
            })();
            match result {
                Ok(()) => conn
                    .execute_batch("COMMIT")
                    .map_err(|e| ServiceError::Database(e.to_string()))?,
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            }
            Ok(())
        })
        .await
    }

    pub async fn get_app_group(&self, id: u32) -> Result<Option<AppGroup>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM app_groups WHERE id = ?1")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let group = stmt
                .query_row(params![id], |row| {
                    Ok(AppGroup {
                        id: Some(row.get(0)?),
                        name: row.get(1)?,
                        description: row.get(2)?,
                        enabled: row.get::<_, i32>(3)? != 0,
                        is_predefined: row.get::<_, i32>(4)? != 0,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .optional()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(group)
        })
        .await
    }

    pub async fn list_app_groups(&self) -> Result<Vec<AppGroup>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM app_groups ORDER BY name")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let groups = stmt
                .query_map([], |row| {
                    Ok(AppGroup {
                        id: Some(row.get(0)?),
                        name: row.get(1)?,
                        description: row.get(2)?,
                        enabled: row.get::<_, i32>(3)? != 0,
                        is_predefined: row.get::<_, i32>(4)? != 0,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(groups)
        })
        .await
    }

    pub async fn add_group_member(&self, group_id: u32, process_path: &str, process_name: Option<String>) -> Result<()> {
        let process_path = process_path.to_string();
        let process_name = process_name;
        let now = chrono::Utc::now().to_rfc3339();

        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO app_group_members (group_id, process_path, process_name, added_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    group_id as i32,
                    process_path,
                    process_name,
                    now,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    pub async fn remove_group_member(&self, group_id: u32, process_path: &str) -> Result<()> {
        let process_path = process_path.to_string();
        self.run_blocking(move |conn| {
            conn.execute(
                "DELETE FROM app_group_members WHERE group_id = ?1 AND process_path = ?2",
                params![group_id as i32, process_path],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    pub async fn get_group_members(&self, group_id: u32) -> Result<Vec<AppGroupMember>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM app_group_members WHERE group_id = ?1 ORDER BY added_at")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let members = stmt
                .query_map(params![group_id as i32], |row| {
                    Ok(AppGroupMember {
                        id: Some(row.get(0)?),
                        group_id: row.get(1)?,
                        process_path: row.get(2)?,
                        process_name: row.get(3)?,
                        added_at: row.get(4)?,
                    })
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(members)
        })
        .await
    }

    // ==================== Connection Decisions ====================

    // ==================== Suspicious Rules ====================

    pub async fn create_suspicious_rule(&self, rule: &SuspiciousRule) -> Result<u32> {
        let rule = rule.clone();
        let now = chrono::Utc::now().to_rfc3339();

        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO suspicious_rules (name, description, enabled, conditions, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    rule.name,
                    rule.description,
                    rule.enabled as i32,
                    json_to_string(&rule.conditions),
                    now,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid() as u32)
        })
        .await
    }

    pub async fn update_suspicious_rule(&self, id: u32, rule: &SuspiciousRule) -> Result<()> {
        let rule = rule.clone();
        self.run_blocking(move |conn| {
            conn.execute(
                "UPDATE suspicious_rules SET name = ?1, description = ?2, enabled = ?3, 
                                  conditions = ?4 WHERE id = ?5",
                params![
                    rule.name,
                    rule.description,
                    rule.enabled as i32,
                    json_to_string(&rule.conditions),
                    id,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    pub async fn delete_suspicious_rule(&self, id: u32) -> Result<()> {
        self.run_blocking(move |conn| {
            conn.execute("DELETE FROM suspicious_rules WHERE id = ?1", params![id])
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn list_suspicious_rules(&self) -> Result<Vec<SuspiciousRule>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM suspicious_rules ORDER BY name")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let rules = stmt
                .query_map([], |row| {
                    let conditions_str: String = row.get(4)?;
                    let conditions = serde_json::from_str(&conditions_str)
                        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e)
                        ))?;
                    Ok(SuspiciousRule {
                        id: Some(row.get(0)?),
                        name: row.get(1)?,
                        description: row.get(2)?,
                        enabled: row.get::<_, i32>(3)? != 0,
                        conditions,
                        created_at: row.get(5)?,
                    })
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(rules)
        })
        .await
    }

    // ==================== Process Bandwidth Limits ====================

    pub async fn set_process_bandwidth_limit(&self, limit: &ProcessBandwidthLimit) -> Result<u32> {
        let limit = limit.clone();
        let now = chrono::Utc::now().to_rfc3339();

        self.run_blocking(move |conn| {
            // 主键按归一化写法落库，避免同一进程的不同写法存成多行
            let process_path = normalize_path(&limit.process_path);
            conn.execute(
                "INSERT OR REPLACE INTO process_bandwidth_limits
                 (process_path, process_name, upload_limit_kbps, download_limit_kbps, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    process_path,
                    limit.process_name,
                    limit.upload_limit_kbps.map(|l| l as i64),
                    limit.download_limit_kbps.map(|l| l as i64),
                    limit.enabled as i32,
                    now,
                    now,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid() as u32)
        })
        .await
    }

    pub async fn get_process_bandwidth_limit(&self, process_path: &str) -> Result<Option<ProcessBandwidthLimit>> {
        let process_path = normalize_path(process_path);
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM process_bandwidth_limits WHERE process_path = ?1")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let limit = stmt
                .query_row(params![process_path], |row| {
                    Ok(ProcessBandwidthLimit {
                        id: Some(row.get(0)?),
                        process_path: row.get(1)?,
                        process_name: row.get(2)?,
                        upload_limit_kbps: row.get::<_, Option<i64>>(3)?.map(|l| l as u32),
                        download_limit_kbps: row.get::<_, Option<i64>>(4)?.map(|l| l as u32),
                        enabled: row.get::<_, i32>(5)? != 0,
                        created_at: Some(row.get::<_, String>(6)?),
                        updated_at: Some(row.get::<_, String>(7)?),
                    })
                })
                .optional()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(limit)
        })
        .await
    }

    pub async fn list_process_bandwidth_limits(&self) -> Result<Vec<ProcessBandwidthLimit>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM process_bandwidth_limits ORDER BY process_path")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let limits = stmt
                .query_map([], |row| {
                    Ok(ProcessBandwidthLimit {
                        id: Some(row.get(0)?),
                        process_path: row.get(1)?,
                        process_name: row.get(2)?,
                        upload_limit_kbps: row.get::<_, Option<i64>>(3)?.map(|l| l as u32),
                        download_limit_kbps: row.get::<_, Option<i64>>(4)?.map(|l| l as u32),
                        enabled: row.get::<_, i32>(5)? != 0,
                        created_at: Some(row.get::<_, String>(6)?),
                        updated_at: Some(row.get::<_, String>(7)?),
                    })
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(limits)
        })
        .await
    }

    /// Returns the number of rows deleted; 0 means no matching entry existed.
    pub async fn delete_process_bandwidth_limit(&self, process_path: &str) -> Result<usize> {
        let process_path = normalize_path(process_path);
        self.run_blocking(move |conn| {
            conn.execute(
                "DELETE FROM process_bandwidth_limits WHERE process_path = ?1",
                params![process_path],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))
        })
        .await
    }

    // ==================== Traffic Aggregations ====================

    pub async fn create_traffic_aggregation(&self, agg: &TrafficAggregation) -> Result<u32> {
        let agg = agg.clone();
        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO traffic_aggregations 
                 (time_bucket, granularity, process_name, protocol, country_code, 
                  bytes_sent, bytes_received, connection_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    agg.timestamp.to_rfc3339(),
                    json_to_string(&agg.period),
                    agg.dimension_value,
                    match agg.dimension {
                        AggregationDimension::Global => None,
                        AggregationDimension::Application => Some(agg.dimension_value.clone()),
                        AggregationDimension::Protocol => agg.protocol.map(|p| json_to_string(&p)),
                        AggregationDimension::Country => Some(agg.dimension_value.clone()),
                    },
                    agg.bytes_sent as i64,
                    agg.bytes_received as i64,
                    agg.connection_count as i32,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid() as u32)
        })
        .await
    }

    pub async fn query_traffic_aggregations(&self, period: AggregationPeriod, start: chrono::DateTime<chrono::Utc>, end: chrono::DateTime<chrono::Utc>) -> Result<Vec<TrafficAggregation>> {
        let period = json_to_string(&period);
        let start = start.to_rfc3339();
        let end = end.to_rfc3339();
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare(
                    "SELECT * FROM traffic_aggregations 
                     WHERE granularity = ?1 AND time_bucket >= ?2 AND time_bucket <= ?3 
                     ORDER BY time_bucket")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let aggs = stmt
                .query_map(params![period, start, end], |row| {
                    let protocol_str: Option<String> = row.get(4)?;
                    let protocol = protocol_str.and_then(|s| serde_json::from_str(&s).ok());
                    
                    Ok(TrafficAggregation {
                        id: Some(row.get(0)?),
                        period: parse_json(&row.get::<_, String>(2)?),
                        timestamp: parse_dt(row.get::<_, String>(1)?),
                        dimension: AggregationDimension::Global, // Simplified
                        dimension_value: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                        protocol,
                        bytes_sent: row.get::<_, i64>(5)? as u64,
                        bytes_received: row.get::<_, i64>(6)? as u64,
                        connection_count: row.get::<_, i32>(7)? as u32,
                    })
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(aggs)
        })
        .await
    }

    // ==================== Network History ====================

    pub async fn create_network_history(&self, record: &NetworkHistoryRecord) -> Result<u32> {
        let record = record.clone();
        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO network_history (timestamp, action, local_addr, local_port, remote_addr, remote_port,
                                   protocol, direction, process_id, process_name, process_path, bytes_sent, 
                                   bytes_received, rule_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    &record.timestamp,
                    json_to_string(&record.action),
                    record.local_addr,
                    record.local_port,
                    record.remote_addr,
                    record.remote_port,
                    json_to_string(&record.protocol),
                    json_to_string(&record.direction),
                    record.process_id.map(|p| p as i32),
                    record.process_name,
                    record.process_path,
                    record.bytes_sent as i64,
                    record.bytes_received as i64,
                    record.rule_id.map(|r| r as i32),
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid() as u32)
        })
        .await
    }

    /// 批量插入网络历史（周期快照路径）：一个快照周期一条事务，
    /// 避免每条活跃连接一次 spawn_blocking + 锁往返。返回值只表达整体
    /// 成败（快照路径不使用自增 id），语义与逐条 create_network_history 一致。
    pub async fn create_network_history_batch(&self, records: &[NetworkHistoryRecord]) -> Result<()> {
        let records = records.to_vec();
        self.run_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            for record in &records {
                tx.execute(
                    "INSERT INTO network_history (timestamp, action, local_addr, local_port, remote_addr, remote_port,
                                       protocol, direction, process_id, process_name, process_path, bytes_sent,
                                       bytes_received, rule_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        &record.timestamp,
                        json_to_string(&record.action),
                        record.local_addr,
                        record.local_port,
                        record.remote_addr,
                        record.remote_port,
                        json_to_string(&record.protocol),
                        json_to_string(&record.direction),
                        record.process_id.map(|p| p as i32),
                        record.process_name,
                        record.process_path,
                        record.bytes_sent as i64,
                        record.bytes_received as i64,
                        record.rule_id.map(|r| r as i32),
                    ],
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            }
            tx.commit().map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(())
        })
        .await
    }

    /// 连接记录真实总数：与 get_network_history 同一套筛选条件做 COUNT(*)，
    /// 供 GUI 分页器显示准确"共 N 条"（此前靠前端估算，页码永远只多一页）。
    pub async fn count_network_history(&self, filters: &HistoryFilters) -> Result<u64> {
        let (where_sql, bind_values) = Self::build_history_where(filters);
        let sql = format!("SELECT COUNT(*) FROM network_history WHERE 1=1{}", where_sql);
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare(&sql)
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let params: Vec<_> = bind_values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let count: u64 = stmt
                .query_row(params.as_slice(), |row| row.get::<_, i64>(0))
                .map(|c| c.max(0) as u64)
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(count)
        })
        .await
    }

    /// HistoryFilters → WHERE 子句与绑定值。action/protocol/direction 是枚举
    /// 名字符串（wire 对称性见 models.rs HistoryFilters 注释），在此解析成枚举
    /// 后按 DB 侧存储格式（JSON 字符串）绑定；解析失败（脏值/旧调用方）按未
    /// 筛选处理，与 parse_json 对 DB 脏数据的宽容策略一致。
    fn build_history_where(filters: &HistoryFilters) -> (String, Vec<rusqlite::types::Value>) {
        let mut where_sql = String::new();
        let mut param_count = 0;
        let mut bind_values: Vec<rusqlite::types::Value> = Vec::new();

        let action_filter = match filters.action.as_deref() {
            Some("Allow") => Some(RuleAction::Allow),
            Some("Block") => Some(RuleAction::Block),
            _ => None,
        };
        let protocol_filter = match filters.protocol.as_deref() {
            Some("Tcp") => Some(Protocol::Tcp),
            Some("Udp") => Some(Protocol::Udp),
            Some("Icmp") => Some(Protocol::Icmp),
            Some("Icmpv6") => Some(Protocol::Icmpv6),
            Some("Any") => Some(Protocol::Any),
            _ => None,
        };
        let direction_filter = match filters.direction.as_deref() {
            Some("Inbound") => Some(Direction::Inbound),
            Some("Outbound") => Some(Direction::Outbound),
            Some("Both") => Some(Direction::Both),
            _ => None,
        };

        if let Some(hours) = filters.hours {
            let cutoff = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
            param_count += 1;
            where_sql.push_str(&format!(" AND timestamp >= ?{}", param_count));
            bind_values.push(rusqlite::types::Value::Text(cutoff.to_rfc3339().into()));
        }

        if let Some(action) = action_filter {
            param_count += 1;
            where_sql.push_str(&format!(" AND action = ?{}", param_count));
            bind_values.push(rusqlite::types::Value::Text(json_to_string(&action).into()));
        }

        if let Some(protocol) = protocol_filter {
            param_count += 1;
            where_sql.push_str(&format!(" AND protocol = ?{}", param_count));
            bind_values.push(rusqlite::types::Value::Text(json_to_string(&protocol).into()));
        }

        if let Some(ref process_path) = filters.process_path {
            param_count += 1;
            where_sql.push_str(&format!(" AND process_path = ?{}", param_count));
            bind_values.push(rusqlite::types::Value::Text(process_path.clone()));
        }

        if let Some(ref remote_addr) = filters.remote_addr {
            param_count += 1;
            where_sql.push_str(&format!(" AND remote_addr = ?{}", param_count));
            bind_values.push(rusqlite::types::Value::Text(remote_addr.clone()));
        }

        if let Some(direction) = direction_filter {
            param_count += 1;
            where_sql.push_str(&format!(" AND direction = ?{}", param_count));
            bind_values.push(rusqlite::types::Value::Text(json_to_string(&direction).into()));
        }

        (where_sql, bind_values)
    }

    pub async fn get_network_history(&self, filters: &HistoryFilters) -> Result<Vec<NetworkHistoryRecord>> {
        let (where_sql, bind_values) = Self::build_history_where(filters);
        let mut sql = format!("SELECT * FROM network_history WHERE 1=1{}", where_sql);

        // 服务端排序：sort_by 走白名单映射到列名（白名单外的值回退 timestamp），
        // sort_order 只接受 ascending/descending（默认 DESC），严禁拼接用户输入。
        // 默认（未指定）保持 timestamp DESC 不变。
        let order_column = match filters.sort_by.as_deref() {
            Some("bytes_sent") => "bytes_sent",
            Some("bytes_received") => "bytes_received",
            Some("remote_addr") => "remote_addr",
            Some("process_name") => "process_name",
            _ => "timestamp",
        };
        let order_dir = match filters.sort_order.as_deref() {
            Some("ascending") => "ASC",
            _ => "DESC",
        };
        sql.push_str(&format!(" ORDER BY {} {}", order_column, order_dir));

        if let Some(limit) = filters.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = filters.offset {
            // SQLite 语法要求 OFFSET 必须跟在 LIMIT 之后；无 LIMIT 时用
            // LIMIT -1（= 不限制行数）占位，否则 prepare 直接报错。
            if filters.limit.is_none() {
                sql.push_str(" LIMIT -1");
            }
            sql.push_str(&format!(" OFFSET {}", offset));
        }

        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare(&sql)
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let params: Vec<_> = bind_values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

            let records = stmt
                .query_map(params.as_slice(), |row| {
                    Ok(NetworkHistoryRecord {
                        id: Some(row.get(0)?),
                        timestamp: row.get::<_, String>(1)?,
                        action: parse_json(&row.get::<_, String>(2)?),
                        local_addr: row.get(3)?,
                        local_port: row.get(4)?,
                        remote_addr: row.get(5)?,
                        remote_port: row.get(6)?,
                        protocol: parse_json(&row.get::<_, String>(7)?),
                        direction: parse_json(&row.get::<_, String>(8)?),
                        process_id: row.get::<_, Option<i32>>(9)?.map(|p| p as u32),
                        process_name: row.get(10)?,
                        process_path: row.get(11)?,
                        bytes_sent: row.get::<_, Option<i64>>(12)?.unwrap_or(0) as u64,
                        bytes_received: row.get::<_, Option<i64>>(13)?.unwrap_or(0) as u64,
                        rule_id: row.get::<_, Option<i32>>(14)?.map(|r| r as u32),
                    })
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(records)
        })
        .await
    }

    // ---- 统计路径专用聚合查询 ----
    //
    // 这些查询为仪表盘统计服务，必须走数据库侧 SUM/GROUP BY，绝不能经过
    // get_network_history：后者受 HistoryFilters::default() 的 limit: Some(100)
    // 约束，统计会退化成"只看最新 100 行"。时间窗口过滤始终在 SQL 内完成
    // （timestamp >= cutoff），不把窗口外数据拉进内存。

    fn history_cutoff_rfc3339(hours: u32) -> String {
        (chrono::Utc::now() - chrono::Duration::hours(hours as i64)).to_rfc3339()
    }

    /// 按进程名聚合流量。SQLite 约定：查询中恰好有一个 max() 聚合时，
    /// 裸列（process_path / process_id）取自 MAX(timestamp) 命中的那一行，
    /// 因此 last_seen 对应的"最近一次进程 ID / 路径"在同一条查询里拿到。
    pub async fn aggregate_app_traffic(
        &self,
        hours: u32,
    ) -> Result<Vec<(Option<String>, Option<String>, Option<i32>, Option<String>, i64, i64, i64)>> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT COALESCE(process_name, ''), process_path, process_id,
                            MAX(timestamp) AS last_seen,
                            SUM(bytes_sent), SUM(bytes_received), COUNT(*)
                     FROM network_history
                     WHERE timestamp >= ?1
                     GROUP BY COALESCE(process_name, '')",
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff], |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i32>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    }

    /// 按协议聚合流量。protocol 列存 JSON 字符串（如 `"Tcp"`），原样返回给调用方解析。
    pub async fn aggregate_protocol_traffic(
        &self,
        hours: u32,
    ) -> Result<Vec<(String, i64, i64, i64)>> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT protocol, SUM(bytes_sent), SUM(bytes_received), COUNT(*)
                     FROM network_history
                     WHERE timestamp >= ?1
                     GROUP BY protocol",
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    }

    /// 按远端地址聚合流量。国家维度需要 GeoIP（数据库外），故先在 SQL 里把
    /// 几万条明细收敛成"每地址一行"，再由调用方做地址 → 国家映射。
    pub async fn aggregate_remote_traffic(
        &self,
        hours: u32,
    ) -> Result<Vec<(String, i64, i64, i64)>> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT remote_addr, SUM(bytes_sent), SUM(bytes_received), COUNT(*)
                     FROM network_history
                     WHERE timestamp >= ?1
                     GROUP BY remote_addr",
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    }

    /// 按时间桶聚合流量（趋势图）。`interval_seconds` 为桶宽（秒），桶键为
    /// UNIX 时间戳对桶宽取整，与调用方预填的零值桶键对齐。
    /// strftime('%s', ...) 由 SQLite 解析 RFC3339 时间戳，桶分组完全在数据库侧。
    pub async fn aggregate_trend_buckets(
        &self,
        hours: u32,
        interval_seconds: i64,
    ) -> Result<Vec<(i64, i64, i64, i64)>> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT (CAST(strftime('%s', timestamp) AS INTEGER) / ?2) * ?2 AS bucket,
                            SUM(bytes_sent), SUM(bytes_received), COUNT(*)
                     FROM network_history
                     WHERE timestamp >= ?1
                     GROUP BY bucket",
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff, interval_seconds], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    }

    /// 按应用堆叠流量时序：窗口内按 (时间桶, process_path) 聚合字节量，
    /// 供 Dashboard 堆叠面积图使用。返回 (bucket, process_path, process_name,
    /// bytes_sent, bytes_received)；process_name 取桶内 MAX（同一进程路径
    /// 名称应一致，MAX 仅作确定性选择）。v4 迁移的 (timestamp, process_path)
    /// 索引覆盖本查询的过滤前缀。
    pub async fn aggregate_app_timeline(
        &self,
        hours: u32,
        interval_seconds: i64,
    ) -> Result<Vec<(i64, String, Option<String>, i64, i64)>> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT (CAST(strftime('%s', timestamp) AS INTEGER) / ?2) * ?2 AS bucket,
                            process_path, MAX(process_name), SUM(bytes_sent), SUM(bytes_received)
                     FROM network_history
                     WHERE timestamp >= ?1 AND process_path IS NOT NULL
                     GROUP BY bucket, process_path
                     ORDER BY bucket",
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff, interval_seconds], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    }

    /// 放行/拦截趋势：窗口内按时间桶 + action 聚合。action 列存 JSON 字符串，
    /// 这里原样返回，由调用方拆分（与日志层同编码）。返回 (bucket, action,
    /// bytes_sent, bytes_received, count)。
    pub async fn aggregate_action_trend(
        &self,
        hours: u32,
        interval_seconds: i64,
    ) -> Result<Vec<(i64, String, i64, i64, i64)>> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT (CAST(strftime('%s', timestamp) AS INTEGER) / ?2) * ?2 AS bucket,
                            action, SUM(bytes_sent), SUM(bytes_received), COUNT(*)
                     FROM network_history
                     WHERE timestamp >= ?1
                     GROUP BY bucket, action
                     ORDER BY bucket",
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff, interval_seconds], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    }

    /// 目标主机排行：窗口内按 remote_addr 聚合，按总流量降序取前 limit 名。
    /// 返回 (remote_addr, bytes_sent, bytes_received, count)。
    pub async fn aggregate_top_hosts(
        &self,
        hours: u32,
        limit: u32,
    ) -> Result<Vec<(String, i64, i64, i64)>> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT remote_addr, SUM(bytes_sent), SUM(bytes_received), COUNT(*)
                     FROM network_history
                     WHERE timestamp >= ?1
                     GROUP BY remote_addr
                     ORDER BY SUM(bytes_sent) + SUM(bytes_received) DESC
                     LIMIT ?2",
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff, limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows)
        })
        .await
    }

    /// 窗口内历史流量的字节总量（不做任何分组），供全局统计使用。
    pub async fn get_history_traffic_totals(&self, hours: u32) -> Result<(u64, u64)> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        self.run_blocking(move |conn| {
            let (sent, received): (i64, i64) = conn
                .query_row(
                    "SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
                     FROM network_history WHERE timestamp >= ?1",
                    params![cutoff],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok((sent as u64, received as u64))
        })
        .await
    }

    /// 单个远端地址在窗口内的完整聚合（计数/字节/首末时间/协议与端口去重集合），
    /// 全部在 SQL 侧完成，不受 get_network_history 的 limit(100) 约束
    /// （否则单地址连接数超过列表上限时总量少计）。protocol 存 JSON 字符串、
    /// 端口为整数，均以 GROUP_CONCAT(DISTINCT ...) 的 CSV 返回给调用方拆分。
    /// 返回元组：(count, bytes_sent, bytes_received, first_seen, last_seen,
    /// protocols_csv, local_ports_csv, remote_ports_csv)；无记录时计数值为 0。
    pub async fn aggregate_remote_address_details(
        &self,
        remote_addr: &str,
        hours: u32,
    ) -> Result<(i64, i64, i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)> {
        let cutoff = Self::history_cutoff_rfc3339(hours);
        let remote_addr = remote_addr.to_string();
        self.run_blocking(move |conn| {
            let row = conn
                .query_row(
                    "SELECT COUNT(*),
                            COALESCE(SUM(bytes_sent), 0),
                            COALESCE(SUM(bytes_received), 0),
                            MIN(timestamp),
                            MAX(timestamp),
                            GROUP_CONCAT(DISTINCT protocol),
                            GROUP_CONCAT(DISTINCT local_port),
                            GROUP_CONCAT(DISTINCT remote_port)
                     FROM network_history
                     WHERE remote_addr = ?1 AND timestamp >= ?2",
                    params![remote_addr, cutoff],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                            row.get::<_, Option<String>>(7)?,
                        ))
                    },
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(row)
        })
        .await
    }

    pub async fn clear_old_network_history(&self, days: u32) -> Result<u32> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);

        self.run_blocking(move |conn| {
            let rows = conn.execute(
                "DELETE FROM network_history WHERE timestamp < ?1",
                params![cutoff.to_rfc3339()],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(rows as u32)
        })
        .await
    }

    // ==================== Connection Decisions ====================

    pub async fn create_connection_decision(&self, decision: &ConnectionDecision) -> Result<u32> {
        let decision = decision.clone();
        let now = chrono::Utc::now().to_rfc3339();

        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO connection_decisions (process_path, process_name, remote_addr, remote_port, 
                                              decision, remember, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    decision.process_path,
                    decision.process_name,
                    decision.remote_addr,
                    decision.remote_port as i32,
                    decision_action_to_str(decision.decision),
                    decision.remember as i32,
                    now,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid() as u32)
        })
        .await
    }

    pub async fn list_connection_decisions(&self) -> Result<Vec<ConnectionDecision>> {
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM connection_decisions ORDER BY created_at DESC")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let decisions = stmt
                .query_map([], row_to_decision)
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(decisions)
        })
        .await
    }

    /// 事件热路径的精确匹配查询：按 remote_addr + remote_port 等值过滤，
    /// 进程名语义与 ConnectionDecisionManager::matches_connection 一致——
    /// 决策的 process_name 为 NULL 时匹配任意进程，否则要求完全相等。
    /// 过期（created_at 早于一天前）的决策在 SQL 里直接排除；created_at 为
    /// NULL 的行按已过期处理（is_expired 同语义）。走 v2 迁移的
    /// idx_decisions_conn_match 索引，替代此前"拉全表再在 Rust 里过滤"。
    pub async fn find_connection_decisions(
        &self,
        remote_addr: &str,
        remote_port: u16,
        process_name: Option<&str>,
    ) -> Result<Vec<ConnectionDecision>> {
        let remote_addr = remote_addr.to_string();
        let process_name = process_name.map(|n| n.to_string());
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();

        self.run_blocking(move |conn| {
            let (sql, name_param) = match &process_name {
                Some(name) => (
                    "SELECT * FROM connection_decisions
                     WHERE remote_addr = ?1 AND remote_port = ?2
                       AND (process_name IS NULL OR process_name = ?4)
                       AND (created_at IS NULL OR created_at >= ?3)
                     ORDER BY created_at DESC",
                    Some(name.clone()),
                ),
                None => (
                    // ?4 恒为 NULL：占位符数量与 Some 分支一致（统一 4 参绑定），
                    // `?4 IS NULL` 恒真，不影响匹配语义
                    "SELECT * FROM connection_decisions
                     WHERE remote_addr = ?1 AND remote_port = ?2
                       AND process_name IS NULL
                       AND (created_at IS NULL OR created_at >= ?3)
                       AND ?4 IS NULL
                     ORDER BY created_at DESC",
                    None,
                ),
            };
            let mut stmt = conn.prepare(sql)
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let decisions = stmt
                .query_map(
                    params![remote_addr, remote_port as i32, cutoff, name_param],
                    row_to_decision,
                )
                .map_err(|e| ServiceError::Database(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(decisions)
        })
        .await
    }

    /// 一次性删除所有过期决策，返回删除条数。
    /// created_at 为 NULL 或早于一天前的行按已过期处理（is_expired 同语义）。
    pub async fn delete_expired_connection_decisions(&self) -> Result<u32> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        self.run_blocking(move |conn| {
            let rows = conn.execute(
                "DELETE FROM connection_decisions
                 WHERE created_at IS NULL OR created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows as u32)
        })
        .await
    }

    /// 删除某进程的全部决策，返回删除条数（替代"拉全表 + 逐条 DELETE"）。
    pub async fn delete_process_decisions(&self, process_path: &str) -> Result<u32> {
        let process_path = process_path.to_string();
        self.run_blocking(move |conn| {
            let rows = conn.execute(
                "DELETE FROM connection_decisions WHERE process_path = ?1",
                params![process_path],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(rows as u32)
        })
        .await
    }

    pub async fn delete_connection_decision(&self, id: u32) -> Result<()> {
        self.run_blocking(move |conn| {
            conn.execute("DELETE FROM connection_decisions WHERE id = ?1", params![id])
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(())
        })
        .await
    }

    // ==================== GeoIP Cache ====================

    pub async fn get_geo_location(&self, ip: &str) -> Result<Option<GeoLocation>> {
        let ip = ip.to_string();
        self.run_blocking(move |conn| {
            let mut stmt = conn.prepare("SELECT * FROM geo_cache WHERE ip = ?1")
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            let geo = stmt
                .query_row(params![ip], |row| {
                    Ok(GeoLocation {
                        ip: row.get(0)?,
                        country_code: row.get(1)?,
                        country_name: row.get(2)?,
                        region: row.get(3)?,
                        city: row.get(4)?,
                        latitude: row.get(5)?,
                        longitude: row.get(6)?,
                        cached_at: Some(parse_dt(row.get::<_, String>(7)?)),
                    })
                })
                .optional()
                .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(geo)
        })
        .await
    }

    pub async fn cache_geo_location(&self, geo: &GeoLocation) -> Result<()> {
        let geo = geo.clone();
        let now = chrono::Utc::now().to_rfc3339();

        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO geo_cache 
                 (ip, country_code, country_name, region, city, latitude, longitude, cached_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    geo.ip,
                    geo.country_code,
                    geo.country_name,
                    geo.region,
                    geo.city,
                    geo.latitude,
                    geo.longitude,
                    now,
                ],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(())
        })
        .await
    }

    /// 保存地理位置信息（别名）
    pub async fn save_geo_location(&self, geo: &GeoLocation) -> Result<()> {
        self.cache_geo_location(geo).await
    }

    /// 清理过期的GeoIP缓存
    pub async fn cleanup_old_geo_locations(&self, hours: i64) -> Result<u32> {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(hours);

        self.run_blocking(move |conn| {
            let rows = conn.execute(
                "DELETE FROM geo_cache WHERE cached_at < ?1",
                params![cutoff.to_rfc3339()],
            )
            .map_err(|e| ServiceError::Database(e.to_string()))?;

            Ok(rows as u32)
        })
        .await
    }

    /// 获取GeoIP缓存数量
    pub async fn get_geo_location_count(&self) -> Result<u32> {
        self.run_blocking(move |conn| {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM geo_cache", [], |row| row.get(0))
                .map_err(|e| ServiceError::Database(e.to_string()))?;
            Ok(count as u32)
        })
        .await
    }
}

/// connection_decisions 行 → ConnectionDecision 模型（列顺序与建表语句一致）。
/// list / find 两条查询共用，避免列索引解析逻辑漂移。
fn row_to_decision(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConnectionDecision> {
    Ok(ConnectionDecision {
        id: Some(row.get(0)?),
        process_path: row.get(1)?,
        process_name: row.get(2)?,
        remote_addr: row.get(3)?,
        remote_port: row.get::<_, i32>(4)? as u16,
        decision: parse_decision(&row.get::<_, String>(5)?),
        remember: row.get::<_, i32>(6)? != 0,
        created_at: row.get(7)?,
    })
}

// ==================== Tolerant serialization helpers ====================
// Corrupt or legacy values in a single column must never panic a service
// thread: these helpers log and fall back instead of unwrapping.

fn json_to_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| {
        tracing::error!("Failed to serialize value: {}", e);
        "\"\"".to_string()
    })
}

fn parse_json<T: serde::de::DeserializeOwned + Default>(s: &str) -> T {
    serde_json::from_str(s).unwrap_or_else(|e| {
        tracing::warn!("Corrupt value in database column ({}), using default", e);
        T::default()
    })
}

/// rules 表行 → Rule（列序依赖 SELECT *；get_rule / list_rules / list_rules_page 共用）
fn rule_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Rule> {
    // Convert port start/end to PortRange
    let remote_port_start: Option<i32> = row.get(12)?;
    let remote_port_end: Option<i32> = row.get(13)?;
    let remote_port = match (remote_port_start, remote_port_end) {
        (Some(start), Some(end)) => Some(PortRange::Range(start as u16, end as u16)),
        (Some(port), None) => Some(PortRange::Single(port as u16)),
        _ => None,
    };

    let local_port_start: Option<i32> = row.get(16)?;
    let local_port_end: Option<i32> = row.get(17)?;
    let local_port = match (local_port_start, local_port_end) {
        (Some(start), Some(end)) => Some(PortRange::Range(start as u16, end as u16)),
        (Some(port), None) => Some(PortRange::Single(port as u16)),
        _ => None,
    };

    // Parse network_zone from JSON
    let network_zone: Option<NetworkZone> = row.get::<_, Option<String>>(18)?
        .map(|s| parse_json(&s));

    // 规则级带宽列（20/21/22）保留在表中但不再读入 Rule（死字段已删）
    Ok(Rule {
        id: Some(row.get(0)?),
        name: row.get(1)?,
        description: row.get(2)?,
        enabled: row.get::<_, i32>(3)? != 0,
        priority: row.get(4)?,
        action: parse_json(&row.get::<_, String>(5)?),
        direction: parse_json(&row.get::<_, String>(6)?),
        protocol: row
            .get::<_, Option<String>>(7)?
            .map(|s| parse_json(&s)),
        process_id: row.get::<_, Option<i32>>(8)?.map(|p| p as u32),
        process_path: row.get(9)?,
        remote_addr: row.get(10)?,
        remote_addr_mask: row.get::<_, Option<i32>>(11)?.map(|m| m as u8),
        remote_port,
        local_addr: row.get(14)?,
        local_addr_mask: row.get::<_, Option<i32>>(15)?.map(|m| m as u8),
        local_port,
        network_zone,
        app_group_id: row.get::<_, Option<i32>>(19)?.map(|id| id as u32),
        created_at: row.get(23)?,
        updated_at: row.get(24)?,
        // v4 迁移追加列，稳定落在 SELECT * 的最后一列
        remote_domain: row.get(25)?,
    })
}

fn parse_dt(s: String) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(&s)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|e| {
            tracing::warn!("Corrupt timestamp '{}', using now: {}", s, e);
            chrono::Utc::now()
        })
}

/// Decision values are stored lowercase to satisfy the table CHECK constraint
/// (decision IN ('allow','block')); legacy rows may contain JSON-cased values.
fn decision_action_to_str(d: DecisionAction) -> &'static str {
    match d {
        DecisionAction::Allow => "allow",
        DecisionAction::Block => "block",
    }
}

fn parse_decision(s: &str) -> DecisionAction {
    match s.trim_matches('"').to_ascii_lowercase().as_str() {
        "allow" => DecisionAction::Allow,
        "block" => DecisionAction::Block,
        other => {
            tracing::warn!("Corrupt decision value '{}', using allow", other);
            DecisionAction::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bandwidth_limit_path_spellings_collapse_to_one_row() {
        let path = std::env::temp_dir().join("cf_bw_norm_test.db");
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let db = Database::open(&path_str).expect("open db");

        let a = ProcessBandwidthLimit {
            id: None,
            process_path: "C:/Program Files/App/APP.exe".to_string(),
            process_name: Some("app.exe".to_string()),
            upload_limit_kbps: Some(100),
            download_limit_kbps: None,
            enabled: true,
            created_at: None,
            updated_at: None,
        };
        let mut b = a.clone();
        b.process_path = r"c:\program files\app\app.exe".to_string();
        b.upload_limit_kbps = Some(200);

        db.set_process_bandwidth_limit(&a).await.unwrap();
        db.set_process_bandwidth_limit(&b).await.unwrap();

        let all = db.list_process_bandwidth_limits().await.unwrap();
        assert_eq!(all.len(), 1, "two spellings must collapse to one row");
        assert_eq!(all[0].process_path, r"c:\program files\app\app.exe");
        assert_eq!(all[0].upload_limit_kbps, Some(200), "later write wins");

        // 删除不存在的路径 → Ok(0)，调用方可据此区分"没删到"
        let removed = db
            .delete_process_bandwidth_limit(r"C:\NoSuch\App.exe")
            .await
            .unwrap();
        assert_eq!(removed, 0, "deleting a non-existent path reports 0 rows");
        assert_eq!(db.list_process_bandwidth_limits().await.unwrap().len(), 1);

        // 反斜杠原样写法删除后表清空（正/反斜杠两种 key 均可删中）
        let removed = db
            .delete_process_bandwidth_limit("C:/Program Files/App/APP.exe")
            .await
            .unwrap();
        assert_eq!(removed, 1, "alternate spelling must match the normalized row");
        assert!(db.list_process_bandwidth_limits().await.unwrap().is_empty());

        let _ = std::fs::remove_file(&path);
    }

    /// 统计聚合不受列表分页 limit(100) 影响：写 150 行窗口内记录，
    /// 各聚合入口的总量必须等于 150 行之和（修复前只会统计到最新 100 行）。
    #[tokio::test]
    async fn traffic_stats_aggregate_beyond_list_limit() {
        let path = std::env::temp_dir().join("cf_stats_agg_test.db");
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let db = Database::open(&path_str).expect("open db");

        let now = chrono::Utc::now();
        for i in 0..150 {
            let record = NetworkHistoryRecord {
                id: None,
                timestamp: (now - chrono::Duration::seconds(i)).to_rfc3339(),
                action: RuleAction::Allow,
                local_addr: "192.168.1.10".to_string(),
                local_port: 40000 + (i as u16),
                remote_addr: "93.184.216.34".to_string(),
                remote_port: 443,
                protocol: Protocol::Tcp,
                direction: Direction::Outbound,
                process_id: Some(1234),
                process_name: Some("app.exe".to_string()),
                process_path: Some(r"C:\Program Files\App\app.exe".to_string()),
                bytes_sent: 10,
                bytes_received: 20,
                rule_id: None,
            };
            db.create_network_history(&record).await.unwrap();
        }

        // 列表路径仍受默认 limit 约束（UI 分页语义不变，修复前提所在）
        let listed = db.get_network_history(&HistoryFilters::default()).await.unwrap();
        assert_eq!(listed.len(), 100, "list path keeps default limit");

        // 全量总量 = 150 行之和（1500, 3000）
        let (sent, received) = db.get_history_traffic_totals(24).await.unwrap();
        assert_eq!(sent, 1500);
        assert_eq!(received, 3000);

        // 按进程聚合：单组，总量与计数覆盖全部 150 行
        let apps = db.aggregate_app_traffic(24).await.unwrap();
        assert_eq!(apps.len(), 1);
        let app = &apps[0];
        assert_eq!(app.0.as_deref(), Some("app.exe"));
        assert_eq!(app.4, 1500);
        assert_eq!(app.5, 3000);
        assert_eq!(app.6, 150);
        assert!(app.3.is_some(), "last_seen must be present");
        assert_eq!(app.2, Some(1234), "process_id from newest row");

        // 按协议聚合：覆盖全部 150 行
        let protocols = db.aggregate_protocol_traffic(24).await.unwrap();
        assert_eq!(protocols.len(), 1);
        assert_eq!(protocols[0].1, 1500);
        assert_eq!(protocols[0].2, 3000);
        assert_eq!(protocols[0].3, 150);

        // 按远端地址聚合：覆盖全部 150 行
        let remotes = db.aggregate_remote_traffic(24).await.unwrap();
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].3, 150);

        // 单地址详情聚合：计数/字节覆盖全部 150 行（不再受列表 limit 少计）
        let (count, sent, received, first, last, protos, lports, rports) = db
            .aggregate_remote_address_details("93.184.216.34", 24)
            .await
            .unwrap();
        assert_eq!(count, 150);
        assert_eq!(sent, 1500);
        assert_eq!(received, 3000);
        assert!(first.is_some() && last.is_some());
        assert_eq!(protos.as_deref(), Some("\"Tcp\""));
        assert!(lports.as_deref().unwrap().contains("40000"));
        assert_eq!(rports.as_deref(), Some("443"));

        // 不存在的地址：全零、无首末时间
        let (count, sent, received, first, _, _, _, _) = db
            .aggregate_remote_address_details("10.9.9.9", 24)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!((sent, received), (0, 0));
        assert!(first.is_none());

        // 趋势按时间桶聚合：所有桶之和覆盖全部 150 行
        let buckets = db.aggregate_trend_buckets(24, 3600).await.unwrap();
        assert!(!buckets.is_empty());
        let total_count: i64 = buckets.iter().map(|b| b.3).sum();
        let total_sent: i64 = buckets.iter().map(|b| b.1).sum();
        let total_received: i64 = buckets.iter().map(|b| b.2).sum();
        assert_eq!(total_count, 150);
        assert_eq!(total_sent, 1500);
        assert_eq!(total_received, 3000);

        // 窗口过滤在 SQL 内：窗口外的旧记录不计入统计
        let old = NetworkHistoryRecord {
            id: None,
            timestamp: (now - chrono::Duration::days(2)).to_rfc3339(),
            action: RuleAction::Allow,
            local_addr: "192.168.1.10".to_string(),
            local_port: 40000,
            remote_addr: "93.184.216.34".to_string(),
            remote_port: 443,
            protocol: Protocol::Tcp,
            direction: Direction::Outbound,
            process_id: Some(1234),
            process_name: Some("app.exe".to_string()),
            process_path: Some(r"C:\Program Files\App\app.exe".to_string()),
            bytes_sent: 999999,
            bytes_received: 999999,
            rule_id: None,
        };
        db.create_network_history(&old).await.unwrap();
        let (sent, received) = db.get_history_traffic_totals(24).await.unwrap();
        assert_eq!(sent, 1500, "out-of-window rows must be filtered in SQL");
        assert_eq!(received, 3000);

        let _ = std::fs::remove_file(&path);
    }

    /// DB 方法在 blocking 线程池执行：即使连接被长时间占用（模拟慢事务 /
    /// WAL checkpoint），等待锁的 DB 调用不会卡住 executor——同 runtime 上的
    /// 其他 async 任务照常调度。修复前（async 里直接 lock）单 worker 会被
    /// 整个挂起，心跳任务无法推进。
    #[tokio::test]
    async fn db_blocking_does_not_stall_other_async_tasks() {
        let path = std::env::temp_dir().join("cf_db_blocking_test.db");
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let db = Database::open(&path_str).expect("open db");

        // 在 blocking 线程上占住连接 300ms（模拟事务里 sleep）
        let held = db.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = held.lock().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(guard);
        });
        // 让持有者先拿到锁，确保后续 DB 调用真的要等锁
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 心跳任务：DB 等锁期间必须持续推进（每个 tick 10ms，共 10 个）
        let heartbeat = tokio::spawn(async move {
            let mut ticks = 0u32;
            for _ in 0..10 {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                ticks += 1;
            }
            ticks
        });

        // DB 调用要等 250ms 左右的锁，但在 2 秒内必须完成且不阻塞心跳
        let listed = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            db.list_rules(),
        )
        .await
        .expect("db call must complete while the connection is briefly held")
        .expect("db call must succeed");

        assert!(listed.is_empty());
        let ticks = heartbeat.await.unwrap();
        assert_eq!(ticks, 10, "async heartbeat must keep ticking while DB waits on the lock");

        let _ = std::fs::remove_file(&path);
    }

    /// find_connection_decisions 的匹配语义：进程名 NULL 的决策匹配任意进程，
    /// 具名决策只匹配同名进程；过期决策不出现在结果里。
    #[tokio::test]
    async fn find_connection_decisions_matches_and_expires() {
        let path = std::env::temp_dir().join("cf_decisions_match_test.db");
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let db = Database::open(&path_str).expect("open db");

        let mk = |name: Option<&str>, addr: &str, port: u16, action: DecisionAction| ConnectionDecision {
            id: None,
            process_path: r"C:\apps\app.exe".to_string(),
            process_name: name.map(|n| n.to_string()),
            remote_addr: addr.to_string(),
            remote_port: port,
            decision: action,
            remember: true,
            created_at: None,
        };

        db.create_connection_decision(&mk(Some("app.exe"), "1.2.3.4", 443, DecisionAction::Allow)).await.unwrap();
        db.create_connection_decision(&mk(None, "1.2.3.4", 443, DecisionAction::Block)).await.unwrap();
        db.create_connection_decision(&mk(Some("other.exe"), "1.2.3.4", 443, DecisionAction::Block)).await.unwrap();
        db.create_connection_decision(&mk(Some("app.exe"), "1.2.3.4", 8443, DecisionAction::Block)).await.unwrap();

        // 具名进程：NULL-name + 同名决策命中；异名/异端口不命中
        let hits = db.find_connection_decisions("1.2.3.4", 443, Some("app.exe")).await.unwrap();
        assert_eq!(hits.len(), 2, "NULL-name and exact-name decisions match");

        // 无进程名的事件：只有 NULL-name 决策命中
        let hits = db.find_connection_decisions("1.2.3.4", 443, None).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].process_name.is_none());

        // 完全不匹配的地址
        assert!(db.find_connection_decisions("5.6.7.8", 443, Some("app.exe")).await.unwrap().is_empty());

        // 过期清理：手工把一条决策改成两天前，delete_expired 应删掉它
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE connection_decisions SET created_at = ?1 WHERE process_name IS NULL",
                params![(chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339()],
            )
            .unwrap();
        }
        let removed = db.delete_expired_connection_decisions().await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(db.list_connection_decisions().await.unwrap().len(), 3);

        // 按进程清理
        let removed = db.delete_process_decisions(r"C:\apps\app.exe").await.unwrap();
        assert_eq!(removed, 3);
        assert!(db.list_connection_decisions().await.unwrap().is_empty());

        let _ = std::fs::remove_file(&path);
    }

    /// offset 不带 limit 的组合：修复前拼出裸 `... OFFSET n`（SQLite 语法
    /// 错误，prepare 直接失败），修复后补 LIMIT -1 占位且跳行行为正确。
    #[tokio::test]
    async fn network_history_offset_without_limit() {
        let path = std::env::temp_dir().join("cf_hist_off_test.db");
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let db = Database::open(&path_str).expect("open db");

        let now = chrono::Utc::now();
        for i in 0..8 {
            let record = NetworkHistoryRecord {
                id: None,
                timestamp: (now - chrono::Duration::seconds(i)).to_rfc3339(),
                action: RuleAction::Allow,
                local_addr: "192.168.1.10".to_string(),
                local_port: 40000 + (i as u16),
                remote_addr: "93.184.216.34".to_string(),
                remote_port: 443,
                protocol: Protocol::Tcp,
                direction: Direction::Outbound,
                process_id: Some(1234),
                process_name: Some("app.exe".to_string()),
                process_path: Some(r"C:\Program Files\App\app.exe".to_string()),
                bytes_sent: 0,
                bytes_received: 0,
                rule_id: None,
            };
            db.create_network_history(&record).await.unwrap();
        }

        let mut filters = HistoryFilters::default();
        filters.limit = None;
        filters.offset = Some(5);
        let rows = db.get_network_history(&filters).await.unwrap();
        assert_eq!(rows.len(), 3, "8 rows minus 5 skipped");
        // 默认 timestamp DESC：最新 5 行（40000..40004）被跳过，从 40005 起返回
        assert_eq!(rows[0].local_port, 40005);
        assert_eq!(rows[2].local_port, 40007);

        // limit + offset 组合行为不变：跳过最新 1 行（40000），取 40001、40002
        let mut filters = HistoryFilters::default();
        filters.limit = Some(2);
        filters.offset = Some(1);
        let rows = db.get_network_history(&filters).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local_port, 40001);
        assert_eq!(rows[1].local_port, 40002);

        let _ = std::fs::remove_file(&path);
    }

    /// retention 语义：settings 未显式设置时默认 30；显式写 0 必须
    /// 原样返回 0（= 永不清理），不再被钳制成 30。
    #[tokio::test]
    async fn log_retention_zero_means_never() {
        let path = std::env::temp_dir().join("cf_retention_test.db");
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let db = Database::open(&path_str).expect("open db");

        // 新库默认 30（settings 建行时写入）
        assert_eq!(db.get_log_retention_days().await.unwrap(), 30);

        // 显式 0 = 永不清理
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE settings SET log_retention_days = 0 WHERE id = 1",
                [],
            )
            .unwrap();
        }
        assert_eq!(db.get_log_retention_days().await.unwrap(), 0);

        let _ = std::fs::remove_file(&path);
    }

    /// Dashboard 图表增强三条聚合查询：按应用时序 / 放行拦截趋势 / 主机排行
    #[tokio::test]
    async fn dashboard_aggregates_group_by_bucket_process_action_host() {
        let path = std::env::temp_dir().join("cf_dash_agg_test.db");
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let db = Database::open(&path_str).expect("open db");

        let now = chrono::Utc::now();
        let mk = |ts: chrono::DateTime<chrono::Utc>, action: RuleAction, path: Option<&str>, remote: &str, sent: i64, recv: i64| NetworkHistoryRecord {
            id: None,
            timestamp: ts.to_rfc3339(),
            action,
            local_addr: "127.0.0.1".to_string(),
            local_port: 10000,
            remote_addr: remote.to_string(),
            remote_port: 443,
            protocol: Protocol::Tcp,
            direction: Direction::Outbound,
            process_id: None,
            process_name: path.map(|p| p.to_string()),
            process_path: path.map(|p| p.to_string()),
            bytes_sent: sent as u64,
            bytes_received: recv as u64,
            rule_id: None,
        };

        let a = r"C:\a.exe".to_string();
        let b = r"C:\b.exe".to_string();
        db.create_network_history(&mk(now, RuleAction::Allow, Some(&a), "1.1.1.1", 100, 200)).await.unwrap();
        db.create_network_history(&mk(now, RuleAction::Allow, Some(&b), "1.1.1.1", 10, 20)).await.unwrap();
        db.create_network_history(&mk(now, RuleAction::Block, Some(&a), "2.2.2.2", 5, 0)).await.unwrap();

        // 按应用时序：同桶两进程分开计数
        let timeline = db.aggregate_app_timeline(1, 60).await.unwrap();
        assert_eq!(timeline.len(), 2, "grouping is per (bucket, process); actions merge");
        let a_row = timeline.iter().find(|(_, p, _, _, _)| *p == a).unwrap();
        assert_eq!((a_row.3, a_row.4), (105, 200), "process a merges across actions");

        // 放行/拦截趋势：同桶两 action 分行返回，聚合正确性由 manager 层拼装
        let trend = db.aggregate_action_trend(1, 60).await.unwrap();
        assert_eq!(trend.len(), 2, "allow and block in separate rows");
        let blocked = trend.iter().find(|(_, act, _, _, _)| act.contains("Block")).unwrap();
        assert_eq!((blocked.2, blocked.3, blocked.4), (5, 0, 1));

        // 主机排行：按总流量降序，1.1.1.1 (330) 在 2.2.2.2 (5) 之前
        let hosts = db.aggregate_top_hosts(1, 10).await.unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].0, "1.1.1.1");
        assert_eq!((hosts[0].1, hosts[0].2, hosts[0].3), (110, 220, 2));

        // 窗口过滤：7 天窗口外写入的记录不计入
        db.create_network_history(&mk(now - chrono::Duration::days(8), RuleAction::Allow, Some(&a), "3.3.3.3", 999, 999)).await.unwrap();
        let hosts = db.aggregate_top_hosts(24 * 7, 10).await.unwrap();
        assert!(!hosts.iter().any(|h| h.0 == "3.3.3.3"), "window filter applied");

        let _ = std::fs::remove_file(&path);
    }
}
