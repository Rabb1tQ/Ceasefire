# Ceasefire Firewall Service

Rust Windows Service 实现，用于管理 Ceasefire 防火墙系统的核心功能。

## 目录结构

```
service/
├── src/
│   ├── main.rs           # 服务入口点
│   ├── lib.rs            # 库入口，导出所有模块
│   ├── models.rs         # 数据模型定义
│   ├── database.rs       # 数据库访问层
│   ├── service/          # Windows Service 管理器
│   ├── rule/            # 规则管理器
│   ├── connection/       # 连接追踪器
│   ├── event/           # 事件处理器
│   ├── ipc/             # IPC 服务器（命名管道）
│   ├── notification/     # 通知模块
│   └── driver/          # 驱动通信模块
├── Cargo.toml
└── README.md
```

## 模块说明

### 1. 数据模型 (models.rs)
- `Rule`: 防火墙规则
- `LogEntry`: 日志条目
- `ConnectionInfo`: 连接信息
- `ConnectionKey`: 连接键（用于哈希）
- `ProcessStats`: 进程统计
- `GlobalStats`: 全局统计
- `Settings`: 设置
- `NetworkEvent`: 网络事件（来自驱动）
- `IpcRequest`: IPC 请求类型
- `IpcResponse`: IPC 响应类型

### 2. 数据库访问层 (database.rs)
- SQLite 数据库管理
- 规则 CRUD 操作
- 日志查询和写入
- 设置读写
- 日志清理功能

### 3. Windows Service 管理器 (service/)
- 服务生命周期管理
- 驱动加载/卸载
- 服务控制处理
- 与 Windows Service Manager 集成

### 4. 规则管理器 (rule/)
- 规则创建、更新、删除
- 规则验证
- 规则与驱动同步
- 优先级管理

### 5. 连接追踪器 (connection/)
- 活动连接追踪
- 流量统计
- 进程统计
- 全局统计计算

### 6. 事件处理器 (event/)
- 从驱动接收网络事件
- 日志缓冲和批量写入
- 连接状态更新
- 通知触发

### 7. IPC 服务器 (ipc/)
- 命名管道服务器
- 请求/响应处理
- 日志导出（CSV/JSON）
- 客户端连接管理

### 8. 通知模块 (notification/)
- Windows 通知发送
- 通知去重
- 通知级别控制

### 9. 驱动通信模块 (driver/)
- IOCTL 通信
- 驱动打开/关闭
- 规则同步到驱动
- 事件接收

## 编译

```bash
cd service
cargo build --release
```

## 运行

### 作为控制台应用（调试模式）

```bash
cd service
cargo run
```

### 作为 Windows Service

需要管理员权限：

```powershell
# 注册服务
sc create CeasefireFirewall binPath= "C:\path\to\service\target\release\ceasefire-service.exe"

# 启动服务
sc start CeasefireFirewall

# 停止服务
sc stop CeasefireFirewall

# 删除服务
sc delete CeasefireFirewall
```

## 环境变量

- `CEASEFIRE_DB`: 数据库路径（默认：`C:\ProgramData\Ceasefire\ceasefire.db`）
- `CEASEFIRE_RUN_AS_SERVICE`: 设置为 "1" 以服务模式运行
- `RUST_LOG`: 日志级别（例如：`ceasefire_service=info`）

## IPC 通信

服务通过命名管道 `\\.\pipe\CeasefireFirewall` 提供 IPC 接口。

GUI 可以通过以下请求与通信：
- `CreateRule(Rule)`: 创建规则
- `UpdateRule { id, rule }`: 更新规则
- `DeleteRule(id)`: 删除规则
- `ListRules`: 获取所有规则
- `GetActiveConnections`: 获取活动连接
- `GetProcessStats(pid)`: 获取进程统计
- `GetGlobalStats`: 获取全局统计
- `QueryLogs(query)`: 查询日志
- `ExportLogs { query, format }`: 导出日志
- `GetSettings`: 获取设置
- `UpdateSettings(settings)`: 更新设置

## 日志

日志文件位置：`C:\ProgramData\Ceasefire\logs\ceasefire-service.log`

## 依赖项

- `windows-service`: Windows 服务集成
- `tokio`: 异步运行时
- `rusqlite`: SQLite 数据库
- `serde`: 序列化/反序列化
- `bincode`: 二进制序列化（用于 IPC 和驱动通信）
- `tracing`: 日志框架
- `chrono`: 时间处理

## 设计说明

1. **模块化设计**: 每个功能模块独立，便于维护和测试
2. **异步 I/O**: 使用 Tokio 异步运行时，提高性能
3. **线程安全**: 使用 Arc 和 Mutex/RwLock 实现线程安全
4. **错误处理**: 统一的错误类型和 Result 处理
5. **日志缓冲**: 批量写入数据库，减少 I/O 操作

## 测试

```bash
cd service
cargo test
```

## 待完善功能

- [ ] Windows Service 完整集成（当前为简化实现）
- [ ] Windows Toast Notifications 集成
- [ ] 真正的 DeviceIoControl 调用（当前为文件写入模拟）
- [ ] 客户端权限验证
- [ ] 服务崩溃自动恢复
- [ ] 性能监控和指标