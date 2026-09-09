# Ceasefire 测试机部署与测试说明

## 一、部署步骤

1. **开启测试签名模式**（驱动为测试签名/未签名，必须先做，只需一次）：
   以管理员运行：
   ```
   bcdedit /set testsigning on
   ```
   然后**重启**测试机。桌面会出现"测试模式"水印，属正常现象。
   （若打包时已用 sign-driver.ps1 完成本机自签并将证书导入 Root/TrustedPublisher，
   且随包携带了 CeasefireTestCert.cer，也可以不开测试签名，改为手动导入证书：
   `certutil -addstore Root driver\CeasefireTestCert.cer` + `certutil -addstore TrustedPublisher driver\CeasefireTestCert.cer`。）

2. **一键部署**：右键 `install-all.bat` → 以管理员身份运行。
   脚本会依次：安装并启动驱动（CeasefireDriver）→ 安装并启动服务（CeasefireFirewall）。

3. **启动 GUI**：进入 `gui\` 目录，**以管理员身份**运行 `Ceasefire.exe`。
   > 重要：服务命名管道 `\\.\pipe\CeasefireFirewall` 的 DACL 只允许
   > SYSTEM 和管理员连接，非管理员启动的 GUI 会连不上服务（界面报连接失败）。

4. **卸载**：以管理员运行 `uninstall-all.bat`（停并删服务与驱动；
   数据文件不删，手动清理位置见脚本末尾提示）。

## 二、日志与排障

- **服务日志**：`C:\ProgramData\Ceasefire\logs\ceasefire-service.log.YYYY-MM-DD`
  （按天滚动）。数据库：`C:\ProgramData\Ceasefire\ceasefire.db`。
- **驱动日志（仅 Debug 版驱动）**：下载微软 [DbgView（DebugView）](https://learn.microsoft.com/sysinternals/downloads/debugview)，
  以管理员运行，菜单 Capture → 勾选 *Capture Kernel* 和 *Enable Verbose Kernel Output*，
  即可看到驱动的 KdPrint 输出。Release 版驱动无 KdPrint 输出。
- 驱动启动失败最常见的原因：未开测试签名（见步骤 1）。
- 服务启动失败：查看上述日志目录；确认 `sc query CeasefireFirewall` 的状态。

## 三、WebView2 运行时

GUI 依赖 WebView2 运行时。Win10/11 一般自带；若 GUI 启动报缺 WebView2，
到 https://developer.microsoft.com/microsoft-edge/webview2/ 安装 Evergreen Runtime 后重试。

## 四、驱动实测清单（请逐项记录通过/失败）

| # | 测试项 | 步骤 | 通过标准 |
|---|--------|------|----------|
| ① | 服务重启 | 在 GUI 或 `services.msc` 中重启 CeasefireFirewall 服务（**不**卸载驱动） | 服务重启后规则加载无 RuleId 冲突（日志无冲突报错），已建规则继续生效 |
| ② | 程序级拦截 | 给某个特定程序（如 curl.exe / 某浏览器）创建 Block 规则并启用 | 该程序网络连接被拦截（GUI 有拦截记录），其他程序上网不受影响 |
| ③ | 域名反查 | 执行 `nslookup www.baidu.com` 或正常浏览网页 | GUI"活动连接"页该连接的"域名"列有值，且与连接目标 IP 对应 |
| ④ | 禁用规则启用 | 创建一条默认"禁用"的规则，之后在 GUI 中启用 | 启用后立即生效（无需重启服务/驱动），被禁用期间不生效 |

## 五、目录结构

```
Ceasefire\
├── driver\   CeasefireDriver.sys、CeasefireTestCert.cer（如有）、install/uninstall-driver.bat
├── service\  ceasefire-service.exe、GeoLite2-City.mmdb
├── gui\      Ceasefire.exe
├── install-all.bat / uninstall-all.bat
└── README.md（本文件）
```

> 注：所有 .bat 脚本为纯 ASCII（英文提示），这是刻意的——cmd 在 65001 代码页下解析含中文的
> 批处理会错位（乱码/幻影命令），部分机器的终端默认就是 65001。中文说明统一看本文件。
