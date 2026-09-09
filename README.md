# 本地防火墙系统 (Local Firewall System)

一个基于 Windows 平台的网络安全应用程序，采用三层架构设计：驱动层（WFP Callout Driver）、服务层（Rust Windows Service）和 GUI 层（Tauri + Vue 3）。

## ⚠️ 重要提示（安装前请务必阅读）

1. **当前发布版本使用测试证书签名**（未购买正式代码签名证书），安装驱动时 Windows 可能弹出安全警告或要求手动信任证书，属正常现象；
2. 本软件涉及**内核级网络拦截**，尽管已经过充分测试，仍可能存在未知问题。**请在安装前做好数据备份，因安装或使用本软件造成的任何系统异常、数据丢失或其他损失，由使用者自行承担后果**；
3. 建议先在虚拟机或非关键业务机器上体验，确认无误后再部署到日常使用环境；
4. 如遇问题，欢迎提 Issue 反馈。

## 架构概览

```
┌─────────────────────────────────────────────────────────┐
│                    GUI Layer                             │
│                 (Tauri + Vue 3)                          │
│  - 规则管理  - 实时监控  - 日志查询  - 系统托盘          │
└──────────────────────┬──────────────────────────────────┘
                       │ 命名管道 IPC
┌──────────────────────▼──────────────────────────────────┐
│                  Service Layer                           │
│              (Rust Windows Service)                      │
│  - 驱动管理  - 规则同步  - 事件处理  - 数据持久化       │
└──────────────────────┬──────────────────────────────────┘
                       │ IOCTL
┌──────────────────────▼──────────────────────────────────┐
│                  Driver Layer                            │
│              (WFP Callout Driver)                        │
│  - 网络拦截  - 规则匹配  - 事件上报                      │
└──────────────────────┬──────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │  WFP (内核)     │
              └─────────────────┘
```

## 技术栈

- **驱动层**: C/C++, Windows Driver Kit (WDK), WFP
- **服务层**: Rust, windows-service, tokio, rusqlite
- **GUI 层**: Tauri 1.x, Vue 3, TypeScript, Element Plus, ECharts
- **数据存储**: SQLite 3

## 项目结构

```
Ceasefire/
├── driver/          # WFP Callout Driver
├── service/         # Rust Windows Service
├── gui/             # Tauri + Vue 3 GUI
├── doc/             # 项目文档
├── packaging/       # 打包脚本与配置
├── build-package.bat# 一键构建打包脚本
└── README.md
```

## 开发环境要求

- Windows 10/11
- Visual Studio 2019/2022 (C++ 桌面开发组件)
- Windows Driver Kit (WDK)
- Rust 1.70+
- Node.js 18+
- npm/yarn/pnpm

## 快速开始

### 构建驱动层

```powershell
cd driver
# 使用 Visual Studio 打开 .sln 文件进行编译
```

### 构建服务层

```powershell
cd service
cargo build --release
```

### 构建并运行 GUI

```powershell
cd gui
npm install
npm run tauri dev
```

## 功能语义与已知限制

- **带宽限速语义 = 仅上行整形 + 双向字节统计**：上传方向在内核
  （OUTBOUND_TRANSPORT_V4/V6 令牌桶）真实限流；下载方向受 TCP post-ACK
  数据不可丢弃约束暂无法强制整形，仅做双向字节统计与超限告警。
  详见 [WFP实现方案.md](WFP实现方案.md)。
- IPv4/IPv6 双栈逐进程管控全对齐（规则、拦截、限速、字节统计）；
  规则的远程地址接受 IPv4/IPv6（含 /prefix CIDR）。

## 许可证

本项目**尚未选择开源许可证**，默认保留所有权利（All Rights Reserved）。

在此之前：

- ✅ **允许**：个人使用、学习研究、阅读源码、fork 修改自用、提 Issue / PR；
- ❌ **禁止**：商用，包括直接或变相出售本软件、二次开发后收费分发或牟利、捆绑进收费软件或服务。

许可证后续可能调整，请以本节最新内容为准。如需商业授权，请联系作者。
