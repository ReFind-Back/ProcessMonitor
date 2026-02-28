# Process Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](https://github.com/ReFind-Back/ProcessMonitor)
[![Version](https://img.shields.io/badge/version-0.48-green.svg)](https://github.com/ReFind-Back/ProcessMonitor/releases)

**Process Monitor** 是一款轻量级的 Windows 系统托盘工具，可自动检测并终止异常进程（基于高 CPU 使用率、高内存使用率或无响应的窗口）。

---

## ✨ 主要特点

- ✅ **实时监控** - 自动扫描所有运行中的进程
- ✅ **自动终止** - 终止超过 CPU、内存或挂起阈值的进程
- ✅ **系统保护** - 内置系统进程保护（关键进程永不终止）
- ✅ **排除列表** - 用户可自定义排除的进程名称
- ✅ **日志记录** - 自动记录所有操作，支持日志轮转
- ✅ **动态配置** - 修改 config.ini 无需重启程序
- ✅ **低资源占用** - 对系统性能影响极小

---

## 📋 系统要求

- **操作系统**：Windows Vista / 7 / 8 / 10 / 11（32位或64位）
- **内存**：至少 50 MB 可用内存
- **磁盘空间**：10 MB
- **权限**：建议以管理员身份运行（以获得完整功能）

---

## 🚀 快速开始

### 下载与运行

1. 从 [Releases](https://github.com/ReFind-Back/ProcessMonitor/releases) 页面下载最新版本
2. 将 `ProcessMonitor.exe` 放在任意文件夹（建议英文路径）
3. 双击运行，程序将最小化到系统托盘

> 💡 **首次运行**：程序会自动创建默认配置文件 `config.ini` 和日志文件 `monitor.log`

### 基本操作

- **右键单击**托盘图标：打开功能菜单
- **双击左键**：显示版本和监控状态
- 菜单选项：
  - `Start Monitoring` - 开始监控
  - `Stop Monitoring` - 停止监控
  - `View Log` - 查看日志文件
  - `Edit Config` - 编辑配置文件
  - `View Manual` - 查看完整手册
  - `Exit` - 退出程序

---

## ⚙️ 配置文件 (config.ini)

```ini
[Settings]
MonitorIntervalMs=5000        ; 扫描间隔（毫秒，1000-60000）
CpuThresholdPercent=80        ; CPU 阈值（1-100）
MemThresholdMb=500             ; 内存阈值（MB，1-65536）
HangTimeoutMs=5000             ; 窗口挂起检测超时（1000-30000）
LogMaxSizeBytes=1048576        ; 日志文件最大字节数（1 MB）
MaxHungWindows=500             ; 每次扫描最大窗口数（10-5000）
NotifyOnTermination=0          ; 终止普通进程时是否弹窗（0=关闭，1=开启）
StartMonitoringOnLaunch=1      ; 启动时自动开始监控（0=关闭，1=开启）
ExcludeProcesses=              ; 排除的进程名（逗号分隔，如 notepad.exe,calc.exe）