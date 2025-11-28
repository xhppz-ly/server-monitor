# 🛸 Server Monitor | 极简服务器实时监控面板

> 专为 Linux 集群设计的轻量级、无代理（Agentless）、现代化运维监控系统。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-green.svg)
![Python](https://img.shields.io/badge/backend-Flask-yellow.svg)
![Vue](https://img.shields.io/badge/frontend-Vue3-success.svg)

## 📖 项目简介

**Server Monitor** 是一套开箱即用的服务器监控解决方案。它摒弃了繁琐的 Agent 安装流程，采用 **SSH 直连** 的方式，自动向目标服务器推送轻量级采集脚本。

系统包含一个基于 **Vue 3 + ECharts** 的科幻风格可视化大屏，以及一个基于 **Flask + SQLite** 的高性能后端。得益于 **Server-Sent Events (SSE)** 技术，它可以实现毫秒级的实时数据流推送，让你像观看电影一样掌控服务器脉搏。

## ✨ 核心特性

### 🚀 极速与实时
* **SSE 实时流**：采用 HTTP 长连接 (Server-Sent Events) 技术，实现 **秒级** 数据即时推送，告别传统轮询的延迟感。
* **无代理模式 (Agentless)**：无需在被监控服务器上安装任何插件或软件，只需 Python3 环境，通过 SSH 协议自动采集。

### 📊 全维度监控
* **基础资源**：实时 CPU 利用率、内存/Swap 使用量、磁盘空间、系统负载 (Load Average 1/5/15)。
* **网络流量**：实时上传/下载速率监测，带有动态波形图展示。
* **进程透视**：**Top 40 进程监控**，实时查看占用 CPU/内存 最高的进程列表，并在前端进行排序分析。
* **健康告警**：内置阈值检测，自动记录 CPU、内存、磁盘过载事件，并生成告警日志。

### 🛡️ 安全与稳定
* **凭证加密**：所有的 SSH 密码均使用 **Fernet 对称加密算法** 存储在本地 SQLite 数据库中，确保敏感信息不泄露。
* **连接风暴防护**：内置连接池管理与断线重连冷却机制，防止因网络波动导致的 SSH 连接风暴。
* **数据持久化**：通过 Docker Volume 挂载，确保数据库文件在容器重启后依然保留。

## 🛠️ 技术栈

| 模块 | 技术选型 | 说明 |
| :--- | :--- | :--- |
| **Frontend** | Vue 3 (ESM) | 现代化的渐进式 JavaScript 框架 |
| | Tailwind CSS | 原子化 CSS 框架，构建极简深色 UI |
| | ECharts 5.5 | 百度开源的强大数据可视化库 |
| **Backend** | Python 3.9 + Flask | 轻量级 Web 服务框架 |
| | Paramiko | Python SSHv2 协议实现库 |
| | SQLite | 嵌入式关系型数据库，无需额外部署 |

## 🐳 快速部署

本项目完全基于 Docker 构建，支持一键启动。

### 前置要求
* Docker & Docker Compose
* 宿主机 8080 端口可用

### 启动命令

1.  **克隆或下载本项目**
    ```bash
    git clone <repository_url>
    cd server-monitor
    ```

2.  **启动服务**
    ```bash
    # 构建镜像并后台运行
    docker-compose up --build -d
    ```
    > 系统会自动构建 `monitor-backend` 和 `monitor-frontend` 两个容器。

3.  **访问面板**
    打开浏览器访问：`http://localhost:8080`

## 🕹️ 使用指南

### 1. 添加主机
点击侧边栏底部的 **"+ ADD HOST"** 按钮，填写以下信息：
* **IP Address**: 目标服务器 IP（需确保 Docker 容器网络可达）。
* **User**: SSH 登录用户名（推荐 `root` 或有 sudo 权限的用户）。
* **Port**: SSH 端口（默认 22）。
* **Password**: SSH 登录密码（系统会自动加密存储）。

### 2. 查看仪表盘
* **左侧列表**：显示所有主机状态。🟢 绿色呼吸灯代表在线，🔴 红色代表离线或连接失败。
* **实时图表**：点击任意主机，右侧即展示 CPU/内存/磁盘 仪表盘及网络流量波形。
* **进程列表**：面板下方包含 "TOP PROCESSES" 表格，可直观看到是谁在占用资源。

### 3. 系统维护
* **数据位置**：数据库文件存储在当前目录的 `./backend_data/monitor_v2.db`。
* **日志查看**：如遇连接问题，可使用 `docker-compose logs -f backend` 查看后端日志。

## 📂 目录结构

```text
.
├── docker-compose.yml      # 容器编排配置
├── backend/                # 后端服务
│   ├── app.py              # Flask 主程序 (API & 调度)
│   ├── stream.py           # SSE 实时流处理模块
│   ├── monitoring_agent.py # 被控端 Python 采集脚本
│   ├── Dockerfile          # 后端镜像构建
│   └── requirements.txt    # Python 依赖
├── frontend/               # 前端服务
│   ├── index.html          # Vue3 单页应用源码
│   ├── nginx.conf          # Nginx 反代配置
│   └── Dockerfile          # 前端镜像构建
└── backend_data/           # (自动生成) 数据持久化目录