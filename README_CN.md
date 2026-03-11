# os-app-router：OPNsense 应用感知路由插件

[English](README.md) | 中文

根据域名/CIDR 分类，将指定 LAN 客户端的流量路由到不同网关。例如，将所有国内视频网站的流量走 WAN2，其余流量走 WAN1。

## 功能特性

- **应用分类**：内置国内视频、社交、电商、音乐、游戏等平台的域名分类
- **DNS 嗅探**：通过 tcpdump 实时捕获 DNS 响应，精准识别 CDN IP
- **CIDR 列表**：支持社区维护的静态 IP 段列表（如 chnroutes2）
- **按客户端分流**：可针对特定 LAN IP/子网设置路由规则，也可应用于所有流量
- **自定义域名**：可为每条规则添加额外域名，Dnsmasq 和 Unbound 模式均支持，自动匹配子域名
- **列表自动更新**：定时从远程源拉取域名和 CIDR 列表
- **服务管理**：在 Web UI 中直接启动/停止/重启 DNS 嗅探器，实时状态指示
- **自定义域名列**：规则列表中直接显示自定义域名，便于快速查看
- **Web 管理界面**：完整的 OPNsense MVC 集成，包含设置、规则管理和实时状态面板
- **pf 表集成**：使用 FreeBSD 原生 pf 表实现零拷贝路由决策

## 工作原理

```
客户端 DNS 查询 → DNS 嗅探器 (tcpdump) 捕获解析出的 IP
                   → IP 按分类写入 pf 表
                   → pf route-to 规则将流量导向指定网关

此外：
- 远程 CIDR 列表（如中国 IP 段）直接加载到 pf 表
- 每 5 分钟通过 drill 主动解析域名作为补充
```

### 架构

```
Web UI ──→ REST API (PHP) ──→ configd ──→ Python/Shell 脚本
                                              │
                                    ┌─────────┼──────────┐
                                    ▼         ▼          ▼
                              list_updater  dns_watcher  table_manager
                              (拉取列表)    (嗅探 DNS)   (pfctl 操作)
                                    │         │          │
                                    └─────────┼──────────┘
                                              ▼
                                     pf 表 + route-to 规则
```

**DNS 嗅探器** (`dns_watcher.py`)：在 LAN 接口上运行 tcpdump，实时捕获 DNS A 记录响应。当客户端解析 `video.iqiyi.com` 时，返回的 CDN IP 会立即写入对应的 pf 表。这能有效应对 CDN 域名因时间和地理位置不同而返回不同边缘 IP 的情况。

**列表更新器** (`list_updater.py`)：定期从 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) 拉取域名列表，从远程源拉取 CIDR 列表，生成 Dnsmasq/Unbound 配置文件并更新 pf 表。

## 安装

```bash
# 在 OPNsense 上执行：
git clone https://github.com/DaneHou/os-app-router.git /tmp/os-app-router
cd /tmp/os-app-router
make install
```

## 卸载

```bash
cd /tmp/os-app-router
make uninstall
```

卸载会移除所有插件文件、缓存、生成的数据和 pf 表。用户配置 (`/usr/local/etc/app-router/config.json`) 会保留。如需完全删除：

```bash
rm -rf /usr/local/etc/app-router
```

## 快速上手

1. 在 **Services > AppRouter > General** 中启用插件
2. 选择 DNS 解析器（Dnsmasq 或 Unbound）
3. 进入 **Routing Rules** 标签页，添加规则：
   - **Description**：规则描述（如 "国内流量走 WAN2"）
   - **Interface**：入站接口（通常选 LAN）
   - **Source**：客户端过滤，支持以下格式：
     - `any` — 所有客户端
     - `192.168.1.100` — 单个 IP
     - `192.168.1.100,192.168.1.200` — 多个 IP
     - `192.168.1.0/24` — 子网
     - `192.168.1.0/24,10.0.0.5` — IP 和子网混合
   - **App Categories**：选择应用分类（如 `Video (All)`、`iQIYI`、`Bilibili`）
   - **Custom Domains**：可选，为此规则添加额外域名（Dnsmasq 和 Unbound 模式均支持；自动匹配子域名，如填入 `ustc.edu.cn` 也会匹配 `test.ustc.edu.cn`）
   - **Gateway**：目标网关
4. 点击 **Save**，然后点击 **Apply**（Apply 会自动启动服务，无需手动点击 Start）
5. 进入 **List Sources** 标签页，点击 **Update Lists Now**

## DNS 模式

### Dnsmasq (ipset)

- 利用 Dnsmasq 原生 `ipset` 指令，在 DNS 查询时直接将域名解析结果写入 pf 表
- 配置文件生成在 `/usr/local/etc/app-router/dnsmasq.d/`
- 效率最高：零延迟 IP 捕获

### Unbound (日志监听)

- `dns_watcher.py` 守护进程通过 tcpdump 在 LAN 接口嗅探 DNS 响应
- 解析 A 记录并通过 pfctl 将 IP 写入 pf 表
- 每 5 分钟通过 `drill` 主动解析作为补充
- 域名-表映射文件位于 `/usr/local/etc/app-router/unbound.d/`

## 验证

```bash
# 检查 pf 表是否有数据
pfctl -t approuter_video -T show

# 检查路由规则
pfctl -sr | grep approuter

# 从 LAN 客户端测试
traceroute bilibili.com   # 应显示流量经过配置的网关
```

## 故障排查

### 流量未被路由

1. 检查 **Status** 标签页：确认 DNS 嗅探器显示绿色（运行中）
2. 检查 pf 表是否有条目——条目为 0 表示 DNS 尚未解析这些域名
3. 尝试 **Force Full Update** 刷新所有列表
4. 在 **System > Gateways > Status** 中检查网关是否在线

### CDN IP 未捕获

CDN 域名（Akamai、Cloudflare 等）会根据解析器位置和时间返回不同的 IP。DNS 嗅探器会在客户端解析时捕获 IP。如果某个 IP 被遗漏：

1. 下次 DNS 查询时嗅探器会捕获到
2. 每 5 分钟的主动解析会作为补充
3. 自动添加 `/24` 子网以覆盖附近的 CDN 边缘 IP

### 中国 CIDR 列表无法加载

默认源为 `misakaio/chnroutes2`。如果配置的 URL 访问失败，插件会自动回退到内置默认 URL。如果两者都失败：
1. 在 **Status** 标签页查看日志中的错误信息
2. 在 **List Sources** 中更新 CIDR URL（旧的 `ruijzhan/chnroute` URL 已不可用）
3. 执行 **Force Full Update**

### 服务无法启动

1. 确认在 **General** 设置中已启用插件
2. 检查系统日志：`grep approuter /var/log/system/latest.log`
3. 检查 DNS 嗅探器日志：`cat /var/log/approuter_dns_watcher.log`
4. 确认 Unbound/Dnsmasq 正在运行

## 数据源

| 来源 | 内容 | 地址 |
|------|------|------|
| dnsmasq-china-list | 中国域名列表 | github.com/felixonmars/dnsmasq-china-list |
| chnroutes2 | 中国 IPv4 CIDR | github.com/misakaio/chnroutes2 |
| v2fly/domain-list-community | 应用专属域名 | github.com/v2fly/domain-list-community |
| 内置分类 | 精选应用域名 | 随插件分发 |

## 开发

```bash
make install          # 安装并激活（在 OPNsense 上）
make install-plugin   # 仅复制文件（不激活）
make activate         # 刷新缓存，重启服务
make lint             # 检查 Python 语法和 XML 格式
make clean            # 清理 __pycache__ 和 .pyc 文件
```

### 文件结构

```
src/
├── etc/inc/plugins.inc.d/
│   └── approuter.inc              # pf 表、规则、服务、定时任务钩子
├── opnsense/mvc/app/
│   ├── controllers/.../Api/
│   │   ├── SettingsController.php  # 规则/设置 CRUD
│   │   └── ServiceController.php   # 重新配置、状态、启停
│   ├── models/.../Approuter.xml    # XML 数据模型（设置、规则、列表）
│   └── views/.../index.volt        # 单页 Web UI
└── opnsense/scripts/.../Approuter/
    ├── list_updater.py             # 拉取/处理远程列表
    ├── dns_watcher.py              # DNS 嗅探守护进程
    ├── table_manager.sh            # pfctl 表操作
    └── app_categories.json         # 内置域名分类
```

## 许可证

BSD 2-Clause License，详见源代码文件头。
