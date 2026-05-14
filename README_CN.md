# os-app-router：OPNsense 应用感知路由插件

[English](README.md) | 中文

根据域名/CIDR 分类，将指定 LAN 客户端的流量路由到不同网关。例如，将所有国内视频网站流量走 WAN2，其余流量走 WAN1；或将公司 VPN 流量单独走企业网关，个人流量继续走主 WAN。

## 功能特性

- **内置分类**：国内视频、社交、电商、音乐、游戏等平台的精选域名列表
- **自定义分类**：创建自己的域名+CIDR 分组（如公司 IP 段），在路由规则中与内置分类一起使用
- **DNS 嗅探**：通过 tcpdump 实时捕获 DNS 响应，精准识别 CDN IP
- **CIDR 列表**：支持社区维护的静态 IP 段列表（如 chnroutes2）
- **按客户端分流**：可针对特定 LAN IP/子网设置规则，也可应用于全部流量（`any`）
- **自定义域名**：为每条规则添加额外域名，自动匹配子域名
- **智能网关**：基于连通性探测的自动网关选择，支持优先级和故障转移
- **列表自动更新**：定时从远程源拉取域名和 CIDR 列表
- **Web 管理界面**：完整的 OPNsense MVC 集成，包含设置、规则管理和实时状态面板
- **pf 表集成**：使用 FreeBSD 原生 pf 表实现零拷贝路由决策

## 系统要求

- OPNsense 23.7 或更高版本
- DNS 解析器：**Dnsmasq**（推荐）或 **Unbound**，需已启用并运行
- `make` 工具（OPNsense/FreeBSD 预装）
- 防火墙能访问互联网（用于初次下载列表）

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

卸载会移除所有插件文件、缓存、生成的数据和 pf 表。用户配置（`/usr/local/etc/app-router/config.json`）会保留。如需完全删除：

```bash
rm -rf /usr/local/etc/app-router
```

## 快速上手

1. 在 **Services > AppRouter > General** 中启用插件，选择 DNS 解析器
2. *（可选）* 进入 **Custom Categories** 标签页，创建自定义分类（如公司 VPN 地址段）
3. 进入 **Routing Rules** 标签页，添加规则：
   - **Source**：`any` 表示所有客户端，`192.168.1.0/24` 表示某个子网
   - **App Categories**：选择内置或自定义分类
   - **Gateway**：目标网关
4. 点击 **Save**，然后点击 **Apply**（会自动启动服务）
5. 进入 **List Sources** 标签页，点击 **Update Lists Now** 下载最新数据

## 配置说明

### 路由规则

每条规则将来源（LAN 客户端）的流量按照分类或自定义域名路由到指定网关。

| 字段 | 说明 |
|------|------|
| Description | 规则名称 |
| Interface | 入站接口（通常选 LAN） |
| Source | 客户端过滤：`any`、单个 IP、子网或逗号分隔列表 |
| App Categories | 一个或多个内置/自定义分类 |
| Custom Domains | 仅用于此规则的额外域名，自动匹配子域名 |
| Gateway | 目标网关——选择多个可启用智能网关 |
| Smart Gateway | 启用自动探测和故障转移（需选择 2 个或以上网关） |

**Source 示例：**
```
any                              — 所有 LAN 客户端
192.168.1.100                   — 单个主机
192.168.1.0/24                  — 子网
192.168.1.0/24,10.0.0.5         — 混合格式
```

### 自定义分类

自定义分类让你创建命名的域名+CIDR 分组，在规则编辑器中与内置分类并列显示。

**创建自定义分类：**
1. 进入 **Custom Categories** 标签页 → **Add Category**
2. 填写：
   - **Slug**：内部唯一标识（小写字母/数字/下划线，如 `ba_work`）
   - **Label**：在规则编辑器中显示的名称
   - **Domains**：每行一个域名，或用逗号分隔；自动匹配子域名（如填 `amazonaws-us-gov.com` 也会匹配 `s3.us-gov-west-1.amazonaws-us-gov.com`）
   - **Static CIDRs**：直接路由的 IP 地址或网段（如 `172.16.20.85`、`10.0.0.0/24`）
3. 点击 **Save**，然后点击 **Apply**

**示例——公司流量：**
```
Slug:    ba_work
Label:   BA Work
Domains: atlassian.net
         confluence.example.com
         amazonaws-us-gov.com
CIDRs:   172.16.20.85
         172.16.16.0/24
```

然后创建一条路由规则，选择 `BA Work` 分类，目标网关设为公司 VPN 网关即可。

### 智能网关

智能网关通过探测连通性实现多网关间的自动切换。

**配置步骤：**
1. 在路由规则中选择**两个或以上**网关（优先级从上到下）
2. 启用 **Smart Gateway** 开关
3. 选择探测方式：
   - `connect_only`：TCP 连接测试（快速，无 HTTP 开销）
   - `http_2xx`：需要收到 HTTP 200–299 响应
   - `body_match`：需要响应体中包含指定内容
4. 填写 **Probe URL**（如 `https://www.google.com`）和 **Probe Interval**（秒）

优先级最高且探测通过的网关成为活跃网关；若失败，则尝试下一个；最后一个网关始终作为兜底。

### 列表源

AppRouter 按计划定时下载域名和 CIDR 列表。在 **List Sources** 标签页中配置源地址和更新间隔。点击 **Update Lists Now** 立即更新，点击 **Force Full Update** 跳过 ETag 缓存强制刷新。

## DNS 模式

### Dnsmasq (ipset) — 推荐

- 利用 Dnsmasq 原生 `ipset` 指令，在 DNS 查询时直接将域名解析结果写入 pf 表
- 配置文件生成在 `/usr/local/etc/app-router/dnsmasq.d/`
- 效率最高：零延迟 IP 捕获

### Unbound（DNS 嗅探）

- `dns_watcher.py` 守护进程通过 tcpdump 在 LAN 接口嗅探 DNS 响应
- 解析 A 记录并通过 pfctl 将 IP 写入 pf 表
- 每 5 分钟通过 `drill` 主动解析作为补充
- 域名-表映射文件位于 `/usr/local/etc/app-router/unbound.d/`

## 验证

```bash
# 检查 pf 表是否有数据
pfctl -t approuter_video -T show

# 检查自定义分类表
pfctl -t approuter_ba_work -T show

# 检查路由规则是否已安装
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

CDN 域名会根据解析器位置和时间返回不同的 IP，DNS 嗅探器会在客户端解析时实时捕获。

1. 客户端每次 DNS 查询都会立即触发捕获
2. 每 5 分钟的主动 `drill` 解析会作为补充
3. 如果某个网站还是没被路由：从客户端访问一下，DNS 查询会立即触发捕获

### 静态 CIDR 未生效

如果在自定义分类中添加了 CIDRs 但流量未被路由：

1. 在 Custom Categories 标签页（或 Routing Rules 标签页）点击 **Apply**
2. 验证表中是否有这些条目：`pfctl -t approuter_SLUG -T show`
3. 如果 Apply 后条目仍不存在，检查系统日志：`grep approuter /var/log/system/latest.log`

### 无关网站被屏蔽或出现地理封锁报错

如果商业网站（如美国电商）在某些设备上出现访问拒绝，在其他设备上正常：

- 这曾是由于 DNS 嗅探器为 CDN IP 自动添加 `/24` 子网段，导致共用同一 CDN 的无关网站被误路由。该行为已移除——AppRouter 现在只写入具体解析 IP。
- 如果旧表中仍有遗留的 `/24` 条目，点击 **Apply** 清空并重新填充即可。

### 中国 CIDR 列表无法加载

默认源为 `misakaio/chnroutes2`。如果配置的 URL 失败，插件会自动回退到内置默认 URL。如果两者都失败：
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
│   │   ├── SettingsController.php  # 规则、设置、自定义分类 CRUD
│   │   └── ServiceController.php   # 重新配置、状态、启停
│   ├── models/.../Approuter.xml    # XML 数据模型（设置、规则、列表、自定义分类）
│   └── views/.../index.volt        # 单页 Web UI
└── opnsense/scripts/.../Approuter/
    ├── list_updater.py             # 拉取/处理远程列表，生成 DNS 配置
    ├── dns_watcher.py              # DNS 嗅探守护进程
    ├── geo_prober.py               # 智能网关连通性探测
    ├── table_manager.sh            # pfctl 表操作
    └── app_categories.json         # 内置域名分类
```

## 许可证

BSD 2-Clause License，详见源代码文件头。
