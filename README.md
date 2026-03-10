# os-app-router: Application-Aware Routing for OPNsense

Route traffic from specific LAN clients through designated gateways based on application categories. Designed for users who need per-app routing policies (e.g., route Chinese video streaming through a specific WAN while other traffic uses the default gateway).

## Features

- **Application Categories**: Built-in categories for Chinese video, social, shopping, music, and gaming platforms
- **DNS-based identification**: Integrates with Dnsmasq (ipset) or Unbound (log watcher) to dynamically identify application traffic
- **CIDR list support**: Static IP range routing using community-maintained lists (chnroute, etc.)
- **Per-client rules**: Apply routing only to specific LAN IPs/subnets
- **Auto-updating lists**: Scheduled fetching of domain and CIDR lists from remote sources
- **Web UI**: Full OPNsense MVC integration with settings, rule management, and status dashboard
- **pf table integration**: Native FreeBSD packet filter tables for zero-copy routing decisions

## How It Works

1. **Domain lists** are loaded for each app category (bilibili.com, douyin.com, etc.)
2. **Dnsmasq ipset** or **Unbound log watcher** captures DNS resolutions and adds resolved IPs to pf tables
3. **CIDR lists** (e.g., China IP blocks) are loaded directly into pf tables
4. **pf route-to rules** redirect matching traffic from configured source IPs through the designated gateway

## Installation

```bash
# On your OPNsense box:
git clone https://github.com/DaneHou/os-app-router.git /tmp/os-app-router
cd /tmp/os-app-router
make install
```

## Uninstall

```bash
cd /tmp/os-app-router
make uninstall
```

This cleans up all caches, generated data, runtime state, and pf tables. User config (`/usr/local/etc/app-router/config.json`) is preserved. To fully remove:

```bash
rm -rf /usr/local/etc/app-router
```

## Quick Start

1. Enable AppRouter in `Services > AppRouter > General`
2. Select your DNS resolver (Dnsmasq or Unbound)
3. Go to the **Routing Rules** tab and add a rule:
   - **Source Networks**: Your LAN subnet (e.g., `192.168.1.0/24`)
   - **Categories**: Select app categories (e.g., China Video)
   - **Gateway**: Select the target gateway (e.g., `WAN2_DHCP`)
   - **Interface**: `lan`
4. Click **Apply**
5. Go to **List Sources** and click **Update Lists Now**

## Verification

```bash
# Check pf tables are populated
pfctl -t approuter_video -T show

# Check routing rules
pfctl -sr | grep approuter

# Test from a LAN client
traceroute bilibili.com   # Should show traffic going through configured gateway
```

## Data Sources

| Source | Content | URL |
|--------|---------|-----|
| dnsmasq-china-list | Chinese domains | github.com/felixonmars/dnsmasq-china-list |
| chnroute | China IPv4 CIDRs | github.com/ruijzhan/chnroute |
| Built-in categories | App-specific domains | Bundled with plugin |

## Architecture

```
OPNsense Web UI
    │
    ├── MVC Model (Approuter.xml) ─── Config Storage (config.xml)
    ├── API Controllers ───────────── REST endpoints
    └── configd actions ───────────── Script execution
         │
         ├── list_updater.py ───── Fetch/process remote lists
         ├── dns_watcher.py ────── Monitor DNS for Unbound mode
         └── table_manager.sh ──── pfctl table operations
              │
              └── pf tables + route-to rules ── Actual traffic routing
```

## License

BSD 2-Clause License
