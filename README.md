# os-app-router: Application-Aware Routing for OPNsense

Route traffic from specific LAN clients through designated gateways based on domain/CIDR categories. For example, route all Chinese video streaming through WAN2 while everything else goes through WAN1.

## Features

- **Application Categories**: Built-in categories for Chinese video, social, shopping, music, and gaming platforms
- **DNS Sniffer**: Real-time capture of DNS responses via tcpdump for reliable CDN IP detection
- **CIDR List Support**: Static IP range routing using community-maintained lists (chnroutes2, etc.)
- **Per-client Rules**: Apply routing only to specific LAN IPs/subnets, or to all traffic
- **Custom Domains**: Add per-rule custom domains beyond built-in categories
- **Auto-updating Lists**: Scheduled fetching of domain and CIDR lists from remote sources
- **Web UI**: Full OPNsense MVC integration with settings, rule management, and live status dashboard
- **pf Table Integration**: Native FreeBSD packet filter tables for zero-copy routing decisions

## How It Works

```
Client DNS query → DNS Sniffer (tcpdump) captures resolved IPs
                    → IPs added to pf tables by category
                    → pf route-to rules match traffic to gateway

Additionally:
- Remote CIDR lists (e.g., China IP ranges) loaded directly into pf tables
- Active DNS resolution (drill) runs every 5 min as fallback
```

### Architecture

```
Web UI ──→ REST API (PHP) ──→ configd ──→ Python/Shell scripts
                                              │
                                    ┌─────────┼──────────┐
                                    ▼         ▼          ▼
                              list_updater  dns_watcher  table_manager
                              (fetch lists) (sniff DNS)  (pfctl ops)
                                    │         │          │
                                    └─────────┼──────────┘
                                              ▼
                                     pf tables + route-to rules
```

**DNS Sniffer** (`dns_watcher.py`): Runs tcpdump on LAN interfaces to capture DNS A record responses in real time. When a client resolves `video.iqiyi.com`, the returned CDN IPs are immediately added to the appropriate pf table. This handles CDN domains that return different edge IPs based on timing and location.

**List Updater** (`list_updater.py`): Periodically fetches domain lists from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) and CIDR lists from remote sources. Generates Dnsmasq/Unbound config files and updates pf tables.

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

This removes all plugin files, caches, generated data, and pf tables. User config (`/usr/local/etc/app-router/config.json`) is preserved. To fully remove:

```bash
rm -rf /usr/local/etc/app-router
```

## Quick Start

1. Enable AppRouter in **Services > AppRouter > General**
2. Select your DNS resolver (Dnsmasq or Unbound)
3. Go to the **Routing Rules** tab and add a rule:
   - **Description**: Human-readable name (e.g., "China traffic via WAN2")
   - **Interface**: Inbound interface (typically LAN)
   - **Source**: `any` or comma-separated IPs/subnets (e.g., `192.168.1.0/24`)
   - **App Categories**: Select categories (e.g., `Video (All)`, `iQIYI`, `Bilibili`)
   - **Custom Domains**: Optional extra domains for this rule
   - **Gateway**: Target gateway for matched traffic
4. Click **Save**, then **Apply**
5. Go to **List Sources** and click **Update Lists Now**

## DNS Modes

### Dnsmasq (ipset)

- Domains resolved directly into pf tables at DNS query time via Dnsmasq's native `ipset` directive
- Config files generated in `/usr/local/etc/app-router/dnsmasq.d/`
- Most efficient: zero-latency IP capture

### Unbound (log watcher)

- `dns_watcher.py` daemon sniffs DNS responses via tcpdump on LAN interfaces
- Parses A record answers and adds IPs to pf tables via pfctl
- Also runs periodic active resolution via `drill` as fallback
- Domain-to-table mapping files in `/usr/local/etc/app-router/unbound.d/`

## Verification

```bash
# Check pf tables are populated
pfctl -t approuter_video -T show

# Check routing rules
pfctl -sr | grep approuter

# Test from a LAN client
traceroute bilibili.com   # Should show traffic going through configured gateway
```

## Troubleshooting

### Traffic not being routed

1. Check **Status** tab: ensure DNS watcher shows green (running)
2. Verify pf tables have entries — tables with 0 entries mean DNS hasn't resolved those domains yet
3. Try **Force Full Update** to refresh all lists
4. Check that the gateway is online in **System > Gateways > Status**

### CDN IPs not captured

CDN domains (Akamai, Cloudflare, etc.) return different IPs based on resolver location and timing. The DNS sniffer captures IPs as clients resolve them. If an IP is missed:

1. The sniffer will catch it on the next DNS query
2. Active resolution runs every 5 minutes as fallback
3. `/24` subnets are automatically added to cover nearby CDN edge IPs

### China CIDR list not loading

The default source is `misakaio/chnroutes2`. If it fails:
1. Check **Status** tab for error messages in logs
2. Try a custom CIDR URL in **List Sources**
3. Run **Force Full Update**

### Service won't start

1. Verify the plugin is enabled in **General** settings
2. Check syslog: `grep approuter /var/log/system/latest.log`
3. Check DNS watcher log: `cat /var/log/approuter_dns_watcher.log`
4. Verify Unbound/Dnsmasq is running

## Data Sources

| Source | Content | URL |
|--------|---------|-----|
| dnsmasq-china-list | Chinese domains | github.com/felixonmars/dnsmasq-china-list |
| chnroutes2 | China IPv4 CIDRs | github.com/misakaio/chnroutes2 |
| v2fly/domain-list-community | App-specific domains | github.com/v2fly/domain-list-community |
| Built-in categories | Curated app domains | Bundled with plugin |

## Development

```bash
make install          # Install + activate on OPNsense host
make install-plugin   # Copy files only (no activation)
make activate         # Flush caches, restart services
make lint             # Check Python syntax and XML validity
make clean            # Remove __pycache__ and .pyc files
```

### File Structure

```
src/
├── etc/inc/plugins.inc.d/
│   └── approuter.inc              # pf tables, rules, services, cron hooks
├── opnsense/mvc/app/
│   ├── controllers/.../Api/
│   │   ├── SettingsController.php  # CRUD for rules/settings
│   │   └── ServiceController.php   # reconfigure, status, start/stop
│   ├── models/.../Approuter.xml    # XML schema (settings, rules, lists)
│   └── views/.../index.volt        # Single-page UI
└── opnsense/scripts/.../Approuter/
    ├── list_updater.py             # Fetch/process remote lists
    ├── dns_watcher.py              # DNS sniffer daemon
    ├── table_manager.sh            # pfctl table operations
    └── app_categories.json         # Built-in domain categories
```

## License

BSD 2-Clause License. See source file headers for details.
