# os-app-router: Application-Aware Routing for OPNsense

English | [中文](README_CN.md)

Route traffic from specific LAN clients through designated gateways based on domain/CIDR categories. For example, route all Chinese video streaming through WAN2 while everything else goes through WAN1 — or route corporate VPN traffic through a company gateway while keeping personal traffic on the main WAN.

## Features

- **Built-in Categories**: Curated domain lists for Chinese video, social, shopping, music, and gaming platforms
- **Custom Categories**: Define your own named groups of domains and static CIDRs (e.g., company IP ranges) and use them in routing rules
- **DNS Sniffer**: Real-time capture of DNS responses via tcpdump for reliable CDN IP detection
- **CIDR List Support**: Static IP range routing using community-maintained lists (chnroutes2, etc.)
- **Per-client Rules**: Apply routing to specific LAN IPs/subnets, or to all traffic (`any`)
- **Custom Domains**: Add per-rule domains beyond built-in categories — subdomains auto-matched
- **Smart Gateway**: Automatic gateway selection with connectivity probing and priority-based fallback
- **Auto-updating Lists**: Scheduled fetching of domain and CIDR lists from remote sources
- **Web UI**: Full OPNsense MVC integration with settings, rule management, and live status dashboard
- **pf Table Integration**: Native FreeBSD packet filter tables for zero-copy routing decisions

## Requirements

- OPNsense 23.7 or later
- DNS resolver: **Dnsmasq** (recommended) or **Unbound** — must be enabled and running
- `make` utility (pre-installed on OPNsense/FreeBSD)
- Internet access from the firewall (for initial list download)

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

Removes all plugin files, caches, generated data, and pf tables. User config (`/usr/local/etc/app-router/config.json`) is preserved. To fully remove:

```bash
rm -rf /usr/local/etc/app-router
```

## Quick Start

1. Enable AppRouter in **Services > AppRouter > General** and select your DNS resolver
2. *(Optional)* Go to **Custom Categories** to define private domain/IP groups (e.g., company VPN ranges)
3. Go to **Routing Rules** and add a rule:
   - **Source**: `any` for all clients, or `192.168.1.0/24` for a subnet
   - **App Categories**: Select built-in or custom categories
   - **Gateway**: Target gateway for matched traffic
4. Click **Save**, then **Apply** — this starts the service automatically
5. Go to **List Sources** and click **Update Lists Now** to download the latest domain/CIDR data

## Configuration

### Routing Rules

Each rule routes traffic from a source (LAN clients) to a gateway based on categories or custom domains.

| Field | Description |
|-------|-------------|
| Description | Human-readable name for the rule |
| Interface | Inbound interface (typically LAN) |
| Source | Client filter: `any`, single IP, subnet, or comma-separated list |
| App Categories | One or more built-in or custom categories |
| Custom Domains | Extra domains for this rule only; subdomains auto-matched |
| Gateway | Target gateway — select multiple to enable Smart Gateway |
| Smart Gateway | Enable automatic gateway probing and fallback (requires 2+ gateways) |

**Source examples:**
```
any                              — all LAN clients
192.168.1.100                   — single host
192.168.1.0/24                  — subnet
192.168.1.0/24,10.0.0.5         — mixed
```

### Custom Categories

Custom categories let you define named groups of domains and static CIDRs that appear alongside built-in categories in the rule editor.

**Creating a category:**
1. Go to **Custom Categories** tab → **Add Category**
2. Fill in:
   - **Slug**: Short ID used internally (lowercase, letters/numbers/underscores, e.g. `ba_work`)
   - **Label**: Display name shown in the rule editor
   - **Domains**: One domain per line or comma-separated; subdomains are auto-matched (e.g. `amazonaws-us-gov.com` catches `s3.us-gov-west-1.amazonaws-us-gov.com`)
   - **Static CIDRs**: IP ranges or host IPs routed directly (e.g. `172.16.20.85`, `10.0.0.0/24`)
3. Click **Save**, then **Apply**

**Example — Company Traffic:**
```
Slug:    ba_work
Label:   BA Work
Domains: atlassian.net
         confluence.example.com
         amazonaws-us-gov.com
CIDRs:   172.16.20.85
         172.16.16.0/24
```

Then create a routing rule using `BA Work` as the category and your VPN gateway as the target.

### Smart Gateway

Smart Gateway enables automatic failover between multiple gateways by probing connectivity.

**Setup:**
1. In a routing rule, select **two or more gateways** (priority order top → bottom)
2. Enable the **Smart Gateway** toggle
3. Choose a probe method:
   - `connect_only` — TCP connect test (fast, no HTTP overhead)
   - `http_2xx` — Requires HTTP 200–299 response
   - `body_match` — Requires a pattern in the HTTP response body
4. Set **Probe URL** (e.g. `https://www.google.com`) and **Probe Interval** (seconds)

The first gateway in priority order that passes the probe becomes active. If it fails, the next gateway is tried. The last gateway always acts as fallback.

### List Sources

AppRouter downloads domain and CIDR lists on a schedule. Configure source URLs and update intervals in the **List Sources** tab. Click **Update Lists Now** for an immediate update or **Force Full Update** to bypass ETag caching.

## DNS Modes

### Dnsmasq (ipset) — Recommended

- Domains resolved directly into pf tables at DNS query time via Dnsmasq's native `ipset` directive
- Config files generated in `/usr/local/etc/app-router/dnsmasq.d/`
- Most efficient: zero-latency IP capture

### Unbound (DNS Sniffer)

- `dns_watcher.py` daemon sniffs DNS responses via tcpdump on LAN interfaces
- Parses A record answers and adds IPs to pf tables via pfctl
- Also runs periodic active resolution via `drill` as fallback (every 5 minutes)
- Domain-to-table mapping files in `/usr/local/etc/app-router/unbound.d/`

## Verification

```bash
# Check pf tables are populated
pfctl -t approuter_video -T show

# Check a custom category table
pfctl -t approuter_ba_work -T show

# Check routing rules are installed
pfctl -sr | grep approuter

# Test from a LAN client
traceroute bilibili.com   # Should show traffic going through configured gateway
```

## Troubleshooting

### Traffic not being routed

1. Check **Status** tab: ensure DNS watcher shows green (running)
2. Verify pf tables have entries — empty tables mean DNS hasn't resolved those domains yet
3. Try **Force Full Update** to refresh all lists
4. Check that the gateway is online in **System > Gateways > Status**

### CDN IPs not captured

CDN domains return different IPs based on resolver location and timing. The DNS sniffer captures IPs as clients resolve them.

1. The sniffer catches new IPs in real time as DNS queries arrive
2. Active resolution runs every 5 minutes as fallback via `drill`
3. If a site still doesn't route: browse to it from a client — the DNS query triggers immediate capture

### Static CIDRs not taking effect

If you added CIDRs to a Custom Category but traffic still doesn't route:

1. Click **Apply** on the Custom Categories tab (or the Routing Rules tab)
2. Verify the table has your entries: `pfctl -t approuter_SLUG -T show`
3. If entries are missing after Apply, check the syslog: `grep approuter /var/log/system/latest.log`

### Unrelated sites blocked or getting geo-errors

If a commercial site (e.g. a US retailer) gives geo-block errors only on some devices:

- This was previously caused by broad `/24` subnet blocks being added to category tables when CDN providers shared IP ranges across sites. This behavior has been removed — AppRouter now only adds specific resolved IPs.
- If you still see stale `/24` entries in a table, click **Apply** to flush and repopulate it cleanly.

### China CIDR list not loading

The default source is `misakaio/chnroutes2`. If the configured URL fails, the plugin falls back to the built-in default URL. If both fail:
1. Check **Status** tab for error messages in logs
2. Update the CIDR URL in **List Sources** (the old `ruijzhan/chnroute` URL is no longer available)
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
│   │   ├── SettingsController.php  # CRUD for rules, settings, categories
│   │   └── ServiceController.php   # reconfigure, status, start/stop/restart
│   ├── models/.../Approuter.xml    # XML schema (settings, rules, lists, custom categories)
│   └── views/.../index.volt        # Single-page UI
└── opnsense/scripts/.../Approuter/
    ├── list_updater.py             # Fetch/process remote lists, generate DNS configs
    ├── dns_watcher.py              # DNS sniffer daemon (tcpdump-based)
    ├── geo_prober.py               # Smart gateway connectivity prober
    ├── table_manager.sh            # pfctl table operations
    └── app_categories.json         # Built-in domain categories
```

## License

BSD 2-Clause License. See source file headers for details.
