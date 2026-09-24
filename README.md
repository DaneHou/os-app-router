# os-app-router: Application-Aware Routing for OPNsense

English | [中文](README_CN.md)

Route traffic from specific LAN clients through designated gateways based on domain/CIDR categories. For example, route Chinese apps and all mainland China IPs through a China exit while everything else goes through the main WAN — or route work traffic through a VPN gateway while keeping personal traffic on the main WAN.

## Features

- **Built-in Categories**: Curated domain lists for Chinese video, social, shopping, music, and gaming platforms
- **Custom Categories**: Define your own named groups of domains and static CIDRs (e.g., company IP ranges) and use them in routing rules
- **DNS Sniffer**: Real-time capture of DNS responses via tcpdump for reliable CDN IP detection, with automatic expiry of IPs that are no longer handed out
- **China IP Category**: Route every mainland China network (chnroutes2) through a gateway — no DNS involved
- **Per-client Rules**: Apply routing to specific LAN IPs/subnets, or to all traffic (`any`)
- **Custom Domains**: Add per-rule domains beyond built-in categories — subdomains auto-matched
- **Smart Gateway**: Automatic gateway selection with connectivity probing and priority-based fallback
- **Auto-updating Lists**: Scheduled fetching of domain and CIDR lists from remote sources
- **Web UI**: Full OPNsense MVC integration with settings, rule management, and live status dashboard
- **pf Table Integration**: Native FreeBSD packet filter tables for zero-copy routing decisions

## Requirements

- OPNsense 23.7 or later (UI checked in CI against the latest stable branch and master; verified on 26.7)
- A local DNS resolver (Unbound or Dnsmasq) that clients use — must be enabled and running
- `make` utility (pre-installed on OPNsense/FreeBSD)
- Internet access from the firewall (for initial list download)

## Installation

```bash
# On your OPNsense box:
git clone https://github.com/DaneHou/os-app-router.git /tmp/os-app-router
cd /tmp/os-app-router
make install
```

## Upgrade

```bash
cd /tmp/os-app-router && git pull && make install
```

Then open **Services > AppRouter** and click **Apply** so the runtime config is regenerated.

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

1. Enable AppRouter in **Services > AppRouter > General**
2. *(Optional)* Go to **Custom Categories** to define private domain/IP groups (e.g., company VPN ranges)
3. Go to **Routing Rules** and add a rule:
   - **Source**: `any` for all clients, or `192.168.1.0/24` for a subnet
   - **App Categories**: Select built-in or custom categories, or **China Mainland IPs (CIDR list)**
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

### General Settings

| Field | Description |
|-------|-------------|
| Enable AppRouter | Master switch |
| List Update Interval | Hourly, daily or weekly list refresh |
| Learned IP Expiry (hours) | Remove IPs learned from DNS when no answer has returned them for this long (default 24, `0` = never) |
| Table Prefix | Prefix for pf table names (default `approuter`) |

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
   - **Slug**: Short ID used internally (lowercase, letters/numbers/underscores, e.g. `work_vpn`; `china_all` is reserved)
   - **Label**: Display name shown in the rule editor
   - **Domains**: One domain per line or comma-separated; subdomains are auto-matched (e.g. `example.com` catches `cdn.eu-west-1.example.com`)
   - **Static CIDRs**: IP ranges or host IPs routed directly (e.g. `203.0.113.10`, `198.51.100.0/24`); never expired
3. Click **Save**, then **Apply**

**Example — Work Traffic:**
```
Slug:    work_vpn
Label:   Work VPN
Domains: corp.example.com
         intranet.example.net
CIDRs:   203.0.113.10
         198.51.100.0/24
```

Then create a routing rule using `Work VPN` as the category and your VPN gateway as the target.

### Smart Gateway

Smart Gateway enables automatic failover between multiple gateways by probing connectivity.

**Setup:**
1. In a routing rule, select **two or more gateways** (priority order top → bottom)
2. Enable the **Smart Gateway** toggle
3. Choose a probe method:
   - `connect_only` — TCP/TLS connect test (fast)
   - `status_code` — HTTP 2xx/3xx passes; 403/451 count as geo-blocked
   - `body_match` — **Probe Pattern** (regex) matched in the body means blocked
   - `latency` — use the fastest passing gateway
4. Set **Probe URL** (`http://` or `https://` only, default `https://www.google.com`) and **Probe Interval** (30–3600 seconds)

A gateway switches after 3 consistent probe results, with at most one switch per 5 minutes.

The first gateway in priority order that passes the probe becomes active. If it fails, the next gateway is tried. The last gateway always acts as fallback.

### List Sources

AppRouter downloads domain and CIDR lists on a schedule. Configure source URLs and update intervals in the **List Sources** tab. Click **Update Lists Now** for an immediate update or **Force Full Update** to bypass ETag caching.

## How Domains Become Routes

Domain based categories are matched by IP address, learned from DNS:

- `dns_watcher.py` sniffs DNS responses the firewall sends to clients (tcpdump, outbound only) on the interfaces used by rules plus WireGuard interfaces
- A record answers for matching domains (and subdomains) are added to the category's pf table
- Periodic active resolution via `drill` pre-populates tables (every 5 minutes)
- Learned IPs expire when no DNS answer has returned them for **Learned IP Expiry** hours (default 24, `0` = never), so rotating/shared CDN addresses don't pile up
- Works with Unbound or Dnsmasq; domain-to-table mapping files live in `/usr/local/etc/app-router/unbound.d/`

**China Mainland IPs (CIDR list)** is an IP based category: every network in the China CIDR list (chnroutes2) is routed, no DNS involved. For "domestic Chinese apps via a China exit" this is the most robust option; combine it with app categories for services hosted abroad.

### Limitations

- Only plain DNS over UDP port 53 answered via the firewall is seen. Clients using DoH/DoT (browser "secure DNS", iCloud Private Relay) or another resolver bypass domain categories — redirect or block those if you depend on them.
- IPv4 only: AAAA answers are ignored and rules are `inet`. Dual-stack clients may reach services over IPv6 around the rules.
- The first connection after a new DNS answer may still leave via the default gateway; existing states for newly learned IPs are killed so the client reconnects through the rule.

## Verification

```bash
# Check pf tables are populated
pfctl -t approuter_video -T show

# Check a custom category / the China IP table
pfctl -t approuter_work_vpn -T show
pfctl -t approuter_china_all -T show | wc -l

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

If a site that isn't in any category (e.g. a US retailer) is routed through the rule gateway, it most likely shares CDN IPs with a categorized app:

- Learned IPs expire after **Learned IP Expiry** hours without a fresh DNS answer — lower it (e.g. 6) if this happens often.
- Check which table holds the address: `pfctl -t approuter_video -T test <ip>`
- A **China Mainland IPs** rule routes by destination network: sites hosted in mainland China always follow it.

### China CIDR list not loading

The list is only used by rules with the **China Mainland IPs (CIDR list)** category. The default source is `misakaio/chnroutes2`. If the configured URL fails, the plugin falls back to the built-in default URL. If both fail:
1. Check **Status** tab for error messages in logs
2. Update the CIDR URL in **List Sources** (the old `ruijzhan/chnroute` URL is no longer available)
3. Run **Force Full Update**

### Service won't start

1. Verify the plugin is enabled in **General** settings
2. Check syslog: `grep approuter /var/log/system/latest.log`
3. Check DNS watcher log: `cat /var/log/approuter_dns_watcher.log`
4. Verify Unbound/Dnsmasq is running
5. For a single domain end to end: `sh /usr/local/opnsense/scripts/OPNsense/Approuter/diagnose.sh example.com`

## Data Sources

| Source | Content | URL |
|--------|---------|-----|
| dnsmasq-china-list | Chinese domains (downloaded, currently informational) | github.com/felixonmars/dnsmasq-china-list |
| chnroutes2 | China IPv4 CIDRs | github.com/misakaio/chnroutes2 |
| v2fly/domain-list-community | App-specific domains | github.com/v2fly/domain-list-community |
| Built-in categories | Curated app domains | Bundled with plugin |

## Security Notes

- Only DNS responses the firewall *sends* are trusted (`tcpdump -Q out`), so LAN hosts cannot inject addresses with forged packets.
- Domains from remote lists and user input are validated before they are written anywhere; the runtime config is rendered with JSON escaping.
- Probe URLs are restricted to http/https; temporary files use private `mktemp` paths.

## Development

```bash
make install          # Install + activate on OPNsense host
make install-plugin   # Copy files only (no activation)
make activate         # Flush caches, restart services
make lint             # Check Python syntax and XML validity
make test             # lint + pytest (needs pytest and jinja2)
make clean            # Remove __pycache__ and .pyc files

# UI compatibility check against an OPNsense core checkout (needs the phalcon PHP extension)
php tests/ui/render.php src /path/to/opnsense-core/src
```

CI (`.github/workflows/ci.yml`) runs the unit tests and renders the UI against OPNsense core master and the latest stable branch on every push, plus weekly, so upstream template changes are caught before a firmware upgrade.

### File Structure

```
src/
├── etc/inc/plugins.inc.d/
│   └── approuter.inc              # pf tables, rules, services, cron hooks
├── opnsense/mvc/app/
│   ├── controllers/.../Approuter/
│   │   ├── Api/SettingsController.php  # CRUD for rules, settings, categories
│   │   ├── Api/ServiceController.php   # reconfigure, status, start/stop/restart
│   │   └── forms/                      # general, lists and rule dialog form definitions
│   ├── models/.../Approuter.xml    # XML schema (settings, rules, lists, custom categories)
│   └── views/.../index.volt        # Single-page UI
├── opnsense/scripts/.../Approuter/
│   ├── list_updater.py             # Fetch/process remote lists, write domain mappings and CIDR files
│   ├── dns_watcher.py              # DNS sniffer daemon (tcpdump-based), learned IP expiry
│   ├── geo_prober.py               # Smart gateway connectivity prober
│   ├── table_manager.sh            # pfctl table operations
│   ├── diagnose.sh                 # Manual troubleshooting helper (sh diagnose.sh <domain>)
│   └── app_categories.json         # Built-in domain categories
└── opnsense/service/templates/.../approuter.conf  # config.json template (configd)
tests/
├── test_*.py                       # pytest: list parsing, expiry, template rendering
└── ui/render.php                   # renders the page against an OPNsense core checkout
```

## License

BSD 2-Clause License. See source file headers for details.
