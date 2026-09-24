# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OPNsense plugin for application-aware traffic routing. Routes traffic through specific gateways based on domain/CIDR categories (e.g., route all video streaming through WAN2). Integrates with FreeBSD's pf packet filter; domain categories are turned into IPs by a DNS response sniffer (works with Unbound or Dnsmasq).

## Build & Install Commands

```bash
make install          # Install plugin to /usr/local and activate (flush caches, restart configd/php-fpm)
make install-plugin   # Copy files without activation
make activate         # Flush caches, verify PHP, restart services
make uninstall        # Remove plugin (preserves config.json)
make clean            # Remove __pycache__ and .pyc files
make lint             # Check Python syntax and XML validity
make test             # lint + pytest (tests/, needs pytest + jinja2)

# UI compatibility check against an OPNsense core checkout (needs the phalcon extension)
php tests/ui/render.php src /path/to/opnsense-core/src
```

CI (`.github/workflows/ci.yml`) runs both, plus a weekly render against core master.

All installation targets `/usr/local/` on the OPNsense/FreeBSD host. Development is done on a separate machine and deployed via `make install` to the firewall.

## Architecture

### Request Flow

```
Web UI (Volt/jQuery) → REST API (PHP Controllers) → configd actions → Python/Shell scripts → pf tables & route-to rules
```

### Layer Breakdown

**PHP MVC Layer** (`src/opnsense/mvc/app/`):
- `models/OPNsense/Approuter/Approuter.xml` — XML schema defining settings, rules, and lists. Central config structure.
- `controllers/.../Api/SettingsController.php` — CRUD for rules/settings. Extends `ApiMutableModelControllerBase`. Augments getRule with gateway dropdown and category multi-select (`china_all` + `app_categories.json` + custom categories).
- `controllers/.../forms/*.xml` — `general`, `lists` and `dialogRule` forms, loaded with `getForm()` in `IndexController`. Dialogs must use a form XML: since OPNsense 26.7 `base_dialog.volt` expects the `getForm()` structure (`{sections: [...]}`); an inline field list crashes the page.
- `controllers/.../Api/ServiceController.php` — reconfigure (Apply), updateLists, forceUpdate, status/detailStatus, start/stop/restart. Extends `ApiMutableServiceControllerBase`. Custom `statusAction` checks dns_watcher via configd and returns `widget` section for `updateServiceControlUI()`.
- `views/.../index.volt` — Single-page UI with Bootstrap/jQuery, uses OPNsense bootgrid for rule table.

**Plugin Hooks** (`src/etc/inc/plugins.inc.d/approuter.inc`):
- `approuter_firewall()` — Registers pf tables and route-to rules with OPNsense firewall engine
- `approuter_services()` — Registers dns_watcher as a managed service
- `approuter_cron()` — Schedules periodic list updates
- `approuter_syslog()` — Registers log facilities

**Backend Scripts** (`src/opnsense/scripts/OPNsense/Approuter/`):
- `list_updater.py` — Fetches remote domain/CIDR lists (with fallback URLs) and v2fly domains, validates domains, aggregates CIDRs, writes domain mapping files (`unbound.d/`) and CIDR files (`cidrs/`). `generate_dns` (run on Apply) reuses the cached merged v2fly domains from `domains/`.
- `dns_watcher.py` — Daemon sniffing outbound DNS responses via tcpdump, adds resolved IPs to pf tables and expires stale ones. Also runs periodic active resolution via `drill` as fallback.
- `geo_prober.py` — Smart gateway prober (curl per gateway interface), fills/flushes `_gwN` tables.
- `table_manager.sh` — Shell wrapper for `pfctl` table operations
- `app_categories.json` — Built-in domain definitions (categories → apps → domains)

**configd Actions** (`src/opnsense/service/conf/actions.d/actions_approuter.conf`):
- Maps API calls to script invocations. INI format. Each action defines command, parameters, message type.

**Config Template** (`src/opnsense/service/templates/OPNsense/Approuter/approuter.conf`):
- Jinja2 template generating runtime `/usr/local/etc/app-router/config.json` from OPNsense config.xml. Every string value must go through `|tojson`.

### Key API Endpoints

```
/api/approuter/settings/{get,set}                    — General settings
/api/approuter/settings/{searchRule,getRule,addRule,setRule,delRule,toggleRule}  — Rule CRUD
/api/approuter/settings/getCategories                — Category list from app_categories.json
/api/approuter/settings/getGateways                  — Gateway list from Routing model
/api/approuter/service/{reconfigure,updateLists,forceUpdate}          — Service operations
/api/approuter/service/{status,start,stop,restart}                   — Service control (used by updateServiceControlUI)
/api/approuter/service/detailStatus                                  — Detailed status (pf tables, rule stats, logs)
```

### DNS Learning

- `dns_watcher.py` sniffs outbound DNS responses (tcpdump `-Q out`) on rule interfaces (resolved via `/conf/config.xml`), Unbound listen interfaces and `wg*`; A answers for mapped domains are added to pf tables via pfctl
- Learned IPs age out after `general.ipExpireHours` (tracked in `ip_seen.json`); static custom-category CIDRs are never expired
- `general.dnsResolver` is kept only for config compatibility; there is no Dnsmasq ipset integration
- `china_all` is a built-in IP category backed by `cidrs/china_all.txt` (chnroutes2); the slug is reserved

### UI Conventions

- `updateServiceControlUI('approuter')` — OPNsense standard service widget (green/red indicator + start/stop/restart). Requires `statusAction` to return `{status, widget}` format.
- Bootgrid URLs for UUID-based endpoints (get/set/del/toggle) must have trailing `/` — OPNsense bootgrid appends UUID directly to the URL string.
- Tab persistence via URL hash (`#general`, `#rules`, `#lists`, `#status`).
- `loadStatus()` defined inside `$(document).ready` — use jQuery `.click()` handler, not inline `onclick`.

## Platform Conventions

- Python shebang: `#!/usr/local/bin/python3` (FreeBSD path)
- Logging: syslog with `daemon` facility, tags `approuter` / `approuter-dns`
- PID file: `/var/run/approuter_dns_watcher.pid`
- State file: `/usr/local/etc/app-router/state.json`
- Config dir: `/usr/local/etc/app-router/`
- OPNsense model mount: `//OPNsense/Approuter`
- PHP base classes: `OPNsense\Base\BaseModel`, `ApiMutableModelControllerBase`, `ApiMutableServiceControllerBase`
