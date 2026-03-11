# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OPNsense plugin for application-aware traffic routing. Routes traffic through specific gateways based on domain/CIDR categories (e.g., route all video streaming through WAN2). Integrates with FreeBSD's pf packet filter and supports Dnsmasq (ipset) or Unbound (log watcher) for DNS-based resolution.

## Build & Install Commands

```bash
make install          # Install plugin to /usr/local and activate (flush caches, restart configd/php-fpm)
make install-plugin   # Copy files without activation
make activate         # Flush caches, verify PHP, restart services
make uninstall        # Remove plugin (preserves config.json)
make clean            # Remove __pycache__ and .pyc files
make lint             # Check Python syntax and XML validity
```

All installation targets `/usr/local/` on the OPNsense/FreeBSD host. Development is done on a separate machine and deployed via `make install` to the firewall.

## Architecture

### Request Flow

```
Web UI (Volt/jQuery) → REST API (PHP Controllers) → configd actions → Python/Shell scripts → pf tables & route-to rules
```

### Layer Breakdown

**PHP MVC Layer** (`src/opnsense/mvc/app/`):
- `models/OPNsense/Approuter/Approuter.xml` — XML schema defining settings, rules, and lists. Central config structure.
- `controllers/.../Api/SettingsController.php` — CRUD for rules/settings. Extends `ApiMutableModelControllerBase`. Augments getRule with gateway dropdown and category multi-select from `app_categories.json`.
- `controllers/.../Api/ServiceController.php` — reconfigure (Apply), updateLists, forceUpdate, status. Extends `ApiMutableServiceControllerBase`.
- `views/.../index.volt` — Single-page UI with Bootstrap/jQuery, uses OPNsense bootgrid for rule table.

**Plugin Hooks** (`src/etc/inc/plugins.inc.d/approuter.inc`):
- `approuter_firewall()` — Registers pf tables and route-to rules with OPNsense firewall engine
- `approuter_services()` — Registers dns_watcher as a managed service
- `approuter_cron()` — Schedules periodic list updates
- `approuter_syslog()` — Registers log facilities

**Backend Scripts** (`src/opnsense/scripts/OPNsense/Approuter/`):
- `list_updater.py` — Fetches remote domain/CIDR lists, aggregates CIDRs, writes pf table files
- `dns_watcher.py` — Daemon monitoring Unbound logs, resolves domains → IPs into pf tables
- `table_manager.sh` — Shell wrapper for `pfctl` table operations
- `app_categories.json` — Built-in domain definitions (categories → apps → domains)

**configd Actions** (`src/opnsense/service/conf/actions.d/actions_approuter.conf`):
- Maps API calls to script invocations. INI format. Each action defines command, parameters, message type.

**Config Template** (`src/opnsense/service/templates/OPNsense/Approuter/approuter.conf`):
- Jinja2 template generating runtime `/usr/local/etc/app-router/config.json` from OPNsense config.xml

### Key API Endpoints

```
/api/approuter/settings/{get,set}                    — General settings
/api/approuter/settings/{searchRule,getRule,addRule,setRule,delRule,toggleRule}  — Rule CRUD
/api/approuter/settings/getCategories                — Category list from app_categories.json
/api/approuter/settings/getGateways                  — Gateway list from Routing model
/api/approuter/service/{reconfigure,updateLists,forceUpdate,status}  — Service operations
```

### Dual DNS Modes

- **Dnsmasq**: Native ipset support — domains resolved directly into pf tables at DNS query time
- **Unbound**: `dns_watcher.py` daemon tails resolver log, parses A/AAAA answers, adds IPs to tables via pfctl

## Platform Conventions

- Python shebang: `#!/usr/local/bin/python3` (FreeBSD path)
- Logging: syslog with `daemon` facility, tags `approuter` / `approuter-dns`
- PID file: `/var/run/approuter_dns_watcher.pid`
- State file: `/usr/local/etc/app-router/state.json`
- Config dir: `/usr/local/etc/app-router/`
- OPNsense model mount: `//OPNsense/Approuter`
- PHP base classes: `OPNsense\Base\BaseModel`, `ApiMutableModelControllerBase`, `ApiMutableServiceControllerBase`
