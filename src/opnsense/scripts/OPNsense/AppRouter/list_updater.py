#!/usr/local/bin/python3
"""
AppRouter List Updater
Fetches and processes domain and CIDR lists from remote sources.
Runs via configd cron to keep routing data up to date.
"""

import json
import os
import sys
import subprocess
import time
import ipaddress
import urllib.request
import urllib.error
import syslog
import hashlib
from pathlib import Path

BASE_DIR = "/usr/local/etc/app-router"
DOMAINS_DIR = os.path.join(BASE_DIR, "domains")
CIDRS_DIR = os.path.join(BASE_DIR, "cidrs")
DNSMASQ_DIR = os.path.join(BASE_DIR, "dnsmasq.d")
UNBOUND_DIR = os.path.join(BASE_DIR, "unbound.d")
CATEGORIES_FILE = "/usr/local/opnsense/scripts/OPNsense/AppRouter/app_categories.json"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
STATE_FILE = os.path.join(BASE_DIR, "state.json")

DEFAULT_SOURCES = {
    "china_domains": {
        "url": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
        "type": "dnsmasq",
        "description": "China accelerated domains (felixonmars)"
    },
    "china_cidrs_v4": {
        "url": "https://raw.githubusercontent.com/ruijzhan/chnroute/master/chnroute.txt",
        "type": "cidr",
        "description": "China IPv4 CIDR blocks (APNIC)"
    }
}


def log(msg, level=syslog.LOG_INFO):
    syslog.openlog("approuter", syslog.LOG_PID, syslog.LOG_DAEMON)
    syslog.syslog(level, msg)
    syslog.closelog()


def ensure_dirs():
    for d in [BASE_DIR, DOMAINS_DIR, CIDRS_DIR, DNSMASQ_DIR, UNBOUND_DIR]:
        os.makedirs(d, mode=0o755, exist_ok=True)


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_categories():
    with open(CATEGORIES_FILE, "r") as f:
        return json.load(f)


def fetch_url(url, etag=None, timeout=30):
    """Fetch URL with optional ETag caching. Returns (content, new_etag, changed)."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "OPNsense-AppRouter/1.0")
    if etag:
        req.add_header("If-None-Match", etag)

    try:
        response = urllib.request.urlopen(req, timeout=timeout)
        content = response.read().decode("utf-8", errors="replace")
        new_etag = response.headers.get("ETag", "")
        return content, new_etag, True
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return None, etag, False
        raise
    except urllib.error.URLError as e:
        log(f"Failed to fetch {url}: {e}", syslog.LOG_ERR)
        raise


def parse_dnsmasq_domains(content):
    """Parse dnsmasq-china-list format: server=/domain.com/114.114.114.114"""
    domains = set()
    for line in content.strip().split("\n"):
        line = line.strip()
        if line.startswith("server=/") and line.count("/") >= 2:
            parts = line.split("/")
            if len(parts) >= 3 and parts[1]:
                domains.add(parts[1].lower())
    return domains


def parse_cidr_list(content):
    cidrs = set()
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            cidrs.add(str(net))
        except ValueError:
            continue
    return cidrs


def aggregate_cidrs(cidrs):
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    collapsed = list(ipaddress.collapse_addresses(networks))
    return sorted([str(n) for n in collapsed])


def write_domain_file(category, domains):
    filepath = os.path.join(DOMAINS_DIR, f"{category}.txt")
    content = "\n".join(sorted(domains)) + "\n"
    write_if_changed(filepath, content)
    return filepath


def write_cidr_file(category, cidrs):
    filepath = os.path.join(CIDRS_DIR, f"{category}.txt")
    content = "\n".join(sorted(cidrs)) + "\n"
    write_if_changed(filepath, content)
    return filepath


def write_if_changed(filepath, content):
    new_hash = hashlib.sha256(content.encode()).hexdigest()
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            old_hash = hashlib.sha256(f.read().encode()).hexdigest()
        if old_hash == new_hash:
            return False
    with open(filepath, "w") as f:
        f.write(content)
    return True


def generate_dnsmasq_conf(categories, table_prefix="approuter"):
    """Generate Dnsmasq ipset config snippets per category."""
    for cat_id, cat_data in categories.items():
        lines = []
        table_name = f"{table_prefix}_{cat_id}"
        for domain in sorted(cat_data.get("domains", [])):
            lines.append(f"ipset=/{domain}/{table_name}")
        content = f"# AppRouter: {cat_data.get('name', cat_id)}\n"
        content += f"# Auto-generated - do not edit\n"
        content += "\n".join(lines) + "\n"
        filepath = os.path.join(DNSMASQ_DIR, f"approuter_{cat_id}.conf")
        write_if_changed(filepath, content)
    log(f"Generated Dnsmasq configs for {len(categories)} categories")


def generate_unbound_conf(categories, table_prefix="approuter"):
    """Generate Unbound domain-to-table mapping files."""
    for cat_id, cat_data in categories.items():
        domains = cat_data.get("domains", [])
        table_name = f"{table_prefix}_{cat_id}"
        mapping = {
            "table": table_name,
            "domains": sorted(domains)
        }
        filepath = os.path.join(UNBOUND_DIR, f"approuter_{cat_id}.json")
        write_if_changed(filepath, json.dumps(mapping, indent=2) + "\n")
    log(f"Generated Unbound configs for {len(categories)} categories")


def update_remote_lists(config, state):
    sources = config.get("sources", DEFAULT_SOURCES)
    custom_sources = config.get("custom_sources", [])
    china_domains = set()
    china_cidrs = set()
    updated = False

    for source_id, source in sources.items():
        url = source["url"]
        etag = state.get(f"etag_{source_id}", "")
        try:
            content, new_etag, changed = fetch_url(url, etag)
            state[f"etag_{source_id}"] = new_etag
            state[f"last_update_{source_id}"] = int(time.time())

            if changed and content:
                if source["type"] == "dnsmasq":
                    domains = parse_dnsmasq_domains(content)
                    china_domains.update(domains)
                    log(f"Fetched {len(domains)} domains from {source_id}")
                elif source["type"] == "cidr":
                    cidrs = parse_cidr_list(content)
                    china_cidrs.update(cidrs)
                    log(f"Fetched {len(cidrs)} CIDRs from {source_id}")
                updated = True
            elif not changed:
                log(f"Source {source_id} not modified (ETag match)")
        except Exception as e:
            log(f"Error fetching {source_id}: {e}", syslog.LOG_ERR)
            state[f"last_error_{source_id}"] = str(e)

    for idx, custom in enumerate(custom_sources):
        url = custom.get("url", "")
        stype = custom.get("type", "cidr")
        if not url:
            continue
        source_id = f"custom_{idx}"
        etag = state.get(f"etag_{source_id}", "")
        try:
            content, new_etag, changed = fetch_url(url, etag)
            state[f"etag_{source_id}"] = new_etag
            if changed and content:
                if stype == "domain":
                    for line in content.strip().split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            china_domains.add(line.lower())
                elif stype == "cidr":
                    china_cidrs.update(parse_cidr_list(content))
                updated = True
        except Exception as e:
            log(f"Error fetching custom source {idx}: {e}", syslog.LOG_ERR)

    if china_cidrs:
        aggregated = aggregate_cidrs(china_cidrs)
        write_cidr_file("china_all", aggregated)
        state["china_cidrs_count"] = len(aggregated)
        log(f"Written {len(aggregated)} aggregated China CIDRs")

    if china_domains:
        write_domain_file("china_all", china_domains)
        state["china_domains_count"] = len(china_domains)
        log(f"Written {len(china_domains)} China domains")

    return updated


def update_tables():
    script = "/usr/local/opnsense/scripts/OPNsense/AppRouter/table_manager.sh"
    if os.path.exists(script):
        try:
            subprocess.run([script, "reload_all"], check=True, timeout=30)
            log("pf tables reloaded successfully")
        except subprocess.CalledProcessError as e:
            log(f"Table reload failed: {e}", syslog.LOG_ERR)
        except subprocess.TimeoutExpired:
            log("Table reload timed out", syslog.LOG_ERR)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "update"

    ensure_dirs()
    config = load_config()
    state = load_state()
    categories = load_categories()

    if action == "update":
        log("Starting list update")
        updated = update_remote_lists(config, state)
        for cat_id, cat_data in categories.items():
            write_domain_file(cat_id, cat_data.get("domains", []))
        generate_dnsmasq_conf(categories)
        generate_unbound_conf(categories)
        state["last_full_update"] = int(time.time())
        save_state(state)
        if updated:
            update_tables()
        log("List update completed")

    elif action == "generate_dns":
        generate_dnsmasq_conf(categories)
        generate_unbound_conf(categories)
        log("DNS configs regenerated")

    elif action == "status":
        state["categories"] = {k: len(v.get("domains", [])) for k, v in categories.items()}
        print(json.dumps(state, indent=2))

    elif action == "force":
        log("Starting forced list update")
        for key in list(state.keys()):
            if key.startswith("etag_"):
                del state[key]
        update_remote_lists(config, state)
        for cat_id, cat_data in categories.items():
            write_domain_file(cat_id, cat_data.get("domains", []))
        generate_dnsmasq_conf(categories)
        generate_unbound_conf(categories)
        state["last_full_update"] = int(time.time())
        save_state(state)
        update_tables()
        log("Forced list update completed")

    else:
        print(f"Usage: {sys.argv[0]} [update|generate_dns|status|force]")
        sys.exit(1)


if __name__ == "__main__":
    main()
