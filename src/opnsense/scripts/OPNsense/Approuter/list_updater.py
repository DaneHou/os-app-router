#!/usr/local/bin/python3
"""
AppRouter List Updater
Fetches and processes domain and CIDR lists from remote sources.
Runs via configd cron to keep routing data up to date.
"""

import json
import os
import socket
import sys
import subprocess
import time
import ipaddress
import urllib.request
import urllib.error
import syslog
import hashlib
from pathlib import Path

# Force IPv4 for all network operations (workaround for broken IPv6 on some systems)
_orig_getaddrinfo = socket.getaddrinfo
def _getaddrinfo_ipv4(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _getaddrinfo_ipv4

BASE_DIR = "/usr/local/etc/app-router"
DOMAINS_DIR = os.path.join(BASE_DIR, "domains")
CIDRS_DIR = os.path.join(BASE_DIR, "cidrs")
DNSMASQ_DIR = os.path.join(BASE_DIR, "dnsmasq.d")
UNBOUND_DIR = os.path.join(BASE_DIR, "unbound.d")
CATEGORIES_FILE = "/usr/local/opnsense/scripts/OPNsense/Approuter/app_categories.json"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
STATE_FILE = os.path.join(BASE_DIR, "state.json")

V2FLY_BASE_URL = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data"

DEFAULT_SOURCES = {
    "china_domains": {
        "url": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
        "type": "dnsmasq",
        "description": "China accelerated domains (felixonmars)"
    },
    "china_cidrs_v4": {
        "url": "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt",
        "type": "cidr",
        "description": "China IPv4 CIDR blocks (chnroutes2)"
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


def fetch_v2fly_domains(name, depth=0):
    """Fetch and parse a v2fly/domain-list-community data file.
    Returns a set of domain suffixes. Follows include: directives up to depth 1.
    Skips @ads tagged entries, keyword:, and regexp: entries.
    """
    if depth > 1:
        return set()
    url = f"{V2FLY_BASE_URL}/{name}"
    try:
        content, _, _ = fetch_url(url, timeout=10)
    except Exception as e:
        log(f"Failed to fetch v2fly/{name}: {e}", syslog.LOG_WARNING)
        return set()

    domains = set()
    if not content:
        return domains

    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Skip ads-tagged entries
        if "@ads" in line:
            continue
        # Handle include directives
        if line.startswith("include:"):
            inc_name = line.split(":")[1].strip().split()[0]
            domains.update(fetch_v2fly_domains(inc_name, depth + 1))
            continue
        # Skip keyword and regexp entries
        if line.startswith("keyword:") or line.startswith("regexp:"):
            continue
        # Strip full: prefix and @attributes
        entry = line
        if entry.startswith("full:"):
            entry = entry[5:]
        # Remove @attr tags
        if " @" in entry or "\t@" in entry:
            entry = entry.split()[0]
        entry = entry.strip().lower()
        if entry:
            domains.add(entry)

    return domains


def update_v2fly_domains(categories, state):
    """Fetch v2fly domain lists for apps that have a 'v2fly' field.
    Merges remote domains with local fallback domains.
    Returns dict of {cat_id.app_id: merged_domains_set}.
    """
    merged = {}
    for cat_id, cat_data in categories.items():
        if "apps" not in cat_data:
            continue
        for app_id, app_data in cat_data["apps"].items():
            v2fly_name = app_data.get("v2fly")
            if not v2fly_name:
                continue
            key = f"{cat_id}.{app_id}"
            state_key = f"v2fly_{v2fly_name}"
            remote_domains = fetch_v2fly_domains(v2fly_name)
            if remote_domains:
                state[f"last_update_{state_key}"] = int(time.time())
                state[f"count_{state_key}"] = len(remote_domains)
                log(f"Fetched {len(remote_domains)} domains from v2fly/{v2fly_name} for {key}")
            else:
                log(f"No domains from v2fly/{v2fly_name}, using local fallback for {key}",
                    syslog.LOG_WARNING)
            # Merge: remote + local fallback
            local_domains = set(app_data.get("domains", []))
            merged[key] = remote_domains | local_domains
    return merged


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


def get_all_domains_for_category(cat_data):
    """Get all domains for a category (union of all apps)."""
    domains = set()
    if "apps" in cat_data:
        for app_data in cat_data["apps"].values():
            domains.update(app_data.get("domains", []))
    elif "domains" in cat_data:
        # Legacy flat format fallback
        domains.update(cat_data["domains"])
    return domains


def generate_dnsmasq_conf(categories, table_prefix="approuter", v2fly_merged=None):
    """Generate Dnsmasq ipset config snippets per category and per app."""
    v2fly_merged = v2fly_merged or {}
    for cat_id, cat_data in categories.items():
        # Category-level config (all apps combined)
        all_domains = get_all_domains_for_category(cat_data)
        # Merge v2fly domains into category level
        if "apps" in cat_data:
            for app_id in cat_data["apps"]:
                key = f"{cat_id}.{app_id}"
                if key in v2fly_merged:
                    all_domains.update(v2fly_merged[key])
        lines = []
        table_name = f"{table_prefix}_{cat_id}"
        for domain in sorted(all_domains):
            lines.append(f"ipset=/{domain}/{table_name}")
        content = f"# AppRouter: {cat_data.get('name', cat_id)}\n"
        content += f"# Auto-generated - do not edit\n"
        content += "\n".join(lines) + "\n"
        filepath = os.path.join(DNSMASQ_DIR, f"approuter_{cat_id}.conf")
        write_if_changed(filepath, content)

        # Per-app configs
        if "apps" in cat_data:
            for app_id, app_data in cat_data["apps"].items():
                key = f"{cat_id}.{app_id}"
                app_domains = v2fly_merged.get(key, set(app_data.get("domains", [])))
                app_table = f"{table_prefix}_{cat_id}_{app_id}"
                app_lines = []
                for domain in sorted(app_domains):
                    app_lines.append(f"ipset=/{domain}/{app_table}")
                app_content = f"# AppRouter: {app_data.get('label', app_id)}\n"
                app_content += f"# Auto-generated - do not edit\n"
                app_content += "\n".join(app_lines) + "\n"
                app_filepath = os.path.join(DNSMASQ_DIR, f"approuter_{cat_id}_{app_id}.conf")
                write_if_changed(app_filepath, app_content)

    log(f"Generated Dnsmasq configs for {len(categories)} categories")


def generate_unbound_conf(categories, table_prefix="approuter", v2fly_merged=None, config=None):
    """Generate Unbound domain-to-table mapping files per category and per app."""
    v2fly_merged = v2fly_merged or {}
    for cat_id, cat_data in categories.items():
        # Category-level
        all_domains = get_all_domains_for_category(cat_data)
        if "apps" in cat_data:
            for app_id in cat_data["apps"]:
                key = f"{cat_id}.{app_id}"
                if key in v2fly_merged:
                    all_domains.update(v2fly_merged[key])
        table_name = f"{table_prefix}_{cat_id}"
        mapping = {
            "table": table_name,
            "domains": sorted(all_domains)
        }
        filepath = os.path.join(UNBOUND_DIR, f"approuter_{cat_id}.json")
        write_if_changed(filepath, json.dumps(mapping, indent=2) + "\n")

        # Per-app
        if "apps" in cat_data:
            for app_id, app_data in cat_data["apps"].items():
                key = f"{cat_id}.{app_id}"
                app_domains = v2fly_merged.get(key, set(app_data.get("domains", [])))
                app_table = f"{table_prefix}_{cat_id}_{app_id}"
                app_mapping = {
                    "table": app_table,
                    "domains": sorted(app_domains)
                }
                app_filepath = os.path.join(UNBOUND_DIR, f"approuter_{cat_id}_{app_id}.json")
                write_if_changed(app_filepath, json.dumps(app_mapping, indent=2) + "\n")

    log(f"Generated Unbound configs for {len(categories)} categories")

    # Generate custom domain mapping files from rules
    if config:
        generate_custom_domain_mappings(config, table_prefix)


def generate_custom_domain_mappings(config, table_prefix="approuter"):
    """Generate Unbound mapping files for per-rule custom domains."""
    rules = config.get("rules", [])
    custom_count = 0
    for rule in rules:
        custom_str = rule.get("custom_domains", "").strip()
        if not custom_str:
            continue
        domains = [d.strip().lower() for d in custom_str.split(",") if d.strip()]
        if not domains:
            continue
        # Match PHP hook: substr(md5(uuid), 0, 8)
        rule_uuid = rule.get("uuid", "")
        rule_id = hashlib.md5(rule_uuid.encode()).hexdigest()[:8]
        table_name = f"{table_prefix}_custom_{rule_id}"
        mapping = {
            "table": table_name,
            "domains": sorted(domains)
        }
        filepath = os.path.join(UNBOUND_DIR, f"approuter_custom_{rule_id}.json")
        write_if_changed(filepath, json.dumps(mapping, indent=2) + "\n")
        custom_count += 1
    if custom_count:
        log(f"Generated {custom_count} custom domain mapping files")


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
    script = "/usr/local/opnsense/scripts/OPNsense/Approuter/table_manager.sh"
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
        # Fetch v2fly domains and merge into categories
        v2fly_merged = update_v2fly_domains(categories, state)
        for cat_id, cat_data in categories.items():
            all_domains = get_all_domains_for_category(cat_data)
            if "apps" in cat_data:
                for app_id, app_data in cat_data["apps"].items():
                    key = f"{cat_id}.{app_id}"
                    app_domains = v2fly_merged.get(key, set(app_data.get("domains", [])))
                    write_domain_file(key, app_domains)
                    all_domains.update(app_domains)
            write_domain_file(cat_id, all_domains)
        generate_dnsmasq_conf(categories, v2fly_merged=v2fly_merged)
        generate_unbound_conf(categories, v2fly_merged=v2fly_merged, config=config)
        state["last_full_update"] = int(time.time())
        save_state(state)
        if updated or v2fly_merged:
            update_tables()
        log("List update completed")

    elif action == "generate_dns":
        generate_dnsmasq_conf(categories)
        generate_unbound_conf(categories, config=config)
        log("DNS configs regenerated")

    elif action == "status":
        state["categories"] = {k: len(get_all_domains_for_category(v)) for k, v in categories.items()}
        print(json.dumps(state, indent=2))

    elif action == "force":
        log("Starting forced list update")
        for key in list(state.keys()):
            if key.startswith("etag_"):
                del state[key]
        update_remote_lists(config, state)
        v2fly_merged = update_v2fly_domains(categories, state)
        for cat_id, cat_data in categories.items():
            all_domains = get_all_domains_for_category(cat_data)
            if "apps" in cat_data:
                for app_id, app_data in cat_data["apps"].items():
                    key = f"{cat_id}.{app_id}"
                    app_domains = v2fly_merged.get(key, set(app_data.get("domains", [])))
                    write_domain_file(key, app_domains)
                    all_domains.update(app_domains)
            write_domain_file(cat_id, all_domains)
        generate_dnsmasq_conf(categories, v2fly_merged=v2fly_merged)
        generate_unbound_conf(categories, v2fly_merged=v2fly_merged, config=config)
        state["last_full_update"] = int(time.time())
        save_state(state)
        update_tables()
        log("Forced list update completed")

    else:
        print(f"Usage: {sys.argv[0]} [update|generate_dns|status|force]")
        sys.exit(1)


if __name__ == "__main__":
    main()
