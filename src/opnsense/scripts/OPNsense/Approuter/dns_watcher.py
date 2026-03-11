#!/usr/local/bin/python3
"""
AppRouter DNS Watcher — Resolves domains via Unbound and updates pf tables.

Queries the local Unbound resolver (same path as clients) to get the actual
CDN IPs that clients will receive. Adds IPs + /24 subnets to pf tables and
kills stale pf states so existing connections get re-routed.

Designed to run as a foreground process under FreeBSD daemon(8).
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import signal
import syslog
from pathlib import Path

CONFIG_DIR = "/usr/local/etc/app-router/unbound.d"
CONFIG_FILE = "/usr/local/etc/app-router/config.json"
CLIENTS_DIR = Path("/usr/local/etc/app-router/clients")
LOG_FILE = "/var/log/approuter_dns_watcher.log"
RESOLVE_INTERVAL = 30  # seconds between full resolution cycles

# Unbound listener — read from unbound.conf at startup
UNBOUND_ADDR = "127.0.0.1"
UNBOUND_PORT = 53530  # OPNsense default

domain_table_map = {}


def log(msg, level=syslog.LOG_INFO):
    try:
        syslog.syslog(level, msg)
    except Exception:
        pass
    try:
        with open(LOG_FILE, "a") as f:
            t = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{t} {msg}\n")
    except Exception:
        pass


def detect_unbound_port():
    """Read Unbound's listening port from its config."""
    global UNBOUND_PORT
    try:
        with open("/var/unbound/unbound.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("port:"):
                    port = int(line.split(":")[1].strip())
                    if port > 0:
                        UNBOUND_PORT = port
                        return
    except (IOError, ValueError):
        pass


def resolve_via_unbound(domain):
    """Resolve a domain using drill via the local Unbound instance.
    Returns a set of IPv4 addresses."""
    ips = set()
    try:
        result = subprocess.run(
            ["/usr/bin/drill", f"@{UNBOUND_ADDR}", "-p", str(UNBOUND_PORT),
             domain, "A"],
            capture_output=True, text=True, timeout=10
        )
        # Parse drill output: look for A records in ANSWER SECTION
        in_answer = False
        for line in result.stdout.splitlines():
            if line.startswith(";; ANSWER SECTION:"):
                in_answer = True
                continue
            if in_answer:
                if line.startswith(";;") or not line.strip():
                    break
                # Format: domain. TTL IN A 1.2.3.4
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "A":
                    ip = parts[4]
                    try:
                        ipaddress.ip_address(ip)
                        ips.add(ip)
                    except ValueError:
                        pass
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Fallback to system resolver if drill fails
    if not ips:
        try:
            results = socket.getaddrinfo(
                domain, None, socket.AF_INET, socket.SOCK_STREAM
            )
            for family, _, _, _, sockaddr in results:
                ips.add(sockaddr[0])
        except (socket.gaierror, OSError):
            pass

    return ips


def load_domain_mappings():
    global domain_table_map
    domain_table_map.clear()

    if not os.path.isdir(CONFIG_DIR):
        log(f"Config dir {CONFIG_DIR} not found")
        return

    for config_file in sorted(Path(CONFIG_DIR).glob("approuter_*.json")):
        try:
            with open(config_file) as f:
                data = json.load(f)
            table = data.get("table", "")
            for domain in data.get("domains", []):
                domain_table_map[domain.lower().rstrip('.')] = table
        except (json.JSONDecodeError, IOError) as e:
            log(f"Error loading {config_file}: {e}", syslog.LOG_ERR)

    log(f"Loaded {len(domain_table_map)} domain mappings from {CONFIG_DIR}")


def get_client_ips():
    """Read client IPs from approuter client table files."""
    client_ips = set()
    if CLIENTS_DIR.is_dir():
        for f in CLIENTS_DIR.glob("approuter_clients_*.txt"):
            for line in f.read_text().splitlines():
                ip = line.strip().split('/')[0]
                if ip and not ip.startswith('#'):
                    client_ips.add(ip)
    return client_ips


def add_to_table(table, addrs):
    """Add IPs/subnets to a pf table. Returns count of newly added entries."""
    if not addrs:
        return 0
    try:
        result = subprocess.run(
            ["/sbin/pfctl", "-t", table, "-T", "add"] + list(addrs),
            capture_output=True, text=True, timeout=10
        )
        output = result.stderr.strip()
        if "added" in output:
            parts = output.split("/")
            if parts[0].strip().isdigit():
                return int(parts[0].strip())
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log(f"Failed to add IPs to {table}: {e}", syslog.LOG_ERR)
    return 0


def kill_stale_states(new_ips, client_ips):
    """Kill existing pf states so new connections use the route-to rule."""
    if not new_ips or not client_ips:
        return
    for client in client_ips:
        for dest in new_ips:
            try:
                subprocess.run(
                    ["/sbin/pfctl", "-k", client, "-k", dest],
                    capture_output=True, timeout=5
                )
            except (subprocess.TimeoutExpired, OSError):
                pass
    log(f"Killed stale states for {len(new_ips)} new IPs x {len(client_ips)} clients")


def resolve_and_update():
    """Resolve all configured domains via Unbound and add IPs + /24 subnets to pf tables."""
    if not domain_table_map:
        log("No domain mappings loaded, skipping resolution")
        return 0

    # Group domains by table
    table_domains = {}
    for domain, table in domain_table_map.items():
        table_domains.setdefault(table, []).append(domain)

    total_added = 0
    all_new_ips = set()
    for table, domains in table_domains.items():
        addrs = set()
        for domain in domains:
            # Resolve both bare domain and www. subdomain
            # CDNs often return different IPs (e.g. iqiyi.com -> domestic,
            # www.iqiyi.com -> Akamai)
            variants = [domain]
            if not domain.startswith("www."):
                variants.append(f"www.{domain}")
            for variant in variants:
                ips = resolve_via_unbound(variant)
                for ip in ips:
                    addrs.add(ip)
                    # Add /24 subnet for CDN coverage
                    addrs.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))

        added = add_to_table(table, addrs)
        if added > 0:
            total_added += added
            all_new_ips.update(addrs)
            log(f"Added {added} new entries to {table}")

    # Kill stale states so existing connections get re-routed
    if all_new_ips:
        client_ips = get_client_ips()
        if client_ips:
            kill_stale_states(all_new_ips, client_ips)

    return total_added


def cleanup(signum=None, frame=None):
    log("DNS watcher stopped")
    sys.exit(0)


def run_daemon():
    """Main daemon loop: resolve domains periodically."""
    log(f"Resolving via Unbound ({UNBOUND_ADDR}:{UNBOUND_PORT}) every {RESOLVE_INTERVAL}s")

    # Initial full resolution
    added = resolve_and_update()
    log(f"Initial resolution: {added} new entries added")

    while True:
        time.sleep(RESOLVE_INTERVAL)
        try:
            # Reload mappings periodically (picks up config changes)
            load_domain_mappings()
            resolve_and_update()
        except Exception as e:
            log(f"Resolution cycle error: {e}", syslog.LOG_ERR)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "start"

    if action == "start":
        syslog.openlog("approuter-dns", syslog.LOG_PID, syslog.LOG_DAEMON)
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGINT, cleanup)

        detect_unbound_port()
        load_domain_mappings()
        log(f"DNS watcher started (PID {os.getpid()})")

        try:
            run_daemon()
        except Exception as e:
            log(f"DNS watcher crashed: {e}", syslog.LOG_ERR)
            sys.exit(1)

    elif action == "stop":
        pid_file = "/var/run/approuter_dns_watcher.pid"
        if os.path.exists(pid_file):
            with open(pid_file) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"Stopped DNS watcher (PID {pid})")
            except ProcessLookupError:
                print("DNS watcher not running")
                os.unlink(pid_file)
        else:
            print("DNS watcher not running")

    elif action == "status":
        pid_file = "/var/run/approuter_dns_watcher.pid"
        if os.path.exists(pid_file):
            with open(pid_file) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                print(json.dumps({"running": True, "pid": pid}))
            except ProcessLookupError:
                print(json.dumps({"running": False}))
                os.unlink(pid_file)
        else:
            print(json.dumps({"running": False}))

    else:
        print(f"Usage: {sys.argv[0]} [start|stop|status]")
        sys.exit(1)


if __name__ == "__main__":
    main()
