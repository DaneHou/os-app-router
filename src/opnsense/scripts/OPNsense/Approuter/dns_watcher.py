#!/usr/local/bin/python3
"""
AppRouter DNS Watcher
Periodically resolves configured domains and updates pf tables with
their IP addresses. Also adds /24 subnets for CDN coverage.
Works with any DNS resolver without special logging configuration.

Designed to run as a foreground process under FreeBSD daemon(8).
"""

import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import signal
import syslog
from pathlib import Path

CONFIG_DIR = "/usr/local/etc/app-router/unbound.d"
CLIENTS_DIR = Path("/usr/local/etc/app-router/clients")
LOG_FILE = "/var/log/approuter_dns_watcher.log"
RESOLVE_INTERVAL = 30  # seconds between full resolution cycles

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
                domain_table_map[domain.lower()] = table
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


def kill_stale_states(new_ips, client_ips):
    """Kill existing pf states so new connections use the route-to rule."""
    if not new_ips or not client_ips:
        return
    killed = 0
    for client in client_ips:
        for dest in new_ips:
            try:
                result = subprocess.run(
                    ["/sbin/pfctl", "-k", client, "-k", dest],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    killed += 1
            except (subprocess.TimeoutExpired, OSError):
                pass
    if killed:
        log(f"Killed stale states for {len(new_ips)} new IPs x {len(client_ips)} clients")


def resolve_and_update():
    """Resolve all configured domains and add IPs + /24 subnets to pf tables."""
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
        ips = set()
        subnets = set()
        for domain in domains:
            try:
                results = socket.getaddrinfo(
                    domain, None, socket.AF_INET,
                    socket.SOCK_STREAM
                )
                for family, _, _, _, sockaddr in results:
                    ip = sockaddr[0]
                    ips.add(ip)
                    # Add /24 subnet for CDN coverage
                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnets.add(str(net))
            except (socket.gaierror, OSError):
                pass

        addrs = list(ips) + list(subnets)
        if addrs:
            try:
                result = subprocess.run(
                    ["/sbin/pfctl", "-t", table, "-T", "add"] + addrs,
                    capture_output=True, text=True, timeout=10
                )
                output = result.stderr.strip()
                if "added" in output:
                    parts = output.split("/")
                    if parts[0].strip().isdigit():
                        added = int(parts[0].strip())
                        if added > 0:
                            total_added += added
                            all_new_ips.update(addrs)
                            log(f"Added {added} new entries to {table}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                log(f"Failed to add IPs to {table}: {e}", syslog.LOG_ERR)

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
    log(f"Resolving domains every {RESOLVE_INTERVAL}s")

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
        # Open syslog once for the lifetime of the process
        syslog.openlog("approuter-dns", syslog.LOG_PID, syslog.LOG_DAEMON)
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGINT, cleanup)
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
