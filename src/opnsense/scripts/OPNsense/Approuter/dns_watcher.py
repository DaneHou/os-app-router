#!/usr/local/bin/python3
"""
AppRouter DNS Watcher — Dual mode: Unbound log parsing + active resolution.

Primary: Tail Unbound's reply log to capture the actual IPs returned to clients.
This is critical for CDN domains where the resolver returns different IPs based
on client location.

Fallback: Periodically resolve configured domains from the firewall itself
to pre-populate pf tables (covers the gap before any client DNS query).

Designed to run as a foreground process under FreeBSD daemon(8).
"""

import ipaddress
import json
import os
import re
import select
import socket
import subprocess
import sys
import time
import signal
import syslog
import threading
from pathlib import Path

CONFIG_DIR = "/usr/local/etc/app-router/unbound.d"
CLIENTS_DIR = Path("/usr/local/etc/app-router/clients")
LOG_FILE = "/var/log/approuter_dns_watcher.log"
UNBOUND_LOG = "/var/log/resolver/latest.log"
RESOLVE_INTERVAL = 300  # active resolution every 5 min (backup only)

domain_table_map = {}

# Unbound reply log pattern:
# [1234567890] unbound[pid]: info: 192.168.1.1 www.iqiyi.com. A IN NOERROR 0.001 0 23.67.33.35
# The clog binary-log format when read via pipe may vary; we match the key fields.
REPLY_RE = re.compile(
    r'info:\s+'
    r'[\d.]+\s+'              # client IP
    r'(\S+)\s+'               # domain (with trailing dot)
    r'(A|AAAA)\s+'            # query type
    r'IN\s+'                  # class
    r'NOERROR\s+'             # rcode
    r'[\d.]+\s+'              # response time
    r'[01]\s+'                # cached flag
    r'([\d.]+|[\da-f:]+)'    # answer IP
)


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


def process_dns_reply(domain, ip):
    """Process a single DNS reply: add IP + /24 subnet to the matching pf table."""
    domain = domain.lower().rstrip('.')
    # Check exact match first, then try parent domains (for CDN CNAMEs)
    table = domain_table_map.get(domain)
    if not table:
        # Try matching parent: e.g. e99042.a.akamaiedge.net won't match,
        # but the original query domain should have matched already.
        return None

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    addrs = {ip}
    if addr.version == 4:
        subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        addrs.add(subnet)

    added = add_to_table(table, addrs)
    if added > 0:
        log(f"[log] Added {added} entries to {table} for {domain} -> {ip}")
        # Kill stale states for the new IPs
        client_ips = get_client_ips()
        if client_ips:
            kill_stale_states(addrs, client_ips)
    return added


def tail_unbound_log():
    """Tail Unbound log using clog (FreeBSD circular log) and process replies."""
    log(f"Starting Unbound log watcher on {UNBOUND_LOG}")

    while True:
        try:
            # Use clog -f to tail the circular log file
            proc = subprocess.Popen(
                ["/usr/sbin/clog", "-f", UNBOUND_LOG],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1  # line buffered
            )
            log("Unbound log tail started")

            for line in proc.stdout:
                if "reply:" not in line and "info:" not in line:
                    continue
                m = REPLY_RE.search(line)
                if not m:
                    continue
                domain = m.group(1).lower().rstrip('.')
                qtype = m.group(2)
                answer_ip = m.group(3)

                # Only process A records for IPv4 (our pf rules are IPv4)
                if qtype == 'A' and domain in domain_table_map:
                    process_dns_reply(domain, answer_ip)

        except Exception as e:
            log(f"Log tail error: {e}", syslog.LOG_ERR)

        # If clog exits or errors, wait and retry
        try:
            proc.kill()
        except Exception:
            pass
        log("Unbound log tail exited, restarting in 5s...")
        time.sleep(5)


def resolve_and_update():
    """Active resolution: resolve all domains from firewall itself (backup mode)."""
    if not domain_table_map:
        return 0

    table_domains = {}
    for domain, table in domain_table_map.items():
        table_domains.setdefault(table, []).append(domain)

    total_added = 0
    all_new_ips = set()
    for table, domains in table_domains.items():
        addrs = set()
        for domain in domains:
            try:
                results = socket.getaddrinfo(
                    domain, None, socket.AF_INET, socket.SOCK_STREAM
                )
                for family, _, _, _, sockaddr in results:
                    ip = sockaddr[0]
                    addrs.add(ip)
                    addrs.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
            except (socket.gaierror, OSError):
                pass

        added = add_to_table(table, addrs)
        if added > 0:
            total_added += added
            all_new_ips.update(addrs)
            log(f"[resolve] Added {added} new entries to {table}")

    if all_new_ips:
        client_ips = get_client_ips()
        if client_ips:
            kill_stale_states(all_new_ips, client_ips)

    return total_added


def active_resolve_loop():
    """Background thread: periodic active resolution as fallback."""
    while True:
        time.sleep(RESOLVE_INTERVAL)
        try:
            load_domain_mappings()
            resolve_and_update()
        except Exception as e:
            log(f"Active resolution error: {e}", syslog.LOG_ERR)


def cleanup(signum=None, frame=None):
    log("DNS watcher stopped")
    sys.exit(0)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "start"

    if action == "start":
        syslog.openlog("approuter-dns", syslog.LOG_PID, syslog.LOG_DAEMON)
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGINT, cleanup)

        load_domain_mappings()
        log(f"DNS watcher started (PID {os.getpid()})")

        # Initial active resolution to pre-populate tables
        added = resolve_and_update()
        log(f"Initial resolution: {added} new entries added")

        # Start active resolution in background thread (fallback, every 5 min)
        resolver_thread = threading.Thread(target=active_resolve_loop, daemon=True)
        resolver_thread.start()

        # Main thread: tail Unbound log for real-time client DNS replies
        try:
            tail_unbound_log()
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
