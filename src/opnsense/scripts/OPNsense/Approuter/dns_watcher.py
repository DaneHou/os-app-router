#!/usr/local/bin/python3
"""
AppRouter DNS Watcher
Periodically resolves configured domains and updates pf tables with
their IP addresses. Also adds /24 subnets for CDN coverage.
Works with any DNS resolver without special logging configuration.
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
PID_FILE = "/var/run/approuter_dns_watcher.pid"
LOG_FILE = "/var/log/approuter_dns_watcher.log"
RESOLVE_INTERVAL = 30  # seconds between full resolution cycles

domain_table_map = {}


def log(msg, level=syslog.LOG_INFO):
    try:
        syslog.openlog("approuter-dns", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(level, msg)
        syslog.closelog()
    except Exception:
        pass
    # Also log to file (syslog may not work after daemonize on FreeBSD)
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
                            log(f"Added {added} new entries to {table}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                log(f"Failed to add IPs to {table}: {e}", syslog.LOG_ERR)

    return total_added


def write_pid():
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def cleanup(signum=None, frame=None):
    try:
        os.unlink(PID_FILE)
    except OSError:
        pass
    log("DNS watcher stopped")
    os._exit(0)


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


def daemonize():
    """Double-fork to detach from parent process (configd)."""
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    # Redirect fds without closing Python file objects first
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    if devnull > 2:
        os.close(devnull)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "start"

    if action == "start":
        # Stop existing instance if running
        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE) as f:
                    old_pid = int(f.read().strip())
                os.kill(old_pid, signal.SIGTERM)
                time.sleep(0.5)
            except (ProcessLookupError, ValueError, OSError):
                pass
            try:
                os.unlink(PID_FILE)
            except OSError:
                pass

        daemonize()
        try:
            signal.signal(signal.SIGTERM, cleanup)
            signal.signal(signal.SIGINT, cleanup)
            write_pid()
            load_domain_mappings()
            log(f"DNS watcher started (PID {os.getpid()})")
            run_daemon()
        except Exception as e:
            log(f"DNS watcher crashed: {e}", syslog.LOG_ERR)
            try:
                os.unlink(PID_FILE)
            except OSError:
                pass
            os._exit(1)

    elif action == "stop":
        if os.path.exists(PID_FILE):
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"Stopped DNS watcher (PID {pid})")
            except ProcessLookupError:
                print("DNS watcher not running")
                os.unlink(PID_FILE)
        else:
            print("DNS watcher not running")

    elif action == "status":
        if os.path.exists(PID_FILE):
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                print(json.dumps({"running": True, "pid": pid}))
            except ProcessLookupError:
                print(json.dumps({"running": False}))
                os.unlink(PID_FILE)
        else:
            print(json.dumps({"running": False}))

    else:
        print(f"Usage: {sys.argv[0]} [start|stop|status]")
        sys.exit(1)


if __name__ == "__main__":
    main()
