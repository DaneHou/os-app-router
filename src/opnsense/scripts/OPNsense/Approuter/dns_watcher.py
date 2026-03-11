#!/usr/local/bin/python3
"""
AppRouter DNS Watcher
Periodically resolves configured domains and updates pf tables with
their IP addresses. Works with any DNS resolver (Unbound, Dnsmasq, etc.)
without requiring special logging configuration.
"""

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
RESOLVE_INTERVAL = 30  # seconds between full resolution cycles

domain_table_map = {}


def log(msg, level=syslog.LOG_INFO):
    syslog.openlog("approuter-dns", syslog.LOG_PID, syslog.LOG_DAEMON)
    syslog.syslog(level, msg)
    syslog.closelog()


def load_domain_mappings():
    global domain_table_map
    domain_table_map.clear()

    if not os.path.isdir(CONFIG_DIR):
        return

    for config_file in Path(CONFIG_DIR).glob("approuter_*.json"):
        try:
            with open(config_file) as f:
                data = json.load(f)
            table = data.get("table", "")
            for domain in data.get("domains", []):
                domain_table_map[domain.lower()] = table
        except (json.JSONDecodeError, IOError) as e:
            log(f"Error loading {config_file}: {e}", syslog.LOG_ERR)

    log(f"Loaded {len(domain_table_map)} domain mappings")


def resolve_and_update():
    """Resolve all configured domains and add IPs to pf tables."""
    if not domain_table_map:
        return 0

    # Group domains by table
    table_domains = {}
    for domain, table in domain_table_map.items():
        table_domains.setdefault(table, []).append(domain)

    total_added = 0
    for table, domains in table_domains.items():
        ips = set()
        for domain in domains:
            try:
                results = socket.getaddrinfo(
                    domain, None, socket.AF_UNSPEC,
                    socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG
                )
                for family, _, _, _, sockaddr in results:
                    ips.add(sockaddr[0])
            except (socket.gaierror, OSError):
                pass
        if ips:
            try:
                result = subprocess.run(
                    ["/sbin/pfctl", "-t", table, "-T", "add"] + list(ips),
                    capture_output=True, text=True, timeout=10
                )
                # Parse "X/Y addresses added" from pfctl output
                output = result.stderr.strip()
                if "added" in output:
                    parts = output.split("/")
                    if parts[0].strip().isdigit():
                        added = int(parts[0].strip())
                        if added > 0:
                            total_added += added
                            log(f"Added {added} new IPs to {table}")
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
    sys.exit(0)


def run_daemon():
    """Main daemon loop: resolve domains periodically."""
    log(f"Resolving domains every {RESOLVE_INTERVAL}s")

    # Initial full resolution
    added = resolve_and_update()
    log(f"Initial resolution: {added} new IPs added")

    while True:
        time.sleep(RESOLVE_INTERVAL)
        try:
            resolve_and_update()
        except Exception as e:
            log(f"Resolution cycle error: {e}", syslog.LOG_ERR)


def daemonize():
    """Double-fork to detach from parent process (configd)."""
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    sys.stdin.close()
    sys.stdout.close()
    sys.stderr.close()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)


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
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGINT, cleanup)
        write_pid()
        load_domain_mappings()
        log("DNS watcher started")
        run_daemon()

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
