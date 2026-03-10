#!/usr/local/bin/python3
"""
AppRouter DNS Watcher
Monitors Unbound DNS resolver log and updates pf tables when matching
domains are resolved. Used as fallback when Dnsmasq ipset is not available.
"""

import json
import os
import re
import subprocess
import sys
import time
import signal
import syslog
from pathlib import Path

UNBOUND_DIR = "/usr/local/etc/app-router/unbound.d"
UNBOUND_LOG = "/var/log/resolver.log"
PID_FILE = "/var/run/approuter_dns_watcher.pid"

domain_table_map = {}


def log(msg, level=syslog.LOG_INFO):
    syslog.openlog("approuter-dns", syslog.LOG_PID, syslog.LOG_DAEMON)
    syslog.syslog(level, msg)
    syslog.closelog()


def load_domain_mappings():
    global domain_table_map
    domain_table_map.clear()

    if not os.path.isdir(UNBOUND_DIR):
        return

    for config_file in Path(UNBOUND_DIR).glob("approuter_*.json"):
        try:
            with open(config_file) as f:
                data = json.load(f)
            table = data.get("table", "")
            for domain in data.get("domains", []):
                domain_table_map[domain.lower()] = table
        except (json.JSONDecodeError, IOError) as e:
            log(f"Error loading {config_file}: {e}", syslog.LOG_ERR)

    log(f"Loaded {len(domain_table_map)} domain mappings")


def match_domain(query_domain):
    """Check if a queried domain matches any configured domain (with wildcard parent walk)."""
    query_domain = query_domain.lower().rstrip(".")
    if query_domain in domain_table_map:
        return domain_table_map[query_domain]
    parts = query_domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in domain_table_map:
            return domain_table_map[parent]
    return None


def add_ip_to_table(table_name, ip):
    try:
        subprocess.run(
            ["/sbin/pfctl", "-t", table_name, "-T", "add", ip],
            check=True,
            capture_output=True,
            timeout=5
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def parse_unbound_log_line(line):
    """Parse Unbound log line for DNS responses. Returns (domain, resolved_ip) or None."""
    patterns = [
        r'reply:\s+(\S+)\.\s+\d+\s+IN\s+(?:A|AAAA)\s+(\S+)',
        r'(\S+)\.\s+IN\s+(?:A|AAAA)\s+(\d+\.\d+\.\d+\.\d+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            domain = match.group(1).rstrip(".")
            ip = match.group(2)
            return domain, ip
    return None


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


def watch_log():
    if not os.path.exists(UNBOUND_LOG):
        log(f"Log file {UNBOUND_LOG} not found, waiting...", syslog.LOG_WARNING)
        while not os.path.exists(UNBOUND_LOG):
            time.sleep(5)

    log(f"Watching {UNBOUND_LOG}")
    recent_additions = {}
    CACHE_TTL = 300

    with open(UNBOUND_LOG, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                now = time.time()
                expired = [k for k, v in recent_additions.items() if now - v > CACHE_TTL]
                for k in expired:
                    del recent_additions[k]
                time.sleep(0.1)
                continue

            result = parse_unbound_log_line(line)
            if not result:
                continue

            domain, ip = result
            table = match_domain(domain)
            if not table:
                continue

            cache_key = f"{table}:{ip}"
            if cache_key in recent_additions:
                continue

            if add_ip_to_table(table, ip):
                recent_additions[cache_key] = time.time()
                log(f"Added {ip} ({domain}) to {table}")


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "start"

    if action == "start":
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGINT, cleanup)
        write_pid()
        load_domain_mappings()
        log("DNS watcher started")
        watch_log()

    elif action == "reload":
        load_domain_mappings()
        log("Domain mappings reloaded")
        if os.path.exists(PID_FILE):
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGHUP)
                print(f"Sent reload signal to PID {pid}")
            except ProcessLookupError:
                print("DNS watcher not running")

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
        print(f"Usage: {sys.argv[0]} [start|stop|reload|status]")
        sys.exit(1)


if __name__ == "__main__":
    main()
