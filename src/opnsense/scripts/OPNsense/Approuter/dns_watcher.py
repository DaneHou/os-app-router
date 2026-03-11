#!/usr/local/bin/python3
"""
AppRouter DNS Watcher — Captures actual DNS responses via tcpdump.

Sniffs DNS response packets on LAN interfaces to capture the real IPs
that Unbound returns to clients. This is the only reliable way to handle
CDN domains (like Akamai) where the resolver returns different edge nodes
based on timing and cache state.

Also runs periodic active resolution (drill via Unbound) as a fallback
to pre-populate tables before any client DNS query arrives.

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
import threading
from pathlib import Path

CONFIG_DIR = "/usr/local/etc/app-router/unbound.d"
CLIENTS_DIR = Path("/usr/local/etc/app-router/clients")
LOG_FILE = "/var/log/approuter_dns_watcher.log"
RESOLVE_INTERVAL = 300  # active resolution every 5 min (backup only)

# Unbound listener — for active resolution fallback
UNBOUND_ADDR = "127.0.0.1"
UNBOUND_PORT = 53530

domain_table_map = {}
# Lock for concurrent table updates from multiple sniffer threads
table_lock = threading.Lock()


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


def detect_lan_interfaces():
    """Find LAN interface names from Unbound's listening IPs."""
    # Read Unbound's interface IPs (skip loopback and link-local)
    listen_ips = set()
    try:
        with open("/var/unbound/unbound.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("interface:"):
                    ip = line.split(":", 1)[1].strip()
                    # Skip loopback and IPv6
                    if ip.startswith("127.") or ":" in ip:
                        continue
                    listen_ips.add(ip)
    except IOError:
        pass

    if not listen_ips:
        return []

    # Map IPs to interface names via ifconfig
    iface_map = {}
    try:
        result = subprocess.run(
            ["/sbin/ifconfig", "-a"],
            capture_output=True, text=True, timeout=5
        )
        current_iface = None
        for line in result.stdout.splitlines():
            # Interface line: "igc2: flags=..."
            if not line.startswith("\t") and not line.startswith(" "):
                current_iface = line.split(":")[0]
            elif current_iface and "inet " in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[1]
                    if ip in listen_ips:
                        iface_map[ip] = current_iface
    except (subprocess.TimeoutExpired, OSError):
        pass

    interfaces = list(set(iface_map.values()))
    if interfaces:
        log(f"Detected LAN interfaces: {interfaces} (IPs: {iface_map})")
    return interfaces


def load_domain_mappings():
    global domain_table_map
    new_map = {}

    if not os.path.isdir(CONFIG_DIR):
        log(f"Config dir {CONFIG_DIR} not found")
        domain_table_map = new_map
        return

    for config_file in sorted(Path(CONFIG_DIR).glob("approuter_*.json")):
        try:
            with open(config_file) as f:
                data = json.load(f)
            table = data.get("table", "")
            for domain in data.get("domains", []):
                new_map[domain.lower().rstrip('.')] = table
        except (json.JSONDecodeError, IOError) as e:
            log(f"Error loading {config_file}: {e}", syslog.LOG_ERR)

    domain_table_map = new_map
    log(f"Loaded {len(domain_table_map)} domain mappings from {CONFIG_DIR}")


def match_domain(query_domain):
    """Check if query_domain or any parent domain is in our domain list.
    Returns the matching table name or None.
    e.g. pcw-data.video.iqiyi.com -> matches iqiyi.com -> approuter_video_iqiyi
    """
    query_domain = query_domain.lower().rstrip('.')
    parts = query_domain.split('.')
    # Try progressively shorter domain suffixes
    for i in range(len(parts)):
        candidate = '.'.join(parts[i:])
        table = domain_table_map.get(candidate)
        if table:
            return table
    return None


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


def process_sniffed_dns(query_domain, answer_ips):
    """Process a sniffed DNS response: match domain, add IPs to pf table."""
    table = match_domain(query_domain)
    if not table:
        return

    addrs = set()
    for ip in answer_ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4 and not addr.is_private:
                addrs.add(ip)
                addrs.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
        except ValueError:
            pass

    if not addrs:
        return

    with table_lock:
        added = add_to_table(table, addrs)
        if added > 0:
            log(f"[sniff] Added {added} entries to {table} for {query_domain}")
            client_ips = get_client_ips()
            if client_ips:
                kill_stale_states(addrs, client_ips)


# Regex to extract query domain and A record IPs from tcpdump -vv output
# Example: "q: A? www.iqiyi.com. 5/0/0 ... A 23.45.123.58, ... A 23.45.123.56 (166)"
QUERY_RE = re.compile(r'q:\s+A\?\s+(\S+?)\.')
ANSWER_RE = re.compile(r'\sA\s+(\d+\.\d+\.\d+\.\d+)')


def sniff_interface(iface):
    """Sniff DNS responses on a single interface using tcpdump."""
    log(f"[sniff] Starting DNS sniffer on {iface}")

    while True:
        proc = None
        try:
            proc = subprocess.Popen(
                ["/usr/sbin/tcpdump", "-U", "-l", "-n", "-i", iface,
                 "udp and src port 53", "-vv"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )

            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                # Only process lines with A record queries
                qm = QUERY_RE.search(line)
                if not qm:
                    continue

                query_domain = qm.group(1).lower()
                answer_ips = ANSWER_RE.findall(line)

                if answer_ips:
                    process_sniffed_dns(query_domain, answer_ips)

        except Exception as e:
            log(f"[sniff] Error on {iface}: {e}", syslog.LOG_ERR)

        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        log(f"[sniff] tcpdump on {iface} exited, restarting in 5s...")
        time.sleep(5)


def resolve_via_unbound(domain):
    """Resolve a domain using drill via the local Unbound instance."""
    ips = set()
    try:
        result = subprocess.run(
            ["/usr/bin/drill", f"@{UNBOUND_ADDR}", "-p", str(UNBOUND_PORT),
             domain, "A"],
            capture_output=True, text=True, timeout=10
        )
        in_answer = False
        for line in result.stdout.splitlines():
            if line.startswith(";; ANSWER SECTION:"):
                in_answer = True
                continue
            if in_answer:
                if line.startswith(";;") or not line.strip():
                    break
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
    return ips


def resolve_and_update():
    """Active resolution via drill as backup. Resolves bare + www. variants."""
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
            variants = [domain]
            if not domain.startswith("www."):
                variants.append(f"www.{domain}")
            for variant in variants:
                ips = resolve_via_unbound(variant)
                for ip in ips:
                    addrs.add(ip)
                    addrs.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))

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

        detect_unbound_port()
        load_domain_mappings()
        log(f"DNS watcher started (PID {os.getpid()})")

        # Detect LAN interfaces for DNS sniffing
        interfaces = detect_lan_interfaces()
        if not interfaces:
            log("No LAN interfaces detected, sniffing disabled",
                syslog.LOG_WARNING)

        # Initial active resolution to seed tables
        added = resolve_and_update()
        log(f"Initial resolution: {added} new entries added")

        # Start DNS sniffers on each LAN interface
        for iface in interfaces:
            t = threading.Thread(target=sniff_interface, args=(iface,),
                                daemon=True)
            t.start()

        # Start periodic active resolution (backup, every 5 min)
        resolver_thread = threading.Thread(target=active_resolve_loop,
                                          daemon=True)
        resolver_thread.start()

        # Main thread stays alive
        try:
            while True:
                time.sleep(60)
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
