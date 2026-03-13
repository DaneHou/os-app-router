#!/usr/local/bin/python3
"""
AppRouter Geo Prober — Smart gateway probe daemon.

Probes gateway availability for smart gateway rules and switches traffic
between gateways by populating/flushing pf _gwN tables.

Designed to run as a foreground process under FreeBSD daemon(8).
"""

import json
import os
import re
import signal
import subprocess
import sys
import syslog
import threading
import time
from pathlib import Path

CONFIG_FILE = "/usr/local/etc/app-router/config.json"
STATE_FILE = "/usr/local/etc/app-router/smart_gateway_state.json"
PID_FILE = "/var/run/approuter_geo_prober.pid"
LOG_FILE = "/var/log/approuter_geo_prober.log"

PFCTL = "/sbin/pfctl"
CURL = "/usr/local/bin/curl"

# Debounce: require N consecutive consistent results before switching
DEBOUNCE_COUNT = 3
# Minimum cooldown between switches (seconds)
SWITCH_COOLDOWN = 300

# Gateway interface cache
gw_interface_cache = {}
gw_interface_cache_time = 0
GW_CACHE_TTL = 60

# Global state
active_tables = set()
active_tables_lock = threading.Lock()
probe_results = {}
probe_results_lock = threading.Lock()
shutdown_event = threading.Event()


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


def load_config():
    """Load config.json and return smart gateway rules."""
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        log(f"Failed to load config: {e}", syslog.LOG_ERR)
        return []

    table_prefix = config.get("table_prefix", "approuter")
    smart_rules = []

    for rule in config.get("rules", []):
        if rule.get("smart_gateway") != "1":
            continue
        gateways = [gw.strip() for gw in rule.get("gateway", "").split(",") if gw.strip()]
        if len(gateways) < 2:
            continue

        categories = [c.strip() for c in rule.get("categories", "").split(",") if c.strip()]
        custom_domains = rule.get("custom_domains", "")

        # Build list of base table names for this rule
        base_tables = []
        for cat in categories:
            base_tables.append(table_prefix + "_" + cat.replace(".", "_"))
        if custom_domains:
            import hashlib
            uuid = rule.get("uuid", "")
            hash8 = hashlib.md5(uuid.encode()).hexdigest()[:8]
            base_tables.append(table_prefix + "_custom_" + hash8)

        smart_rules.append({
            "description": rule.get("description", ""),
            "gateways": gateways,
            "base_tables": base_tables,
            "probe_url": rule.get("probe_url", ""),
            "probe_interval": rule.get("probe_interval", 300),
            "probe_method": rule.get("probe_method", "connect_only"),
            "probe_pattern": rule.get("probe_pattern", ""),
        })

    return smart_rules


def get_gateway_interface(gw_name):
    """Get the network interface for a gateway name."""
    global gw_interface_cache, gw_interface_cache_time

    now = time.time()
    if now - gw_interface_cache_time > GW_CACHE_TTL:
        try:
            result = subprocess.run(
                ["configctl", "interface", "gateways", "status"],
                capture_output=True, text=True, timeout=10
            )
            gateways = json.loads(result.stdout)
            new_cache = {}
            if isinstance(gateways, dict):
                for gw_data in gateways.values():
                    if isinstance(gw_data, dict):
                        name = gw_data.get("name", "")
                        iface = gw_data.get("interface", "")
                        if name and iface:
                            new_cache[name] = iface
            elif isinstance(gateways, list):
                for gw_data in gateways:
                    if isinstance(gw_data, dict):
                        name = gw_data.get("name", "")
                        iface = gw_data.get("interface", "")
                        if name and iface:
                            new_cache[name] = iface
            gw_interface_cache = new_cache
            gw_interface_cache_time = now
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            log(f"Failed to refresh gateway interfaces: {e}", syslog.LOG_ERR)

    return gw_interface_cache.get(gw_name, "")


def probe_gateway(gw_name, probe_url, probe_method, probe_pattern):
    """Probe a gateway and return (available, latency_ms, detail).

    Returns:
        (bool, float, str): (is_available, latency_in_ms, detail_message)
    """
    iface = get_gateway_interface(gw_name)
    if not iface:
        return False, 0.0, f"no interface for {gw_name}"

    if not probe_url:
        # Default: TCP connect test to a well-known endpoint
        probe_url = "https://www.google.com"

    curl_base = [
        CURL, "-s", "--interface", iface,
        "--connect-timeout", "10",
        "--max-time", "15",
        "-o", "/dev/null",
    ]

    try:
        if probe_method == "connect_only":
            result = subprocess.run(
                curl_base + ["-w", "%{time_connect}", probe_url],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0:
                try:
                    latency = float(result.stdout.strip()) * 1000
                except ValueError:
                    latency = 0.0
                return True, latency, "connected"
            return False, 0.0, f"curl exit {result.returncode}"

        elif probe_method == "status_code":
            result = subprocess.run(
                curl_base + ["-w", "%{http_code}", probe_url],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0:
                return False, 0.0, f"curl exit {result.returncode}"
            code = result.stdout.strip()
            # 403/451 = geo-restricted
            if code in ("403", "451"):
                return False, 0.0, f"restricted (HTTP {code})"
            if code.startswith("2") or code.startswith("3"):
                return True, 0.0, f"HTTP {code}"
            return False, 0.0, f"HTTP {code}"

        elif probe_method == "body_match":
            # Need actual body content
            curl_body = [
                CURL, "-s", "--interface", iface,
                "--connect-timeout", "10",
                "--max-time", "15",
                probe_url,
            ]
            result = subprocess.run(
                curl_body, capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0:
                return False, 0.0, f"curl exit {result.returncode}"
            body = result.stdout
            if probe_pattern:
                if re.search(probe_pattern, body):
                    return False, 0.0, "body matched restriction pattern"
            return True, 0.0, "body ok"

        elif probe_method == "latency":
            result = subprocess.run(
                curl_base + ["-w", "%{time_total}", probe_url],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0:
                try:
                    latency = float(result.stdout.strip()) * 1000
                except ValueError:
                    latency = 9999.0
                return True, latency, f"{latency:.0f}ms"
            return False, 0.0, f"curl exit {result.returncode}"

        else:
            return False, 0.0, f"unknown method {probe_method}"

    except subprocess.TimeoutExpired:
        return False, 0.0, "timeout"
    except OSError as e:
        return False, 0.0, str(e)


def sync_table(base_table, gw_index):
    """Copy IPs from main table to _gwN table."""
    gw_table = f"{base_table}_gw{gw_index}"
    try:
        # Get IPs from main table
        result = subprocess.run(
            [PFCTL, "-t", base_table, "-T", "show"],
            capture_output=True, text=True, timeout=10
        )
        ips = [ip.strip() for ip in result.stdout.splitlines() if ip.strip()]
        if not ips:
            return

        # Write to temp file and replace
        tmpfile = f"/tmp/approuter_sync_{gw_table}.txt"
        with open(tmpfile, "w") as f:
            f.write("\n".join(ips) + "\n")
        subprocess.run(
            [PFCTL, "-t", gw_table, "-T", "replace", "-f", tmpfile],
            capture_output=True, timeout=10
        )
        os.unlink(tmpfile)
        log(f"[sync] Copied {len(ips)} entries from {base_table} to {gw_table}")
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"[sync] Failed to sync {gw_table}: {e}", syslog.LOG_ERR)


def flush_table(base_table, gw_index):
    """Flush _gwN table."""
    gw_table = f"{base_table}_gw{gw_index}"
    try:
        subprocess.run(
            [PFCTL, "-t", gw_table, "-T", "flush"],
            capture_output=True, timeout=10
        )
        log(f"[flush] Flushed {gw_table}")
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"[flush] Failed to flush {gw_table}: {e}", syslog.LOG_ERR)


def kill_states_for_table(table_name):
    """Kill pf states matching IPs in a table to force reconnection."""
    try:
        result = subprocess.run(
            [PFCTL, "-t", table_name, "-T", "show"],
            capture_output=True, text=True, timeout=10
        )
        ips = [ip.strip() for ip in result.stdout.splitlines() if ip.strip()]
        for ip in ips[:100]:  # Limit to avoid excessive state kills
            subprocess.run(
                [PFCTL, "-k", "0.0.0.0/0", "-k", ip],
                capture_output=True, timeout=5
            )
    except (subprocess.TimeoutExpired, OSError):
        pass


def write_state():
    """Write current active tables to state file for dns_watcher."""
    with active_tables_lock:
        state = {"active_tables": sorted(active_tables)}
    try:
        tmpfile = STATE_FILE + ".tmp"
        with open(tmpfile, "w") as f:
            json.dump(state, f)
        os.rename(tmpfile, STATE_FILE)
    except IOError as e:
        log(f"Failed to write state file: {e}", syslog.LOG_ERR)


def notify_dns_watcher():
    """Send SIGHUP to dns_watcher so it reloads the smart gateway state."""
    pid_file = "/var/run/approuter_dns_watcher.pid"
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGHUP)
    except (IOError, ValueError, ProcessLookupError):
        pass


def probe_rule_loop(rule):
    """Probe loop for a single smart rule. Runs in its own thread."""
    gateways = rule["gateways"]
    base_tables = rule["base_tables"]
    probe_url = rule["probe_url"]
    probe_interval = rule["probe_interval"]
    probe_method = rule["probe_method"]
    probe_pattern = rule["probe_pattern"]
    desc = rule["description"] or "unnamed"

    # State per non-fallback gateway
    # gw_index 0..N-2 are probed; N-1 is fallback (always uses main table)
    num_probed = len(gateways) - 1
    gw_states = {}
    for i in range(num_probed):
        gw_states[i] = {
            "available": False,
            "consecutive_ok": 0,
            "consecutive_fail": 0,
            "last_switch_time": 0,
            "latency": 0.0,
        }

    log(f"[probe] Starting probe loop for '{desc}': "
        f"gateways={gateways}, interval={probe_interval}s, method={probe_method}")

    # Track which gateway is currently active for switch logging
    current_active_gw = gateways[-1]  # starts with fallback

    while not shutdown_event.is_set():
        probe_summary = []
        for i in range(num_probed):
            if shutdown_event.is_set():
                return

            gw_name = gateways[i]
            available, latency, detail = probe_gateway(
                gw_name, probe_url, probe_method, probe_pattern
            )

            state = gw_states[i]
            if available:
                state["consecutive_ok"] += 1
                state["consecutive_fail"] = 0
                state["latency"] = latency
            else:
                state["consecutive_fail"] += 1
                state["consecutive_ok"] = 0
                state["latency"] = 0.0

            # Log each probe result
            status_str = "OK" if available else "FAIL"
            latency_str = f" {latency:.0f}ms" if latency > 0 else ""
            probe_summary.append(
                f"{gw_name}={status_str}{latency_str}"
                f"(ok:{state['consecutive_ok']}/fail:{state['consecutive_fail']})"
            )

            # Store probe result for status reporting
            with probe_results_lock:
                key = f"{desc}:{gw_name}"
                probe_results[key] = {
                    "gateway": gw_name,
                    "available": available,
                    "latency": latency,
                    "detail": detail,
                    "consecutive_ok": state["consecutive_ok"],
                    "consecutive_fail": state["consecutive_fail"],
                    "timestamp": time.time(),
                }

        # Log probe round summary
        log(f"[probe] '{desc}': {', '.join(probe_summary)}")

        # Determine which gateways should be active after debounce
        now = time.time()
        changed = False
        prev_active_gw = current_active_gw

        if probe_method == "latency":
            # Latency mode: pick the best available gateway
            best_gw = -1
            best_latency = float("inf")
            for i in range(num_probed):
                state = gw_states[i]
                if state["consecutive_ok"] >= DEBOUNCE_COUNT and state["latency"] < best_latency:
                    best_latency = state["latency"]
                    best_gw = i

            for i in range(num_probed):
                state = gw_states[i]
                should_be_active = (i == best_gw)
                if should_be_active != state["available"]:
                    if now - state["last_switch_time"] >= SWITCH_COOLDOWN:
                        state["available"] = should_be_active
                        state["last_switch_time"] = now
                        changed = True
                        action = "ENABLE" if should_be_active else "DISABLE"
                        log(f"[switch] {action} {gateways[i]} for '{desc}' "
                            f"(latency: {state['latency']:.0f}ms, "
                            f"best: {gateways[best_gw] if best_gw >= 0 else 'none'} {best_latency:.0f}ms)")
        else:
            # Standard mode: enable all gateways that pass probes
            for i in range(num_probed):
                state = gw_states[i]
                if not state["available"] and state["consecutive_ok"] >= DEBOUNCE_COUNT:
                    if now - state["last_switch_time"] >= SWITCH_COOLDOWN:
                        state["available"] = True
                        state["last_switch_time"] = now
                        changed = True
                        log(f"[switch] ENABLE {gateways[i]} for '{desc}' "
                            f"(passed {DEBOUNCE_COUNT} consecutive probes)")
                elif state["available"] and state["consecutive_fail"] >= DEBOUNCE_COUNT:
                    if now - state["last_switch_time"] >= SWITCH_COOLDOWN:
                        state["available"] = False
                        state["last_switch_time"] = now
                        changed = True
                        log(f"[switch] DISABLE {gateways[i]} for '{desc}' "
                            f"(failed {DEBOUNCE_COUNT} consecutive probes)")

        if changed:
            # Determine new active gateway (highest priority enabled, or fallback)
            new_active_gw = gateways[-1]  # fallback
            for i in range(num_probed):
                if gw_states[i]["available"]:
                    new_active_gw = gateways[i]
                    break

            # Log the actual traffic switch
            if new_active_gw != prev_active_gw:
                log(f"[switch] '{desc}': traffic switching {prev_active_gw} -> {new_active_gw}",
                    syslog.LOG_NOTICE)
            current_active_gw = new_active_gw

            # Apply changes to pf tables
            with active_tables_lock:
                for i in range(num_probed):
                    for base_table in base_tables:
                        gw_table = f"{base_table}_gw{i}"
                        if gw_states[i]["available"]:
                            sync_table(base_table, i)
                            active_tables.add(gw_table)
                        else:
                            flush_table(base_table, i)
                            active_tables.discard(gw_table)

            # Kill stale states for affected tables
            for base_table in base_tables:
                kill_states_for_table(base_table)

            # Update state file and notify dns_watcher
            write_state()
            notify_dns_watcher()

            # Log final state summary
            gw_summary = []
            for i in range(num_probed):
                s = "active" if gw_states[i]["available"] else "standby"
                gw_summary.append(f"{gateways[i]}={s}")
            gw_summary.append(f"{gateways[-1]}=fallback")
            log(f"[switch] '{desc}' gateway status: {', '.join(gw_summary)}")

        # Wait for next probe cycle
        shutdown_event.wait(probe_interval)


def get_status():
    """Return status dict for API consumption."""
    with probe_results_lock:
        results = dict(probe_results)
    with active_tables_lock:
        tables = sorted(active_tables)
    return {
        "running": True,
        "pid": os.getpid(),
        "active_tables": tables,
        "probes": results,
    }


def reload_config(signum=None, frame=None):
    """SIGHUP handler — just log for now, threads will pick up new config on restart."""
    log("Received SIGHUP, config will be reloaded on next restart")


def cleanup(signum=None, frame=None):
    log("Geo prober stopping")
    shutdown_event.set()
    # Clean up state file
    try:
        if os.path.exists(STATE_FILE):
            os.unlink(STATE_FILE)
    except OSError:
        pass
    sys.exit(0)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "start"

    if action == "start":
        syslog.openlog("approuter-geo", syslog.LOG_PID, syslog.LOG_DAEMON)
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGHUP, reload_config)

        log(f"Geo prober started (PID {os.getpid()})")

        smart_rules = load_config()
        if not smart_rules:
            log("No smart gateway rules found, exiting")
            sys.exit(0)

        log(f"Found {len(smart_rules)} smart gateway rules")

        # Initialize: ensure all _gwN tables are empty (fallback mode)
        for rule in smart_rules:
            for base_table in rule["base_tables"]:
                for i in range(len(rule["gateways"]) - 1):
                    flush_table(base_table, i)

        # Write initial empty state
        write_state()
        notify_dns_watcher()

        # Start probe threads
        threads = []
        for rule in smart_rules:
            t = threading.Thread(
                target=probe_rule_loop, args=(rule,), daemon=True
            )
            t.start()
            threads.append(t)

        # Main thread stays alive
        try:
            while not shutdown_event.is_set():
                shutdown_event.wait(60)
        except Exception as e:
            log(f"Geo prober crashed: {e}", syslog.LOG_ERR)
            sys.exit(1)

    elif action == "stop":
        if os.path.exists(PID_FILE):
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                for _ in range(50):
                    try:
                        os.kill(pid, 0)
                        time.sleep(0.1)
                    except ProcessLookupError:
                        break
                print(f"Stopped geo prober (PID {pid})")
            except ProcessLookupError:
                print("Geo prober not running")
            if os.path.exists(PID_FILE):
                os.unlink(PID_FILE)
        else:
            print("Geo prober not running")

    elif action == "status":
        if os.path.exists(PID_FILE):
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                # Read state file for details
                status = {"running": True, "pid": pid}
                try:
                    with open(STATE_FILE) as f:
                        state = json.load(f)
                    status["active_tables"] = state.get("active_tables", [])
                except (IOError, json.JSONDecodeError):
                    status["active_tables"] = []
                print(json.dumps(status))
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
