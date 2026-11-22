#!/usr/local/bin/python3
"""Clear Unbound's cached failures for App Router's forward zones after Apply.

Apply ends with a filter reload. While pf reloads, Unbound's TCP queries to
the "Resolve DNS via gateway" server (e.g. 223.6.6.6 through FRP_GW) time
out. Unbound then backs off from that server (infra cache: rtt/rto) and
answers SERVFAIL for the forward zones until it probes the server again,
about a minute later.

This script, run detached at the end of Apply:
  1. waits (max ROUTE_WAIT s) until each forward server is routed through
     its gateway again (dns_routes.json),
  2. runs `unbound-control flush_infra <server>` for each forward server
     (forget the timeouts) and `unbound-control flush_zone <zone>` for each
     forward zone (drop cached SERVFAIL answers),
  3. asks Unbound for one zone and repeats the flush if it still answers
     SERVFAIL (max VERIFY_TRIES times).

Only App Router's zones and servers are touched. Best effort: every failure
is logged, the exit code is always 0.
"""
import json
import os
import re
import subprocess
import sys
import syslog
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns_routes  # noqa: E402

UNBOUND_CONTROL = "/usr/local/sbin/unbound-control"
UNBOUND_CONF = "/var/unbound/unbound.conf"   # same -c as core's scripts/unbound/*.py
UNBOUND_PID = "/var/run/unbound.pid"
ZONES_FILE = "/usr/local/etc/unbound.opnsense.d/approuter_dns.conf"
STATUS_FILE = "/usr/local/etc/app-router/dns_forward_status.json"
DRILL = "/usr/bin/drill"

ROUTE_WAIT = 15        # seconds to wait for the forward servers' routes
VERIFY_TRIES = 3
VERIFY_DELAY = 5
CMD_TIMEOUT = 10

ZONE_RE = re.compile(r'name:\s*"([^"]+?)\.?"\s*\n\s*forward-addr:\s*(\S+)')
RCODE_RE = re.compile(r"rcode:\s*([A-Z]+)")


def log(msg, level=syslog.LOG_INFO):
    try:
        syslog.syslog(level, f"unbound_flush: {msg}")
    except Exception:
        pass
    print(msg)


def parse_zones(text):
    """App Router's Unbound include -> {zone: forward server}."""
    return {name.lower(): addr for name, addr in ZONE_RE.findall(text or "")}


def load_zones(path=ZONES_FILE):
    try:
        with open(path) as f:
            return parse_zones(f.read())
    except OSError:
        return {}


def flush_commands(zones):
    """unbound-control arguments: servers first, then the zones."""
    cmds = [["flush_infra", ip] for ip in sorted(set(zones.values()))]
    cmds += [["flush_zone", zone] for zone in sorted(zones)]
    return cmds


def unbound_running(pidfile=UNBOUND_PID):
    try:
        with open(pidfile) as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


def unbound_port(status_file=STATUS_FILE, conf=UNBOUND_CONF):
    try:
        with open(status_file) as f:
            port = int(json.load(f).get("unbound_port") or 0)
        if port:
            return port
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    try:
        with open(conf) as f:
            m = re.search(r"^\s*port:\s*(\d+)", f.read(), re.M)
        if m:
            return int(m.group(1))
    except OSError:
        pass
    return 53


def routes_ready(servers, run, desired=None):
    """Is every forward server with a desired route routed through its gateway interface?"""
    desired = dns_routes.load_desired() if desired is None else desired
    for r in desired:
        if r["dns"] not in servers:
            continue
        try:
            _gw, iface = dns_routes.current_route(r["dns"], run)
        except Exception:
            return False
        if iface != r["interface"]:
            return False
    return True


def wait_routes(servers, run, sleep, timeout=ROUTE_WAIT, desired=None):
    for i in range(timeout + 1):
        if routes_ready(servers, run, desired):
            return True
        if i < timeout:
            sleep(1)
    return False


def flush(zones, run):
    """Run the flush commands; returns (number ok, list of errors)."""
    ok, errors = 0, []
    for args in flush_commands(zones):
        try:
            proc = run([UNBOUND_CONTROL, "-c", UNBOUND_CONF] + args,
                       capture_output=True, text=True, timeout=CMD_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as e:
            errors.append(f"{' '.join(args)}: {e}")
            continue
        if proc.returncode == 0:
            ok += 1
        else:
            errors.append(f"{' '.join(args)}: {(proc.stderr or proc.stdout or '').strip()[:200]}")
    return ok, errors


def probe(zone, port, run):
    """rcode Unbound returns for `zone A` (SERVFAIL, NOERROR, ...) or None."""
    try:
        proc = run([DRILL, "-p", str(port), zone, "@127.0.0.1", "A"],
                   capture_output=True, text=True, timeout=CMD_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    m = RCODE_RE.search(proc.stdout or "")
    return m.group(1) if m else None


def run_flush(run=subprocess.run, sleep=time.sleep, zones=None, desired=None,
              control=UNBOUND_CONTROL, running=None, port=None):
    """The whole flow; returns a summary dict (also used by the tests)."""
    zones = load_zones() if zones is None else zones
    if not zones:
        return {"status": "skipped", "reason": "no forward zones"}
    if not os.path.exists(control):
        log(f"{control} not found, cache not flushed", syslog.LOG_WARNING)
        return {"status": "skipped", "reason": "unbound-control not found"}
    if not (unbound_running() if running is None else running):
        log("Unbound is not running, cache not flushed", syslog.LOG_WARNING)
        return {"status": "skipped", "reason": "unbound not running"}

    servers = set(zones.values())
    routed = wait_routes(servers, run, sleep, desired=desired)
    if not routed:
        log(f"route to {', '.join(sorted(servers))} not via its gateway after {ROUTE_WAIT}s, flushing anyway",
            syslog.LOG_WARNING)

    port = unbound_port() if port is None else port
    check_zone = sorted(zones)[0]
    rcode = None
    total_ok, all_errors, tries = 0, [], 0
    for tries in range(1, VERIFY_TRIES + 1):
        ok, errors = flush(zones, run)
        total_ok += ok
        all_errors += errors
        if ok == 0:
            break           # unbound-control does not work at all: retrying won't help
        rcode = probe(check_zone, port, run)
        if rcode != "SERVFAIL":
            break
        if tries < VERIFY_TRIES:
            sleep(VERIFY_DELAY)

    for e in all_errors[:5]:
        log(f"unbound-control {e}", syslog.LOG_WARNING)
    servers_txt = ", ".join(sorted(servers))
    msg = (f"flushed Unbound infra cache for {servers_txt} and {len(zones)} forward zones"
           f" ({tries} pass{'es' if tries > 1 else ''}); {check_zone} -> {rcode or 'no answer'}")
    level = syslog.LOG_WARNING if rcode == "SERVFAIL" or all_errors else syslog.LOG_INFO
    log(msg, level)
    return {"status": "ok" if total_ok else "failed", "zones": len(zones), "servers": sorted(servers),
            "passes": tries, "check": {check_zone: rcode}, "errors": all_errors, "routed": routed}


def main():
    syslog.openlog("approuter", syslog.LOG_PID, syslog.LOG_DAEMON)
    try:
        result = run_flush()
        if result["status"] == "skipped" and result["reason"] == "no forward zones":
            print("no forward zones, nothing to flush")
    except Exception as e:      # never fail Apply
        log(f"failed: {e}", syslog.LOG_ERR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
