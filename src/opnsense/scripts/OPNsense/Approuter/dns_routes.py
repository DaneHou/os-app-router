#!/usr/local/bin/python3
"""Host routes for "Resolve DNS via gateway" (see dns_forward.php).

dns_forward.php writes the desired routes to dns_routes.json:
    {"routes": [{"dns": "223.6.6.6", "interface": "pgw_China",
                 "gateway": "172.31.175.170"}]}

`dns_routes.py sync` installs them and removes routes this script installed
earlier that are no longer wanted. dns_watcher calls ensure_routes() every
minute, because tunnel interfaces (and their routes) get recreated.
"""
import json
import os
import subprocess
import sys
import syslog

BASE_DIR = "/usr/local/etc/app-router"
DESIRED_FILE = os.path.join(BASE_DIR, "dns_routes.json")
APPLIED_FILE = os.path.join(BASE_DIR, "dns_routes_applied.json")
ROUTE = "/sbin/route"


def log(msg, level=syslog.LOG_INFO):
    syslog.syslog(level, f"dns_routes: {msg}")


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_desired():
    data = _load(DESIRED_FILE, {})
    routes = data.get("routes", []) if isinstance(data, dict) else []
    return [r for r in routes if isinstance(r, dict) and r.get("dns") and r.get("interface") and r.get("gateway")]


def current_route(ip, run=subprocess.run):
    """Return (gateway, interface) of the route the kernel uses for ip."""
    proc = run([ROUTE, "-n", "get", "-host", ip], capture_output=True, text=True)
    gw = iface = None
    for line in proc.stdout.splitlines():
        key, _, val = line.strip().partition(":")
        if key == "gateway":
            gw = val.strip()
        elif key == "interface":
            iface = val.strip()
    return gw, iface


def interface_exists(name, run=subprocess.run):
    return run(["/sbin/ifconfig", name], capture_output=True).returncode == 0


def ensure_route(r, run=subprocess.run):
    """Make sure r["dns"] is routed via r["gateway"] on r["interface"].

    Returns "ok", "added" or an error string.
    """
    dns, gw, iface = r["dns"], r["gateway"], r["interface"]
    cur_gw, cur_if = current_route(dns, run)
    if cur_if == iface and cur_gw in (gw, None):
        return "ok"
    if not interface_exists(iface, run):
        return f"interface {iface} does not exist"
    # The gateway must be reachable on the interface. On a LAN-style interface
    # it is (connected subnet); a point-to-point tunnel (/32 address) needs an
    # interface route to its peer, which is lost when the tunnel is recreated.
    _, gw_if = current_route(gw, run)
    if gw_if != iface:
        run([ROUTE, "-q", "delete", "-host", gw], capture_output=True)
        run([ROUTE, "-q", "add", "-host", gw, "-interface", iface], capture_output=True)
    run([ROUTE, "-q", "delete", "-host", dns], capture_output=True)
    proc = run([ROUTE, "-q", "add", "-host", dns, gw], capture_output=True, text=True)
    if proc.returncode != 0:
        return f"route add {dns} via {gw} failed: {(proc.stderr or proc.stdout).strip()}"
    return "added"


def ensure_routes(run=subprocess.run, logger=log):
    """Install every desired route; returns list of (dns, result)."""
    results = []
    for r in load_desired():
        res = ensure_route(r, run)
        if res == "added":
            logger(f"route {r['dns']} -> {r['gateway']} ({r['interface']}) installed")
        elif res != "ok":
            logger(f"route {r['dns']}: {res}", syslog.LOG_WARNING)
        results.append((r["dns"], res))
    return results


def sync(run=subprocess.run):
    desired = load_desired()
    want = {r["dns"] for r in desired}
    applied = set(_load(APPLIED_FILE, []))
    for ip in sorted(applied - want):
        run([ROUTE, "-q", "delete", "-host", ip], capture_output=True)
        print(f"route {ip} removed")
        log(f"route {ip} removed")
    for dns, res in ensure_routes(run):
        print(f"route {dns}: {res}")
    tmp = APPLIED_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(want), f)
    os.replace(tmp, APPLIED_FILE)


def cleanup(run=subprocess.run):
    """Remove every route installed by App Router (uninstall)."""
    for ip in _load(APPLIED_FILE, []):
        run([ROUTE, "-q", "delete", "-host", ip], capture_output=True)
    for path in (APPLIED_FILE, DESIRED_FILE):
        try:
            os.remove(path)
        except OSError:
            pass


def main():
    syslog.openlog("approuter", syslog.LOG_PID, syslog.LOG_DAEMON)
    action = sys.argv[1] if len(sys.argv) > 1 else "sync"
    if action == "sync":
        sync()
    elif action == "ensure":
        for dns, res in ensure_routes():
            print(f"route {dns}: {res}")
    elif action == "cleanup":
        cleanup()
    else:
        print(f"Usage: {sys.argv[0]} [sync|ensure|cleanup]")
        sys.exit(1)


if __name__ == "__main__":
    main()
