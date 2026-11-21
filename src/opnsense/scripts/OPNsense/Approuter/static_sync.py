#!/usr/local/bin/python3
"""Merge static CIDR lists into category pf tables without losing learned IPs.

Category tables (<prefix>_<slug>) hold two kinds of entries: static CIDRs
from cidrs/<slug>.txt (china_all, custom categories) and IPs dns_watcher
learned from DNS answers. `pfctl -T replace` with the static list would drop
every learned IP, and clients keep their DNS caches, so they would not be
relearned until the TTL runs out (traffic falls back to the default route).

Instead: add the static entries missing from pf, and delete only entries that
an earlier version of the static list contained and the current one doesn't.
The previously applied list is kept in cidrs/.applied/<slug>.txt. Entries
dns_watcher learned (ip_seen.json) are never deleted here.

usage: static_sync.py [all|<slug> ...]
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import syslog
import tempfile

APPROUTER_DIR = "/usr/local/etc/app-router"
CIDRS_DIR = f"{APPROUTER_DIR}/cidrs"
APPLIED_DIR = f"{CIDRS_DIR}/.applied"
CONFIG_FILE = f"{APPROUTER_DIR}/config.json"
SEEN_FILE = f"{APPROUTER_DIR}/ip_seen.json"
PFCTL = "/sbin/pfctl"
SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def log(msg, level=syslog.LOG_INFO):
    syslog.openlog("approuter", syslog.LOG_PID, syslog.LOG_DAEMON)
    syslog.syslog(level, msg)


def norm(entry):
    """Canonical form of an address/CIDR (hosts without /32), None if invalid."""
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def read_list(path):
    result = set()
    try:
        with open(path) as f:
            for line in f:
                n = norm(line)
                if n:
                    result.add(n)
    except OSError:
        pass
    return result


def pfctl(*args, input_lines=None):
    """Run pfctl; with input_lines the entries are passed via a temp file."""
    cmd = [PFCTL] + list(args)
    tmp = None
    try:
        if input_lines is not None:
            fd, tmp = tempfile.mkstemp(prefix="approuter_sync_")
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(sorted(input_lines)) + "\n")
            cmd += ["-f", tmp]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    finally:
        if tmp:
            os.unlink(tmp)


def pf_tables():
    r = pfctl("-s", "Tables")
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}


def table_entries(table):
    r = pfctl("-t", table, "-T", "show")
    if r.returncode != 0:
        return None
    return {n for n in (norm(line) for line in r.stdout.splitlines()) if n}


def learned_entries(table):
    try:
        with open(SEEN_FILE) as f:
            data = json.load(f)
        return {n for n in (norm(ip) for ip in data.get(table, {})) if n}
    except (OSError, ValueError, AttributeError):
        return set()


def plan(current, static_new, static_old, learned):
    """(to_add, to_delete): never deletes learned or still-static entries."""
    to_add = static_new - current
    to_delete = (static_old - static_new - learned) & current
    return to_add, to_delete


def write_applied(slug, entries):
    os.makedirs(APPLIED_DIR, mode=0o750, exist_ok=True)
    path = os.path.join(APPLIED_DIR, f"{slug}.txt")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("".join(e + "\n" for e in sorted(entries)))
    os.replace(tmp, path)


def sync_table(slug, prefix, existing_tables):
    table = f"{prefix}_{slug}"
    static_new = read_list(os.path.join(CIDRS_DIR, f"{slug}.txt"))
    if table not in existing_tables:
        # not used by any rule: don't create it (pfctl -T add would)
        return None
    current = table_entries(table)
    if current is None:
        return None
    static_old = read_list(os.path.join(APPLIED_DIR, f"{slug}.txt"))
    to_add, to_delete = plan(current, static_new, static_old, learned_entries(table))
    ok = True
    if to_add:
        r = pfctl("-t", table, "-T", "add", input_lines=to_add)
        ok = ok and r.returncode == 0
    if to_delete:
        r = pfctl("-t", table, "-T", "delete", input_lines=to_delete)
        ok = ok and r.returncode == 0
    if ok:
        write_applied(slug, static_new)
        log(f"{table}: static list merged (+{len(to_add)} -{len(to_delete)}, "
            f"{len(current) + len(to_add) - len(to_delete)} entries)")
    else:
        log(f"{table}: static list merge failed", syslog.LOG_ERR)
    return to_add, to_delete


def table_prefix():
    try:
        with open(CONFIG_FILE) as f:
            prefix = json.load(f).get("table_prefix") or "approuter"
    except (OSError, ValueError, AttributeError):
        prefix = "approuter"
    return prefix if SLUG_RE.match(prefix) else "approuter"


def main(argv):
    targets = argv[1:] or ["all"]
    if targets == ["all"]:
        try:
            targets = sorted(f[:-4] for f in os.listdir(CIDRS_DIR) if f.endswith(".txt"))
        except OSError:
            targets = []
    prefix = table_prefix()
    existing = pf_tables()
    for slug in targets:
        if SLUG_RE.match(slug):
            sync_table(slug, prefix, existing)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
