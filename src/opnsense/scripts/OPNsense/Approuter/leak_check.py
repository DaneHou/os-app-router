#!/usr/local/bin/python3
"""Leak check: connections that should be routed by a rule but leave another way.

For every enabled rule it looks at the current pf states of the rule's
clients. The destination host name comes from the DNS answers dns_watcher
sniffed (dns_names.json, last 2 h, any resolver on the firewall). When that
name belongs to the rule (categories / custom domains) but the state was not
created by one of App Router's route-to rules, the connection leaked out the
default route. Prints JSON.
"""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns_watcher as dw  # noqa: E402

NAMES_FILE = dw.NAMES_FILE
MAX_LEAKS_PER_RULE = 50

# "IF PROTO A [(A')] -> B" (outbound state, A' = address before NAT) or
# "IF PROTO B <- A [(A')]" (inbound state: pf prints the destination first)
STATE_RE = re.compile(
    r"^\S+\s+(?P<proto>tcp|udp)\s+(?P<a>\S+)(?:\s+\((?P<ainner>[^)]+)\))?\s+(?P<dir>->|<-)\s+"
    r"(?P<b>\S+)(?:\s+\((?P<binner>[^)]+)\))?")
RULE_RE = re.compile(r"\brule (\d+)\b")
BYTES_RE = re.compile(r"\b(\d+):(\d+) bytes\b")
AGE_RE = re.compile(r"\bage (\d+):(\d+):(\d+)")
RULE_LINE_RE = re.compile(r"^@(\d+)\s+(.*)$")


def split_hostport(s):
    host, _, port = s.rpartition(":")
    return host, port


def parse_states(text):
    """pfctl -vss output -> list of dicts (client, cport, dst, dport, proto, rule)."""
    states = []
    cur = None
    for line in text.splitlines():
        m = STATE_RE.match(line)
        if m:
            if cur:
                states.append(cur)
            cur = None
            if m.group("dir") == "->":
                src, dst = m.group("ainner") or m.group("a"), m.group("b")
            else:
                src, dst = m.group("binner") or m.group("b"), m.group("a")
            client, cport = split_hostport(src)
            dst, dport = split_hostport(dst)
            cur = {"proto": m.group("proto"), "client": client, "cport": cport,
                   "dst": dst, "dport": dport, "rule": None, "inbound": m.group("dir") == "<-",
                   "bytes": 0, "age": 0}
            continue
        if cur and cur["rule"] is None:
            r = RULE_RE.search(line)
            if r:
                cur["rule"] = int(r.group(1))
            b = BYTES_RE.search(line)
            if b:
                cur["bytes"] = int(b.group(1)) + int(b.group(2))
            a = AGE_RE.search(line)
            if a:
                cur["age"] = int(a.group(1)) * 3600 + int(a.group(2)) * 60 + int(a.group(3))
    if cur:
        states.append(cur)
    return states


def parse_routed_rules(text, prefix):
    """pfctl -vvsr output -> {rule number: set of destination tables} for App Router route-to rules.

    A routed connection has an inbound state created by such a rule (on the
    client interface) and an outbound state created by the gateway's own
    rule; a leaked one has neither from App Router.
    """
    routed = {}
    for line in text.splitlines():
        m = RULE_LINE_RE.match(line)
        if not m or "route-to" not in m.group(2):
            continue
        # pfctl -vvsr prints table sizes: <approuter_video_iqiyi:301>
        tables = set(re.findall(r"to <(" + re.escape(prefix) + r"_[A-Za-z0-9_]+)(?::\d+)?>", m.group(2)))
        if tables:
            routed[int(m.group(1))] = tables
    return routed


def rule_tables(rule, prefix):
    tables = set()
    for cat in str(rule.get("categories", "")).split(","):
        cat = cat.strip()
        if cat:
            tables.add(f"{prefix}_{cat.replace('.', '_')}")
    if str(rule.get("custom_domains", "")).strip() and rule.get("uuid"):
        tables.add(f"{prefix}_custom_{hashlib.md5(rule['uuid'].encode()).hexdigest()[:8]}")
    return tables


def rule_clients(rule, prefix, show_table=None):
    """Client networks of a rule: its client table file plus alias sources."""
    show_table = show_table or dw.show_table
    h = hashlib.md5(rule["uuid"].encode()).hexdigest()[:8]
    nets = []
    if str(rule.get("source_nets", "")).strip().lower() == "any":
        return [ipaddress.ip_network("0.0.0.0/0")]
    base = dw.CLIENTS_DIR / f"{prefix}_clients_{h}"
    entries = []
    txt = base.with_suffix(".txt")
    if txt.is_file():
        entries += txt.read_text().splitlines()
    aliases = base.with_suffix(".aliases")
    if aliases.is_file():
        for name in aliases.read_text().splitlines():
            if dw.ALIAS_NAME_RE.match(name.strip()):
                entries += show_table(name.strip()) or []
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(e.strip(), strict=False))
        except ValueError:
            pass
    return nets


def in_nets(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def table_has(table, ip):
    return subprocess.run(["/sbin/pfctl", "-t", table, "-T", "test", ip],
                          capture_output=True).returncode == 0


def check(rules, prefix, states, routed, names, match_domain, clients_of, has=table_has):
    routed_numbers = set(routed)
    out = []
    for rule in rules:
        tables = rule_tables(rule, prefix)
        nets = clients_of(rule)
        conns = {}
        for st in states:
            if not in_nets(st["client"], nets):
                continue
            host = names.get(st["dst"])
            if not host or not (match_domain(host) & tables):
                continue
            key = (st["client"], st["cport"], st["dst"], st["dport"], st["proto"])
            ok = st["rule"] in routed_numbers
            conns[key] = conns.get(key, False) or ok
            conns.setdefault(("host",) + key, host)
        routed_n = sum(1 for k, v in conns.items() if k[0] != "host" and v)
        leaks = []
        for key, ok in sorted(conns.items(), key=lambda kv: str(kv[0])):
            if key[0] == "host" or ok:
                continue
            client, _cport, dst, dport, proto = key
            learned = any(has(t, dst) for t in tables)
            leaks.append({
                "client": client, "host": conns[("host",) + key], "dst": dst, "port": dport, "proto": proto,
                "in_table": learned,
                "reason": ("connection opened before the IP was learned (old state)" if learned else
                           "IP not learned: the client got it from a DNS answer App Router didn't see "
                           "(own DNS / DoH, or cached before learning)"),
            })
        out.append({
            "rule": rule.get("description") or rule.get("uuid", ""),
            "routed": routed_n,
            "leaked": len(leaks),
            "leaks": leaks[:MAX_LEAKS_PER_RULE],
        })
    return out


def main():
    dw.log = lambda *a, **k: None      # don't write to the watcher's log
    dw.load_settings()
    dw.load_domain_mappings()
    prefix = dw.settings["table_prefix"]
    rules = dw.settings["rules"]

    try:
        with open(NAMES_FILE) as f:
            names_data = json.load(f)
        names = {ip: v[0] for ip, v in names_data.get("names", {}).items()}
        names_age = int(time.time() - names_data.get("updated", 0))
    except (OSError, ValueError):
        names, names_age = {}, None

    states = parse_states(subprocess.run(["/sbin/pfctl", "-vss"], capture_output=True, text=True).stdout)
    routed = parse_routed_rules(subprocess.run(["/sbin/pfctl", "-vvsr"], capture_output=True, text=True).stdout, prefix)
    result = {
        "status": "ok",
        "checked_at": int(time.time()),
        "states": len(states),
        "known_names": len(names),
        "names_age": names_age,
        "rules": check(rules, prefix, states, routed, names, dw.match_domain,
                       lambda r: rule_clients(r, prefix)),
    }
    if names_age is None or names_age > 300:
        result["status"] = "warning"
        result["message"] = "No recent DNS name data: is the DNS watcher running?"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
