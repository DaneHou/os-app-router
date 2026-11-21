#!/usr/local/bin/python3
"""Route inspector: explain how a client's traffic to a domain is routed.

    inspect_route.py trace <client-ip> <domain>
    inspect_route.py connections <client-ip>
    inspect_route.py clients

trace walks the same steps as a manual investigation: rules covering the
client, the domain's category, how the firewall resolves it (Resolve DNS via
Gateway), the addresses it resolves to now and recently, whether each one is
in the rule's table, and the client's live connections to them with the path
pf actually used. connections lists all live connections of a client with
host name and path. Prints JSON.
"""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns_watcher as dw  # noqa: E402
import dns_routes  # noqa: E402
import leak_check as lc  # noqa: E402

UNBOUND_ZONES = "/usr/local/etc/unbound.opnsense.d/approuter_dns.conf"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{0,62}$")
ROUTE_TO_RE = re.compile(r"^@(\d+)\s+pass in .*?\bon (\S+) route-to \((\S+) ([0-9.]+)\).*? from (\S+) to (\S+)")
LABEL_RE = re.compile(r'\blabel "([^"]+)"')
MAX_IPS = 24
MAX_CONNECTIONS = 300


# ---------------------------------------------------------------- data ---

def load_rules():
    dw.load_settings()
    dw.load_domain_mappings()
    return dw.settings["table_prefix"], dw.settings["rules"]


def all_category_mappings():
    """table -> domains for every category file, used or not."""
    out = {}
    for f in sorted(Path(dw.CONFIG_DIR).glob("approuter_*.json")):
        try:
            data = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        out.setdefault(data.get("table", ""), set()).update(d.lower().rstrip(".") for d in data.get("domains", []))
    return out


def suffix_match(name, domains):
    parts = name.split(".")
    return next(('.'.join(parts[i:]) for i in range(len(parts)) if '.'.join(parts[i:]) in domains), None)


def load_names():
    try:
        with open(dw.NAMES_FILE) as f:
            return {ip: v[0] for ip, v in json.load(f).get("names", {}).items()}
    except (OSError, ValueError):
        return {}


def load_seen():
    try:
        with open(dw.SEEN_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def forward_zones(path=UNBOUND_ZONES):
    zones = {}
    try:
        text = Path(path).read_text()
    except OSError:
        return zones
    for name, addr in re.findall(r'name:\s*"([^"]+)\."\s*\n\s*forward-addr:\s*(\S+)', text):
        zones[name.lower()] = addr
    return zones


def rule_hash(rule):
    return hashlib.md5(rule["uuid"].encode()).hexdigest()[:8]


def rule_for_source_token(token, rules, prefix):
    """Map a pf 'from <table>' token of a route-to rule to App Router rule names."""
    t = token.strip("<>").split(":")[0]
    out = []
    for r in rules:
        h = rule_hash(r)
        if t == f"{prefix}_clients_{h}" or t == f"ar_{r['uuid'][:8]}_mac":
            out.append(r)
        else:
            aliases = dw.CLIENTS_DIR / f"{prefix}_clients_{h}.aliases"
            if aliases.is_file() and t in aliases.read_text().split():
                out.append(r)
    return out


def parse_route_to(text):
    """pfctl -vvsr -> {rule no: {iface, gw_if, gw_ip, src, dst}} for every 'pass in ... route-to' rule."""
    out = {}
    for line in text.splitlines():
        m = ROUTE_TO_RE.match(line)
        if m:
            entry = {"iface": m.group(2), "gw_if": m.group(3), "gw_ip": m.group(4),
                     "src": m.group(5), "dst": m.group(6)}
            out[int(m.group(1))] = entry
            lab = LABEL_RE.search(line)
            if lab:
                out["label:" + lab.group(1)] = entry
    return out


def default_route(run=subprocess.run):
    gw = iface = None
    for line in run(["/sbin/route", "-n", "get", "default"], capture_output=True, text=True).stdout.splitlines():
        key, _, val = line.strip().partition(":")
        if key == "gateway":
            gw = val.strip()
        elif key == "interface":
            iface = val.strip()
    return gw or "?", iface or "?"


def describe_path(st, route_to, rules, prefix, default):
    """Human-readable path for a state, from the rule that created it.

    Rule numbers change on every filter reload while states live on, so the
    state's rule label (rlabel) is preferred.
    """
    rule_no = st["rule"]
    rt = route_to.get("label:" + st["rlabel"]) if st.get("rlabel") else route_to.get(rule_no)
    if rt is None:
        return {"kind": "default", "label": f"default route via {default[1]} ({default[0]})"}
    names = [r.get("description") or r["uuid"] for r in rule_for_source_token(rt["src"], rules, prefix)]
    if rt["dst"].strip("<>").startswith(prefix + "_") and names:
        return {"kind": "approuter", "label": f"{rt['gw_if']} ({rt['gw_ip']}) by App Router rule {', '.join(names)}"}
    return {"kind": "policy", "label": f"{rt['gw_if']} ({rt['gw_ip']}) by firewall rule @{rule_no}"}


def connections_of(client, states, route_to, rules, prefix, names, default, only_ips=None):
    conns = {}
    for st in states:
        if st["client"] != client or (only_ips is not None and st["dst"] not in only_ips):
            continue
        key = (st["cport"], st["dst"], st["dport"], st["proto"])
        c = conns.setdefault(key, {"dst": st["dst"], "port": st["dport"], "proto": st["proto"],
                                   "host": names.get(st["dst"], ""), "bytes": 0, "age": 0, "path": None})
        c["bytes"] = max(c["bytes"], st["bytes"])
        c["age"] = max(c["age"], st["age"])
        if st["inbound"] or c["path"] is None:
            # the inbound state (client interface) decides the path
            path = describe_path(st, route_to, rules, prefix, default)
            if st["inbound"] or path["kind"] != "default":
                c["path"] = path
    for c in conns.values():
        c["path"] = c["path"] or {"kind": "default", "label": f"default route via {default[1]} ({default[0]})"}
    return sorted(conns.values(), key=lambda c: -c["bytes"])


def pf_snapshot():
    states = lc.parse_states(subprocess.run(["/sbin/pfctl", "-vss"], capture_output=True, text=True).stdout)
    rules_text = subprocess.run(["/sbin/pfctl", "-vvsr"], capture_output=True, text=True).stdout
    return states, parse_route_to(rules_text)


# --------------------------------------------------------------- trace ---

def step(status, title, detail="", items=None):
    s = {"status": status, "title": title, "detail": detail}
    if items:
        s["items"] = items
    return s


def trace(client, domain, *, prefix, rules, mappings, names, seen, zones, resolve, states, route_to,
          clients_of, table_has, route_of, default):
    steps = []
    addr = ipaddress.ip_address(client)

    # 1. rules covering the client
    mine = [r for r in rules if any(addr in n for n in clients_of(r))]
    if not mine:
        steps.append(step("info", "No App Router rule covers this client",
                          f"All its traffic uses the default route via {default[1]}."))
    else:
        steps.append(step("ok", f"Client is covered by {len(mine)} rule(s)", "", [
            f"{r.get('description') or r['uuid']}: interface {r.get('interface')}, gateway {r.get('gateway')}, "
            f"categories {r.get('categories') or '-'}" + (", custom domains" if str(r.get('custom_domains', '')).strip() else "")
            for r in mine]))

    # 2. which table / rule the domain belongs to
    hits = {}
    for table, domains in mappings.items():
        m = suffix_match(domain, domains)
        if m:
            hits[table] = m
    my_tables = {}
    for r in mine:
        for t in lc.rule_tables(r, prefix):
            if t in hits:
                my_tables.setdefault(t, []).append(r)
    if my_tables:
        steps.append(step("ok", "Domain belongs to the client's rules", "", [
            f"{domain} matches {hits[t]} in {t} -> rule {', '.join(r.get('description') or r['uuid'] for r in rs)}"
            for t, rs in my_tables.items()]))
    elif hits:
        steps.append(step("info", "Domain is in a category, but none of this client's rules uses it", "", [
            f"{domain} matches {m} in {t}" for t, m in hits.items()]))
    else:
        steps.append(step("info", "Domain is not in any category or custom domain list",
                          "App Router does not route it. To route it, add it to a rule's custom domains or a category."))
    rule = next(iter(my_tables.values()))[0] if my_tables else None
    tables = set(my_tables)

    # 3. DNS path
    zone = suffix_match(domain, zones)
    if zone:
        want = next((r for r in dns_routes.load_desired() if r["dns"] == zones[zone]), None)
        gw, iface = route_of(zones[zone])
        ok = want is not None and iface == want["interface"]
        steps.append(step("ok" if ok else "bad",
                          f"Unbound resolves {zone} via {zones[zone]} (Resolve DNS via Gateway)",
                          (f"Route to {zones[zone]}: {iface} ({gw})" if ok else
                           f"Route to {zones[zone]} uses {iface} ({gw}), expected {want['interface'] if want else 'the rule gateway'}: "
                           "answers come from this router's location")))
    elif rule is not None:
        steps.append(step("info", "Unbound resolves this domain from this router's location",
                          "If the site redirects to its international version or refuses service although the traffic "
                          "is routed, enable Resolve DNS via Gateway on the rule."))

    # 4. addresses: now (via Unbound) and recently seen in answers to clients
    now_ips = sorted(resolve(domain))
    recent = sorted(ip for ip, n in names.items() if n == domain)
    steps.append(step("ok" if now_ips else "warn", f"Resolves now to {len(now_ips)} address(es) via Unbound",
                      ", ".join(now_ips[:MAX_IPS]) or "no A record"))
    if recent:
        extra = [ip for ip in recent if ip not in now_ips]
        steps.append(step("info", f"Clients recently received {len(recent)} address(es) for this name",
                          ", ".join(recent[:MAX_IPS]) + (f" ({len(extra)} differ from the current answer)" if extra else "")))

    # 5. per address verdict
    if rule is not None:
        items, bad = [], 0
        for ip in (now_ips + [ip for ip in recent if ip not in now_ips])[:MAX_IPS]:
            in_tables = [t for t in tables if table_has(t, ip)]
            if in_tables:
                ts = max((seen.get(t, {}).get(ip, 0) for t in in_tables), default=0)
                when = time.strftime("%H:%M", time.localtime(ts)) if ts else "static/unknown"
                items.append(f"{ip}: in {in_tables[0]} (learned {when}) -> {rule.get('gateway')}")
            else:
                bad += 1
                items.append(f"{ip}: NOT in the table -> default route via {default[1]}")
        steps.append(step("bad" if bad else "ok",
                          f"{len(items) - bad} of {len(items)} address(es) are routed via {rule.get('gateway')}", "", items))

    # 6. live connections
    ips = set(now_ips) | set(recent) | {ip for ip, n in names.items() if suffix_match(n, {domain})}
    conns = connections_of(client, states, route_to, rules, prefix, names, default, only_ips=ips)
    if conns:
        leaked = [c for c in conns if rule is not None and c["path"]["kind"] != "approuter"]
        grouped = {}
        for c in conns:
            line = f"{c['host'] or c['dst']} {c['dst']}:{c['port']}/{c['proto']} -> {c['path']['label']}"
            grouped[line] = grouped.get(line, 0) + 1
        steps.append(step("bad" if leaked else "ok",
                          f"{len(conns)} live connection(s) from the client" + (f", {len(leaked)} NOT through the rule gateway" if leaked else ""),
                          "", [line + (f"  (x{n})" if n > 1 else "") for line, n in list(grouped.items())[:30]]))
    else:
        steps.append(step("info", "No live connections from the client to these addresses"))

    verdict = "routed" if rule is not None else "default"
    problems = sum(1 for s in steps if s["status"] == "bad")
    if rule is not None:
        summary = f"{domain} from {client} should go via {rule.get('gateway')} (rule {rule.get('description') or rule['uuid']})"
        summary += f": {problems} problem(s) found below" if problems else ": everything checks out"
    else:
        summary = f"{domain} from {client} uses the default route via {default[1]} ({default[0]}), App Router does not route it"
    return {"client": client, "domain": domain, "verdict": verdict, "problems": problems, "summary": summary,
            "gateway": rule.get("gateway") if rule else default[1], "steps": steps}


# ---------------------------------------------------------------- main ---

def known_clients(rules, prefix):
    out = []
    for r in rules:
        for n in lc.rule_clients(r, prefix):
            if n.num_addresses <= 256:
                for a in (n.hosts() if n.num_addresses > 1 else [n.network_address]):
                    out.append({"ip": str(a), "rule": r.get("description") or r["uuid"]})
    seen, uniq = set(), []
    for c in out:
        if c["ip"] not in seen:
            seen.add(c["ip"])
            uniq.append(c)
    return uniq


def main():
    dw.log = lambda *a, **k: None
    args = sys.argv[1:]
    action = args[0] if args else ""
    prefix, rules = load_rules()

    if action == "clients":
        print(json.dumps({"status": "ok", "clients": known_clients(rules, prefix)}))
        return
    try:
        client = str(ipaddress.IPv4Address(args[1]))
    except (IndexError, ValueError):
        print(json.dumps({"status": "error", "message": "Enter the client's IPv4 address"}))
        return
    states, route_to = pf_snapshot()
    names = load_names()
    default = default_route()
    if action == "connections":
        conns = connections_of(client, states, route_to, rules, prefix, names, default)
        print(json.dumps({"status": "ok", "client": client, "total": len(conns), "connections": conns[:MAX_CONNECTIONS]}))
        return
    if action == "trace":
        domain = (args[2] if len(args) > 2 else "").strip().lower().rstrip(".")
        domain = re.sub(r"^[a-z]+://", "", domain).split("/")[0].split(":")[0]
        if not DOMAIN_RE.match(domain):
            print(json.dumps({"status": "error", "message": "Enter a domain name such as m.iqiyi.com"}))
            return
        result = trace(client, domain, prefix=prefix, rules=rules, mappings=all_category_mappings(),
                       names=names, seen=load_seen(), zones=forward_zones(), resolve=dw.resolve_via_unbound,
                       states=states, route_to=route_to, clients_of=lambda r: lc.rule_clients(r, prefix),
                       table_has=lc.table_has, route_of=dns_routes.current_route, default=default)
        print(json.dumps(dict(result, status="ok")))
        return
    print(json.dumps({"status": "error", "message": "usage: trace <ip> <domain> | connections <ip> | clients"}))


if __name__ == "__main__":
    main()
