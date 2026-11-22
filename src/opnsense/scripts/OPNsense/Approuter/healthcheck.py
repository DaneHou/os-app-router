#!/usr/local/bin/python3
"""App Router health check (plugin health contract).

    configctl approuter healthcheck

Prints {"checks": [{"name", "ok", "severity", "detail", "fix"?}]}: ok is true,
false or null (not applicable); severity is medium (default), low or info.
Read-only and fast: it reads App Router's state files, pf (`pfctl -sr`,
`-s Tables`, `-T show` of the device aliases), the core gateway status and
the process table. When the stored DNS forward check failed it asks the local
resolver (127.0.0.1) once more for the marker record. It never sends traffic
to other hosts and never runs the leak check itself: it reports the last
stored result.

A failing check may carry "fix" (plugin health contract): the configd action
Netbaseline may run to repair it (restart the DNS watcher, flush Unbound's
failures for the forward zones). Only safe, idempotent actions that do not
change config.xml; no fix triggers a filter reload.
"""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

APPROUTER_DIR = "/usr/local/etc/app-router"
CONFIG_FILE = f"{APPROUTER_DIR}/config.json"
DNS_FORWARD_STATUS = f"{APPROUTER_DIR}/dns_forward_status.json"
LEAK_CHECK_LAST = f"{APPROUTER_DIR}/leak_check_last.json"
UNBOUND_ZONES = "/usr/local/etc/unbound.opnsense.d/approuter_dns.conf"
DNS_WATCHER_PID = "/var/run/approuter_dns_watcher.pid"
GEO_PROBER_PID = "/var/run/approuter_geo_prober.pid"
GATEWAY_STATUS = "/usr/local/opnsense/scripts/routes/gateway_status.php"
PFCTL = "/sbin/pfctl"
DRILL = "/usr/bin/drill"

CMD_TIMEOUT = 4
DEADLINE = 8              # seconds: stop running commands after this
LEAK_MAX_AGE = 8 * 86400  # a weekly leak check older than this is stale
DOWN_STATES = {"down", "force_down"}

MAC_RE = re.compile(r"^[0-9a-f]{1,2}([:-])[0-9a-f]{1,2}(\1[0-9a-f]{1,2}){4}$", re.I)
ALIAS_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")
# "... route-to (gw ip) inet from <src> to <dst> ..." ("route-to" itself contains "to")
PF_FROM_TO_RE = re.compile(r"\sfrom (\S+) to (\S+)")
# marker record dns_forward.php puts into App Router's Unbound include
MARKER_RE = re.compile(r'local-data:\s*"(_approuter-check\.[A-Za-z0-9.\-]{1,250}?)\.?\s+\d+\s+IN\s+TXT\s+approuter"')

# repairs Netbaseline may run (plugin health contract "fix"); safe, idempotent, no config.xml change
FIX_DNS_WATCHER = {"action": "approuter dns_watcher_restart", "title": "Restart the App Router DNS watcher"}
FIX_UNBOUND_FLUSH = {"action": "approuter unbound_flush",
                     "title": "Flush Unbound failures for App Router forward zones"}


class System:
    """Access to the firewall; the tests replace it with fixtures."""

    def __init__(self):
        self.start = time.monotonic()

    def now(self):
        return time.time()

    def read(self, path):
        try:
            with open(path) as f:
                return f.read()
        except OSError:
            return None

    def run(self, argv):
        """stdout of a command, or None (failed, timed out or past the deadline)."""
        left = DEADLINE - (time.monotonic() - self.start)
        if left <= 0:
            return None
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=min(CMD_TIMEOUT, left))
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout if proc.returncode == 0 else None

    def pid_alive(self, pidfile):
        try:
            with open(pidfile) as f:
                os.kill(int(f.read().strip()), 0)
            return True
        except (OSError, ValueError):
            return False

    def count_processes(self, pattern):
        out = self.run(["/bin/pgrep", "-f", pattern])
        return len(out.split()) if out else 0


def check(name, ok, detail, severity="medium", fix=None):
    out = {"name": name, "ok": ok, "severity": severity, "detail": detail}
    if fix and ok is False:
        out["fix"] = dict(fix)
    return out


def load_json(system, path, lenient=False):
    text = system.read(path)
    if text is None:
        return None
    if lenient:
        # config.json comes from a Jinja2 template: tolerate trailing commas
        text = re.sub(r",\s*([}\]])", r"\1", text)
    try:
        return json.loads(text)
    except ValueError:
        return None


# ------------------------------------------------------------- rules ---

def csv(value):
    return [v.strip() for v in str(value or "").split(",") if v.strip()]


def rule_name(rule):
    return rule.get("description") or rule.get("uuid", "?")


def rule_hash(rule):
    return hashlib.md5(str(rule.get("uuid", "")).encode()).hexdigest()[:8]


def mac_alias_name(rule):
    hexchars = re.sub(r"[^0-9a-f]", "", str(rule.get("uuid", "")).lower())
    return f"ar_{hexchars[:8]}_mac"


def parse_sources(source_nets):
    """Same split as approuter_parse_sources(): any / nets / aliases / macs."""
    out = {"any": False, "nets": [], "aliases": [], "macs": []}
    for entry in csv(source_nets):
        mac = entry[4:] if entry.lower().startswith("mac:") else entry
        if entry.lower() == "any":
            out["any"] = True
        elif MAC_RE.match(mac):
            out["macs"].append(mac.lower())
        else:
            try:
                ipaddress.ip_network(entry, strict=False)
                out["nets"].append(entry)
            except ValueError:
                if ALIAS_RE.match(entry):
                    out["aliases"].append(entry)
    return out


def source_tokens(rule, prefix):
    """pf 'from' tokens the firewall hook generates for a rule."""
    src = parse_sources(rule.get("source_nets"))
    if src["any"]:
        return {"any"}
    tokens = set(src["aliases"])
    if src["nets"]:
        tokens.add(f"{prefix}_clients_{rule_hash(rule)}")
    if src["macs"]:
        tokens.add(mac_alias_name(rule))
    return tokens


def rule_tables(rule, prefix):
    tables = {f"{prefix}_{c.replace('.', '_')}" for c in csv(rule.get("categories"))}
    if str(rule.get("custom_domains", "")).strip() and rule.get("uuid"):
        tables.add(f"{prefix}_custom_{rule_hash(rule)}")
    return tables


def rule_gateways(rule):
    """Gateways a rule uses: all of them for smart rules, the first otherwise."""
    gws = csv(rule.get("gateway"))
    return gws if is_smart(rule) else gws[:1]


def is_smart(rule):
    return str(rule.get("smart_gateway")) == "1" and len(csv(rule.get("gateway"))) > 1


def parse_pf_rules(text):
    """pfctl -sr -> list of (from token, to token) of the route-to rules."""
    out = []
    for line in (text or "").splitlines():
        if not line.startswith("pass") or "route-to" not in line:
            continue
        m = PF_FROM_TO_RE.search(line)
        if m:
            out.append(tuple(tok.strip("<>{}").split(":")[0] for tok in m.groups()))
    return out


# ------------------------------------------------------------ checks ---

def check_enabled(config):
    name = "Plugin enabled"
    if config is None:
        return check(name, None, "No configuration generated yet (config.json missing): App Router was never applied",
                     "info")
    if str(config.get("enabled")) != "1":
        return check(name, None, "App Router is disabled", "info")
    return check(name, True, f"App Router is enabled with {len(config.get('rules', []))} active rule(s)", "info")


def check_dns_forward(system):
    name = "DNS forward reaches Unbound"
    st = load_json(system, DNS_FORWARD_STATUS)
    if not isinstance(st, dict) or not st.get("zones"):
        return check(name, None, "No rule uses \"Resolve DNS via gateway\"")
    age = ""
    if st.get("checked"):
        age = f", checked {int((system.now() - st['checked']) // 60)} min ago"
    if st.get("reaches_unbound"):
        return check(name, True, f"Port 53 ({st.get('port53') or 'unknown server'}) forwards the "
                                 f"{st['zones']} zone(s) to Unbound (port {st.get('unbound_port')}){age}")
    # the stored result is from the last Apply/list update (Unbound may have been restarting):
    # ask port 53 for the marker record once more
    if marker_reaches_unbound(system):
        return check(name, True, f"Port 53 ({st.get('port53') or 'unknown server'}) forwards the "
                                 f"{st['zones']} zone(s) to Unbound now (stored check failed{age})")
    return check(name, False, f"DNS queries on port 53 ({st.get('port53') or 'unknown server'}) do not reach "
                              f"Unbound: the {st['zones']} forward zone(s) have no effect. Forward the domains in "
                              f"{APPROUTER_DIR}/dns_via_gateway.txt to 127.0.0.1:{st.get('unbound_port')}{age}",
                 fix=FIX_UNBOUND_FLUSH)


def marker_reaches_unbound(system):
    """Does a TXT query for the marker on 127.0.0.1:53 get App Router's answer? False when unknown."""
    m = MARKER_RE.search(system.read(UNBOUND_ZONES) or "")
    if not m:
        return False
    out = system.run([DRILL, "-Q", m.group(1), "TXT", "@127.0.0.1"])
    return "approuter" in (out or "")


def check_pf(system, rules, prefix):
    name = "Firewall rules and tables loaded"
    wanted = [r for r in rules if rule_tables(r, prefix) and csv(r.get("gateway"))]
    if not wanted:
        return check(name, None, "No enabled rule with app categories or custom domains")
    rules_out = system.run([PFCTL, "-sr"])
    tables_out = system.run([PFCTL, "-s", "Tables"])
    if rules_out is None or tables_out is None:
        return check(name, None, "Could not read pf rules/tables")
    pf_rules = parse_pf_rules(rules_out)
    pf_tables = {t.strip() for t in tables_out.splitlines() if t.strip()}
    missing_rules, missing_tables = [], set()
    for r in wanted:
        tables, tokens = rule_tables(r, prefix), source_tokens(r, prefix)
        if not any(t in tables and f in tokens for f, t in pf_rules):
            missing_rules.append(rule_name(r))
        missing_tables |= tables - pf_tables
    if missing_rules or missing_tables:
        parts = []
        if missing_rules:
            parts.append("no route-to rule loaded for: " + ", ".join(missing_rules) +
                         " (interface missing/disabled, no valid source, or Apply pending)")
        if missing_tables:
            parts.append("pf tables missing: " + ", ".join(sorted(missing_tables)))
        return check(name, False, "; ".join(parts))
    n_pf = sum(1 for f, t in pf_rules if t.startswith(prefix + "_"))
    return check(name, True, f"{len(wanted)} rule(s) loaded as {n_pf} route-to rule(s); all tables present "
                             "(App Router uses core filter rules, no anchors)")


def check_dns_watcher(system, rules, prefix):
    name = "DNS watcher running"
    if not any(rule_tables(r, prefix) for r in rules):
        return check(name, None, "No enabled rule with app categories or custom domains")
    if not system.pid_alive(DNS_WATCHER_PID):
        return check(name, False, "dns_watcher is not running: new CDN addresses are not learned, "
                                  "so their traffic leaves via the default gateway", fix=FIX_DNS_WATCHER)
    sniffers = system.count_processes("tcpdump.*-Q out")
    if sniffers == 0:
        return check(name, False, "dns_watcher is running but has no tcpdump sniffer: DNS answers are not seen",
                     fix=FIX_DNS_WATCHER)
    return check(name, True, f"dns_watcher is running with {sniffers} sniffer(s)")


def check_gateways(system, rules):
    name = "Rule gateways up"
    used = sorted({gw for r in rules for gw in rule_gateways(r)})
    if not used:
        return check(name, None, "No enabled rule")
    data = load_json_text(system.run([GATEWAY_STATUS]))
    if data is None:
        return check(name, None, "Could not read the gateway status")
    items = data.values() if isinstance(data, dict) else data
    status = {g.get("name"): g for g in items if isinstance(g, dict)}
    bad, parts = [], []
    for gw in used:
        g = status.get(gw)
        if g is None:
            bad.append(gw)
            parts.append(f"{gw}: not found (disabled or deleted)")
            continue
        label = g.get("status_translated") or g.get("status") or "?"
        if g.get("status") in DOWN_STATES:
            bad.append(gw)
        parts.append(f"{gw}: {label}")
    return check(name, not bad, "; ".join(parts))


def load_json_text(text):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def check_devices(system, rules):
    name = "Device sources resolved"
    mac_rules = [r for r in rules if parse_sources(r.get("source_nets"))["macs"]]
    if not mac_rules:
        return check(name, None, "No rule uses device (MAC) sources", "low")
    unresolved, parts = [], []
    for r in mac_rules:
        alias = mac_alias_name(r)
        out = system.run([PFCTL, "-t", alias, "-T", "show"])
        ips = [line.strip() for line in (out or "").splitlines() if line.strip()]
        v4 = [ip for ip in ips if ":" not in ip]
        n_macs = len(parse_sources(r.get("source_nets"))["macs"])
        if not v4:
            unresolved.append(rule_name(r))
            parts.append(f"{rule_name(r)}: none of {n_macs} device(s) currently has an IPv4 address ({alias})")
        else:
            parts.append(f"{rule_name(r)}: {len(v4)} IPv4 address(es) for {n_macs} device(s)")
    # current state only (device offline / private MAC rotated); history is Netbaseline's job
    return check(name, not unresolved, "; ".join(parts), "low")


def check_smart(system, rules):
    name = "Smart gateway prober"
    smart = [r for r in rules if is_smart(r)]
    single = [rule_name(r) for r in rules if str(r.get("smart_gateway")) == "1" and not is_smart(r)]
    note = (f" Smart Gateway is on with a single gateway (no effect) for: {', '.join(single)}." if single else "")
    if not smart:
        return check(name, None, "No rule uses Smart Gateway with 2+ gateways." + note, "low")
    if system.pid_alive(GEO_PROBER_PID):
        return check(name, True, f"geo_prober is running for {len(smart)} rule(s)." + note, "low")
    return check(name, False, f"geo_prober is not running: {len(smart)} smart rule(s) stay on their fallback "
                              "gateway." + note, "low")


def check_leaks(system):
    name = "Last leak check"
    last = load_json(system, LEAK_CHECK_LAST)
    if not isinstance(last, dict) or not last.get("checked_at"):
        return check(name, None, "No stored leak check result (run: configctl approuter leak_check)", "low")
    age = system.now() - last["checked_at"]
    when = f"{int(age // 3600)} h ago" if age < 172800 else f"{int(age // 86400)} days ago"
    if age > LEAK_MAX_AGE:
        return check(name, None, f"Last leak check is stale ({when})", "low")
    rules = last.get("rules") or []
    leaked = sum(int(r.get("leaked", 0)) for r in rules)
    routed = sum(int(r.get("routed", 0)) for r in rules)
    if leaked:
        which = ", ".join(f"{r.get('rule')} ({r.get('leaked')})" for r in rules if r.get("leaked"))
        return check(name, False, f"{leaked} connection(s) bypassed their rule's gateway, {routed} routed ({when}): "
                                  f"{which}", "low")
    return check(name, True, f"No leaks, {routed} connection(s) routed ({when})", "low")


def run_checks(system=None):
    system = system or System()
    config = load_json(system, CONFIG_FILE, lenient=True)
    checks = [check_enabled(config)]
    if config is None or str(config.get("enabled")) != "1":
        for name, sev in (("DNS forward reaches Unbound", "medium"), ("Firewall rules and tables loaded", "medium"),
                          ("DNS watcher running", "medium"), ("Rule gateways up", "medium"),
                          ("Device sources resolved", "low"), ("Smart gateway prober", "low"),
                          ("Last leak check", "low")):
            checks.append(check(name, None, "App Router is disabled", sev))
        return {"checks": checks}
    prefix = config.get("table_prefix") or "approuter"
    rules = [r for r in config.get("rules", []) if isinstance(r, dict)]
    checks += [
        check_dns_forward(system),
        check_pf(system, rules, prefix),
        check_dns_watcher(system, rules, prefix),
        check_gateways(system, rules),
        check_devices(system, rules),
        check_smart(system, rules),
        check_leaks(system),
    ]
    return {"checks": checks}


def main():
    try:
        result = run_checks()
    except Exception as e:      # always print valid JSON
        result = {"checks": [check("Health check", False, f"health check failed: {e}")]}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
