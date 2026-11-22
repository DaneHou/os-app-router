#!/usr/local/bin/python3
"""Keep AdGuard Home's upstreams in line with App Router's "Resolve DNS via gateway".

App Router forwards the zones of rules with "Resolve DNS via gateway" from
Unbound to the rule's DNS server through the gateway (dns_forward.php,
export: dns_via_gateway.txt). When AdGuard Home answers on port 53, those
names reach Unbound only if AdGuard Home sends them there. This script keeps a
managed block at the top of AdGuard Home's ``upstream_dns`` list:

    - '# --- App Router: DNS via gateway (managed) ---'
    - '[/iqiyi.com/]127.0.0.1:53530'
    ...
    - '# --- App Router end ---'

and removes other domain-specific entries for exactly those domains (e.g. a
China list sending iqiyi.com to doh.pub): AdGuard Home merges the upstreams of
duplicate domain entries, which would defeat the gateway path.

Only ``dns.upstream_dns`` list items are touched; everything else in the file
is kept byte for byte. The file is rewritten (backup first, mode kept) and
AdGuard Home restarted only when the list changed. Never prints the file.

Usage: agh_resync.py [--check] [--no-restart]
  --check       report only (JSON), change nothing
  --no-restart  write the file but leave the restart to the caller
Exit 0 always; the JSON status says what happened.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import syslog
import tempfile
import time

AGH_CONF = "/usr/local/AdGuardHome/AdGuardHome.yaml"
APPROUTER_DIR = "/usr/local/etc/app-router"
EXPORT_FILE = os.path.join(APPROUTER_DIR, "dns_via_gateway.txt")
CONFIG_FILE = os.path.join(APPROUTER_DIR, "config.json")
STATUS_FILE = os.path.join(APPROUTER_DIR, "dns_forward_status.json")
RESULT_FILE = os.path.join(APPROUTER_DIR, "agh_resync_last.json")
BACKUP_FILE = os.path.join(APPROUTER_DIR, "AdGuardHome.yaml.bak")
UNBOUND_CONF = "/var/unbound/unbound.conf"

BEGIN = "# --- App Router: DNS via gateway (managed) ---"
END = "# --- App Router end ---"
ITEM_RE = re.compile(r"^(\s+)- (.*?)\s*$")
SPEC_RE = re.compile(r"^\[/(.+?)/\](.*)$")
DOMAIN_RE = re.compile(r"^[a-z0-9_*.-]{1,253}$")


def log(msg, level=syslog.LOG_INFO):
    try:
        syslog.openlog("approuter", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(level, f"agh_resync: {msg}")
    except Exception:
        pass


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def enabled(config_text):
    """App Router enabled and its "Sync AdGuard Home" setting on (default on)."""
    try:
        cfg = json.loads(config_text or "")
    except ValueError:
        return False
    return str(cfg.get("enabled")) == "1" and str(cfg.get("agh_sync", 1)) == "1"


def export_domains(text):
    out = []
    for line in (text or "").splitlines():
        d = line.split("#", 1)[0].strip().lower().rstrip(".")
        if d and DOMAIN_RE.match(d) and d not in out:
            out.append(d)
    return sorted(out)


def unbound_port(status_text, unbound_conf_text):
    try:
        p = int(json.loads(status_text or "{}").get("unbound_port") or 0)
        if 0 < p < 65536:
            return p
    except (ValueError, TypeError, AttributeError):
        pass
    for line in (unbound_conf_text or "").splitlines():
        line = line.strip()
        if line.startswith("port:"):
            try:
                return int(line.split(":", 1)[1])
            except ValueError:
                pass
    return 53


def unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def find_upstreams(lines):
    """-> (first item line, end line (exclusive), item indent, [(start, end) per item]) of the
    block-style dns.upstream_dns list, or None. AdGuard Home folds long values onto
    continuation lines (deeper indent, no "- "); they belong to the item above."""
    in_dns = False
    for i, line in enumerate(lines):
        if re.match(r"^dns:\s*$", line):
            in_dns = True
            continue
        if in_dns and re.match(r"^\S", line):
            in_dns = False
        if in_dns and re.match(r"^  upstream_dns:\s*$", line):
            j = i + 1
            indent = None
            items = []
            while j < len(lines):
                m = ITEM_RE.match(lines[j])
                if m and (indent is None or m.group(1) == indent):
                    indent = m.group(1)
                    items.append([j, j + 1])
                elif items and lines[j].startswith(indent + "  ") and lines[j].strip():
                    items[-1][1] = j + 1          # continuation of a folded value
                else:
                    break
                j += 1
            return i + 1, j, indent or "    ", items
    return None


def item_value(lines, start, end):
    first = ITEM_RE.match(lines[start]).group(2)
    rest = [l.strip() for l in lines[start + 1:end]]
    return unquote(" ".join([first] + rest))


def plan(yaml_text, domains, port):
    """-> (new text or None when nothing to do, summary dict). Pure function (tests)."""
    lines = yaml_text.split("\n")
    loc = find_upstreams(lines)
    if loc is None:
        return None, {"status": "error", "reason": "upstream_dns list not found in AdGuardHome.yaml"}
    first, end, indent, items = loc
    managed = set(domains)
    upstream = f"127.0.0.1:{port}"
    kept, removed = [], []
    in_block = False
    for a, b in items:
        v = item_value(lines, a, b)
        if v == BEGIN:
            in_block = True
            continue
        if v == END:
            in_block = False
            continue
        if in_block:
            continue
        m = SPEC_RE.match(v)
        if m:
            names = {n.strip().lower().rstrip(".") for n in m.group(1).split("/") if n.strip()}
            if names and names <= managed:
                removed.append(v)
                continue
        kept.extend(lines[a:b])
    block = []
    if domains:
        block = [f"{indent}- '{BEGIN}'"] + [f"{indent}- '[/{d}/]{upstream}'" for d in domains] + [f"{indent}- '{END}'"]
    if not any(ITEM_RE.match(l) for l in block + kept):
        return None, {"status": "error", "reason": "refusing to leave upstream_dns empty"}
    new_text = "\n".join(lines[:first] + block + kept + lines[end:])
    conflicts = [r for r in removed if not r.endswith("]" + upstream)]
    n_kept = sum(1 for l in kept if ITEM_RE.match(l) and not l.startswith(indent + "  "))
    summary = {"domains": len(domains), "upstream": upstream, "conflicts_removed": len(conflicts),
               "items_before": len(items), "items_after": len(block) + n_kept}
    if new_text == yaml_text:
        return None, dict(summary, status="unchanged")
    return new_text, dict(summary, status="changed")


def check(yaml_text, domains, port):
    """Read-only verdict for the health check: (ok, detail)."""
    _new, summary = plan(yaml_text, domains, port)
    if summary["status"] == "error":
        return False, summary["reason"]
    if summary["status"] == "unchanged":
        return True, f"{len(domains)} domain(s) sent to Unbound (127.0.0.1:{port})"
    if summary["conflicts_removed"]:
        return False, (f"{summary['conflicts_removed']} AdGuard Home upstream entry(ies) send gateway-resolved "
                       "domains elsewhere")
    return False, "AdGuard Home upstreams are not in sync with the gateway-resolved domains"


def write_atomic(path, text):
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix=".agh_resync.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def agh_running():
    return subprocess.run(["/bin/pgrep", "-x", "AdGuardHome"], capture_output=True).returncode == 0


def run(argv):
    check_only = "--check" in argv
    no_restart = "--no-restart" in argv
    result = {"checked_at": int(time.time())}
    yaml_text = read(AGH_CONF)
    if yaml_text is None:
        return dict(result, status="skipped", reason="AdGuard Home not installed")
    if not enabled(read(CONFIG_FILE)):
        return dict(result, status="skipped", reason="App Router disabled or AdGuard Home sync off")
    domains = export_domains(read(EXPORT_FILE))
    port = unbound_port(read(STATUS_FILE), read(UNBOUND_CONF))
    new_text, summary = plan(yaml_text, domains, port)
    result.update(summary)
    if check_only or new_text is None:
        return result
    os.makedirs(APPROUTER_DIR, exist_ok=True)
    shutil.copy2(AGH_CONF, BACKUP_FILE)
    os.chmod(BACKUP_FILE, 0o600)
    write_atomic(AGH_CONF, new_text)
    log(f"AdGuard Home upstreams updated: {summary['domains']} domain(s) -> {summary['upstream']}, "
        f"{summary['conflicts_removed']} conflicting entry(ies) removed")
    if not no_restart and agh_running():
        rc = subprocess.run(["/usr/local/sbin/configctl", "adguardhome", "restart"],
                            capture_output=True, text=True, timeout=60).returncode
        result["restarted"] = rc == 0
    return result


def main():
    try:
        result = run(sys.argv[1:])
    except Exception as e:      # never a traceback for configd
        result = {"status": "error", "reason": f"{type(e).__name__}: {e}"}
        log(result["reason"], syslog.LOG_WARNING)
    if "--check" not in sys.argv:
        try:
            with open(RESULT_FILE, "w") as f:
                json.dump(result, f)
        except OSError:
            pass
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
