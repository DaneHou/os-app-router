"""healthcheck.py: plugin health contract output, against fixtures in tests/fixtures/healthcheck."""
import json
import os
import subprocess
import sys

import pytest

from conftest import ROOT, SCRIPTS, load_script

FIX = os.path.join(ROOT, "tests", "fixtures", "healthcheck")
NOW = 1795300600        # 10 min after dns_forward_status.json "checked"


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read()


IFCONFIG_V4_ONLY = """igc0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet6 fe80::1%igc0 prefixlen 64 scopeid 0x1
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet6 ::1 prefixlen 128
wg0: flags=10080c1<UP,RUNNING,NOARP,MULTICAST,LOWER_UP> metric 0 mtu 1420
\tinet6 fd00:10::1 prefixlen 64
"""


class FakeSystem:
    """Firewall as seen by healthcheck.py, built from the fixture files."""

    def __init__(self, hc):
        self.hc = hc
        self.files = {
            hc.CONFIG_FILE: fixture("config.json"),
            hc.DNS_FORWARD_STATUS: fixture("dns_forward_status.json"),
            hc.LEAK_CHECK_LAST: fixture("leak_check_last.json"),
        }
        self.commands = {
            (hc.PFCTL, "-sr"): fixture("pfctl_sr.txt"),
            (hc.PFCTL, "-s", "Tables"): fixture("pfctl_tables.txt"),
            (hc.PFCTL, "-t", "ar_6f877413_mac", "-T", "show"): fixture("ar_6f877413_mac.txt"),
            (hc.GATEWAY_STATUS,): fixture("gateway_status.json"),
            ("/bin/pgrep", "-f", "tcpdump.*-Q out"): "101\n102\n103\n104\n",
            (hc.IFCONFIG, "-a", "inet6"): IFCONFIG_V4_ONLY,
        }
        self.pids = {hc.DNS_WATCHER_PID: True, hc.GEO_PROBER_PID: True}
        self.ran = []

    def now(self):
        return NOW

    def read(self, path):
        return self.files.get(path)

    def run(self, argv):
        self.ran.append(tuple(argv))
        return self.commands.get(tuple(argv))

    def pid_alive(self, pidfile):
        return self.pids.get(pidfile, False)

    def count_processes(self, pattern):
        out = self.run(["/bin/pgrep", "-f", pattern])
        return len(out.split()) if out else 0


@pytest.fixture
def hc():
    return load_script("healthcheck")


@pytest.fixture
def system(hc):
    return FakeSystem(hc)


def by_name(result):
    return {c["name"]: c for c in result["checks"]}


def test_contract_shape(hc, system):
    result = hc.run_checks(system)
    assert set(result) == {"checks"}
    assert len(result["checks"]) == 10
    for c in result["checks"]:
        assert set(c) == {"name", "ok", "severity", "detail"}
        assert isinstance(c["name"], str) and c["name"]
        assert c["ok"] in (True, False, None)
        assert c["severity"] in ("medium", "low", "info")
        assert isinstance(c["detail"], str) and c["detail"]
    json.dumps(result)


def test_healthy_fixture(hc, system):
    checks = by_name(hc.run_checks(system))
    assert {n: c["ok"] for n, c in checks.items()} == {
        "Plugin enabled": True,
        "DNS forward reaches Unbound": True,
        "Firewall rules and tables loaded": True,
        "DNS watcher running": True,
        "Rule gateways up": True,
        "Device sources resolved": True,
        "Smart gateway prober": True,
        "Last leak check": True,
        "AdGuard Home upstreams": None,     # no AdGuardHome.yaml in the fixture
        "No IPv6 bypass": True,
    }
    assert "AdGuardHom" in checks["DNS forward reaches Unbound"]["detail"]
    assert "10 min ago" in checks["DNS forward reaches Unbound"]["detail"]
    assert "4 rule(s) loaded as 6 route-to rule(s)" in checks["Firewall rules and tables loaded"]["detail"]
    assert checks["Rule gateways up"]["detail"] == "FRP_GW: Online; WAN_DHCP: Online"
    assert "my-iphone: 1 IPv4 address(es) for 1 device(s)" in checks["Device sources resolved"]["detail"]
    # my-mbp has Smart Gateway on with one gateway: reported, not a failure
    assert "single gateway (no effect) for: my-mbp" in checks["Smart gateway prober"]["detail"]
    assert checks["Last leak check"]["detail"].startswith("No leaks, 19 connection(s) routed")


@pytest.mark.parametrize("stored_ok", [True, False])
def test_read_only_commands(hc, system, stored_ok):
    if not stored_ok:
        system.files[hc.DNS_FORWARD_STATUS] = fixture("dns_forward_status.json").replace("true", "false")
        system.files[hc.UNBOUND_ZONES] = MARKER_CONF
    hc.run_checks(system)
    for argv in system.ran:
        assert argv[0] in (hc.PFCTL, hc.GATEWAY_STATUS, "/bin/pgrep", hc.DRILL, hc.IFCONFIG)
        if argv[0] == hc.IFCONFIG:
            assert argv == (hc.IFCONFIG, "-a", "inet6")
        if argv[0] == hc.PFCTL:
            assert argv[1:] in (("-sr",), ("-s", "Tables")) or argv[-2:] == ("-T", "show")
        if argv[0] == hc.DRILL:         # one query to the local resolver, only after a stored failure
            assert not stored_ok and argv == MARKER_QUERY


def test_disabled_plugin_everything_not_applicable(hc, system):
    system.files[hc.CONFIG_FILE] = fixture("config.json").replace('"enabled": 1', '"enabled": 0')
    checks = hc.run_checks(system)["checks"]
    assert len(checks) == 10
    assert all(c["ok"] is None for c in checks)
    assert checks[0]["detail"] == "App Router is disabled"
    assert system.ran == []


def test_missing_config(hc, system):
    del system.files[hc.CONFIG_FILE]
    checks = by_name(hc.run_checks(system))
    assert checks["Plugin enabled"]["ok"] is None
    assert "never applied" in checks["Plugin enabled"]["detail"]


def test_dns_forward_not_reaching_unbound(hc, system):
    system.files[hc.DNS_FORWARD_STATUS] = json.dumps(
        {"checked": NOW, "zones": 11, "port53": "AdGuardHom", "unbound_port": 53530, "reaches_unbound": False})
    c = by_name(hc.run_checks(system))["DNS forward reaches Unbound"]
    assert c["ok"] is False and c["severity"] == "medium"
    assert "127.0.0.1:53530" in c["detail"]


@pytest.mark.parametrize("content", [None, '{"checked": 1795300000, "zones": 0}'])
def test_dns_forward_not_applicable(hc, system, content):
    if content is None:
        del system.files[hc.DNS_FORWARD_STATUS]
    else:
        system.files[hc.DNS_FORWARD_STATUS] = content
    assert by_name(hc.run_checks(system))["DNS forward reaches Unbound"]["ok"] is None


MARKER_CONF = ('# Generated by App Router\nserver:\n    local-data: "_approuter-check.bilibili.com. 60 IN TXT approuter"\n'
               'forward-zone:\n    name: "bilibili.com."\n    forward-addr: 223.6.6.6\n')
MARKER_QUERY = ("/usr/bin/drill", "-Q", "_approuter-check.bilibili.com", "TXT", "@127.0.0.1")


def test_dns_forward_failure_carries_the_unbound_flush_fix(hc, system):
    system.files[hc.DNS_FORWARD_STATUS] = json.dumps(
        {"checked": NOW, "zones": 11, "port53": "AdGuardHom", "unbound_port": 53530, "reaches_unbound": False})
    system.files[hc.UNBOUND_ZONES] = MARKER_CONF
    c = by_name(hc.run_checks(system))["DNS forward reaches Unbound"]
    assert c["ok"] is False and MARKER_QUERY in system.ran
    assert c["fix"] == {"action": "approuter unbound_flush",
                        "title": "Flush Unbound failures for App Router forward zones"}


def test_dns_forward_stale_failure_rechecked_live(hc, system):
    """The stored check ran while Unbound restarted; the marker answers now: not a failure."""
    system.files[hc.DNS_FORWARD_STATUS] = json.dumps(
        {"checked": NOW - 3600, "zones": 11, "port53": "AdGuardHom", "unbound_port": 53530, "reaches_unbound": False})
    system.files[hc.UNBOUND_ZONES] = MARKER_CONF
    system.commands[MARKER_QUERY] = '"approuter"\n'
    c = by_name(hc.run_checks(system))["DNS forward reaches Unbound"]
    assert c["ok"] is True and "now (stored check failed" in c["detail"] and "fix" not in c


def test_marker_only_from_app_routers_include(hc, system):
    system.files[hc.UNBOUND_ZONES] = 'server:\n    local-data: "evil.example. 60 IN TXT approuter"\n'
    assert hc.marker_reaches_unbound(system) is False and system.ran == []


def test_dns_watcher_fix_and_no_fix_when_healthy(hc, system):
    assert all("fix" not in c for c in hc.run_checks(system)["checks"])
    system.pids[hc.DNS_WATCHER_PID] = False
    c = by_name(hc.run_checks(system))["DNS watcher running"]
    assert c["fix"] == {"action": "approuter dns_watcher_restart", "title": "Restart the App Router DNS watcher"}
    system.pids[hc.DNS_WATCHER_PID] = True
    system.commands[("/bin/pgrep", "-f", "tcpdump.*-Q out")] = None
    assert by_name(hc.run_checks(system))["DNS watcher running"]["fix"]["action"] == "approuter dns_watcher_restart"


def test_pf_failure_has_no_fix(hc, system):
    """Missing route-to rules or tables need a filter reload (Apply); no automatic repair does that."""
    system.commands[(hc.PFCTL, "-s", "Tables")] = fixture("pfctl_tables.txt").replace("approuter_video_bilibili\n", "")
    c = by_name(hc.run_checks(system))["Firewall rules and tables loaded"]
    assert c["ok"] is False and "fix" not in c


def test_fix_actions_are_safe_configd_actions(hc):
    """Every declared fix is a parameterless script action of actions_approuter.conf (Netbaseline's rules)."""
    import configparser
    import re
    cp = configparser.ConfigParser(interpolation=None, delimiters=(":",))
    cp.read(os.path.join(ROOT, "src/opnsense/service/conf/actions.d/actions_approuter.conf"))
    safe, unsafe = {"restart", "reload", "start", "flush"}, {"stop", "reconfigure", "configure", "apply", "set",
                                                               "all", "reset", "delete", "remove", "update"}
    for fix in (hc.FIX_DNS_WATCHER, hc.FIX_UNBOUND_FLUSH):
        plugin, action = fix["action"].split()
        assert plugin == "approuter" and re.fullmatch(r"[a-z][a-z0-9_]{0,47}", action)
        words = set(action.split("_"))
        assert words & safe and not words & unsafe, action
        assert cp[action]["type"] in ("script", "script_output") and not cp[action]["parameters"].strip()
        assert "filter" not in cp[action]["command"] and "configctl" not in cp[action]["command"]
        assert len(fix["title"]) <= 80
    restart = cp["dns_watcher_restart"]["command"]
    assert restart.index("dns_watcher.py stop") < restart.index("dns_watcher.py start")
    assert restart.split("; ", 1)[1] == cp["dns_watcher_start"]["command"]


def test_rule_without_pf_rule(hc, system):
    # wg-phone's interface was removed: the firewall hook skipped it
    system.commands[(hc.PFCTL, "-sr")] = "\n".join(
        line for line in fixture("pfctl_sr.txt").splitlines() if "on wg0 route-to" not in line)
    c = by_name(hc.run_checks(system))["Firewall rules and tables loaded"]
    assert c["ok"] is False
    assert "no route-to rule loaded for: wg-phone" in c["detail"]


def test_missing_table(hc, system):
    system.commands[(hc.PFCTL, "-s", "Tables")] = fixture("pfctl_tables.txt").replace("approuter_video_bilibili\n", "")
    c = by_name(hc.run_checks(system))["Firewall rules and tables loaded"]
    assert c["ok"] is False and "approuter_video_bilibili" in c["detail"]


def test_dns_watcher_down(hc, system):
    system.pids[hc.DNS_WATCHER_PID] = False
    c = by_name(hc.run_checks(system))["DNS watcher running"]
    assert c["ok"] is False and "not running" in c["detail"]


def test_dns_watcher_without_sniffers(hc, system):
    system.commands[("/bin/pgrep", "-f", "tcpdump.*-Q out")] = None
    assert by_name(hc.run_checks(system))["DNS watcher running"]["ok"] is False


def test_gateway_down(hc, system):
    gws = json.loads(fixture("gateway_status.json"))
    gws["FRP_GW"].update(status="down", status_translated="Offline")
    system.commands[(hc.GATEWAY_STATUS,)] = json.dumps(gws)
    c = by_name(hc.run_checks(system))["Rule gateways up"]
    assert c["ok"] is False and "FRP_GW: Offline" in c["detail"]


def test_gateway_missing_and_list_format(hc, system):
    # gateway_status.php may also return a list; a deleted gateway is a failure
    gws = json.loads(fixture("gateway_status.json"))
    system.commands[(hc.GATEWAY_STATUS,)] = json.dumps([gws["FRP_GW"]])
    c = by_name(hc.run_checks(system))["Rule gateways up"]
    assert c["ok"] is False and "WAN_DHCP: not found" in c["detail"]


def test_gateway_loss_is_not_down(hc, system):
    gws = json.loads(fixture("gateway_status.json"))
    gws["FRP_GW"].update(status="loss", status_translated="Packetloss")
    system.commands[(hc.GATEWAY_STATUS,)] = json.dumps(gws)
    c = by_name(hc.run_checks(system))["Rule gateways up"]
    assert c["ok"] is True and "FRP_GW: Packetloss" in c["detail"]


def test_device_offline_is_low(hc, system):
    system.commands[(hc.PFCTL, "-t", "ar_6f877413_mac", "-T", "show")] = "   fe80::1\n"
    c = by_name(hc.run_checks(system))["Device sources resolved"]
    assert c["ok"] is False and c["severity"] == "low"
    assert "my-iphone: none of 1 device(s)" in c["detail"]


def test_smart_prober_down(hc, system):
    system.pids[hc.GEO_PROBER_PID] = False
    c = by_name(hc.run_checks(system))["Smart gateway prober"]
    assert c["ok"] is False and c["severity"] == "low"


def test_smart_not_applicable_with_single_gateways(hc, system):
    system.files[hc.CONFIG_FILE] = fixture("config.json").replace('"WAN_DHCP,FRP_GW"', '"FRP_GW"')
    c = by_name(hc.run_checks(system))["Smart gateway prober"]
    assert c["ok"] is None
    assert "my-mbp, kids" in c["detail"]


def test_leaks_reported(hc, system):
    last = json.loads(fixture("leak_check_last.json"))
    last["rules"][0].update(leaked=2)
    system.files[hc.LEAK_CHECK_LAST] = json.dumps(last)
    c = by_name(hc.run_checks(system))["Last leak check"]
    assert c["ok"] is False and c["severity"] == "low"
    assert "my-mbp (2)" in c["detail"]


def test_leak_check_stale_or_missing(hc, system):
    last = json.loads(fixture("leak_check_last.json"))
    last["checked_at"] = NOW - 9 * 86400
    system.files[hc.LEAK_CHECK_LAST] = json.dumps(last)
    assert by_name(hc.run_checks(system))["Last leak check"]["ok"] is None
    del system.files[hc.LEAK_CHECK_LAST]
    assert by_name(hc.run_checks(system))["Last leak check"]["ok"] is None


def test_parse_sources(hc):
    src = hc.parse_sources("any,10.0.0.0/24, Kids ,mac:AA:BB:CC:DD:EE:FF,aa-bb-cc-dd-ee-01,bad name!")
    assert src == {"any": True, "nets": ["10.0.0.0/24"], "aliases": ["Kids"],
                   "macs": ["aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-01"]}


def test_main_always_prints_json(hc, monkeypatch, capsys):
    def boom(system=None):
        raise RuntimeError("x")
    monkeypatch.setattr(hc, "run_checks", boom)
    assert hc.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["checks"][0]["ok"] is False


def test_runs_as_script_without_firewall(tmp_path):
    """On a machine without pf/config the script still prints valid JSON quickly."""
    proc = subprocess.run([sys.executable, os.path.join(SCRIPTS, "healthcheck.py")],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0
    assert "checks" in json.loads(proc.stdout)


def test_ipv6_on_a_lan_is_a_bypass(hc, system):
    system.commands[(hc.IFCONFIG, "-a", "inet6")] = IFCONFIG_V4_ONLY + (
        "igc2: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n"
        "\tinet6 2001:db8:1::1 prefixlen 64\n\tinet6 2600:1700:1::1 prefixlen 64\n")
    c = by_name(hc.run_checks(system))["No IPv6 bypass"]
    assert c["ok"] is False and "igc2" in c["detail"] and "igc0" not in c["detail"] and "wg0" not in c["detail"]


def test_ipv6_unreadable_is_not_applicable(hc, system):
    del system.commands[(hc.IFCONFIG, "-a", "inet6")]
    assert by_name(hc.run_checks(system))["No IPv6 bypass"]["ok"] is None
