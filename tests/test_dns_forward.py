"""Resolve DNS via gateway: dns_forward.php planning (PHP), dns_routes.py, wiring."""
import json
import os
import pathlib
import subprocess
import types

import pytest

from conftest import ROOT, SCRIPTS, load_script
from test_php_hook import php_command

PHP_SCRIPT = os.path.join("tests", "php", "test_dns_forward.php")
PHP_CASES = ["basic_plan", "custom_domains_and_china_all", "first_rule_wins",
             "dns_server_gateway_conflict", "invalid_inputs", "domain_cap", "render"]


@pytest.fixture(scope="module")
def php_results():
    cmd = php_command()
    if cmd is None:
        pytest.skip("php not available (install php-cli or pull php:8.4-cli)")
    proc = subprocess.run(cmd + [PHP_SCRIPT], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("case", PHP_CASES)
def test_dns_forward_plan(php_results, case):
    assert case in php_results, f"case {case} did not run"
    assert php_results[case] == []


def test_all_dns_forward_cases_listed(php_results):
    assert sorted(php_results) == sorted(PHP_CASES)


class FakeRoute:
    """Minimal kernel routing table for route/ifconfig commands."""

    def __init__(self, routes, interfaces, default=("198.18.0.1", "igc0")):
        self.routes = dict(routes)          # host -> (gateway, interface)
        self.interfaces = set(interfaces)
        self.default = default
        self.calls = []

    def __call__(self, cmd, capture_output=True, text=False):
        self.calls.append(cmd)
        ok = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if cmd[0] == "/sbin/ifconfig":
            return types.SimpleNamespace(returncode=0 if cmd[1] in self.interfaces else 1, stdout="", stderr="")
        args = [a for a in cmd[1:] if a not in ("-q", "-n")]
        if args[0] == "get":
            gw, iface = self.routes.get(args[2], self.default)
            return types.SimpleNamespace(returncode=0, stdout=f"   gateway: {gw}\n interface: {iface}\n", stderr="")
        if args[0] == "delete":
            self.routes.pop(args[2], None)
            return ok
        if args[0] == "add":
            host = args[2]
            if args[3] == "-interface":
                self.routes[host] = (None, args[4])
            else:
                gw = args[3]
                iface = self.routes.get(gw, self.default)[1]
                if gw not in self.routes and iface == self.default[1] and not gw.startswith("97."):
                    return types.SimpleNamespace(returncode=1, stdout="", stderr="Invalid argument")
                self.routes[host] = (gw, iface)
            return ok
        raise AssertionError(cmd)


ROUTE = {"dns": "223.6.6.6", "interface": "pgw_China", "gateway": "172.31.175.170", "far": True}


@pytest.fixture
def dr(tmp_path, monkeypatch):
    mod = load_script("dns_routes")
    monkeypatch.setattr(mod, "DESIRED_FILE", str(tmp_path / "dns_routes.json"))
    monkeypatch.setattr(mod, "APPLIED_FILE", str(tmp_path / "applied.json"))
    monkeypatch.setattr(mod, "log", lambda *a, **k: None)
    return mod


def write_desired(mod, routes):
    pathlib.Path(mod.DESIRED_FILE).write_text(json.dumps({"routes": routes}))


def test_far_gateway_route_installed(dr):
    k = FakeRoute({}, {"pgw_China"})
    assert dr.ensure_route(ROUTE, k) == "added"
    assert k.routes["172.31.175.170"] == (None, "pgw_China")
    assert k.routes["223.6.6.6"] == ("172.31.175.170", "pgw_China")


def test_route_already_correct_is_noop(dr):
    k = FakeRoute({"223.6.6.6": ("172.31.175.170", "pgw_China")}, {"pgw_China"})
    assert dr.ensure_route(ROUTE, k) == "ok"
    assert all(c[1] == "-n" for c in k.calls if c[0] == "/sbin/route")


def test_lan_gateway_not_rerouted(dr):
    k = FakeRoute({"10.0.0.1": (None, "igc3")}, {"igc3"})
    r = {"dns": "1.1.1.1", "interface": "igc3", "gateway": "10.0.0.1"}
    assert dr.ensure_route(r, k) == "added"
    assert k.routes["10.0.0.1"] == (None, "igc3")
    assert not any(c[-2:] == ["-interface", "igc3"] for c in k.calls)


def test_missing_interface_reported(dr):
    k = FakeRoute({}, set())
    assert "does not exist" in dr.ensure_route(ROUTE, k)
    assert "223.6.6.6" not in k.routes


def test_sync_removes_routes_no_longer_wanted(dr):
    write_desired(dr, [ROUTE])
    k = FakeRoute({}, {"pgw_China"})
    dr.sync(k)
    assert json.loads(pathlib.Path(dr.APPLIED_FILE).read_text()) == ["223.6.6.6"]
    write_desired(dr, [])
    dr.sync(k)
    assert "223.6.6.6" not in k.routes
    assert json.loads(pathlib.Path(dr.APPLIED_FILE).read_text()) == []


def test_ensure_routes_ignores_malformed(dr):
    write_desired(dr, [{"dns": "1.1.1.1"}, ROUTE])
    k = FakeRoute({}, {"pgw_China"})
    assert dr.ensure_routes(k, logger=lambda *a, **k: None) == [("223.6.6.6", "added")]


def test_wiring():
    src = pathlib.Path(SCRIPTS)
    lu = (src / "list_updater.py").read_text()
    assert lu.count("run_dns_forward()") == 3          # def + full_update + generate_dns
    dw = (src / "dns_watcher.py").read_text()
    assert "target=dns_route_loop" in dw
    actions = pathlib.Path(ROOT, "src/opnsense/service/conf/actions.d/actions_approuter.conf").read_text()
    assert "[dns_forward]" in actions
    mk = pathlib.Path(ROOT, "Makefile").read_text()
    assert "dns_routes.py $(PLUGIN_SCRIPTS)/" in mk and "dns_forward.php $(PLUGIN_SCRIPTS)/" in mk
    assert "dns_routes.py cleanup" in mk
    model = pathlib.Path(ROOT, "src/opnsense/mvc/app/models/OPNsense/Approuter/Approuter.xml").read_text()
    form = pathlib.Path(ROOT, "src/opnsense/mvc/app/controllers/OPNsense/Approuter/forms/dialogRule.xml").read_text()
    for field in ("dnsViaGateway", "dnsServer"):
        assert f"<{field} " in model and f"rule.{field}" in form
