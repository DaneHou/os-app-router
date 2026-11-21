"""inspect_route.py: route-to parsing, connection paths and trace steps."""
import hashlib
import ipaddress

import pytest

from conftest import load_script
from test_leak_check import RULES, STATES

UUID = "700da3ee-0000-4000-8000-000000000003"
H = hashlib.md5(UUID.encode()).hexdigest()[:8]
RULE = {"uuid": UUID, "description": "wg-iphone", "categories": "video.iqiyi", "custom_domains": "",
        "gateway": "FRP_GW", "interface": "opt8"}
ROUTE_TO_RULES = RULES.replace("approuter_clients_fadb28cc", f"approuter_clients_{H}")
DEFAULT = ("198.18.0.1", "igc0")


@pytest.fixture
def ir():
    mod = load_script("inspect_route")
    mod.dns_routes.load_desired = lambda: [{"dns": "223.6.6.6", "interface": "pgw_China", "gateway": "172.31.175.170"}]
    return mod


def run_trace(ir, domain="m.iqiyi.com", client="10.10.0.3", table=None, route=("172.31.175.170", "pgw_China"),
              zones=None, resolve=None):
    table = table if table is not None else {"110.242.72.117", "23.46.216.204"}
    return ir.trace(
        client, domain, prefix="approuter", rules=[RULE],
        mappings={"approuter_video_iqiyi": {"iqiyi.com"}, "approuter_video_youku": {"youku.com"}},
        names={"110.242.72.117": "m.iqiyi.com", "23.46.216.204": "m.iqiyi.com"},
        seen={"approuter_video_iqiyi": {"110.242.72.117": 0}},
        zones={"iqiyi.com": "223.6.6.6"} if zones is None else zones,
        resolve=resolve or (lambda d: {"110.242.72.117"}),
        states=ir.lc.parse_states(STATES), route_to=ir.parse_route_to(ROUTE_TO_RULES),
        clients_of=lambda r: [ipaddress.ip_network("10.10.0.3/32")],
        table_has=lambda t, ip: ip in table, route_of=lambda ip: route, default=DEFAULT)


def statuses(res):
    return [(s["status"], s["title"].split(" ")[0]) for s in res["steps"]]


def test_parse_route_to(ir):
    rt = ir.parse_route_to(ROUTE_TO_RULES)
    assert set(rt) == {56, 75}      # outbound gateway rules (@76/@77) are not "pass in"
    assert rt[75]["gw_if"] == "pgw_China" and rt[75]["src"] == f"<approuter_clients_{H}:1>"


def test_connection_paths(ir):
    conns = ir.connections_of("10.10.0.3", ir.lc.parse_states(STATES), ir.parse_route_to(ROUTE_TO_RULES),
                              [RULE], "approuter", {"110.242.72.117": "t7z.cupid.iqiyi.com"}, DEFAULT)
    by_dst = {c["dst"]: c for c in conns if c["proto"] == "tcp"}
    assert by_dst["110.242.72.117"]["path"]["kind"] == "approuter"
    assert "wg-iphone" in by_dst["110.242.72.117"]["path"]["label"]
    assert by_dst["23.46.216.204"]["path"]["kind"] == "default"
    assert by_dst["110.242.72.117"]["host"] == "t7z.cupid.iqiyi.com"


def test_trace_flags_leaked_connection(ir):
    res = run_trace(ir)
    assert res["verdict"] == "routed" and res["gateway"] == "FRP_GW"
    last = res["steps"][-1]
    assert last["status"] == "bad" and "1 NOT through the rule gateway" in last["title"]
    assert res["problems"] == 1


def test_trace_address_not_in_table(ir):
    res = run_trace(ir, table=set())
    addr_step = next(s for s in res["steps"] if "address(es) are routed" in s["title"])
    assert addr_step["status"] == "bad" and any("NOT in the table" in i for i in addr_step["items"])


def test_trace_dns_route_broken(ir):
    res = run_trace(ir, route=DEFAULT)
    dns = next(s for s in res["steps"] if "Resolve DNS via Gateway" in s["title"])
    assert dns["status"] == "bad" and "expected pgw_China" in dns["detail"]


def test_trace_no_dns_option_hint(ir):
    res = run_trace(ir, zones={})
    assert any(s["status"] == "info" and "router's location" in s["title"] for s in res["steps"])


def test_trace_unrouted_domain_is_info_not_error(ir):
    res = run_trace(ir, domain="github.com", resolve=lambda d: {"140.82.114.4"})
    assert res["verdict"] == "default" and res["problems"] == 0
    assert "default route via igc0" in res["summary"]


def test_trace_category_not_used_by_client(ir):
    res = run_trace(ir, domain="v.youku.com", resolve=lambda d: set())
    assert any("none of this client's rules uses it" in s["title"] for s in res["steps"])
