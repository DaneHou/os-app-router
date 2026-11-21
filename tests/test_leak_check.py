"""leak_check.py: pf state/rule parsing and leak classification."""
import json

import pytest

from conftest import load_script

STATES = """\
all tcp 110.242.72.117:443 <- 10.10.0.3:55077       ESTABLISHED:ESTABLISHED
   [1 + 2] wscale 7  [3 + 4] wscale 6
   age 00:01:46, expires in 00:00:44, 19:17 pkts, 3799:8641 bytes, rule 75, rlabel 2d97
all tcp 172.31.175.169:32169 (10.10.0.3:55077) -> 110.242.72.117:443       ESTABLISHED:ESTABLISHED
   [1 + 2] wscale 6  [3 + 4] wscale 7
   age 00:01:46, expires in 00:00:44, 19:17 pkts, 3799:8641 bytes, rule 76, rlabel e277, allow-opts
all tcp 23.46.216.204:443 <- 10.10.0.3:54458       ESTABLISHED:ESTABLISHED
   age 00:00:40, expires in 24:00:00, 10:12 pkts, 1:2 bytes, rule 80
all tcp 198.18.0.200:57892 (10.10.0.3:54458) -> 23.46.216.204:443       ESTABLISHED:ESTABLISHED
   age 00:00:40, expires in 24:00:00, 10:12 pkts, 1:2 bytes, rule 77
all tcp 198.18.0.200:50000 (10.10.0.3:50000) -> 17.57.156.39:993       ESTABLISHED:ESTABLISHED
   age 00:00:40, rule 77
all udp 192.168.70.1:53 <- 10.10.0.3:5353       MULTIPLE:SINGLE
   age 00:00:01, rule 12
all tcp 198.18.0.200:40000 (192.168.70.50:40000) -> 23.46.216.204:443       ESTABLISHED:ESTABLISHED
   age 00:00:40, rule 3
"""

RULES = """\
@56 pass in quick on igc2 route-to (pgw_China 172.31.175.170) inet from <approuter_clients_a6a42fca:1> to <approuter_custom_a6a42fca:1> flags S/SA keep state
@75 pass in quick on wg0 route-to (pgw_China 172.31.175.170) inet from <approuter_clients_fadb28cc:1> to <approuter_video_iqiyi:301> flags S/SA keep state label "x"
  [ Evaluations: 1091      Packets: 15632     Bytes: 9562535     States: 6     ]
@76 pass out log route-to (pgw_China 172.31.175.170) inet from (pgw_China:1) to ! (pgw_China:network:1) flags S/SA keep state allow-opts
@77 pass out log route-to (igc0 198.18.0.1) inet from (igc0:1) to ! (igc0:network:1) flags S/SA keep state allow-opts
@80 pass in quick on wg0 inet from 10.10.0.0/24 to any flags S/SA keep state
"""


@pytest.fixture
def lc():
    return load_script("leak_check")


def test_parse_states(lc):
    st = lc.parse_states(STATES)
    assert len(st) == 7
    assert st[0] == {"proto": "tcp", "client": "10.10.0.3", "cport": "55077", "dst": "110.242.72.117", "dport": "443", "rule": 75}
    assert st[1] == {"proto": "tcp", "client": "10.10.0.3", "cport": "55077", "dst": "110.242.72.117", "dport": "443", "rule": 76}
    assert st[2]["dst"] == "23.46.216.204" and st[2]["rule"] == 80


def test_parse_routed_rules(lc):
    assert lc.parse_routed_rules(RULES, "approuter") == {56: {"approuter_custom_a6a42fca"}, 75: {"approuter_video_iqiyi"}}


def test_check_classifies_and_dedupes(lc):
    import ipaddress
    rule = {"uuid": "u", "description": "wg-iphone", "categories": "video.iqiyi", "custom_domains": ""}
    names = {"110.242.72.117": "t7z.cupid.iqiyi.com", "23.46.216.204": "m.iqiyi.com", "17.57.156.39": "imap.mail.me.com"}
    match = lambda h: {"approuter_video_iqiyi"} if h.endswith("iqiyi.com") else set()
    res = lc.check([rule], "approuter", lc.parse_states(STATES), lc.parse_routed_rules(RULES, "approuter"),
                   names, match, lambda r: [ipaddress.ip_network("10.10.0.3/32")], has=lambda t, ip: False)
    r = res[0]
    assert r["routed"] == 1
    assert r["leaked"] == 1        # NAT state + LAN-side state of one connection
    leak = r["leaks"][0]
    assert (leak["client"], leak["host"], leak["dst"], leak["port"]) == ("10.10.0.3", "m.iqiyi.com", "23.46.216.204", "443")
    assert leak["in_table"] is False and "not learned" in leak["reason"]


def test_check_in_table_reason(lc):
    import ipaddress
    rule = {"uuid": "u", "description": "r", "categories": "video.iqiyi", "custom_domains": ""}
    res = lc.check([rule], "approuter", lc.parse_states(STATES), {}, {"23.46.216.204": "m.iqiyi.com"},
                   lambda h: {"approuter_video_iqiyi"}, lambda r: [ipaddress.ip_network("10.10.0.3/32")],
                   has=lambda t, ip: True)
    assert res[0]["leaks"][0]["in_table"] is True and "old state" in res[0]["leaks"][0]["reason"]


def test_names_dump_prunes(dns_watcher, tmp_path):
    dns_watcher.recent_names.clear()
    dns_watcher.record_names("old.example", ["1.1.1.1"], now=1000)
    dns_watcher.record_names("m.iqiyi.com", ["2.2.2.2"], now=9000)
    path = str(tmp_path / "names.json")
    dns_watcher.dump_names(path, now=9100)
    data = json.loads(open(path).read())
    assert data["names"] == {"2.2.2.2": ["m.iqiyi.com", 9000]}
