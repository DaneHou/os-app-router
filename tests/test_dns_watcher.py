import json
import time


def test_match_domain_suffixes(dns_watcher):
    dns_watcher.domain_table_map = {
        "iqiyi.com": {"approuter_video"},
        "video.iqiyi.com": {"approuter_video_iqiyi"},
    }
    assert dns_watcher.match_domain("pcw.video.iqiyi.com.") == {"approuter_video", "approuter_video_iqiyi"}
    assert dns_watcher.match_domain("IQIYI.com") == {"approuter_video"}
    assert dns_watcher.match_domain("notiqiyi.com") == set()


def test_tcpdump_line_parsing(dns_watcher):
    line = ("10.0.0.1.53 > 10.0.0.5.51000: [udp sum ok] 1234 q: A? www.iqiyi.com. 2/0/0 "
            "www.iqiyi.com. A 23.45.123.58, www.iqiyi.com. A 23.45.123.56 (80)")
    assert dns_watcher.QUERY_RE.search(line).group(1) == "www.iqiyi.com"
    assert dns_watcher.ANSWER_RE.findall(line) == ["23.45.123.58", "23.45.123.56"]


def test_sniffer_ignores_private_answers(dns_watcher, monkeypatch):
    added = {}
    monkeypatch.setattr(dns_watcher, "add_to_table", lambda t, a: added.setdefault(t, set(a)) and 0)
    dns_watcher.domain_table_map = {"example.com": {"approuter_video"}}
    dns_watcher.process_sniffed_dns("example.com", ["192.168.1.10", "8.8.8.8"])
    assert added == {"approuter_video": {"8.8.8.8"}}


def _fake_pf(monkeypatch, dns_watcher, tables):
    deleted = {}
    monkeypatch.setattr(dns_watcher, "show_table", lambda t: list(tables.get(t, [])))

    def delete(table, addrs):
        deleted.setdefault(table, set()).update(addrs)
        tables[table] = [ip for ip in tables[table] if ip not in addrs]
    monkeypatch.setattr(dns_watcher, "delete_from_table", delete)
    return deleted


def test_expiry_removes_only_stale_learned_ips(dns_watcher, monkeypatch, tmp_path):
    table = "approuter_work"
    (tmp_path / "cidrs" / "work.txt").write_text("203.0.113.5/32\n10.0.0.0/8\n")
    tables = {table: ["1.1.1.1", "2.2.2.2", "3.3.3.3", "203.0.113.5", "10.0.0.0/8"]}
    deleted = _fake_pf(monkeypatch, dns_watcher, tables)
    dns_watcher.domain_table_map = {"work.example": {table}}
    dns_watcher.settings.update(table_prefix="approuter", expire_seconds=3600)
    now = time.time()
    dns_watcher.ip_seen = {table: {"1.1.1.1": now - 7200, "2.2.2.2": now - 60}}

    assert dns_watcher.expire_stale_entries() == 1
    assert deleted == {table: {"1.1.1.1"}}
    # unknown entry starts its grace period; static CIDRs are never tracked
    assert set(dns_watcher.ip_seen[table]) == {"2.2.2.2", "3.3.3.3"}
    assert json.load(open(dns_watcher.SEEN_FILE))[table].keys() == {"2.2.2.2", "3.3.3.3"}


def test_expiry_disabled(dns_watcher, monkeypatch):
    deleted = _fake_pf(monkeypatch, dns_watcher, {"approuter_video": ["1.1.1.1"]})
    dns_watcher.domain_table_map = {"x.com": {"approuter_video"}}
    dns_watcher.settings.update(expire_seconds=0)
    dns_watcher.ip_seen = {"approuter_video": {"1.1.1.1": 0}}
    assert dns_watcher.expire_stale_entries() == 0
    assert deleted == {}


def test_rule_interface_devices(dns_watcher, monkeypatch, tmp_path):
    cfg = tmp_path / "config.xml"
    cfg.write_text("<opnsense><interfaces><lan><if>igc1</if></lan><opt1><if>vlan0.10</if></opt1>"
                   "<wan><if>igc0</if></wan></interfaces></opnsense>")
    monkeypatch.setattr(dns_watcher, "OPNSENSE_CONFIG", str(cfg))
    dns_watcher.settings["rules"] = [{"interface": "lan"}, {"interface": "opt1"}, {"interface": "missing"}]
    assert dns_watcher.rule_interface_devices() == ["igc1", "vlan0.10"]


def test_client_ips_include_alias_sources(dns_watcher, tmp_path, monkeypatch):
    clients = tmp_path / "clients"
    clients.mkdir()
    (clients / "approuter_clients_aaaaaaaa.txt").write_text("192.168.70.124/32\n10.10.0.4\n")
    (clients / "approuter_clients_bbbbbbbb.aliases").write_text("Kids_MAC\nbad;name\nHuge\n")
    monkeypatch.setattr(dns_watcher, "CLIENTS_DIR", clients)
    pf = {"Kids_MAC": ["192.168.70.50", "192.168.70.51"],
          "Huge": [f"10.1.{i // 256}.{i % 256}" for i in range(dns_watcher.MAX_ALIAS_CLIENTS + 1)]}
    asked = []
    monkeypatch.setattr(dns_watcher, "show_table", lambda t: asked.append(t) or pf.get(t))
    assert dns_watcher.get_client_ips() == {
        "192.168.70.124/32", "10.10.0.4/32", "192.168.70.50/32", "192.168.70.51/32"}
    assert sorted(asked) == ["Huge", "Kids_MAC"]  # invalid names never reach pfctl


def test_client_ips_alias_table_missing(dns_watcher, tmp_path, monkeypatch):
    clients = tmp_path / "clients"
    clients.mkdir()
    (clients / "approuter_clients_bbbbbbbb.aliases").write_text("Gone\n")
    monkeypatch.setattr(dns_watcher, "CLIENTS_DIR", clients)
    monkeypatch.setattr(dns_watcher, "show_table", lambda t: None)
    assert dns_watcher.get_client_ips() == set()



def _fake_pf_add(monkeypatch, dns_watcher, tables):
    added = {}

    def add(table, addrs):
        new = set(addrs) - set(tables.setdefault(table, []))
        tables[table] = list(tables[table]) + sorted(new)
        added.setdefault(table, set()).update(addrs)
        return len(new)
    monkeypatch.setattr(dns_watcher, "add_to_table", add)
    return added


def test_restore_readds_fresh_learned_ips(dns_watcher, monkeypatch):
    tables = {"approuter_video_iqiyi": []}
    monkeypatch.setattr(dns_watcher, "show_table", lambda t: tables.get(t))
    added = _fake_pf_add(monkeypatch, dns_watcher, tables)
    dns_watcher.domain_table_map = {"iqiyi.com": {"approuter_video_iqiyi", "approuter_gone"},
                                    "x.com": {"approuter_unmapped_never"}}
    dns_watcher.settings.update(expire_seconds=3600)
    now = time.time()
    dns_watcher.ip_seen = {
        "approuter_video_iqiyi": {"1.1.1.1": now - 60, "2.2.2.2": now - 7200},
        "approuter_gone": {"3.3.3.3": now},          # table not in pf: not created
        "approuter_other": {"4.4.4.4": now},         # no longer mapped: not restored
    }
    assert dns_watcher.restore_seen() == 1
    assert added == {"approuter_video_iqiyi": {"1.1.1.1"}}


def test_expiry_keeps_fresh_ips_missing_from_pf(dns_watcher, monkeypatch):
    table = "approuter_video_iqiyi"
    tables = {table: []}   # table was reset
    _fake_pf(monkeypatch, dns_watcher, tables)
    _fake_pf_add(monkeypatch, dns_watcher, tables)
    dns_watcher.domain_table_map = {"iqiyi.com": {table}}
    dns_watcher.settings.update(table_prefix="approuter", expire_seconds=3600)
    now = time.time()
    dns_watcher.ip_seen = {table: {"1.1.1.1": now - 60, "2.2.2.2": now - 7200}}
    dns_watcher.expire_stale_entries()
    assert set(dns_watcher.ip_seen[table]) == {"1.1.1.1"}
    assert tables[table] == ["1.1.1.1"]


def test_seen_file_is_root_only(dns_watcher):
    import os
    import stat
    dns_watcher.ip_seen = {"approuter_video": {"1.1.1.1": time.time()}}
    dns_watcher.save_seen()
    assert stat.S_IMODE(os.stat(dns_watcher.SEEN_FILE).st_mode) == 0o600


def test_iqiyi_carrier_cdn_domain_listed():
    import os
    from conftest import SCRIPTS
    cats = json.load(open(os.path.join(SCRIPTS, "app_categories.json")))
    assert "71edge.com" in cats["video"]["apps"]["iqiyi"]["domains"]


def test_sniffers_start_before_initial_resolution_and_sighup_is_async():
    import pathlib, re
    src = pathlib.Path(__file__).resolve().parent.parent.joinpath(
        "src/opnsense/scripts/OPNsense/Approuter/dns_watcher.py").read_text()
    main = src[src.index("def main():"):]
    assert main.index("target=sniff_interface") < main.index('start_background_resolve("initial")')
    hup = src[src.index("def reload_mappings("):src.index("def cleanup(")]
    assert "resolve_and_update()" not in hup
    assert 'start_background_resolve("SIGHUP")' in hup


def _dns_response(qid, answers, rcode=0):
    """Build a DNS response: answers = [(type, rdata bytes)] for name example.com."""
    import struct
    q = b"\x07example\x03com\x00"
    out = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0) + q + struct.pack(">HH", 1, 1)
    for rtype, rdata in answers:
        out += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return out


def test_parse_a_records_follows_cname_chain_and_checks_id(dns_watcher):
    import socket
    cname = b"\x03cdn\xc0\x0c"
    data = _dns_response(42, [(5, cname), (1, socket.inet_aton("1.2.3.4")), (1, socket.inet_aton("5.6.7.8"))])
    assert dns_watcher.parse_a_records(data, 42) == {"1.2.3.4", "5.6.7.8"}
    assert dns_watcher.parse_a_records(data, 43) == set()
    assert dns_watcher.parse_a_records(_dns_response(42, [], rcode=3), 42) == set()
    assert dns_watcher.parse_a_records(b"\x00\x2a", 42) == set()


def test_used_tables_only_from_rules(dns_watcher):
    dns_watcher.settings["table_prefix"] = "approuter"
    dns_watcher.settings["rules"] = [
        {"uuid": "u1", "categories": "video.iqiyi,china_all", "custom_domains": ""},
        {"uuid": "u2", "categories": "", "custom_domains": "example.cn"},
    ]
    import hashlib
    assert dns_watcher.used_tables() == {"approuter_video_iqiyi", "approuter_china_all",
                                f"approuter_custom_{hashlib.md5(b'u2').hexdigest()[:8]}"}


def test_load_domain_mappings_skips_unused_categories(dns_watcher, tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(dns_watcher, "log", lambda *a, **k: None)
    (tmp_path / "approuter_video_iqiyi.json").write_text(json.dumps({"table": "approuter_video_iqiyi", "domains": ["iqiyi.com"]}))
    (tmp_path / "approuter_video_douyin.json").write_text(json.dumps({"table": "approuter_video_douyin", "domains": ["douyin.com"]}))
    monkeypatch.setattr(dns_watcher, "CONFIG_DIR", str(tmp_path))
    dns_watcher.settings["table_prefix"] = "approuter"
    dns_watcher.settings["rules"] = [{"uuid": "u1", "categories": "video.iqiyi", "custom_domains": ""}]
    dns_watcher.load_domain_mappings()
    assert dns_watcher.domain_table_map == {"iqiyi.com": {"approuter_video_iqiyi"}}


def test_resolve_and_update_resolves_each_name_once(dns_watcher, monkeypatch):
    dns_watcher.domain_table_map = {"iqiyi.com": {"approuter_video", "approuter_video_iqiyi"}, "www.qy.net": {"approuter_video"}}
    calls = []

    def fake_resolve(name):
        calls.append(name)
        return {"iqiyi.com": {"1.1.1.1"}, "www.iqiyi.com": {"2.2.2.2", "10.0.0.1"}}.get(name, set())

    added = {}
    monkeypatch.setattr(dns_watcher, "resolve_via_unbound", fake_resolve)
    monkeypatch.setattr(dns_watcher, "add_to_table", lambda t, a: added.setdefault(t, set()).update(a) or len(a))
    monkeypatch.setattr(dns_watcher, "mark_seen", lambda *a: None)
    monkeypatch.setattr(dns_watcher, "get_client_ips", lambda: set())
    monkeypatch.setattr(dns_watcher, "log", lambda *a, **k: None)
    dns_watcher.resolve_and_update()
    assert sorted(calls) == ["iqiyi.com", "www.iqiyi.com", "www.qy.net"]
    assert added["approuter_video_iqiyi"] == {"1.1.1.1", "2.2.2.2"}     # private dropped
    assert added["approuter_video"] == {"1.1.1.1", "2.2.2.2"}


def test_kill_orphan_sniffers_only_kills_reparented_tcpdump(dns_watcher, monkeypatch):
    import types
    ps = ("  5572     1 /usr/sbin/tcpdump -U -l -n -Q out -i igc3 udp and src port 53 -vv\n"
          " 23788 19758 /usr/sbin/tcpdump -U -l -n -Q out -i wg0 udp and src port 53 -vv\n"
          "  6000     1 /usr/sbin/tcpdump -n -i igc0 port 80\n")
    monkeypatch.setattr(dns_watcher.subprocess, "run", lambda *a, **k: types.SimpleNamespace(stdout=ps))
    killed = []
    monkeypatch.setattr(dns_watcher.os, "kill", lambda pid, sig: killed.append(pid))
    assert dns_watcher.kill_orphan_sniffers() == 1
    assert killed == [5572]


def test_unbound_restart_detection(dns_watcher, tmp_path):
    assert dns_watcher.unbound_restarted(None, 100) is False      # first look
    assert dns_watcher.unbound_restarted(100, None) is False      # Unbound down
    assert dns_watcher.unbound_restarted(100, 100) is False
    assert dns_watcher.unbound_restarted(100, 200) is True
    pid = tmp_path / "unbound.pid"
    pid.write_text("4242\n")
    assert dns_watcher.read_unbound_pid(str(pid)) == 4242
    pid.write_text("garbage")
    assert dns_watcher.read_unbound_pid(str(pid)) is None
    assert dns_watcher.read_unbound_pid(str(tmp_path / "missing")) is None


def test_flush_after_restart_never_raises(dns_watcher, monkeypatch):
    import sys
    import types
    fake = types.ModuleType("unbound_flush")

    def boom():
        raise RuntimeError("x")
    fake.run_flush = boom
    monkeypatch.setitem(sys.modules, "unbound_flush", fake)
    monkeypatch.setattr(dns_watcher, "log", lambda *a, **k: None)
    assert dns_watcher.flush_after_unbound_restart() is None
    fake.run_flush = lambda: {"status": "ok"}
    assert dns_watcher.flush_after_unbound_restart() == {"status": "ok"}
