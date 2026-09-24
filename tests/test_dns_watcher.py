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


def test_expiry_also_cleans_active_gw_tables(dns_watcher, monkeypatch):
    tables = {"approuter_video": ["1.1.1.1"], "approuter_video_gw0": ["1.1.1.1"]}
    deleted = _fake_pf(monkeypatch, dns_watcher, tables)
    dns_watcher.domain_table_map = {"x.com": {"approuter_video"}}
    dns_watcher.active_gw_tables = {"approuter_video_gw0"}
    dns_watcher.settings.update(table_prefix="approuter", expire_seconds=10)
    dns_watcher.ip_seen = {"approuter_video": {"1.1.1.1": 0}}
    dns_watcher.expire_stale_entries()
    assert deleted == {"approuter_video": {"1.1.1.1"}, "approuter_video_gw0": {"1.1.1.1"}}


def test_rule_interface_devices(dns_watcher, monkeypatch, tmp_path):
    cfg = tmp_path / "config.xml"
    cfg.write_text("<opnsense><interfaces><lan><if>igc1</if></lan><opt1><if>vlan0.10</if></opt1>"
                   "<wan><if>igc0</if></wan></interfaces></opnsense>")
    monkeypatch.setattr(dns_watcher, "OPNSENSE_CONFIG", str(cfg))
    dns_watcher.settings["rules"] = [{"interface": "lan"}, {"interface": "opt1"}, {"interface": "missing"}]
    assert dns_watcher.rule_interface_devices() == ["igc1", "vlan0.10"]
