import json
import os
import sys


def test_valid_domains_filters_injection(list_updater):
    result = list_updater.valid_domains(
        ["Example.COM.", "a.b-c.org", "bad/dom", "evil.com\nconf-file=/x", "*.wild.net", "", " sp.com "]
    )
    assert result == {"example.com", "a.b-c.org", "*.wild.net", "sp.com"}


def test_parse_dnsmasq_domains(list_updater):
    content = "server=/qq.com/114.114.114.114\nserver=/bad dom/1.1.1.1\n#comment\nserver=/163.com/1.2.3.4\n"
    assert list_updater.parse_dnsmasq_domains(content) == {"qq.com", "163.com"}


def test_parse_and_aggregate_cidrs(list_updater):
    cidrs = list_updater.parse_cidr_list("1.0.1.0/24\n1.0.0.0/24\n# x\nnot-a-cidr\n1.0.2.5/16\n")
    assert list_updater.aggregate_cidrs(cidrs) == ["1.0.0.0/16"]


def test_custom_categories_validation(list_updater):
    config = {"custom_categories": [
        {"slug": "work", "label": "W", "domains": "a.com,bad/dom,b.org", "cidrs": "10.0.0.0/8,zzz"},
        {"slug": "../../etc", "label": "x", "domains": "c.com", "cidrs": ""},
        {"slug": "china_all", "label": "reserved", "domains": "", "cidrs": "1.2.3.0/24"},
    ]}
    list_updater.process_custom_categories(config, "myrt")
    mapping = json.load(open(os.path.join(list_updater.UNBOUND_DIR, "approuter_usercat_work.json")))
    assert mapping == {"table": "myrt_work", "domains": ["a.com", "b.org"]}
    assert open(os.path.join(list_updater.CIDRS_DIR, "work.txt")).read() == "10.0.0.0/8\n"
    # traversal slug and the reserved china_all slug must not write anything
    assert sorted(os.listdir(list_updater.CIDRS_DIR)) == ["work.txt"]


def test_generate_dns_keeps_cached_v2fly_domains(list_updater, monkeypatch):
    """Apply (generate_dns) must not drop domains fetched from v2fly."""
    categories = list_updater.load_categories()
    cat_id, app_id = next(
        (c, a) for c, d in categories.items() for a, ad in d.get("apps", {}).items() if ad.get("v2fly")
    )
    key = f"{cat_id}.{app_id}"
    list_updater.write_domain_file(key, {"only-from-v2fly.example"})
    json.dump({"table_prefix": "approuter", "rules": []}, open(list_updater.CONFIG_FILE, "w"))

    monkeypatch.setattr(sys, "argv", ["list_updater.py", "generate_dns"])
    list_updater.main()

    app_map = json.load(open(os.path.join(list_updater.UNBOUND_DIR, f"approuter_{cat_id}_{app_id}.json")))
    cat_map = json.load(open(os.path.join(list_updater.UNBOUND_DIR, f"approuter_{cat_id}.json")))
    assert "only-from-v2fly.example" in app_map["domains"]
    assert "only-from-v2fly.example" in cat_map["domains"]


def test_rule_custom_domain_mappings(list_updater):
    config = {"rules": [{"uuid": "u1", "custom_domains": "ok.com, evil.com/x"}]}
    list_updater.generate_custom_domain_mappings(config, "approuter")
    files = [f for f in os.listdir(list_updater.UNBOUND_DIR) if f.startswith("approuter_custom_")]
    assert len(files) == 1
    assert json.load(open(os.path.join(list_updater.UNBOUND_DIR, files[0])))["domains"] == ["ok.com"]


def test_legacy_dnsmasq_dir_removed(list_updater):
    os.makedirs(os.path.join(list_updater.LEGACY_DNSMASQ_DIR, "sub"))
    list_updater.ensure_dirs()
    assert not os.path.exists(list_updater.LEGACY_DNSMASQ_DIR)


def test_list_problem_bounds(list_updater):
    lp = list_updater.list_problem
    assert lp(0, 10, 100) == "empty"
    assert lp(101, 0, 100).startswith("101 entries")
    assert lp(40, 100, 1000) == "shrank from 100 to 40 entries"
    assert lp(60, 100, 1000) is None
    assert lp(250, 20, 1000) == "grew from 20 to 250 entries"     # tenfold and +200
    assert lp(210, 20, 1000) is None and lp(5000, 0, 10000) is None


def test_public_networks_drop_local_and_too_wide(list_updater):
    kept, dropped = list_updater.public_networks(
        ["1.0.1.0/24", "10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/0", "1.0.0.0/7", "224.0.0.0/8",
         "127.0.0.0/8", "100.64.0.0/10", "junk", "36.0.0.0/8", "2001:db8::/32", "240e::/18"])
    assert kept == {"1.0.1.0/24", "36.0.0.0/8", "240e::/18"} and dropped == 9


def _fetch(contents):
    def fake(url, etag=None, timeout=30):
        return contents[url], "etag-" + str(len(contents[url])), True
    return fake


def test_remote_update_keeps_last_good_list(list_updater, monkeypatch):
    lu = list_updater
    cidr_url, dom_url = lu.DEFAULT_SOURCES["china_cidrs_v4"]["url"], lu.DEFAULT_SOURCES["china_domains"]["url"]
    good_cidrs = "\n".join(f"1.{i}.0.0/16" for i in range(0, 200, 2))
    good_doms = "\n".join(f"server=/d{i}.cn/114.114.114.114" for i in range(100))
    state = {}
    monkeypatch.setattr(lu, "fetch_url", _fetch({cidr_url: good_cidrs, dom_url: good_doms}))
    lu.update_remote_lists({}, state)
    cidr_file = os.path.join(lu.CIDRS_DIR, "china_all.txt")
    dom_file = os.path.join(lu.DOMAINS_DIR, "china_all.txt")
    before = open(cidr_file).read(), open(dom_file).read()
    assert len(before[0].split()) == 100 and len(before[1].split()) == 100 and not state.get("rejected")

    # a truncated download (shrinks by more than half) and a list full of junk
    junk = good_cidrs + "\n" + "\n".join(["10.0.0.0/8", "0.0.0.0/0", "192.168.0.0/16"] * 5)
    monkeypatch.setattr(lu, "fetch_url", _fetch({cidr_url: junk, dom_url: "server=/only.cn/1.1.1.1\n"}))
    lu.update_remote_lists({}, state)
    assert (open(cidr_file).read(), open(dom_file).read()) == before
    assert set(state["rejected"]) == {"china_cidrs_v4", "china_all domains"}
    assert "not public networks" in state["rejected"]["china_cidrs_v4"]["reason"]
    assert state["rejected"]["china_all domains"]["reason"] == "shrank from 100 to 1 entries"

    # the next sane download is taken and clears the rejection
    monkeypatch.setattr(lu, "fetch_url", _fetch({cidr_url: good_cidrs + "\n2.0.0.0/16", dom_url: good_doms}))
    lu.update_remote_lists({}, state)
    assert len(open(cidr_file).read().split()) == 101 and state["rejected"] == {}


def test_v2fly_failure_or_explosion_keeps_cached_list(list_updater, monkeypatch):
    lu = list_updater
    cats = {"video": {"apps": {"iqiyi": {"v2fly": "iqiyi", "domains": ["iqiyi.com"]}}}}
    lu.write_domain_file("video.iqiyi", {"iqiyi.com", "qy.net", "71.am"})
    state = {}
    monkeypatch.setattr(lu, "fetch_v2fly_domains", lambda name, depth=0: set())
    assert lu.update_v2fly_domains(cats, state)["video.iqiyi"] == {"iqiyi.com", "qy.net", "71.am"}
    monkeypatch.setattr(lu, "fetch_v2fly_domains", lambda name, depth=0: {f"x{i}.example" for i in range(500)})
    assert lu.update_v2fly_domains(cats, state)["video.iqiyi"] == {"iqiyi.com", "qy.net", "71.am"}
    assert "grew from 3" in state["rejected"]["v2fly/iqiyi"]["reason"]
    monkeypatch.setattr(lu, "fetch_v2fly_domains", lambda name, depth=0: {"iqiyi.com", "qy.net", "iqiyipic.com"})
    assert lu.update_v2fly_domains(cats, state)["video.iqiyi"] == {"iqiyi.com", "qy.net", "iqiyipic.com"}
    assert "v2fly/iqiyi" not in state["rejected"]
