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
