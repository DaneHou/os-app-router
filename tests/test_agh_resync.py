import json
import os
import sys

import pytest

from conftest import SCRIPTS, load_script

YAML = """http:
  address: 0.0.0.0:3000
users:
  - name: admin
    password: $2y$10$hash
dns:
  bind_hosts:
    - 0.0.0.0
  upstream_dns:
    - '# --- 自动更新列表开始 ---'
    - '[/baidu.com/]https://doh.pub/dns-query https://dns.alidns.com/dns-query'
    - '[/iqiyi.com/]https://doh.pub/dns-query https://dns.alidns.com/dns-query'
    - '[/71.am/]127.0.0.1:53530'
    - '# --- 自动更新列表结束 ---'
    - 127.0.0.1:53530
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.10
"""


@pytest.fixture
def agh():
    return load_script("agh_resync")


def test_plan_inserts_block_and_removes_conflicts(agh):
    new, s = agh.plan(YAML, ["71.am", "iqiyi.com"], 53530)
    assert s["status"] == "changed" and s["conflicts_removed"] == 1 and s["domains"] == 2
    lines = new.split("\n")
    i = lines.index("  upstream_dns:")
    assert lines[i + 1:i + 5] == ["    - '# --- App Router: DNS via gateway (managed) ---'",
                                  "    - '[/71.am/]127.0.0.1:53530'",
                                  "    - '[/iqiyi.com/]127.0.0.1:53530'",
                                  "    - '# --- App Router end ---'"]
    assert "[/iqiyi.com/]https://doh.pub" not in new and "[/baidu.com/]https://doh.pub" in new
    assert new.count("[/71.am/]") == 1                  # the old copy outside the block is gone
    # everything outside upstream_dns is untouched
    assert new.split("  upstream_dns:")[0] == YAML.split("  upstream_dns:")[0]
    assert new.split("  upstream_dns_file")[1] == YAML.split("  upstream_dns_file")[1]
    # idempotent
    again, s2 = agh.plan(new, ["71.am", "iqiyi.com"], 53530)
    assert again is None and s2["status"] == "unchanged"
    assert agh.check(new, ["71.am", "iqiyi.com"], 53530)[0] is True
    ok, detail = agh.check(YAML, ["71.am", "iqiyi.com"], 53530)
    assert ok is False and "1 AdGuard Home upstream" in detail


def test_plan_removes_block_when_no_domains_and_never_empties_list(agh):
    new, _ = agh.plan(YAML, ["iqiyi.com"], 53530)
    back, s = agh.plan(new, [], 53530)
    assert agh.BEGIN not in back and s["status"] == "changed"
    only = "dns:\n  upstream_dns:\n    - '[/iqiyi.com/]1.1.1.1'\n  x: 1\n"
    none, s = agh.plan(only, ["iqiyi.com"], 53530)
    assert none is not None      # block replaces the conflicting entry: list not empty
    none, s = agh.plan("dns:\n  upstream_dns:\n    - '[/a.com/]1.1.1.1'\n", [], 53530)
    assert none is None and s["status"] == "unchanged"
    bad, s = agh.plan("dns:\n  upstream_dns: []\n", ["a.com"], 53530)
    assert bad is None and s["status"] == "error"


def test_inputs(agh):
    assert agh.export_domains("IQIYI.com.\n# c\n\n71.am\nbad domain\n71.am\n") == ["71.am", "iqiyi.com"]
    assert agh.unbound_port('{"unbound_port": 53530}', None) == 53530
    assert agh.unbound_port("{}", "server:\n  port: 5353\n") == 5353
    assert agh.enabled('{"enabled": 1}') and not agh.enabled('{"enabled": 1, "agh_sync": 0}')
    assert not agh.enabled('{"enabled": 0}') and not agh.enabled(None)


def test_run_writes_backup_keeps_mode_and_restarts_only_on_change(agh, tmp_path, monkeypatch):
    conf = tmp_path / "AdGuardHome.yaml"
    conf.write_text(YAML)
    os.chmod(conf, 0o640)
    d = tmp_path / "ar"
    d.mkdir()
    (d / "config.json").write_text('{"enabled": 1}')
    (d / "dns_via_gateway.txt").write_text("iqiyi.com\n71.am\n")
    (d / "dns_forward_status.json").write_text('{"unbound_port": 53530}')
    for k, v in {"AGH_CONF": conf, "APPROUTER_DIR": d, "CONFIG_FILE": d / "config.json",
                 "EXPORT_FILE": d / "dns_via_gateway.txt", "STATUS_FILE": d / "dns_forward_status.json",
                 "RESULT_FILE": d / "last.json", "BACKUP_FILE": d / "bak.yaml",
                 "UNBOUND_CONF": tmp_path / "none"}.items():
        monkeypatch.setattr(agh, k, str(v))
    calls = []
    monkeypatch.setattr(agh, "AGH_LOCK", str(tmp_path / "agh.lock"))
    monkeypatch.setattr(agh.time, "sleep", lambda s: None)
    monkeypatch.setattr(agh, "agh_running", lambda: True)
    monkeypatch.setattr(agh.subprocess, "run", lambda argv, **kw: calls.append(argv) or type("R", (), {"returncode": 0})())
    monkeypatch.setattr(agh, "log", lambda *a, **k: None)
    monkeypatch.setattr(os, "chown", lambda *a: None)
    r = agh.run([])
    assert r["status"] == "changed" and r["restarted"] is True and len(calls) == 1
    assert (d / "bak.yaml").read_text() == YAML and oct(os.stat(conf).st_mode & 0o777) == "0o640"
    assert agh.run([])["status"] == "unchanged" and len(calls) == 1
    conf.write_text(YAML)
    assert agh.run(["--check"])["status"] == "changed" and conf.read_text() == YAML   # check never writes
    assert agh.run(["--no-restart"])["status"] == "changed" and len(calls) == 1


def test_healthcheck_reports_and_offers_fix(monkeypatch):
    sys.path.insert(0, SCRIPTS)
    hc = load_script("healthcheck")
    agh = sys.modules.get("agh_resync") or __import__("agh_resync")

    class S:
        files = {agh.AGH_CONF: YAML, agh.CONFIG_FILE: '{"enabled": 1}', agh.EXPORT_FILE: "iqiyi.com\n",
                 agh.STATUS_FILE: '{"unbound_port": 53530}'}

        def read(self, p):
            return self.files.get(p)
    c = hc.check_agh(S())
    assert c["ok"] is False and c["fix"]["action"] == "approuter agh_resync" and c["severity"] == "medium"
    S.files[agh.AGH_CONF] = agh.plan(YAML, ["iqiyi.com"], 53530)[0]
    assert hc.check_agh(S())["ok"] is True
    del S.files[agh.AGH_CONF]
    assert hc.check_agh(S())["ok"] is None


def test_folded_long_values_are_one_item(agh):
    y = ("dns:\n  upstream_dns:\n"
         "    - '[/very.long.example.com/]https://doh.pub/dns-query\n"
         "      https://dns.alidns.com/dns-query'\n"
         "    - '[/iqiyi.com/]https://doh.pub/dns-query\n"
         "      https://dns.alidns.com/dns-query'\n"
         "    - '[/71.am/]127.0.0.1:53530'\n"
         "  upstream_dns_file: \"\"\n")
    new, s = agh.plan(y, ["71.am", "iqiyi.com"], 53530)
    assert s["items_before"] == 3 and s["conflicts_removed"] == 1 and s["items_after"] == 5
    assert "very.long.example.com/]https://doh.pub/dns-query\n      https://dns.alidns.com" in new
    assert "[/iqiyi.com/]https://doh.pub" not in new and "      https://dns.alidns.com/dns-query'\n    - '[/71" not in new
    assert new.count("[/71.am/]") == 1 and new.endswith('  upstream_dns_file: ""\n')


def test_restart_failure_restores_previous_file(agh, tmp_path, monkeypatch):
    """AdGuard Home exits on a file it cannot use (whole-house DNS outage): put the old one back."""
    conf = tmp_path / "AdGuardHome.yaml"
    conf.write_text(YAML)
    d = tmp_path / "ar"
    d.mkdir()
    (d / "config.json").write_text('{"enabled": 1}')
    (d / "dns_via_gateway.txt").write_text("iqiyi.com\n71.am\n")
    (d / "dns_forward_status.json").write_text('{"unbound_port": 53530}')
    for k, v in {"AGH_CONF": conf, "APPROUTER_DIR": d, "CONFIG_FILE": d / "config.json",
                 "EXPORT_FILE": d / "dns_via_gateway.txt", "STATUS_FILE": d / "dns_forward_status.json",
                 "RESULT_FILE": d / "last.json", "BACKUP_FILE": d / "bak.yaml",
                 "UNBOUND_CONF": tmp_path / "none", "AGH_LOCK": tmp_path / "agh.lock"}.items():
        monkeypatch.setattr(agh, k, str(v))
    state = {"restarts": 0}

    def fake_run(argv, **kw):
        if argv == agh.AGH_RESTART:
            state["restarts"] += 1
        return type("R", (), {"returncode": 0})()

    # running before the change, gone after the first restart, back after the second
    monkeypatch.setattr(agh, "agh_running", lambda: state["restarts"] != 1)
    monkeypatch.setattr(agh.subprocess, "run", fake_run)
    monkeypatch.setattr(agh.time, "sleep", lambda s: None)
    monkeypatch.setattr(agh, "log", lambda *a, **k: None)
    monkeypatch.setattr(os, "chown", lambda *a: None)
    r = agh.run([])
    assert r["status"] == "error" and r["rolled_back"] is True and r["restarted"] is False
    assert conf.read_text() == YAML and state["restarts"] == 2


def test_lock_is_exclusive(agh, tmp_path, monkeypatch):
    import fcntl
    lock = tmp_path / "agh.lock"
    monkeypatch.setattr(agh, "AGH_LOCK", str(lock))
    monkeypatch.setattr(agh.time, "sleep", lambda s: None)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(TimeoutError):
            with agh.agh_lock(timeout=0):
                pass
    finally:
        os.close(fd)
    with agh.agh_lock(timeout=0):
        pass


def test_validate_accepts_plan_and_rejects_anything_else(agh):
    new, _s = agh.plan(YAML, ["iqiyi.com", "71.am"], 53530)
    assert agh.validate(YAML, new) == (True, "")
    folded = ("dns:\n  upstream_dns:\n    - '[/a.example/]https://doh.pub/dns-query\n"
              "      https://dns.alidns.com/dns-query'\n    - 127.0.0.1:53530\n")
    fnew, _s = agh.plan(folded, ["b.example"], 53530)
    assert agh.validate(folded, fnew)[0] is True          # folded values read the same both ways
    ok, reason = agh.validate(YAML, new.replace("    - 9.9.9.10", "    - 1.1.1.1"))
    assert not ok and "other settings" in reason
    ok, reason = agh.validate(YAML, new.replace("  upstream_dns:\n", "  upstream_dns:\n   - [bad\n", 1))
    assert not ok


def test_run_refuses_to_write_an_unvalidated_file(agh, tmp_path, monkeypatch):
    conf = tmp_path / "AdGuardHome.yaml"
    conf.write_text(YAML)
    d = tmp_path / "ar"
    d.mkdir()
    (d / "config.json").write_text('{"enabled": 1}')
    (d / "dns_via_gateway.txt").write_text("iqiyi.com\n")
    (d / "dns_forward_status.json").write_text('{"unbound_port": 53530}')
    for k, v in {"AGH_CONF": conf, "APPROUTER_DIR": d, "CONFIG_FILE": d / "config.json",
                 "EXPORT_FILE": d / "dns_via_gateway.txt", "STATUS_FILE": d / "dns_forward_status.json",
                 "RESULT_FILE": d / "last.json", "BACKUP_FILE": d / "bak.yaml",
                 "UNBOUND_CONF": tmp_path / "none", "AGH_LOCK": tmp_path / "agh.lock"}.items():
        monkeypatch.setattr(agh, k, str(v))
    calls = []
    monkeypatch.setattr(agh.subprocess, "run", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(agh, "log", lambda *a, **k: None)
    monkeypatch.setattr(agh, "validate", lambda old, new: (False, "the edit would change other settings"))
    r = agh.run([])
    assert r["status"] == "error" and "other settings" in r["reason"]
    assert conf.read_text() == YAML and calls == [] and not (d / "bak.yaml").exists()
