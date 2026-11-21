"""Static CIDR lists are merged into category tables, never replaced:
IPs learned by dns_watcher must survive Apply / list updates / reinstall."""
import json
import os
import subprocess
import time

import pytest

from conftest import load_script


class FakePf:
    """Minimal pfctl: -s Tables, -t T -T show|add|delete [-f file], replace is fatal."""

    def __init__(self, tables):
        self.tables = {t: set(v) for t, v in tables.items()}
        self.calls = []

    def run(self, cmd, capture_output=True, text=True, timeout=None):
        args = cmd[1:]
        self.calls.append(args)
        out = ""
        rc = 0
        if args[:2] == ["-s", "Tables"]:
            out = "\n".join(sorted(self.tables)) + "\n"
        else:
            table, op = args[1], args[3]
            assert op != "replace", "category tables must never be replaced"
            assert op != "flush", "category tables must never be flushed"
            entries = []
            if "-f" in args:
                with open(args[args.index("-f") + 1]) as f:
                    entries = [line.strip() for line in f if line.strip()]
            if op == "show":
                if table not in self.tables:
                    rc = 1
                else:
                    out = "".join(f"   {e}\n" for e in sorted(self.tables[table]))
            elif op == "add":
                self.tables.setdefault(table, set()).update(entries)
            elif op == "delete":
                self.tables[table] -= set(entries)
        return subprocess.CompletedProcess(cmd, rc, out, "")


@pytest.fixture
def sync(tmp_path, monkeypatch):
    ss = load_script("static_sync")
    base = tmp_path / "app-router"
    (base / "cidrs").mkdir(parents=True)
    monkeypatch.setattr(ss, "CIDRS_DIR", str(base / "cidrs"))
    monkeypatch.setattr(ss, "APPLIED_DIR", str(base / "cidrs" / ".applied"))
    monkeypatch.setattr(ss, "CONFIG_FILE", str(base / "config.json"))
    monkeypatch.setattr(ss, "SEEN_FILE", str(base / "ip_seen.json"))
    monkeypatch.setattr(ss, "log", lambda *a, **k: None)
    ss.base = base
    return ss


def use_pf(ss, monkeypatch, tables):
    pf = FakePf(tables)
    monkeypatch.setattr(ss.subprocess, "run", pf.run)
    return pf


def test_plan_never_deletes_learned_or_still_static(sync):
    add, delete = sync.plan(
        current={"1.2.3.4", "10.0.0.0/8", "192.0.2.0/24"},
        static_new={"10.0.0.0/8", "172.16.0.0/12"},
        static_old={"10.0.0.0/8", "192.0.2.0/24", "1.2.3.4"},
        learned={"1.2.3.4"},
    )
    assert add == {"172.16.0.0/12"}
    assert delete == {"192.0.2.0/24"}


def test_norm(sync):
    assert sync.norm("1.2.3.4/32") == "1.2.3.4"
    assert sync.norm(" 10.1.2.3/8 ") == "10.0.0.0/8"
    assert sync.norm("# comment") is None and sync.norm("junk") is None


def test_learned_entry_survives_simulated_apply(sync, monkeypatch):
    table = "approuter_ba_work"
    cidrs = sync.base / "cidrs"
    (cidrs / "ba_work.txt").write_text("10.0.0.0/8\n192.0.2.0/24\n")
    # first Apply: static entries go in, a learned IP is already there
    pf = use_pf(sync, monkeypatch, {table: {"1.2.3.4"}, "approuter_video_iqiyi": {"5.6.7.8"}})
    sync.main(["static_sync.py", "all"])
    assert pf.tables[table] == {"1.2.3.4", "10.0.0.0/8", "192.0.2.0/24"}
    # list edited (192.0.2.0/24 removed, 172.16.0.0/12 added), Apply again
    (cidrs / "ba_work.txt").write_text("10.0.0.0/8\n172.16.0.0/12\n")
    sync.main(["static_sync.py", "all"])
    assert pf.tables[table] == {"1.2.3.4", "10.0.0.0/8", "172.16.0.0/12"}
    # tables without a static list (DNS-only categories) are not touched
    assert pf.tables["approuter_video_iqiyi"] == {"5.6.7.8"}
    assert all("approuter_video_iqiyi" not in c for c in pf.calls)


def test_learned_ip_in_old_static_list_kept(sync, monkeypatch):
    table = "approuter_ba_work"
    cidrs = sync.base / "cidrs"
    (cidrs / ".applied").mkdir()
    (cidrs / ".applied" / "ba_work.txt").write_text("1.2.3.4\n")
    (cidrs / "ba_work.txt").write_text("")
    (sync.base / "ip_seen.json").write_text(json.dumps({table: {"1.2.3.4": time.time()}}))
    pf = use_pf(sync, monkeypatch, {table: {"1.2.3.4"}})
    sync.main(["static_sync.py", "ba_work"])
    assert pf.tables[table] == {"1.2.3.4"}


def test_unused_table_not_created(sync, monkeypatch):
    (sync.base / "cidrs" / "china_all.txt").write_text("1.0.1.0/24\n")
    pf = use_pf(sync, monkeypatch, {})
    sync.main(["static_sync.py", "all"])
    assert pf.tables == {}
    assert not os.path.exists(sync.base / "cidrs" / ".applied" / "china_all.txt")


def test_learned_entry_survives_apply_and_reset_with_watcher(sync, dns_watcher, monkeypatch, tmp_path):
    """Full Apply sequence: static merge, then a table reset (reboot / old
    replace), then the SIGHUP Apply sends: the learned CDN IP is back."""
    table = "approuter_video_iqiyi"
    pf = use_pf(sync, monkeypatch, {table: {"23.45.123.58"}})
    monkeypatch.setattr(dns_watcher, "show_table",
                        lambda t: sorted(pf.tables[t]) if t in pf.tables else None)

    def add(t, a):
        new = set(a) - pf.tables[t]
        pf.tables[t].update(new)
        return len(new)
    monkeypatch.setattr(dns_watcher, "add_to_table", add)
    dns_watcher.domain_table_map = {"71edge.com": {table}}
    dns_watcher.settings.update(table_prefix="approuter", expire_seconds=24 * 3600)
    dns_watcher.mark_seen(table, {"23.45.123.58"})
    dns_watcher.save_seen()
    sync.main(["static_sync.py", "all"])
    assert pf.tables[table] == {"23.45.123.58"}
    # watcher restart + reboot: table empty, state only on disk
    pf.tables[table] = set()
    dns_watcher.ip_seen = {}
    dns_watcher.load_seen()
    assert dns_watcher.restore_seen() == 1
    assert pf.tables[table] == {"23.45.123.58"}
