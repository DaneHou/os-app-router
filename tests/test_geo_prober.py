"""Smart gateway state across prober restarts (Apply stops and starts geo_prober)."""
import json
import time

import pytest

from conftest import load_script

MAIN = "approuter_video_iqiyi"
GW0 = MAIN + "_gw0"
IPS = ["1.1.1.1", "2.2.2.2"]


def make_rule(gp, gateways=("WAN_DHCP", "FRP_GW"), uuid="u1", probe_url="https://www.iqiyi.com/"):
    tables = [MAIN]
    return {
        "uuid": uuid,
        "signature": gp.rule_signature(list(gateways), tables, probe_url, "status_code", ""),
        "description": "my-mbp",
        "gateways": list(gateways),
        "base_tables": tables,
        "probe_url": probe_url,
        "probe_interval": 300,
        "probe_method": "status_code",
        "probe_pattern": None,
    }


@pytest.fixture
def gp(tmp_path, monkeypatch):
    mod = load_script("geo_prober")
    monkeypatch.setattr(mod, "STATE_FILE", str(tmp_path / "smart_gateway_state.json"))
    monkeypatch.setattr(mod, "PERSIST_FILE", str(tmp_path / "smart_gateway_persist.json"))
    monkeypatch.setattr(mod, "LOG_FILE", str(tmp_path / "geo.log"))
    monkeypatch.setattr(mod, "log", lambda *a, **k: None)
    monkeypatch.setattr(mod, "notify_dns_watcher", lambda: None)
    monkeypatch.setattr(mod, "kill_states_for_table", lambda t: None)
    # fake pf: main table holds learned IPs, gw0 was filled by the previous run
    mod.pf = {MAIN: list(IPS), GW0: list(IPS)}
    mod.calls = []

    def sync(base, i):
        mod.calls.append(("sync", f"{base}_gw{i}"))
        mod.pf[f"{base}_gw{i}"] = list(mod.pf.get(base, []))

    def flush(base, i):
        mod.calls.append(("flush", f"{base}_gw{i}"))
        mod.pf[f"{base}_gw{i}"] = []

    monkeypatch.setattr(mod, "sync_table", sync)
    monkeypatch.setattr(mod, "flush_table", flush)
    return mod


def save_previous_run(gp, rule, available=True, age=5):
    """What the previous prober instance left behind when Apply stopped it."""
    states = {0: gp.new_gw_state()}
    states[0].update(available=available, latency=42.0, last_switch_time=time.time() - 3600)
    gp.rule_registry[rule["uuid"]] = {"signature": rule["signature"], "gw_states": states}
    gp.save_persisted()
    gp.rule_registry.clear()
    if age:
        data = json.load(open(gp.PERSIST_FILE))
        for r in data["rules"].values():
            r["saved_at"] -= age
        json.dump(data, open(gp.PERSIST_FILE, "w"))


def start(gp, monkeypatch, rules):
    """Run the start-up path of main() without probe threads or the idle loop."""
    started = []

    class FakeThread:
        def __init__(self, target, args, daemon):
            started.append(args)

        def start(self):
            pass

    monkeypatch.setattr(gp, "load_config", lambda: rules)
    monkeypatch.setattr(gp.threading, "Thread", FakeThread)
    monkeypatch.setattr(gp.signal, "signal", lambda *a: None)
    monkeypatch.setattr(gp.sys, "argv", ["geo_prober.py", "start"])
    gp.shutdown_event.set()
    gp.main()
    return started


def test_apply_restart_keeps_active_gw_table(gp, monkeypatch):
    rule = make_rule(gp)
    save_previous_run(gp, rule)
    started = start(gp, monkeypatch, [rule])
    assert ("flush", GW0) not in gp.calls
    assert gp.pf[GW0] == IPS
    assert GW0 in gp.active_tables
    assert json.load(open(gp.STATE_FILE))["active_tables"] == [GW0]
    # the probe loop resumes with the restored decision
    (_, states), = started
    assert states[0]["available"] is True
    assert states[0]["consecutive_ok"] == gp.DEBOUNCE_COUNT


def test_changed_rule_starts_in_fallback(gp, monkeypatch):
    save_previous_run(gp, make_rule(gp))
    changed = make_rule(gp, gateways=("WAN_DHCP", "BA_VPNV4", "FRP_GW"))
    start(gp, monkeypatch, [changed])
    assert ("flush", GW0) in gp.calls
    assert gp.pf[GW0] == []
    assert gp.active_tables == set()


def test_changed_probe_url_starts_in_fallback(gp, monkeypatch):
    save_previous_run(gp, make_rule(gp))
    start(gp, monkeypatch, [make_rule(gp, probe_url="https://example.org/")])
    assert gp.pf[GW0] == []


def test_stale_state_not_restored(gp, monkeypatch):
    rule = make_rule(gp)
    save_previous_run(gp, rule, age=3600)  # older than max(2 * 300s, 600s)
    start(gp, monkeypatch, [rule])
    assert gp.pf[GW0] == []


def test_standby_gateway_still_flushed(gp, monkeypatch):
    rule = make_rule(gp)
    save_previous_run(gp, rule, available=False)
    start(gp, monkeypatch, [rule])
    assert gp.pf[GW0] == []


def test_no_saved_state_starts_in_fallback(gp, monkeypatch):
    start(gp, monkeypatch, [make_rule(gp)])
    assert gp.pf[GW0] == []


def test_corrupt_persist_file_ignored(gp, monkeypatch):
    open(gp.PERSIST_FILE, "w").write("{not json")
    start(gp, monkeypatch, [make_rule(gp)])
    assert gp.pf[GW0] == []


def test_stop_saves_decisions(gp):
    rule = make_rule(gp)
    states = {0: gp.new_gw_state()}
    states[0]["available"] = True
    gp.rule_registry[rule["uuid"]] = {"signature": rule["signature"], "gw_states": states}
    open(gp.STATE_FILE, "w").write("{}")
    with pytest.raises(SystemExit):
        gp.cleanup()
    saved = json.load(open(gp.PERSIST_FILE))["rules"]["u1"]
    assert saved["signature"] == rule["signature"]
    assert saved["gateways"][0]["available"] is True
    restored = gp.restored_gw_states(rule, gp.load_persisted())
    assert restored[0]["available"] is True


def test_restored_gateway_survives_single_failed_probe(gp, monkeypatch):
    rule = make_rule(gp)
    states = {0: gp.new_gw_state()}
    states[0].update(available=True, consecutive_ok=gp.DEBOUNCE_COUNT)

    class OneRound:
        done = False

        def is_set(self):
            return self.done

        def wait(self, timeout=None):
            self.done = True

    monkeypatch.setattr(gp, "shutdown_event", OneRound())
    monkeypatch.setattr(gp, "probe_gateway", lambda *a: (False, 0.0, "timeout"))
    gp.probe_rule_loop(rule, states)
    assert states[0]["available"] is True
    assert states[0]["consecutive_fail"] == 1
    assert gp.calls == []  # no flush until DEBOUNCE_COUNT failures


def test_start_without_smart_rules_exits_silently(tmp_path, monkeypatch):
    """Rules with Smart Gateway on but a single gateway: no log line, no state files."""
    mod = load_script("geo_prober")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"table_prefix": "approuter", "rules": [
        {"uuid": "u1", "description": "my-mbp", "gateway": "FRP_GW", "smart_gateway": "1",
         "categories": "video.iqiyi", "custom_domains": ""},
        {"uuid": "u2", "description": "x", "gateway": "WAN_DHCP,FRP_GW", "smart_gateway": "0",
         "categories": "video.iqiyi", "custom_domains": ""},
    ]}))
    logged = []
    monkeypatch.setattr(mod, "CONFIG_FILE", str(cfg))
    monkeypatch.setattr(mod, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(mod, "PERSIST_FILE", str(tmp_path / "persist.json"))
    monkeypatch.setattr(mod, "log", lambda *a, **k: logged.append(a[0]))
    monkeypatch.setattr(mod.signal, "signal", lambda *a: None)
    monkeypatch.setattr(mod.sys, "argv", ["geo_prober.py", "start"])
    with pytest.raises(SystemExit) as e:
        mod.main()
    assert e.value.code == 0
    assert logged == []
    assert list(tmp_path.iterdir()) == [cfg]
