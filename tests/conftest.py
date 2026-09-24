import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "src", "opnsense", "scripts", "OPNsense", "Approuter")
TEMPLATES = os.path.join(ROOT, "src", "opnsense", "service", "templates", "OPNsense", "Approuter")


def load_script(name):
    """Import one of the plugin scripts (they are not a package)."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPTS, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def list_updater(tmp_path, monkeypatch):
    lu = load_script("list_updater")
    base = tmp_path / "app-router"
    monkeypatch.setattr(lu, "BASE_DIR", str(base))
    monkeypatch.setattr(lu, "DOMAINS_DIR", str(base / "domains"))
    monkeypatch.setattr(lu, "CIDRS_DIR", str(base / "cidrs"))
    monkeypatch.setattr(lu, "UNBOUND_DIR", str(base / "unbound.d"))
    monkeypatch.setattr(lu, "LEGACY_DNSMASQ_DIR", str(base / "dnsmasq.d"))
    monkeypatch.setattr(lu, "CONFIG_FILE", str(base / "config.json"))
    monkeypatch.setattr(lu, "STATE_FILE", str(base / "state.json"))
    monkeypatch.setattr(lu, "CATEGORIES_FILE", os.path.join(SCRIPTS, "app_categories.json"))
    monkeypatch.setattr(lu, "log", lambda *a, **k: None)
    monkeypatch.setattr(lu, "signal_dns_watcher", lambda: None)
    lu.ensure_dirs()
    return lu


@pytest.fixture
def dns_watcher(tmp_path, monkeypatch):
    dw = load_script("dns_watcher")
    monkeypatch.setattr(dw, "log", lambda *a, **k: None)
    monkeypatch.setattr(dw, "CIDRS_DIR", str(tmp_path / "cidrs"))
    monkeypatch.setattr(dw, "SEEN_FILE", str(tmp_path / "ip_seen.json"))
    (tmp_path / "cidrs").mkdir()
    return dw


sys.dont_write_bytecode = True
