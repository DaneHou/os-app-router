"""Render the configd config.json template the way OPNsense does and parse it."""
import json

import jinja2

from conftest import TEMPLATES


class Helpers:
    """Minimal stand-in for OPNsense's template helpers object."""

    def __init__(self, data):
        self.data = data

    def _get(self, path):
        cur = self.data
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    def empty(self, path):
        return self._get(path) in (None, "", "0")

    def exists(self, path):
        return self._get(path) is not None

    def toList(self, path):
        value = self._get(path)
        if value is None:
            return []
        return value if isinstance(value, list) else [value]


def render(approuter):
    data = {"OPNsense": {"Approuter": approuter}}
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES), trim_blocks=True)
    return env.get_template("approuter.conf").render(helpers=Helpers(data), **data)


def test_hostile_values_produce_valid_json():
    out = render({
        "general": {"enabled": "1", "tablePrefix": "approuter", "ipExpireHours": "12"},
        "lists": {"customDomains": None},
        "customCategories": {"category": {"slug": "work", "label": 'Work "VPN" \\ x', "domains": "a.com"}},
        "rules": {"rule": [
            {"@uuid": "u1", "enabled": "1", "description": 'say "hi"\\', "gateway": "WAN2",
             "probePattern": r"\d+|地区限制", "probeInterval": ""},
            {"@uuid": "u2", "enabled": "0"},
            {"@uuid": "u3", "enabled": "1", "probeInterval": "60"},
        ]},
    })
    config = json.loads(out)
    assert [r["uuid"] for r in config["rules"]] == ["u1", "u3"]
    assert config["rules"][0]["probe_pattern"] == r"\d+|地区限制"
    assert config["rules"][0]["probe_interval"] == 300
    assert config["rules"][1]["probe_interval"] == 60
    assert config["ip_expire_hours"] == 12
    assert config["custom_categories"][0]["label"] == 'Work "VPN" \\ x'


def test_disabled_renders_nothing():
    assert render({"general": {"enabled": "0"}}).strip() == ""
