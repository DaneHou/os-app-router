"""Run tests/php/test_firewall.php (firewall hook rule generation) under PHP.

Uses `php` from PATH; without it, a local docker image (APPROUTER_PHP_IMAGE,
default php:8.4-cli) if one is already present. Skips otherwise.
"""
import json
import os
import shutil
import subprocess

import pytest

from conftest import ROOT

SCRIPT = os.path.join("tests", "php", "test_firewall.php")
CASES = [
    "parse_sources_kinds",
    "parse_sources_rejects_garbage",
    "parse_sources_without_alias_model",
    "rule_ip_only_unchanged",
    "rule_alias_only",
    "rule_mixed_ip_and_aliases",
    "rule_invalid_sources_skipped_not_any",
    "rule_any",
    "category_tables_stay_fileless",
    "smart_gateway_rules_use_alias_sources",
    "orphan_client_files_removed",
]


def php_command():
    if shutil.which("php"):
        return ["php"]
    image = os.environ.get("APPROUTER_PHP_IMAGE", "php:8.4-cli")
    if shutil.which("docker"):
        probe = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
        if probe.returncode == 0:
            return ["docker", "run", "--rm", "-v", f"{ROOT}:{ROOT}:ro", "-w", ROOT, image, "php"]
    return None


@pytest.fixture(scope="module")
def php_results():
    cmd = php_command()
    if cmd is None:
        pytest.skip("php not available (install php-cli or pull php:8.4-cli)")
    proc = subprocess.run(cmd + [SCRIPT], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("case", CASES)
def test_firewall_hook(php_results, case):
    assert case in php_results, f"case {case} did not run"
    assert php_results[case] == []


def test_all_php_cases_listed(php_results):
    assert sorted(php_results) == sorted(CASES)
