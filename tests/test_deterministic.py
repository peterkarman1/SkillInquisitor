from pathlib import Path

import yaml


def test_fixture_manifest_exists():
    manifest_path = Path("tests/fixtures/manifest.yaml")
    assert manifest_path.exists()


def test_manifest_has_five_active_safe_baselines():
    manifest = yaml.safe_load(Path("tests/fixtures/manifest.yaml").read_text(encoding="utf-8"))
    safe_fixtures = [
        entry
        for entry in manifest["fixtures"]
        if entry["status"] == "active" and "safe" in entry["tags"]
    ]
    assert len(safe_fixtures) >= 5


def test_template_fixture_is_indexed():
    manifest = yaml.safe_load(Path("tests/fixtures/manifest.yaml").read_text(encoding="utf-8"))
    assert any(entry["status"] == "template" for entry in manifest["fixtures"])
