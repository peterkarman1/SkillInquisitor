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


def test_load_active_fixture_specs(load_active_fixture_specs):
    specs = load_active_fixture_specs("deterministic")
    assert len(specs) >= 5
    assert all(spec.status == "active" for spec in specs)


def test_validate_fixture_expectation_schema(load_fixture_expectation):
    expectation = load_fixture_expectation("safe/simple-formatter")
    assert expectation.schema_version == 1
    assert expectation.match_mode == "exact"
    assert expectation.findings == []
