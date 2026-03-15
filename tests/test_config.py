from pathlib import Path

from skillinquisitor.config import load_config
from skillinquisitor.detectors.rules.engine import build_rule_registry
from skillinquisitor.models import ScanConfig, ScanResult, SegmentType


def test_scan_config_has_default_format():
    config = ScanConfig()
    assert config.default_format == "text"


def test_scan_result_defaults_to_empty_findings():
    result = ScanResult(skills=[])
    assert result.findings == []


def test_segment_type_contains_original():
    assert SegmentType.ORIGINAL.value == "original"


def test_config_merges_global_then_project(tmp_path: Path):
    global_config = tmp_path / "global.yaml"
    global_config.write_text("default_format: json\n", encoding="utf-8")
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    config_dir = project_dir / ".skillinquisitor"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text("default_format: text\n", encoding="utf-8")

    config = load_config(
        project_root=project_dir,
        global_config_path=global_config,
        env={},
        cli_overrides={},
    )

    assert config.default_format == "text"


def test_env_overrides_project_config(tmp_path: Path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    config_dir = project_dir / ".skillinquisitor"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text("default_format: text\n", encoding="utf-8")

    config = load_config(
        project_root=project_dir,
        env={"SKILLINQUISITOR_DEFAULT_FORMAT": "json"},
        cli_overrides={},
    )

    assert config.default_format == "json"


def test_cli_overrides_env_config(tmp_path: Path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    config = load_config(
        project_root=project_dir,
        env={"SKILLINQUISITOR_DEFAULT_FORMAT": "json"},
        cli_overrides={"default_format": "text"},
    )

    assert config.default_format == "text"


def test_custom_regex_rules_register_as_segment_rules(tmp_path: Path):
    config = load_config(
        project_root=tmp_path,
        env={},
        cli_overrides={
            "custom_rules": [
                {
                    "id": "CUSTOM-1",
                    "pattern": "ignore previous instructions",
                    "severity": "high",
                    "category": "custom",
                    "message": "Custom detection",
                }
            ]
        },
    )

    registry = build_rule_registry(config)

    assert any(rule.rule_id == "CUSTOM-1" and rule.origin == "custom" for rule in registry.list_rules())
