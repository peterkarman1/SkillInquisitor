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


def test_load_config_exposes_epic4_deterministic_bounds(tmp_path: Path):
    project_root = tmp_path

    config = load_config(project_root=project_root, env={}, cli_overrides={})

    assert config.layers.deterministic.max_derived_depth >= 1
    assert config.layers.deterministic.max_derived_segments_per_artifact >= 1
    assert config.layers.deterministic.max_decode_candidates_per_segment >= 1


def test_load_config_includes_default_behavior_chains(tmp_path: Path):
    config = load_config(project_root=tmp_path, env={}, cli_overrides={})

    chain_names = {chain.name for chain in config.chains}

    assert "Data Exfiltration" in chain_names
    assert "Credential Theft" in chain_names
    assert "Cloud Metadata SSRF" in chain_names


def test_load_config_supports_frontmatter_url_and_typosquatting_policy(tmp_path: Path):
    config = load_config(project_root=tmp_path, env={}, cli_overrides={})

    assert "description" in config.frontmatter_policy.allowed_fields
    assert config.url_policy.allow_hosts
    assert config.typosquatting.protected_packages.python


def test_trusted_urls_merge_into_url_policy_allow_hosts(tmp_path: Path):
    config = load_config(
        project_root=tmp_path,
        env={},
        cli_overrides={"trusted_urls": ["example.com"]},
    )

    assert "example.com" in config.url_policy.allow_hosts


def test_scan_config_exposes_epic9_ml_runtime_controls():
    config = ScanConfig()

    assert config.layers.ml.auto_download is True
    assert config.layers.ml.max_concurrency == 1
    assert config.layers.ml.max_batch_size >= 1
    assert config.layers.ml.chunk_max_chars >= 256
    assert config.layers.ml.chunk_overlap_lines >= 0


def test_scan_config_default_ml_models():
    config = ScanConfig()

    model_ids = {model.id for model in config.layers.ml.models}

    assert "protectai/deberta-v3-base-prompt-injection-v2" in model_ids
    assert "patronus-studio/wolf-defender-prompt-injection" in model_ids
    assert "madhurjindal/Jailbreak-Detector" in model_ids
    assert len(model_ids) == 3
