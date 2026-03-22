from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from skillinquisitor.benchmark.dataset import (
    BenchmarkManifest,
    EntryMetadata,
    FalsePositiveRisk,
    GroundTruth,
    ManifestEntry,
    filter_entries,
    load_manifest,
    resolve_skill_path,
)


def _make_entry(
    id: str,
    *,
    verdict: str = "SAFE",
    tier: str = "standard",
    tags: list[str] | None = None,
) -> dict:
    return {
        "id": id,
        "path": f"dataset/{id}",
        "ground_truth": {"verdict": verdict},
        "metadata": {
            "tier": tier,
            "tags": tags or [],
        },
    }


@pytest.fixture()
def three_entry_manifest(tmp_path: Path) -> tuple[Path, BenchmarkManifest]:
    """Create a manifest with 3 entries: safe/smoke, malicious/standard, ambiguous/full."""
    data = {
        "schema_version": 1,
        "dataset_version": "1.0.0",
        "decision_policy": {"default_threshold": 60.0},
        "entries": [
            {
                "id": "safe-smoke",
                "path": "dataset/synthetic/safe/test-safe-001",
                "ground_truth": {
                    "verdict": "SAFE",
                    "attack_categories": [],
                    "severity": None,
                    "expected_rules": [],
                    "min_category_coverage": [],
                    "false_positive_risk": [
                        {"category": "structural", "reason": "Minimal safe skill"},
                    ],
                    "notes": "Baseline safe skill",
                },
                "metadata": {
                    "tier": "smoke",
                    "difficulty": "easy",
                    "source_type": "synthetic",
                    "tags": ["safe", "baseline"],
                },
            },
            {
                "id": "malicious-standard",
                "path": "dataset/synthetic/malicious/test-skill-001",
                "ground_truth": {
                    "verdict": "MALICIOUS",
                    "attack_categories": ["prompt_injection"],
                    "severity": "high",
                    "expected_rules": ["PROMPT_INJECTION_BASIC"],
                    "min_category_coverage": ["prompt_injection"],
                    "false_positive_risk": [],
                    "notes": "Basic prompt injection",
                },
                "metadata": {
                    "tier": "standard",
                    "difficulty": "easy",
                    "source_type": "synthetic",
                    "tags": ["malicious", "prompt_injection"],
                },
                "containment": {
                    "sandboxed": True,
                    "defanged_urls": True,
                    "defanged_payloads": True,
                    "original_threat": "prompt injection",
                    "containment_notes": "Plain-text injection",
                },
            },
            {
                "id": "ambiguous-full",
                "path": "dataset/synthetic/ambiguous/test-ambig-001",
                "ground_truth": {
                    "verdict": "AMBIGUOUS",
                    "attack_categories": ["data_exfiltration"],
                    "severity": "medium",
                    "expected_rules": [],
                    "min_category_coverage": ["data_exfiltration"],
                    "false_positive_risk": [
                        {"category": "data_exfiltration", "reason": "Could be legit analytics"},
                    ],
                    "notes": "Reads env vars and sends data",
                },
                "metadata": {
                    "tier": "full",
                    "difficulty": "medium",
                    "source_type": "synthetic",
                    "tags": ["ambiguous", "data_exfiltration"],
                },
                "provenance": {
                    "source_url": "",
                    "source_ref": "",
                    "fetch_date": "",
                    "license": "",
                    "upstream_status": "unknown",
                },
            },
        ],
    }
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    manifest = load_manifest(manifest_path)
    return manifest_path, manifest


# -- Loading tests --


class TestLoadManifest:
    def test_load_valid_manifest_all_fields(self, three_entry_manifest: tuple[Path, BenchmarkManifest]):
        _, manifest = three_entry_manifest

        assert manifest.schema_version == 1
        assert manifest.dataset_version == "1.0.0"
        assert manifest.decision_policy.default_threshold == 60.0
        assert len(manifest.entries) == 3

        safe = manifest.entries[0]
        assert safe.id == "safe-smoke"
        assert safe.ground_truth.verdict == "SAFE"
        assert safe.ground_truth.attack_categories == []
        assert safe.ground_truth.severity is None
        assert safe.ground_truth.false_positive_risk == [
            FalsePositiveRisk(category="structural", reason="Minimal safe skill"),
        ]
        assert safe.metadata.tier == "smoke"
        assert safe.metadata.difficulty == "easy"
        assert safe.metadata.source_type == "synthetic"
        assert safe.metadata.tags == ["safe", "baseline"]
        assert safe.provenance is None
        assert safe.containment is None

        malicious = manifest.entries[1]
        assert malicious.id == "malicious-standard"
        assert malicious.ground_truth.verdict == "MALICIOUS"
        assert malicious.ground_truth.attack_categories == ["prompt_injection"]
        assert malicious.ground_truth.severity == "high"
        assert malicious.ground_truth.expected_rules == ["PROMPT_INJECTION_BASIC"]
        assert malicious.containment is not None
        assert malicious.containment.sandboxed is True
        assert malicious.containment.original_threat == "prompt injection"

        ambiguous = manifest.entries[2]
        assert ambiguous.id == "ambiguous-full"
        assert ambiguous.ground_truth.verdict == "AMBIGUOUS"
        assert ambiguous.provenance is not None
        assert ambiguous.provenance.upstream_status == "unknown"

    def test_load_minimal_defaults(self, tmp_path: Path):
        data = {
            "entries": [
                {
                    "id": "minimal-entry",
                    "path": "dataset/minimal",
                    "ground_truth": {"verdict": "SAFE"},
                },
            ],
        }
        manifest_path = tmp_path / "minimal.yaml"
        manifest_path.write_text(yaml.dump(data), encoding="utf-8")

        manifest = load_manifest(manifest_path)

        assert manifest.schema_version == 1
        assert manifest.dataset_version == "1.0.0"
        assert manifest.decision_policy.default_threshold == 60.0

        entry = manifest.entries[0]
        assert entry.metadata.tier == "standard"
        assert entry.metadata.difficulty == "medium"
        assert entry.metadata.source_type == "synthetic"
        assert entry.metadata.tags == []
        assert entry.ground_truth.attack_categories == []
        assert entry.ground_truth.expected_rules == []
        assert entry.ground_truth.notes == ""
        assert entry.provenance is None
        assert entry.containment is None

    def test_load_invalid_verdict_raises_value_error(self, tmp_path: Path):
        data = {
            "entries": [
                {
                    "id": "bad-verdict",
                    "path": "dataset/bad",
                    "ground_truth": {"verdict": "MAYBE_BAD"},
                },
            ],
        }
        manifest_path = tmp_path / "bad.yaml"
        manifest_path.write_text(yaml.dump(data), encoding="utf-8")

        with pytest.raises(ValueError, match="Invalid benchmark manifest"):
            load_manifest(manifest_path)

    def test_load_non_mapping_raises_value_error(self, tmp_path: Path):
        manifest_path = tmp_path / "list.yaml"
        manifest_path.write_text("- item1\n- item2\n", encoding="utf-8")

        with pytest.raises(ValueError, match="Expected a YAML mapping"):
            load_manifest(manifest_path)


# -- Filtering tests --


class TestFilterEntries:
    def test_smoke_tier_returns_only_smoke(self, three_entry_manifest: tuple[Path, BenchmarkManifest]):
        _, manifest = three_entry_manifest
        results = filter_entries(manifest, tier="smoke")
        assert len(results) == 1
        assert results[0].id == "safe-smoke"

    def test_standard_tier_returns_smoke_and_standard(self, three_entry_manifest: tuple[Path, BenchmarkManifest]):
        _, manifest = three_entry_manifest
        results = filter_entries(manifest, tier="standard")
        assert len(results) == 2
        ids = {e.id for e in results}
        assert ids == {"safe-smoke", "malicious-standard"}

    def test_full_tier_returns_all(self, three_entry_manifest: tuple[Path, BenchmarkManifest]):
        _, manifest = three_entry_manifest
        results = filter_entries(manifest, tier="full")
        assert len(results) == 3

    def test_tag_filter_requires_all_tags(self, three_entry_manifest: tuple[Path, BenchmarkManifest]):
        _, manifest = three_entry_manifest

        results = filter_entries(manifest, tier="full", tags=["malicious", "prompt_injection"])
        assert len(results) == 1
        assert results[0].id == "malicious-standard"

    def test_tag_filter_no_match_returns_empty(self, three_entry_manifest: tuple[Path, BenchmarkManifest]):
        _, manifest = three_entry_manifest

        results = filter_entries(manifest, tier="full", tags=["nonexistent_tag"])
        assert len(results) == 0

    def test_tag_filter_with_tier_restriction(self, three_entry_manifest: tuple[Path, BenchmarkManifest]):
        _, manifest = three_entry_manifest

        # data_exfiltration tag is only on the full-tier entry
        results = filter_entries(manifest, tier="standard", tags=["data_exfiltration"])
        assert len(results) == 0


class TestRealWorldBenchmarkManifest:
    def test_benchmark_manifest_contains_real_world_safe_and_malicious_entries(self):
        manifest = load_manifest(Path("benchmark/manifest.yaml"))

        source_types = {entry.metadata.source_type for entry in manifest.entries}
        verdicts = {entry.ground_truth.verdict for entry in manifest.entries}
        malicious_entries = [entry for entry in manifest.entries if entry.ground_truth.verdict == "MALICIOUS"]
        safe_entries = [entry for entry in manifest.entries if entry.ground_truth.verdict == "SAFE"]

        assert source_types == {"github", "huggingface_mirror"}
        assert verdicts == {"SAFE", "MALICIOUS"}
        assert len(safe_entries) == 298
        assert len(malicious_entries) == 124
        assert len(manifest.entries) == 422

    def test_real_world_smoke_tier_contains_safe_and_malicious_entries(self):
        manifest = load_manifest(Path("benchmark/manifest.yaml"))

        smoke_entries = filter_entries(manifest, tier="smoke")
        verdicts = {entry.ground_truth.verdict for entry in smoke_entries}
        malicious_count = sum(1 for entry in smoke_entries if entry.ground_truth.verdict == "MALICIOUS")
        safe_count = sum(1 for entry in smoke_entries if entry.ground_truth.verdict == "SAFE")

        assert verdicts == {"SAFE", "MALICIOUS"}
        assert safe_count == 20
        assert malicious_count == 20
        assert len(smoke_entries) == 40

    def test_real_world_malicious_entries_have_openclaw_provenance_tags(self):
        manifest = load_manifest(Path("benchmark/manifest.yaml"))

        malicious_entries = [entry for entry in manifest.entries if entry.ground_truth.verdict == "MALICIOUS"]

        assert malicious_entries
        for entry in malicious_entries:
            assert "malicious" in entry.metadata.tags
            assert "real-world" in entry.metadata.tags
            assert "openclaw" in entry.metadata.tags
            assert entry.provenance is not None
            assert entry.provenance.source_url
            assert entry.provenance.source_ref
            assert "ClawHub" in entry.ground_truth.notes or "OpenClaw" in entry.ground_truth.notes

    def test_real_world_safe_entries_include_hf_benign_openclaw_samples(self):
        manifest = load_manifest(Path("benchmark/manifest.yaml"))

        safe_entries = [
            entry
            for entry in manifest.entries
            if entry.ground_truth.verdict == "SAFE" and entry.metadata.source_type == "huggingface_mirror"
        ]

        assert safe_entries
        for entry in safe_entries:
            assert "safe" in entry.metadata.tags
            assert "openclaw" in entry.metadata.tags
            assert entry.provenance is not None
            assert entry.provenance.source_url
            assert entry.provenance.source_ref


# -- Path resolution tests --


class TestResolveSkillPath:
    def test_valid_path_resolves(self, tmp_path: Path):
        skill_dir = tmp_path / "dataset" / "skill-001"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# test", encoding="utf-8")

        entry = ManifestEntry(
            id="skill-001",
            path="dataset/skill-001",
            ground_truth=GroundTruth(verdict="SAFE"),
        )

        resolved = resolve_skill_path(entry, tmp_path)
        assert resolved == skill_dir
        assert resolved.exists()

    def test_missing_path_raises_file_not_found(self, tmp_path: Path):
        entry = ManifestEntry(
            id="missing",
            path="dataset/does-not-exist",
            ground_truth=GroundTruth(verdict="SAFE"),
        )

        with pytest.raises(FileNotFoundError, match="Skill path does not exist"):
            resolve_skill_path(entry, tmp_path)

    def test_resolve_against_real_benchmark_dataset(self):
        """Test resolution against the actual benchmark dataset in the repo."""
        repo_root = Path(__file__).resolve().parent.parent
        dataset_root = repo_root / "benchmark" / "dataset"
        manifest = load_manifest(repo_root / "benchmark" / "manifest.yaml")

        for entry in manifest.entries:
            resolved = resolve_skill_path(entry, dataset_root)
            assert resolved.exists(), f"Entry {entry.id} path does not exist: {resolved}"
