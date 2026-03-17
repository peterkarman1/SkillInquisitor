"""Tests for the benchmark runner module."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from skillinquisitor.benchmark.dataset import ManifestEntry
from skillinquisitor.benchmark.metrics import BenchmarkMetrics, BenchmarkResult, FindingSummary
from skillinquisitor.benchmark.runner import (
    BenchmarkRun,
    BenchmarkRunConfig,
    _build_scan_config,
    _scan_single_skill,
    generate_run_id,
    load_run_summary,
    run_benchmark,
    save_results,
)
from skillinquisitor.models import (
    Category,
    Finding,
    ScanConfig,
    ScanResult,
    Severity,
    Skill,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manifest_yaml(entries: list[dict]) -> dict:
    """Build a minimal manifest dict for writing to YAML."""
    return {
        "schema_version": 1,
        "dataset_version": "1.0.0-test",
        "decision_policy": {"default_threshold": 60.0},
        "entries": entries,
    }


def _make_entry_dict(
    *,
    entry_id: str = "test-skill-001",
    path: str = "dataset/synthetic/malicious/test-skill-001",
    verdict: str = "MALICIOUS",
    attack_categories: list[str] | None = None,
    severity: str | None = "high",
    expected_rules: list[str] | None = None,
    tier: str = "smoke",
) -> dict:
    return {
        "id": entry_id,
        "path": path,
        "ground_truth": {
            "verdict": verdict,
            "attack_categories": attack_categories or ["prompt_injection"],
            "severity": severity,
            "expected_rules": expected_rules or ["D-11A"],
            "min_category_coverage": attack_categories or ["prompt_injection"],
            "notes": "test entry",
        },
        "metadata": {
            "tier": tier,
            "difficulty": "easy",
            "source_type": "synthetic",
            "tags": ["test"],
        },
    }


def _mock_scan_result() -> ScanResult:
    """Return a predictable ScanResult for mocking."""
    return ScanResult(
        skills=[],
        findings=[
            Finding(
                rule_id="D-11A",
                severity=Severity.HIGH,
                category=Category.PROMPT_INJECTION,
                message="test",
            )
        ],
        risk_score=25,
        verdict="HIGH RISK",
        layer_metadata={},
        total_timing=0.1,
    )


# ===========================================================================
# 1. generate_run_id
# ===========================================================================


class TestGenerateRunId:
    """Verify run ID format: YYYYMMDD-HHMMSS-<sha>[-dirty]."""

    def test_format_matches_pattern(self):
        run_id = generate_run_id()
        # Pattern: 8 digits, dash, 6 digits, dash, hex sha (or 'nogit'), optional '-dirty'
        pattern = r"^\d{8}-\d{6}-[a-f0-9]+(-dirty)?$|^\d{8}-\d{6}-nogit(-dirty)?$"
        assert re.match(pattern, run_id), f"Run ID {run_id!r} does not match expected format"

    def test_starts_with_date_time(self):
        run_id = generate_run_id()
        parts = run_id.split("-")
        # First part is YYYYMMDD (8 digits)
        assert len(parts[0]) == 8
        assert parts[0].isdigit()
        # Second part is HHMMSS (6 digits)
        assert len(parts[1]) == 6
        assert parts[1].isdigit()

    def test_contains_sha_or_nogit(self):
        run_id = generate_run_id()
        parts = run_id.split("-")
        # Third part is the short sha or 'nogit'
        sha_part = parts[2]
        assert sha_part == "nogit" or re.match(r"^[a-f0-9]+$", sha_part)

    @patch("skillinquisitor.benchmark.runner.subprocess.run")
    def test_nogit_fallback(self, mock_run):
        """Falls back to 'nogit' when git commands fail."""
        mock_run.side_effect = FileNotFoundError("git not found")
        run_id = generate_run_id()
        assert "nogit" in run_id

    @patch("skillinquisitor.benchmark.runner.subprocess.run")
    def test_dirty_suffix(self, mock_run):
        """Appends '-dirty' when working tree has changes."""
        def side_effect(cmd, **kwargs):
            class FakeResult:
                stdout = ""
                returncode = 0
            result = FakeResult()
            if "rev-parse" in cmd:
                result.stdout = "abc1234"
            elif "status" in cmd:
                result.stdout = " M some-file.py\n"
            return result

        mock_run.side_effect = side_effect
        run_id = generate_run_id()
        assert run_id.endswith("-dirty")
        assert "abc1234" in run_id

    @patch("skillinquisitor.benchmark.runner.subprocess.run")
    def test_clean_no_dirty_suffix(self, mock_run):
        """No '-dirty' suffix when working tree is clean."""
        def side_effect(cmd, **kwargs):
            class FakeResult:
                stdout = ""
                returncode = 0
            result = FakeResult()
            if "rev-parse" in cmd:
                result.stdout = "abc1234"
            elif "status" in cmd:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect
        run_id = generate_run_id()
        assert not run_id.endswith("-dirty")
        assert "abc1234" in run_id


# ===========================================================================
# 2. _scan_single_skill — successful scan
# ===========================================================================


class TestScanSingleSkillSuccess:
    """Mock resolve_input and run_pipeline, verify BenchmarkResult is built correctly."""

    @pytest.fixture()
    def entry(self) -> ManifestEntry:
        return ManifestEntry(**_make_entry_dict())

    @pytest.fixture()
    def dataset_root(self, tmp_path: Path) -> Path:
        skill_dir = tmp_path / "dataset" / "synthetic" / "malicious" / "test-skill-001"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# Test skill\n", encoding="utf-8")
        return tmp_path

    @pytest.mark.asyncio()
    async def test_builds_result_from_scan(self, entry: ManifestEntry, dataset_root: Path):
        scan_result = _mock_scan_result()

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
        ):
            result = await _scan_single_skill(
                entry, dataset_root, ScanConfig(), timeout=60.0,
            )

        assert result.skill_id == "test-skill-001"
        assert result.risk_score == 25
        assert result.verdict == "HIGH RISK"
        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "D-11A"
        assert result.findings[0].category == "prompt_injection"
        assert result.findings[0].severity == "high"
        assert result.findings[0].message == "test"
        assert "total_ms" in result.timing
        assert result.timing["total_ms"] > 0.0

    @pytest.mark.asyncio()
    async def test_ground_truth_fields_propagated(self, entry: ManifestEntry, dataset_root: Path):
        scan_result = _mock_scan_result()

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
        ):
            result = await _scan_single_skill(
                entry, dataset_root, ScanConfig(), timeout=60.0,
            )

        assert result.ground_truth_verdict == "MALICIOUS"
        assert result.ground_truth_categories == ["prompt_injection"]
        assert result.ground_truth_severity == "high"
        assert result.ground_truth_expected_rules == ["D-11A"]
        assert result.ground_truth_min_categories == ["prompt_injection"]
        assert result.ground_truth_notes == "test entry"

    @pytest.mark.asyncio()
    async def test_extracts_per_layer_timing(self, entry: ManifestEntry, dataset_root: Path):
        scan_result = ScanResult(
            skills=[],
            findings=[],
            risk_score=90,
            verdict="SAFE",
            layer_metadata={
                "deterministic": {"timing_ms": 10.5, "findings": 0},
                "ml": {"timing_ms": 25.3},
                "llm": {"timing_ms": 100.0},
            },
            total_timing=0.136,
        )

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
        ):
            result = await _scan_single_skill(
                entry, dataset_root, ScanConfig(), timeout=60.0,
            )

        assert result.timing["deterministic_ms"] == 10.5
        assert result.timing["ml_ms"] == 25.3
        assert result.timing["llm_ms"] == 100.0

    @pytest.mark.asyncio()
    async def test_handles_none_confidence(self, entry: ManifestEntry, dataset_root: Path):
        """Findings with confidence=None should default to 1.0 in the summary."""
        scan_result = ScanResult(
            skills=[],
            findings=[
                Finding(
                    rule_id="TEST-1",
                    severity=Severity.LOW,
                    category=Category.STRUCTURAL,
                    message="no confidence",
                    confidence=None,
                )
            ],
            risk_score=80,
            verdict="LOW RISK",
            layer_metadata={},
            total_timing=0.05,
        )

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
        ):
            result = await _scan_single_skill(
                entry, dataset_root, ScanConfig(), timeout=60.0,
            )

        assert result.findings[0].confidence == 1.0


# ===========================================================================
# 3. _scan_single_skill — error handling
# ===========================================================================


class TestScanSingleSkillError:
    """Verify errors are captured, not raised."""

    @pytest.fixture()
    def entry(self) -> ManifestEntry:
        return ManifestEntry(**_make_entry_dict())

    @pytest.fixture()
    def dataset_root(self, tmp_path: Path) -> Path:
        skill_dir = tmp_path / "dataset" / "synthetic" / "malicious" / "test-skill-001"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# Test\n", encoding="utf-8")
        return tmp_path

    @pytest.mark.asyncio()
    async def test_pipeline_error_captured(self, entry: ManifestEntry, dataset_root: Path):
        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(side_effect=RuntimeError("model download failed"))

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
        ):
            result = await _scan_single_skill(
                entry, dataset_root, ScanConfig(), timeout=60.0,
            )

        assert result.error is not None
        assert "RuntimeError" in result.error
        assert "model download failed" in result.error
        assert result.skill_id == "test-skill-001"
        # Ground truth fields still populated
        assert result.ground_truth_verdict == "MALICIOUS"

    @pytest.mark.asyncio()
    async def test_resolve_input_error_captured(self, entry: ManifestEntry, dataset_root: Path):
        mock_resolve = AsyncMock(side_effect=FileNotFoundError("skill not found"))

        with patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve):
            result = await _scan_single_skill(
                entry, dataset_root, ScanConfig(), timeout=60.0,
            )

        assert result.error is not None
        assert "FileNotFoundError" in result.error

    @pytest.mark.asyncio()
    async def test_timeout_captured(self, entry: ManifestEntry, dataset_root: Path):
        """A scan that exceeds the timeout produces an error result."""

        async def slow_pipeline(**kwargs):
            import asyncio
            await asyncio.sleep(10)
            return _mock_scan_result()

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", side_effect=slow_pipeline),
        ):
            result = await _scan_single_skill(
                entry, dataset_root, ScanConfig(), timeout=0.01,
            )

        assert result.error is not None
        # asyncio.TimeoutError or TimeoutError
        assert "Timeout" in result.error or "timeout" in result.error.lower()

    @pytest.mark.asyncio()
    async def test_missing_skill_path_captured(self, tmp_path: Path):
        """When the skill path does not exist on disk, error is captured."""
        entry = ManifestEntry(**_make_entry_dict(
            path="nonexistent/path/skill",
        ))
        result = await _scan_single_skill(
            entry, tmp_path, ScanConfig(), timeout=60.0,
        )
        assert result.error is not None
        assert "FileNotFoundError" in result.error


# ===========================================================================
# 4. run_benchmark — full integration with mocked pipeline
# ===========================================================================


class TestRunBenchmark:
    """Mock the pipeline to avoid needing ML/LLM models."""

    @pytest.fixture()
    def manifest_dir(self, tmp_path: Path) -> Path:
        """Create a manifest file and dataset directories."""
        manifest_data = _make_manifest_yaml([
            _make_entry_dict(
                entry_id="safe-001",
                path="dataset/safe/safe-001",
                verdict="SAFE",
                attack_categories=[],
                severity=None,
                expected_rules=[],
                tier="smoke",
            ),
            _make_entry_dict(
                entry_id="mal-001",
                path="dataset/malicious/mal-001",
                verdict="MALICIOUS",
                attack_categories=["prompt_injection"],
                severity="high",
                expected_rules=["D-11A"],
                tier="smoke",
            ),
            _make_entry_dict(
                entry_id="ambig-001",
                path="dataset/ambiguous/ambig-001",
                verdict="AMBIGUOUS",
                attack_categories=["data_exfiltration"],
                severity="medium",
                tier="smoke",
            ),
        ])

        manifest_path = tmp_path / "manifest.yaml"
        manifest_path.write_text(yaml.dump(manifest_data), encoding="utf-8")

        # Create dataset directories with SKILL.md files
        for sub in ["dataset/safe/safe-001", "dataset/malicious/mal-001", "dataset/ambiguous/ambig-001"]:
            d = tmp_path / sub
            d.mkdir(parents=True)
            (d / "SKILL.md").write_text("# Test\n", encoding="utf-8")

        return tmp_path

    @pytest.mark.asyncio()
    async def test_run_benchmark_computes_metrics(self, manifest_dir: Path):
        scan_result = _mock_scan_result()

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        config = BenchmarkRunConfig(
            tier="smoke",
            layers=["deterministic"],
            concurrency=2,
            timeout=30.0,
            threshold=60.0,
            manifest_path=manifest_dir / "manifest.yaml",
            dataset_root=manifest_dir,
        )

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
            patch("skillinquisitor.benchmark.runner._build_scan_config", return_value=ScanConfig()),
        ):
            run = await run_benchmark(config)

        # 3 entries, all tier=smoke
        assert len(run.results) == 3
        assert run.metrics.total_skills == 3
        assert run.dataset_version == "1.0.0-test"
        assert run.wall_clock_seconds > 0.0
        assert run.timestamp != ""
        assert run.run_id != ""

    @pytest.mark.asyncio()
    async def test_results_have_correct_skill_ids(self, manifest_dir: Path):
        scan_result = _mock_scan_result()

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        config = BenchmarkRunConfig(
            tier="smoke",
            layers=["deterministic"],
            manifest_path=manifest_dir / "manifest.yaml",
            dataset_root=manifest_dir,
        )

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
            patch("skillinquisitor.benchmark.runner._build_scan_config", return_value=ScanConfig()),
        ):
            run = await run_benchmark(config)

        skill_ids = {r.skill_id for r in run.results}
        assert skill_ids == {"safe-001", "mal-001", "ambig-001"}

    @pytest.mark.asyncio()
    async def test_metrics_reflect_ground_truth(self, manifest_dir: Path):
        """Verify classification: risk_score=25 < threshold=60 means flagged.
        SAFE+flagged=FP, MALICIOUS+flagged=TP, AMBIGUOUS=EXCLUDED."""
        scan_result = _mock_scan_result()  # risk_score=25

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        config = BenchmarkRunConfig(
            tier="smoke",
            layers=["deterministic"],
            threshold=60.0,
            manifest_path=manifest_dir / "manifest.yaml",
            dataset_root=manifest_dir,
        )

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
            patch("skillinquisitor.benchmark.runner._build_scan_config", return_value=ScanConfig()),
        ):
            run = await run_benchmark(config)

        # Build a lookup by skill_id
        by_id = {r.skill_id: r for r in run.results}

        # risk_score=25 < 60 => flagged
        # MALICIOUS + flagged => TP
        assert by_id["mal-001"].binary_outcome == "TP"
        # SAFE + flagged => FP
        assert by_id["safe-001"].binary_outcome == "FP"
        # AMBIGUOUS => EXCLUDED
        assert by_id["ambig-001"].binary_outcome == "EXCLUDED"

        # Confusion matrix
        assert run.metrics.confusion_matrix.tp == 1
        assert run.metrics.confusion_matrix.fp == 1
        assert run.metrics.confusion_matrix.tn == 0
        assert run.metrics.confusion_matrix.fn == 0
        assert run.metrics.ambiguous_count == 1

    @pytest.mark.asyncio()
    async def test_pipeline_called_for_each_entry(self, manifest_dir: Path):
        scan_result = _mock_scan_result()

        mock_resolve = AsyncMock(return_value=[Skill(path="test")])
        mock_pipeline = AsyncMock(return_value=scan_result)

        config = BenchmarkRunConfig(
            tier="smoke",
            layers=["deterministic"],
            manifest_path=manifest_dir / "manifest.yaml",
            dataset_root=manifest_dir,
        )

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", mock_resolve),
            patch("skillinquisitor.benchmark.runner.run_pipeline", mock_pipeline),
            patch("skillinquisitor.benchmark.runner._build_scan_config", return_value=ScanConfig()),
        ):
            run = await run_benchmark(config)

        assert mock_pipeline.call_count == 3
        assert mock_resolve.call_count == 3

    @pytest.mark.asyncio()
    async def test_run_benchmark_preserves_manifest_order_with_concurrency(self, manifest_dir: Path):
        scan_result = _mock_scan_result()
        started: list[str] = []
        max_inflight = 0
        inflight = 0

        async def fake_pipeline(*, skills, config, runtime=None):
            nonlocal inflight, max_inflight
            skill_id = skills[0].path
            started.append(skill_id)
            inflight += 1
            max_inflight = max(max_inflight, inflight)
            if skill_id.endswith("safe-001"):
                await asyncio.sleep(0.05)
            else:
                await asyncio.sleep(0.01)
            inflight -= 1
            return scan_result

        async def fake_resolve_input(target: str):
            return [Skill(path=str(target))]

        config = BenchmarkRunConfig(
            tier="smoke",
            layers=["deterministic"],
            concurrency=2,
            manifest_path=manifest_dir / "manifest.yaml",
            dataset_root=manifest_dir,
        )

        with (
            patch("skillinquisitor.benchmark.runner.resolve_input", fake_resolve_input),
            patch("skillinquisitor.benchmark.runner.run_pipeline", fake_pipeline),
            patch("skillinquisitor.benchmark.runner._build_scan_config", return_value=ScanConfig()),
        ):
            run = await run_benchmark(config)

        assert max_inflight >= 2
        assert [result.skill_id for result in run.results] == ["safe-001", "mal-001", "ambig-001"]


# ===========================================================================
# 5. save_results and load_run_summary
# ===========================================================================


class TestSaveAndLoad:
    """Test persistence to disk."""

    def _make_run(self) -> BenchmarkRun:
        return BenchmarkRun(
            run_id="20260315-120000-abc1234",
            config=BenchmarkRunConfig(),
            results=[
                BenchmarkResult(
                    skill_id="test-001",
                    ground_truth_verdict="MALICIOUS",
                    ground_truth_categories=["prompt_injection"],
                    ground_truth_severity="high",
                    risk_score=25,
                    verdict="HIGH RISK",
                    findings=[
                        FindingSummary(
                            rule_id="D-11A",
                            category="prompt_injection",
                            severity="high",
                            confidence=0.95,
                            message="test finding",
                        )
                    ],
                    timing={"total_ms": 123.4},
                ),
                BenchmarkResult(
                    skill_id="test-002",
                    ground_truth_verdict="SAFE",
                    risk_score=90,
                    verdict="SAFE",
                    findings=[],
                    timing={"total_ms": 50.0},
                ),
            ],
            metrics=BenchmarkMetrics(total_skills=2, error_count=0),
            git_sha="abc1234567890",
            dirty=False,
            timestamp="2026-03-15T12:00:00+00:00",
            dataset_version="1.0.0-test",
            wall_clock_seconds=1.5,
        )

    def test_creates_output_directory(self, tmp_path: Path):
        output_dir = tmp_path / "results" / "run-1"
        run = self._make_run()
        save_results(run, output_dir)
        assert output_dir.is_dir()

    def test_writes_results_jsonl(self, tmp_path: Path):
        output_dir = tmp_path / "output"
        run = self._make_run()
        save_results(run, output_dir)

        jsonl_path = output_dir / "results.jsonl"
        assert jsonl_path.exists()
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2

        # Parse each line as valid JSON
        first = json.loads(lines[0])
        assert first["skill_id"] == "test-001"
        assert first["risk_score"] == 25
        assert len(first["findings"]) == 1
        assert first["findings"][0]["rule_id"] == "D-11A"

        second = json.loads(lines[1])
        assert second["skill_id"] == "test-002"
        assert second["risk_score"] == 90

    def test_writes_summary_json(self, tmp_path: Path):
        output_dir = tmp_path / "output"
        run = self._make_run()
        save_results(run, output_dir)

        summary_path = output_dir / "summary.json"
        assert summary_path.exists()
        summary = json.loads(summary_path.read_text(encoding="utf-8"))

        assert summary["run_id"] == "20260315-120000-abc1234"
        assert summary["git_sha"] == "abc1234567890"
        assert summary["dirty"] is False
        assert summary["timestamp"] == "2026-03-15T12:00:00+00:00"
        assert summary["dataset_version"] == "1.0.0-test"
        assert summary["total_skills"] == 2
        assert summary["error_count"] == 0
        assert summary["wall_clock_seconds"] == 1.5
        assert "config" in summary
        assert "metrics" in summary
        assert "runtime" in summary

    def test_summary_config_is_serializable(self, tmp_path: Path):
        output_dir = tmp_path / "output"
        run = self._make_run()
        save_results(run, output_dir)

        summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
        config = summary["config"]
        assert config["tier"] == "standard"
        assert isinstance(config["layers"], list)
        assert "deterministic" in config["layers"]

    def test_summary_includes_runtime_telemetry(self, tmp_path: Path):
        output_dir = tmp_path / "output"
        run = self._make_run().model_copy(
            update={
                "runtime": {
                    "scan_workers": 2,
                    "ml_lifecycle": "command",
                    "llm_lifecycle": "command",
                }
            }
        )
        save_results(run, output_dir)

        summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
        assert summary["runtime"]["scan_workers"] == 2
        assert summary["runtime"]["llm_lifecycle"] == "command"

    def test_load_run_summary(self, tmp_path: Path):
        output_dir = tmp_path / "output"
        run = self._make_run()
        save_results(run, output_dir)

        loaded = load_run_summary(output_dir / "summary.json")
        assert loaded["run_id"] == "20260315-120000-abc1234"
        assert loaded["total_skills"] == 2

    def test_load_run_summary_roundtrip(self, tmp_path: Path):
        """Saved summary can be loaded and has the same structure."""
        output_dir = tmp_path / "output"
        run = self._make_run()
        save_results(run, output_dir)

        loaded = load_run_summary(output_dir / "summary.json")
        assert loaded["metrics"]["confusion_matrix"]["tp"] == 0
        assert loaded["metrics"]["total_skills"] == 2
        assert loaded["config"]["manifest_path"] is not None

    def test_overwrite_existing(self, tmp_path: Path):
        """Writing twice to the same directory succeeds."""
        output_dir = tmp_path / "output"
        run = self._make_run()
        save_results(run, output_dir)
        save_results(run, output_dir)
        assert (output_dir / "summary.json").exists()
        assert (output_dir / "results.jsonl").exists()


# ===========================================================================
# 6. BenchmarkRunConfig defaults
# ===========================================================================


class TestBenchmarkRunConfigDefaults:
    """Verify default values for BenchmarkRunConfig."""

    def test_default_tier(self):
        config = BenchmarkRunConfig()
        assert config.tier == "standard"

    def test_default_layers(self):
        config = BenchmarkRunConfig()
        assert config.layers == ["deterministic", "ml", "llm"]

    def test_default_timeout(self):
        config = BenchmarkRunConfig()
        assert config.timeout == 120.0

    def test_default_concurrency(self):
        config = BenchmarkRunConfig()
        assert config.concurrency == 1

    def test_default_threshold(self):
        config = BenchmarkRunConfig()
        assert config.threshold == 60.0

    def test_default_manifest_path(self):
        config = BenchmarkRunConfig()
        assert config.manifest_path == Path("benchmark/manifest.yaml")

    def test_default_dataset_root(self):
        config = BenchmarkRunConfig()
        assert config.dataset_root == Path("benchmark/dataset")

    def test_default_output_dir_is_none(self):
        config = BenchmarkRunConfig()
        assert config.output_dir is None

    def test_default_baseline_path_is_none(self):
        config = BenchmarkRunConfig()
        assert config.baseline_path is None

    def test_custom_values(self):
        config = BenchmarkRunConfig(
            tier="full",
            layers=["deterministic"],
            concurrency=2,
            timeout=180.0,
            threshold=40.0,
            llm_group="balanced",
        )
        assert config.tier == "full"
        assert config.layers == ["deterministic"]
        assert config.concurrency == 2
        assert config.timeout == 180.0
        assert config.threshold == 40.0
        assert config.llm_group == "balanced"


class TestBuildScanConfig:
    def test_honors_process_environment_and_llm_group_override(self, monkeypatch):
        seen: dict[str, object] = {}

        def fake_load_config(*, project_root, global_config_path, env, cli_overrides):
            seen["project_root"] = project_root
            seen["global_config_path"] = global_config_path
            seen["env"] = env
            seen["cli_overrides"] = cli_overrides
            return ScanConfig()

        monkeypatch.setattr("skillinquisitor.benchmark.runner.load_config", fake_load_config)
        monkeypatch.setenv("SKILLINQUISITOR_LAYERS__LLM__REPOMIX__COMMAND", "npx")

        config = BenchmarkRunConfig(
            layers=["deterministic", "llm"],
            concurrency=1,
            llm_group="balanced",
        )
        _build_scan_config(config)

        assert isinstance(seen["env"], dict)
        assert seen["env"]["SKILLINQUISITOR_LAYERS__LLM__REPOMIX__COMMAND"] == "npx"
        assert seen["cli_overrides"]["layers"]["llm"]["default_group"] == "balanced"
        assert seen["cli_overrides"]["layers"]["llm"]["auto_select_group"] is False

    def test_raises_runtime_slots_for_parallel_benchmark_on_capable_hardware(self, monkeypatch):
        monkeypatch.setattr(
            "skillinquisitor.benchmark.runner.load_config",
            lambda **kwargs: ScanConfig.model_validate(kwargs["cli_overrides"]),
        )
        monkeypatch.setattr(
            "skillinquisitor.benchmark.runner.detect_hardware_profile",
            lambda *args, **kwargs: type("Hardware", (), {"accelerator": "mps", "gpu_vram_gb": 32.0})(),
        )
        monkeypatch.setattr(
            "skillinquisitor.benchmark.runner.resolve_group_models",
            lambda *args, **kwargs: ("balanced", [object(), object(), object()]),
        )

        config = BenchmarkRunConfig(
            layers=["deterministic", "ml", "llm"],
            concurrency=4,
            llm_group="balanced",
        )

        scan_config = _build_scan_config(config)

        assert scan_config.runtime.scan_workers == 4
        assert scan_config.runtime.ml_lifecycle == "command"
        assert scan_config.runtime.ml_global_slots == 4
        assert scan_config.runtime.llm_lifecycle == "command"
        assert scan_config.runtime.llm_global_slots == 4
        assert scan_config.runtime.llm_server_parallel_requests == 4


# ===========================================================================
# 7. BenchmarkRun model
# ===========================================================================


class TestBenchmarkRunModel:
    """Verify BenchmarkRun construction and defaults."""

    def test_minimal_construction(self):
        run = BenchmarkRun(
            run_id="test-run",
            config=BenchmarkRunConfig(),
        )
        assert run.run_id == "test-run"
        assert run.results == []
        assert run.git_sha == ""
        assert run.dirty is False
        assert run.timestamp == ""
        assert run.dataset_version == ""
        assert run.wall_clock_seconds == 0.0
        assert run.runtime == {}

    def test_metrics_default(self):
        run = BenchmarkRun(
            run_id="test-run",
            config=BenchmarkRunConfig(),
        )
        assert run.metrics.total_skills == 0
        assert run.metrics.confusion_matrix.total == 0
