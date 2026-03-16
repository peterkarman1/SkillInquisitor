"""Benchmark runner — orchestrates scanning skills and collecting results."""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from skillinquisitor.benchmark.dataset import (
    BenchmarkManifest,
    ManifestEntry,
    filter_entries,
    load_manifest,
    resolve_skill_path,
)
from skillinquisitor.benchmark.metrics import (
    BenchmarkMetrics,
    BenchmarkResult,
    FindingSummary,
    compute_all_metrics,
)
from skillinquisitor.config import load_config
from skillinquisitor.input import resolve_input
from skillinquisitor.pipeline import run_pipeline


class BenchmarkRunConfig(BaseModel):
    """Configuration for a benchmark run."""
    tier: str = "standard"
    layers: list[str] = Field(default_factory=lambda: ["deterministic", "ml", "llm"])
    timeout: float = 120.0
    threshold: float = 60.0
    manifest_path: Path = Path("benchmark/manifest.yaml")
    dataset_root: Path = Path("benchmark/dataset")
    output_dir: Path | None = None  # Auto-generated if None
    baseline_path: Path | None = None


class BenchmarkRun(BaseModel):
    """Complete results of a benchmark run."""
    run_id: str
    config: BenchmarkRunConfig
    results: list[BenchmarkResult] = Field(default_factory=list)
    metrics: BenchmarkMetrics = Field(default_factory=BenchmarkMetrics)
    git_sha: str = ""
    dirty: bool = False
    timestamp: str = ""
    dataset_version: str = ""
    wall_clock_seconds: float = 0.0


def generate_run_id() -> str:
    """Generate a run ID: YYYYMMDD-HHMMSS-<short-git-sha>.

    Falls back to 'nogit' if git is not available.
    Appends '-dirty' if the working tree has uncommitted changes.
    """
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d-%H%M%S")
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip() or "nogit"
    except (subprocess.SubprocessError, FileNotFoundError):
        sha = "nogit"

    dirty = False
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=5,
        )
        dirty = bool(result.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    run_id = f"{ts}-{sha}"
    if dirty:
        run_id += "-dirty"
    return run_id


def _get_git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def _is_git_dirty() -> bool:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=5,
        )
        return bool(result.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _build_scan_config(run_config: BenchmarkRunConfig) -> "ScanConfig":
    """Build a ScanConfig with layers enabled/disabled per the benchmark config."""
    overrides: dict[str, object] = {
        "layers": {
            "deterministic": {"enabled": "deterministic" in run_config.layers},
            "ml": {"enabled": "ml" in run_config.layers},
            "llm": {"enabled": "llm" in run_config.layers},
        }
    }
    return load_config(
        project_root=Path.cwd(),
        global_config_path=None,
        env={},
        cli_overrides=overrides,
    )


async def _scan_single_skill(
    entry: ManifestEntry,
    dataset_root: Path,
    scan_config: "ScanConfig",
    timeout: float,
) -> BenchmarkResult:
    """Scan a single skill and produce a BenchmarkResult.

    Captures errors without raising. Times the scan.
    """
    skill_id = entry.id
    gt = entry.ground_truth

    # Build base result from ground truth
    base = dict(
        skill_id=skill_id,
        ground_truth_verdict=gt.verdict,
        ground_truth_categories=gt.attack_categories,
        ground_truth_severity=gt.severity,
        ground_truth_expected_rules=gt.expected_rules,
        ground_truth_min_categories=gt.min_category_coverage,
        ground_truth_notes=gt.notes,
    )

    try:
        skill_path = resolve_skill_path(entry, dataset_root)
        start = time.monotonic()
        skills = await resolve_input(str(skill_path))
        scan_result = await asyncio.wait_for(
            run_pipeline(skills=skills, config=scan_config),
            timeout=timeout,
        )
        elapsed_ms = (time.monotonic() - start) * 1000.0

        # Extract findings as summaries (no raw content)
        finding_summaries = [
            FindingSummary(
                rule_id=f.rule_id,
                category=f.category.value if hasattr(f.category, "value") else str(f.category),
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                confidence=f.confidence if f.confidence is not None else 1.0,
                message=f.message,
            )
            for f in scan_result.findings
        ]

        timing = {"total_ms": elapsed_ms}
        # Extract per-layer timing from layer_metadata if available
        for layer_name in ("deterministic", "ml", "llm"):
            layer_meta = scan_result.layer_metadata.get(layer_name, {})
            if isinstance(layer_meta, dict) and "timing_ms" in layer_meta:
                timing[f"{layer_name}_ms"] = layer_meta["timing_ms"]

        return BenchmarkResult(
            **base,
            risk_score=scan_result.risk_score,
            verdict=scan_result.verdict,
            findings=finding_summaries,
            timing=timing,
        )
    except Exception as exc:
        return BenchmarkResult(
            **base,
            error=f"{type(exc).__name__}: {exc}",
        )


async def run_benchmark(config: BenchmarkRunConfig) -> BenchmarkRun:
    """Run the full benchmark: load manifest, scan skills, compute metrics."""
    start_time = time.monotonic()

    # Load and filter manifest
    manifest = load_manifest(config.manifest_path)
    entries = filter_entries(manifest, tier=config.tier)

    # Build scan config
    scan_config = _build_scan_config(config)

    # Determine threshold (use manifest default if not overridden)
    threshold = config.threshold

    # Scan skills sequentially — ML/LLM model loading is not safe under
    # concurrent access (models load/unload per scan in the current pipeline)
    results: list[BenchmarkResult] = []
    for entry in entries:
        result = await _scan_single_skill(
            entry, config.dataset_root, scan_config, config.timeout,
        )
        results.append(result)

    # Compute metrics
    results_list = list(results)
    metrics = compute_all_metrics(results_list, threshold=threshold)

    wall_clock = time.monotonic() - start_time

    return BenchmarkRun(
        run_id=generate_run_id(),
        config=config,
        results=results_list,
        metrics=metrics,
        git_sha=_get_git_sha(),
        dirty=_is_git_dirty(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        dataset_version=manifest.dataset_version,
        wall_clock_seconds=wall_clock,
    )


def save_results(run: BenchmarkRun, output_dir: Path) -> None:
    """Save benchmark results to disk.

    Creates output_dir if it doesn't exist.
    Writes results.jsonl (per-skill) and summary.json (aggregate).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write per-skill results as JSONL (findings-focused, no raw content)
    jsonl_path = output_dir / "results.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as f:
        for r in run.results:
            line = r.model_dump_json()
            f.write(line + "\n")

    # Write summary
    summary = {
        "run_id": run.run_id,
        "git_sha": run.git_sha,
        "dirty": run.dirty,
        "timestamp": run.timestamp,
        "dataset_version": run.dataset_version,
        "config": run.config.model_dump(mode="json"),
        "metrics": run.metrics.model_dump(),
        "total_skills": run.metrics.total_skills,
        "error_count": run.metrics.error_count,
        "wall_clock_seconds": run.wall_clock_seconds,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, default=str),
        encoding="utf-8",
    )


def load_run_summary(path: Path) -> dict:
    """Load a benchmark run summary from a JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))
