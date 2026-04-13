from __future__ import annotations

import asyncio
import os
from pathlib import Path

import typer

from skillinquisitor.config import ConfigError, load_config
from skillinquisitor.detectors.llm import download_llm_models, list_llm_model_statuses
from skillinquisitor.detectors.rules import build_rule_registry, run_registered_rules
from skillinquisitor.formatters.console import format_console
from skillinquisitor.formatters.json import format_json
from skillinquisitor.input import resolve_input
from skillinquisitor.models import ScanResult
from skillinquisitor.pipeline import _update_skill_names_from_frontmatter, normalize_skills
from skillinquisitor.progress import ProgressRenderer, ProgressSink
from skillinquisitor.service import scan_target

app = typer.Typer(help="Security scanner for AI agent skills.")
models_app = typer.Typer(help="Manage ML/LLM models.")
rules_app = typer.Typer(help="Inspect deterministic rules.")
benchmark_app = typer.Typer(help="Run benchmark suites.")

app.add_typer(models_app, name="models")
app.add_typer(rules_app, name="rules")
app.add_typer(benchmark_app, name="benchmark")


@app.callback()
def root() -> None:
    """SkillInquisitor command line interface."""


@app.command()
def scan(
    target: str,
    format: str = typer.Option("text", "--format"),
    commit: str | None = typer.Option(None, "--commit"),
    checks: list[str] | None = typer.Option(None, "--checks"),
    skip: list[str] | None = typer.Option(None, "--skip"),
    severity: str | None = typer.Option(None, "--severity"),
    config: Path | None = typer.Option(None, "--config"),
    quiet: bool = typer.Option(False, "--quiet"),
    verbose: bool = typer.Option(False, "--verbose"),
    baseline: Path | None = typer.Option(None, "--baseline"),
    llm_group: str | None = typer.Option(None, "--llm-group"),
    workers: int = typer.Option(1, "--workers"),
) -> None:
    try:
        result, effective_config = asyncio.run(
            _run_scan(
                target=target,
                output_format=format,
                config_path=config,
                commit_sha=commit,
                workers=workers,
                event_sink=None if quiet else _build_progress_renderer(verbose=verbose),
                cli_overrides=_build_config_overrides(
                    output_format=format,
                    severity=severity,
                    llm_group=llm_group,
                ),
            )
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if quiet:
        raise typer.Exit(code=0 if result.binary_label == "not_malicious" else 1)

    if effective_config.default_format == "json":
        typer.echo(format_json(result))
    elif effective_config.default_format == "sarif":
        from skillinquisitor.formatters.sarif import format_sarif

        typer.echo(format_sarif(result))
    else:
        typer.echo(format_console(result, verbose=verbose))

    raise typer.Exit(code=0 if result.binary_label == "not_malicious" else 1)


@models_app.command("list")
def models_list(config: Path | None = typer.Option(None, "--config")) -> None:
    try:
        effective_config = load_config(
            project_root=Path.cwd(),
            global_config_path=_resolve_config_path(config),
            env=dict(os.environ),
            cli_overrides={},
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    for status in list_llm_model_statuses(effective_config):
        weight = status.get("weight")
        group = status.get("group")
        filename = status.get("filename")
        typer.echo(
            f"{status['layer']}\t{status['model_id']}\t{status['status']}"
            + (f"\tgroup={group}" if group else "")
            + (f"\tfile={filename}" if filename else "")
            + (f"\tweight={weight}" if weight is not None else "")
        )

    raise typer.Exit(code=0)


@models_app.command("download")
def models_download(
    config: Path | None = typer.Option(None, "--config"),
    llm_group: str | None = typer.Option(None, "--llm-group"),
) -> None:
    try:
        effective_config = load_config(
            project_root=Path.cwd(),
            global_config_path=_resolve_config_path(config),
            env=dict(os.environ),
            cli_overrides={},
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    downloads = list(download_llm_models(effective_config, requested_group=llm_group))
    for model_id, status in downloads:
        typer.echo(f"{model_id}\t{status}")

    raise typer.Exit(code=0)


@rules_app.command("list")
def rules_list(config: Path | None = typer.Option(None, "--config")) -> None:
    try:
        effective_config = load_config(
            project_root=Path.cwd(),
            global_config_path=_resolve_config_path(config),
            env=dict(os.environ),
            cli_overrides={},
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    registry = build_rule_registry(effective_config)
    for rule in registry.list_rules():
        typer.echo(
            f"{rule.rule_id}\t{rule.scope}\t{rule.category.value}\t{rule.severity.value}\t{rule.origin}"
        )

    raise typer.Exit(code=0)


@rules_app.command("test")
def rules_test(rule_id: str, target: str, config: Path | None = typer.Option(None, "--config")) -> None:
    try:
        result = asyncio.run(_run_rules_test(rule_id=rule_id, target=target, config_path=config))
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(format_console(result))
    raise typer.Exit(code=0 if not result.findings else 1)


@benchmark_app.command("run")
def benchmark_run(
    tier: str = typer.Option("standard", "--tier", help="Tier filter: smoke, standard, full"),
    layer: list[str] | None = typer.Option(None, "--layer", help="Layers to enable (repeatable)"),
    llm_group: str | None = typer.Option(None, "--llm-group", help="Force LLM model group: tiny, balanced, large"),
    dataset_profile: str = typer.Option(
        "real_world",
        "--dataset-profile",
        help="Benchmark data profile: real_world, safe_only, malicious_only",
    ),
    concurrency: int = typer.Option(0, "--concurrency", help="Maximum concurrent benchmark workers (0 = auto)"),
    timeout: float = typer.Option(120.0, "--timeout", help="Per-skill timeout in seconds"),
    threshold: float = typer.Option(60.0, "--threshold", help="Legacy binary decision threshold (unused, kept for CLI compat)"),
    dataset: Path = typer.Option(Path("benchmark/manifest.yaml"), "--dataset", help="Path to manifest.yaml"),
    output: Path | None = typer.Option(None, "--output", help="Output directory"),
    baseline: Path | None = typer.Option(None, "--baseline", help="Baseline summary.json for comparison"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress progress output"),
) -> None:
    """Run the benchmark suite against labeled skills."""
    from skillinquisitor.benchmark.report import generate_report
    from skillinquisitor.benchmark.runner import (
        BenchmarkRunConfig,
        load_run_summary,
        run_benchmark as _run_benchmark,
        save_results,
    )

    layers = layer if layer else ["deterministic", "llm"]
    dataset_root = dataset.parent / "dataset"

    run_config = BenchmarkRunConfig(
        tier=tier,
        layers=layers,
        llm_group=llm_group,
        dataset_profile=dataset_profile,
        concurrency=concurrency,
        timeout=timeout,
        threshold=threshold,
        manifest_path=dataset,
        dataset_root=dataset_root,
        output_dir=output,
        baseline_path=baseline,
    )

    try:
        run = asyncio.run(_run_benchmark(run_config, event_sink=None if quiet else _build_progress_renderer(verbose=False)))
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    out_dir = output or Path("benchmark/results") / run.run_id
    save_results(run, out_dir)

    baseline_metrics = None
    baseline_results = None
    if baseline and baseline.exists():
        import json as _json

        summary = load_run_summary(baseline)
        baseline_metrics = summary.get("metrics")
        baseline_jsonl = baseline.parent / "results.jsonl"
        if baseline_jsonl.exists():
            baseline_results = []
            for bline in baseline_jsonl.read_text().splitlines():
                if bline.strip():
                    baseline_results.append(_json.loads(bline))

    report = generate_report(
        run_id=run.run_id,
        git_sha=run.git_sha,
        dirty=run.dirty,
        timestamp=run.timestamp,
        dataset_version=run.dataset_version,
        wall_clock_seconds=run.wall_clock_seconds,
        tier=tier,
        layers=layers,
        threshold=threshold,
        dataset_profile=dataset_profile,
        results=run.results,
        metrics=run.metrics,
        baseline_metrics=baseline_metrics,
        baseline_results=baseline_results,
        runtime=run.runtime,
    )
    (out_dir / "report.md").write_text(report, encoding="utf-8")

    if not quiet:
        cm = run.metrics.confusion_matrix
        typer.echo(f"Benchmark complete: {run.metrics.total_skills} skills in {run.wall_clock_seconds:.1f}s")
        typer.echo(f"  Precision: {cm.precision:.1%}  Recall: {cm.recall:.1%}  F1: {cm.f1:.1%}")
        typer.echo(f"  TP: {cm.tp}  FP: {cm.fp}  TN: {cm.tn}  FN: {cm.fn}")
        if run.metrics.error_count:
            typer.echo(f"  Errors: {run.metrics.error_count}")
        typer.echo(f"  Results: {out_dir}")

    has_regressions = False
    if baseline_results:
        baseline_outcomes = {r.get("skill_id"): r.get("binary_outcome") for r in baseline_results}
        for r in run.results:
            prev = baseline_outcomes.get(r.skill_id)
            if prev in ("TP", "TN") and r.binary_outcome in ("FP", "FN"):
                has_regressions = True
                break

    raise typer.Exit(code=1 if has_regressions else 0)


@benchmark_app.command("compare")
def benchmark_compare(
    run_a: Path = typer.Argument(..., help="Path to first run's summary.json"),
    run_b: Path = typer.Argument(..., help="Path to second run's summary.json"),
    fmt: str = typer.Option("table", "--format", help="Output format: table, json, markdown"),
) -> None:
    """Compare two benchmark runs and show metric deltas."""
    import json as _json

    from skillinquisitor.benchmark.runner import load_run_summary

    try:
        summary_a = load_run_summary(run_a)
        summary_b = load_run_summary(run_b)
    except (FileNotFoundError, _json.JSONDecodeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    metrics_a = summary_a.get("metrics", {})
    metrics_b = summary_b.get("metrics", {})
    cm_a = metrics_a.get("confusion_matrix", {})
    cm_b = metrics_b.get("confusion_matrix", {})

    def _safe_div(n: float, d: float) -> float:
        return n / d if d > 0 else 0.0

    pairs = [
        ("Precision", _safe_div(cm_a.get("tp", 0), cm_a.get("tp", 0) + cm_a.get("fp", 0)),
         _safe_div(cm_b.get("tp", 0), cm_b.get("tp", 0) + cm_b.get("fp", 0))),
        ("Recall", _safe_div(cm_a.get("tp", 0), cm_a.get("tp", 0) + cm_a.get("fn", 0)),
         _safe_div(cm_b.get("tp", 0), cm_b.get("tp", 0) + cm_b.get("fn", 0))),
        ("TP", cm_a.get("tp", 0), cm_b.get("tp", 0)),
        ("FP", cm_a.get("fp", 0), cm_b.get("fp", 0)),
        ("TN", cm_a.get("tn", 0), cm_b.get("tn", 0)),
        ("FN", cm_a.get("fn", 0), cm_b.get("fn", 0)),
        ("Total Skills", metrics_a.get("total_skills", 0), metrics_b.get("total_skills", 0)),
        ("Errors", metrics_a.get("error_count", 0), metrics_b.get("error_count", 0)),
    ]

    if fmt == "json":
        result_data = {name: {"run_a": va, "run_b": vb, "delta": vb - va} for name, va, vb in pairs}
        typer.echo(_json.dumps(result_data, indent=2))
    else:
        typer.echo(f"{'Metric':<15} {'Run A':>10} {'Run B':>10} {'Delta':>10}")
        typer.echo("-" * 47)
        for name, va, vb in pairs:
            delta = vb - va
            sign = "+" if delta > 0 else ""
            if isinstance(va, float):
                typer.echo(f"{name:<15} {va:>10.1%} {vb:>10.1%} {sign}{delta:>9.1%}")
            else:
                typer.echo(f"{name:<15} {va:>10} {vb:>10} {sign}{delta:>9}")

    raise typer.Exit(code=0)


@benchmark_app.command("bless")
def benchmark_bless(
    run_dir: Path = typer.Argument(..., help="Path to run results directory"),
    name: str = typer.Option("v1", "--name", help="Baseline name"),
) -> None:
    """Bless a benchmark run as the regression baseline."""
    import shutil

    summary_src = run_dir / "summary.json"
    results_src = run_dir / "results.jsonl"

    if not summary_src.exists():
        typer.echo(f"No summary.json found in {run_dir}", err=True)
        raise typer.Exit(code=2)

    baselines_dir = Path("benchmark/baselines")
    baselines_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(summary_src, baselines_dir / f"{name}.json")
    if results_src.exists():
        shutil.copy2(results_src, baselines_dir / f"{name}.jsonl")

    typer.echo(f"Baseline '{name}' saved to {baselines_dir}")
    raise typer.Exit(code=0)


async def _run_scan(
    target: str,
    output_format: str,
    config_path: Path | None,
    cli_overrides: dict[str, object],
    commit_sha: str | None = None,
    workers: int = 1,
    event_sink: ProgressSink | None = None,
):
    effective_config = load_config(
        project_root=Path.cwd(),
        global_config_path=_resolve_config_path(config_path),
        env=dict(os.environ),
        cli_overrides={
            **cli_overrides,
            "default_format": output_format,
            "runtime": {"scan_workers": workers},
        },
    )
    result = await scan_target(
        target=target,
        config=effective_config,
        workers=workers,
        commit_sha=commit_sha,
        event_sink=event_sink,
    )
    return result, effective_config


async def _run_rules_test(rule_id: str, target: str, config_path: Path | None) -> ScanResult:
    effective_config = load_config(
        project_root=Path.cwd(),
        global_config_path=_resolve_config_path(config_path),
        env=dict(os.environ),
        cli_overrides={},
    )
    registry = build_rule_registry(effective_config)
    if registry.get(rule_id) is None:
        raise ValueError(f"Unknown rule id: {rule_id}")

    skills = await resolve_input(target)
    normalized_skills = normalize_skills(skills, config=effective_config)
    normalized_skills = _update_skill_names_from_frontmatter(normalized_skills)
    findings = run_registered_rules(normalized_skills, effective_config, registry, only_rule_id=rule_id)

    from skillinquisitor.adjudication import final_adjudicate, map_risk_label_to_binary
    from skillinquisitor.scoring import prepare_findings

    findings = prepare_findings(findings, effective_config)
    adjudication = final_adjudicate(findings, effective_config)

    return ScanResult(
        skills=normalized_skills,
        findings=findings,
        risk_label=adjudication.risk_label,
        binary_label=map_risk_label_to_binary(adjudication.risk_label, effective_config.decision_policy.binary_cutoff),
        adjudication=adjudication.model_dump(mode="python"),
        layer_metadata={
            "deterministic": {"enabled": effective_config.layers.deterministic.enabled, "findings": len(findings)},
            "llm": {"enabled": effective_config.layers.llm.enabled, "findings": 0},
        },
        total_timing=0.0,
    )


def _not_implemented(command_name: str) -> None:
    typer.echo(f"{command_name} is not implemented yet.")
    raise typer.Exit(code=2)


def _build_config_overrides(
    output_format: str,
    severity: str | None,
    llm_group: str | None = None,
) -> dict[str, object]:
    overrides: dict[str, object] = {"default_format": output_format}
    if severity:
        overrides["default_severity"] = severity.lower()
    if llm_group:
        overrides["layers"] = {"llm": {"default_group": llm_group, "auto_select_group": False}}
    return overrides


def _resolve_config_path(config_path: Path | None) -> Path | None:
    if config_path is not None:
        return config_path
    env_path = os.environ.get("SKILLINQUISITOR_CONFIG")
    if not env_path:
        return None
    return Path(env_path).expanduser()


def main() -> None:
    app()


def _build_progress_renderer(*, verbose: bool) -> ProgressSink:
    renderer = ProgressRenderer(
        lambda message: typer.echo(message, err=True),
        verbose=verbose,
    )
    return renderer
