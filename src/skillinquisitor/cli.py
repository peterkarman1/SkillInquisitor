from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from skillinquisitor.config import ConfigError, load_config
from skillinquisitor.detectors.llm import download_llm_models, list_llm_model_statuses
from skillinquisitor.detectors.ml import download_configured_models, list_model_statuses
from skillinquisitor.detectors.rules import build_rule_registry, run_registered_rules
from skillinquisitor.formatters.console import format_console
from skillinquisitor.formatters.json import format_json
from skillinquisitor.input import resolve_input
from skillinquisitor.models import ScanResult
from skillinquisitor.pipeline import _update_skill_names_from_frontmatter, normalize_skills, run_pipeline

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
    checks: list[str] | None = typer.Option(None, "--checks"),
    skip: list[str] | None = typer.Option(None, "--skip"),
    severity: str | None = typer.Option(None, "--severity"),
    config: Path | None = typer.Option(None, "--config"),
    quiet: bool = typer.Option(False, "--quiet"),
    verbose: bool = typer.Option(False, "--verbose"),
    baseline: Path | None = typer.Option(None, "--baseline"),
    llm_group: str | None = typer.Option(None, "--llm-group"),
) -> None:
    try:
        result, effective_config = asyncio.run(
            _run_scan(
                target=target,
                output_format=format,
                config_path=config,
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
        raise typer.Exit(code=0 if not result.findings else 1)

    if effective_config.default_format == "json":
        typer.echo(format_json(result))
    else:
        typer.echo(format_console(result))
        if verbose:
            typer.echo(f"Effective config format: {effective_config.default_format}")

    raise typer.Exit(code=0 if not result.findings else 1)


@models_app.command("list")
def models_list(config: Path | None = typer.Option(None, "--config")) -> None:
    try:
        effective_config = load_config(
            project_root=Path.cwd(),
            global_config_path=config,
            env={},
            cli_overrides={},
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    for status in [*list_model_statuses(effective_config), *list_llm_model_statuses(effective_config)]:
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
            global_config_path=config,
            env={},
            cli_overrides={},
        )
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    downloads = [
        *download_configured_models(effective_config),
        *download_llm_models(effective_config, requested_group=llm_group),
    ]
    for model_id, status in downloads:
        typer.echo(f"{model_id}\t{status}")

    raise typer.Exit(code=0)


@rules_app.command("list")
def rules_list(config: Path | None = typer.Option(None, "--config")) -> None:
    try:
        effective_config = load_config(
            project_root=Path.cwd(),
            global_config_path=config,
            env={},
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
def benchmark_run() -> None:
    _not_implemented("benchmark run")


@benchmark_app.command("compare")
def benchmark_compare() -> None:
    _not_implemented("benchmark compare")


async def _run_scan(
    target: str,
    output_format: str,
    config_path: Path | None,
    cli_overrides: dict[str, object],
):
    effective_config = load_config(
        project_root=Path.cwd(),
        global_config_path=config_path,
        env={},
        cli_overrides={
            **cli_overrides,
            "default_format": output_format,
        },
    )
    skills = await resolve_input(target)
    result = await run_pipeline(skills=skills, config=effective_config)
    return result, effective_config


async def _run_rules_test(rule_id: str, target: str, config_path: Path | None) -> ScanResult:
    effective_config = load_config(
        project_root=Path.cwd(),
        global_config_path=config_path,
        env={},
        cli_overrides={},
    )
    registry = build_rule_registry(effective_config)
    if registry.get(rule_id) is None:
        raise ValueError(f"Unknown rule id: {rule_id}")

    skills = await resolve_input(target)
    normalized_skills = normalize_skills(skills, config=effective_config)
    normalized_skills = _update_skill_names_from_frontmatter(normalized_skills)
    findings = run_registered_rules(normalized_skills, effective_config, registry, only_rule_id=rule_id)
    return ScanResult(
        skills=normalized_skills,
        findings=findings,
        risk_score=100,
        verdict="SAFE" if not findings else "MEDIUM RISK",
        layer_metadata={
            "deterministic": {"enabled": effective_config.layers.deterministic.enabled, "findings": len(findings)},
            "ml": {"enabled": effective_config.layers.ml.enabled, "findings": 0},
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


def main() -> None:
    app()
