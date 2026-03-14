from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from skillinquisitor.config import ConfigError, load_config
from skillinquisitor.formatters.console import format_console
from skillinquisitor.formatters.json import format_json
from skillinquisitor.input import resolve_input
from skillinquisitor.pipeline import run_pipeline

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
def models_list() -> None:
    _not_implemented("models list")


@models_app.command("download")
def models_download() -> None:
    _not_implemented("models download")


@rules_app.command("list")
def rules_list() -> None:
    _not_implemented("rules list")


@rules_app.command("test")
def rules_test() -> None:
    _not_implemented("rules test")


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


def _not_implemented(command_name: str) -> None:
    typer.echo(f"{command_name} is not implemented yet.")
    raise typer.Exit(code=2)


def _build_config_overrides(output_format: str, severity: str | None) -> dict[str, object]:
    overrides: dict[str, object] = {"default_format": output_format}
    if severity:
        overrides["default_severity"] = severity.lower()
    return overrides


def main() -> None:
    app()
