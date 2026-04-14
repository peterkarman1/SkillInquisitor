import asyncio
from importlib import import_module
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillinquisitor.cli import app

runner = CliRunner()


def test_package_imports():
    module = import_module("skillinquisitor")
    assert getattr(module, "__version__")


def test_models_list_outputs_configured_model_statuses(monkeypatch):
    def fake_list_llm_model_statuses(config):
        return [
            {
                "layer": "llm",
                "group": "tiny",
                "model_id": "unsloth/Qwen3.5-0.8B-GGUF",
                "status": "cached",
                "filename": "Qwen3.5-0.8B-Q4_K_M.gguf",
            }
        ]

    monkeypatch.setattr("skillinquisitor.cli.list_llm_model_statuses", fake_list_llm_model_statuses)

    result = runner.invoke(app, ["models", "list"])

    assert result.exit_code == 0
    assert "cached" in result.stdout
    assert "group=tiny" in result.stdout
    assert "Qwen3.5-0.8B-Q4_K_M.gguf" in result.stdout


def test_models_download_runs_configured_download(monkeypatch):
    def fake_download_llm_models(config, requested_group=None):
        assert requested_group == "tiny"
        return [("unsloth/Qwen3.5-0.8B-GGUF", "downloaded")]

    monkeypatch.setattr("skillinquisitor.cli.download_llm_models", fake_download_llm_models)

    result = runner.invoke(app, ["models", "download", "--llm-group", "tiny"])

    assert result.exit_code == 0
    assert "downloaded" in result.stdout


def test_rules_list_outputs_registered_unicode_rules():
    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    assert "D-1A" in result.stdout
    assert "D-6A" in result.stdout


def test_rules_list_outputs_registered_encoding_rules():
    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    assert "D-3A" in result.stdout
    assert "D-22A" in result.stdout


def test_rules_list_outputs_registered_epic5_rules():
    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    assert "D-7A" in result.stdout
    assert "D-19A" in result.stdout


def test_rules_list_outputs_registered_epic6_epic7_epic8_rules():
    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    assert "D-11A" in result.stdout
    assert "D-14" in result.stdout
    assert "D-16A" in result.stdout


def test_rules_test_runs_single_rule_against_normalized_file():
    result = runner.invoke(
        app,
        ["rules", "test", "D-1B", "tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md"],
    )

    assert result.exit_code == 1
    assert "D-1B" in result.stdout


def test_rules_test_runs_postprocessed_d19_rule():
    result = runner.invoke(
        app,
        ["rules", "test", "D-19A", "tests/fixtures/deterministic/secrets/D-19-read-send-chain"],
    )

    assert result.exit_code == 1
    assert "D-19A" in result.stdout


def test_benchmark_run_against_test_manifest():
    result = runner.invoke(
        app,
        ["benchmark", "run", "--tier", "smoke", "--layer", "deterministic", "--dataset", "benchmark/manifest.yaml"],
    )
    assert result.exit_code == 0
    assert "benchmark complete" in result.stdout.lower()


def test_benchmark_run_accepts_concurrency_option(monkeypatch):
    async def fake_run_benchmark(config, event_sink=None):
        assert config.concurrency == 2
        from skillinquisitor.benchmark.runner import BenchmarkRun
        from skillinquisitor.benchmark.metrics import BenchmarkMetrics

        return BenchmarkRun(
            run_id="test-run",
            config=config,
            metrics=BenchmarkMetrics(total_skills=0),
        )

    monkeypatch.setattr("skillinquisitor.benchmark.runner.run_benchmark", fake_run_benchmark)
    monkeypatch.setattr("skillinquisitor.benchmark.runner.save_results", lambda run, out_dir: out_dir.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr("skillinquisitor.benchmark.report.generate_report", lambda **kwargs: "report")

    result = runner.invoke(
        app,
        ["benchmark", "run", "--tier", "smoke", "--concurrency", "2", "--layer", "deterministic"],
    )

    assert result.exit_code == 0


def test_benchmark_run_accepts_llm_group_option(monkeypatch):
    async def fake_run_benchmark(config, event_sink=None):
        assert config.llm_group == "balanced"
        from skillinquisitor.benchmark.runner import BenchmarkRun
        from skillinquisitor.benchmark.metrics import BenchmarkMetrics

        return BenchmarkRun(
            run_id="test-run",
            config=config,
            metrics=BenchmarkMetrics(total_skills=0),
        )

    monkeypatch.setattr("skillinquisitor.benchmark.runner.run_benchmark", fake_run_benchmark)
    monkeypatch.setattr("skillinquisitor.benchmark.runner.save_results", lambda run, out_dir: out_dir.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr("skillinquisitor.benchmark.report.generate_report", lambda **kwargs: "report")

    result = runner.invoke(
        app,
        ["benchmark", "run", "--tier", "smoke", "--llm-group", "balanced", "--layer", "deterministic"],
    )

    assert result.exit_code == 0


def test_benchmark_run_accepts_dataset_profile_option(monkeypatch):
    async def fake_run_benchmark(config, event_sink=None):
        assert config.dataset_profile == "malicious_only"
        from skillinquisitor.benchmark.runner import BenchmarkRun
        from skillinquisitor.benchmark.metrics import BenchmarkMetrics

        return BenchmarkRun(
            run_id="test-run",
            config=config,
            metrics=BenchmarkMetrics(total_skills=0),
        )

    monkeypatch.setattr("skillinquisitor.benchmark.runner.run_benchmark", fake_run_benchmark)
    monkeypatch.setattr("skillinquisitor.benchmark.runner.save_results", lambda run, out_dir: out_dir.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr("skillinquisitor.benchmark.report.generate_report", lambda **kwargs: "report")

    result = runner.invoke(
        app,
        ["benchmark", "run", "--tier", "smoke", "--dataset-profile", "malicious_only", "--layer", "deterministic"],
    )

    assert result.exit_code == 0


def test_scan_command_outputs_empty_result():
    result = runner.invoke(app, ["scan", "tests/fixtures/local/basic-skill"])

    assert result.exit_code == 0
    assert "0 findings" in result.stdout.lower()


def test_scan_command_outputs_json():
    result = runner.invoke(
        app,
        ["scan", "tests/fixtures/local/basic-skill", "--format", "json"],
    )

    assert result.exit_code == 0
    assert '"risk_label": "LOW"' in result.stdout
    assert '"findings": []' in result.stdout


def test_build_config_overrides_can_force_llm_group():
    from skillinquisitor.cli import _build_config_overrides

    overrides = _build_config_overrides(output_format="text", severity=None, llm_group="balanced")

    assert overrides["layers"]["llm"]["default_group"] == "balanced"


def test_scan_command_accepts_workers_option(monkeypatch):
    async def fake_run_scan(*, target, output_format, config_path, cli_overrides, workers, commit_sha=None, event_sink=None):
        assert workers == 2
        assert commit_sha is None
        from skillinquisitor.models import ScanConfig, ScanResult

        return ScanResult(skills=[], findings=[]), ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli._run_scan", fake_run_scan)

    result = runner.invoke(app, ["scan", "tests/fixtures/local/basic-skill", "--workers", "2"])

    assert result.exit_code == 0


def test_scan_command_accepts_commit_option(monkeypatch):
    async def fake_run_scan(*, target, output_format, config_path, cli_overrides, workers, commit_sha, event_sink=None):
        assert commit_sha == "abc1234"
        from skillinquisitor.models import ScanConfig, ScanResult

        return ScanResult(skills=[], findings=[]), ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli._run_scan", fake_run_scan)

    result = runner.invoke(app, ["scan", "https://gitlab.com/openai/example.git", "--commit", "abc1234"])

    assert result.exit_code == 0


def test_scan_command_emits_progress_to_stderr_by_default(monkeypatch):
    echo_calls = []

    async def fake_run_scan(*, target, output_format, config_path, cli_overrides, workers, commit_sha=None, event_sink=None):
        assert event_sink is not None
        from skillinquisitor.models import ScanConfig, ScanResult

        event_sink("scan.started", target=target, workers=workers)
        event_sink("scan.completed", skills=1)
        return ScanResult(skills=[], findings=[]), ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli._run_scan", fake_run_scan)
    monkeypatch.setattr("skillinquisitor.cli.typer.echo", lambda message="", err=False, **kwargs: echo_calls.append((message, err)))

    result = runner.invoke(app, ["scan", "tests/fixtures/local/basic-skill"])

    assert result.exit_code == 0
    assert any(err and "[scan]" in message for message, err in echo_calls)
    assert any((not err) and "0 findings" in message.lower() for message, err in echo_calls)


def test_scan_command_quiet_suppresses_progress_stderr(monkeypatch):
    echo_calls = []

    async def fake_run_scan(*, target, output_format, config_path, cli_overrides, workers, commit_sha=None, event_sink=None):
        assert event_sink is None
        from skillinquisitor.models import ScanConfig, ScanResult

        return ScanResult(skills=[], findings=[]), ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli._run_scan", fake_run_scan)
    monkeypatch.setattr("skillinquisitor.cli.typer.echo", lambda message="", err=False, **kwargs: echo_calls.append((message, err)))

    result = runner.invoke(app, ["scan", "tests/fixtures/local/basic-skill", "--quiet"])

    assert result.exit_code == 0
    assert echo_calls == []


def test_scan_command_json_keeps_progress_off_stdout(monkeypatch):
    echo_calls = []

    async def fake_run_scan(*, target, output_format, config_path, cli_overrides, workers, commit_sha=None, event_sink=None):
        from skillinquisitor.models import ScanConfig, ScanResult

        if event_sink is not None:
            event_sink("scan.started", target=target, workers=workers)
        return ScanResult(skills=[], findings=[]), ScanConfig(default_format="json")

    monkeypatch.setattr("skillinquisitor.cli._run_scan", fake_run_scan)
    monkeypatch.setattr("skillinquisitor.cli.typer.echo", lambda message="", err=False, **kwargs: echo_calls.append((message, err)))

    result = runner.invoke(
        app,
        ["scan", "tests/fixtures/local/basic-skill", "--format", "json"],
    )

    assert result.exit_code == 0
    assert any(err and "[scan]" in message for message, err in echo_calls)
    assert any((not err) and '"risk_label": "LOW"' in message for message, err in echo_calls)


def test_benchmark_run_emits_progress_to_stderr_by_default(monkeypatch):
    echo_calls = []

    async def fake_run_benchmark(config, event_sink=None):
        assert event_sink is not None
        from skillinquisitor.benchmark.metrics import BenchmarkMetrics, ConfusionMatrix
        from skillinquisitor.benchmark.runner import BenchmarkRun

        event_sink("benchmark.started", total_skills=3, tier=config.tier)
        event_sink("benchmark.skill.completed", index=1, total=3, skill_id="skill-1", binary_label="malicious", risk_label="HIGH", elapsed_ms=123.0)
        return BenchmarkRun(
            run_id="test-run",
            config=config,
            metrics=BenchmarkMetrics(total_skills=3, confusion_matrix=ConfusionMatrix(tp=1, fp=0, tn=2, fn=0)),
        )

    monkeypatch.setattr("skillinquisitor.benchmark.runner.run_benchmark", fake_run_benchmark)
    monkeypatch.setattr("skillinquisitor.benchmark.runner.save_results", lambda run, out_dir: out_dir.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr("skillinquisitor.benchmark.report.generate_report", lambda **kwargs: "report")
    monkeypatch.setattr("skillinquisitor.cli.typer.echo", lambda message="", err=False, **kwargs: echo_calls.append((message, err)))

    result = runner.invoke(
        app,
        ["benchmark", "run", "--tier", "smoke", "--layer", "deterministic"],
    )

    assert result.exit_code == 0
    assert any(err and "[benchmark]" in message for message, err in echo_calls)
    assert any((not err) and "benchmark complete" in message.lower() for message, err in echo_calls)


@pytest.mark.asyncio
async def test_run_scan_delegates_to_shared_scan_helper(monkeypatch):
    from skillinquisitor.cli import _run_scan
    from skillinquisitor.models import ScanConfig, ScanResult

    monkeypatch.setattr("skillinquisitor.cli.load_config", lambda **kwargs: ScanConfig())

    async def fake_scan_target(*, target, config, runtime=None, workers=None, commit_sha=None, event_sink=None):
        assert target == "multi-skill"
        assert runtime is None
        assert workers == 2
        assert commit_sha is None
        return ScanResult(skills=[], findings=[])

    monkeypatch.setattr("skillinquisitor.cli.scan_target", fake_scan_target)

    result, _ = await _run_scan(
        target="multi-skill",
        output_format="console",
        config_path=None,
        cli_overrides={},
        workers=2,
    )

    assert result.skills == []


def test_models_list_passes_environment_to_load_config(monkeypatch):
    captured: dict[str, object] = {}

    def fake_load_config(*, project_root, global_config_path=None, env=None, cli_overrides=None):
        captured["env"] = env
        from skillinquisitor.models import ScanConfig

        return ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli.load_config", fake_load_config)
    monkeypatch.setattr("skillinquisitor.cli.list_llm_model_statuses", lambda config: [])

    result = runner.invoke(
        app,
        ["models", "list"],
        env={"SKILLINQUISITOR_DEFAULT_FORMAT": "json"},
    )

    assert result.exit_code == 0
    assert captured["env"]["SKILLINQUISITOR_DEFAULT_FORMAT"] == "json"


def test_models_list_uses_skillinquisitor_config_env_when_flag_omitted(monkeypatch, tmp_path: Path):
    config_path = tmp_path / "container-config.yaml"
    config_path.write_text("default_format: json\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_load_config(*, project_root, global_config_path=None, env=None, cli_overrides=None):
        captured["global_config_path"] = global_config_path
        from skillinquisitor.models import ScanConfig

        return ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli.load_config", fake_load_config)
    monkeypatch.setattr("skillinquisitor.cli.list_llm_model_statuses", lambda config: [])

    result = runner.invoke(
        app,
        ["models", "list"],
        env={"SKILLINQUISITOR_CONFIG": str(config_path)},
    )

    assert result.exit_code == 0
    assert captured["global_config_path"] == config_path


def test_models_list_prefers_explicit_config_flag_over_env(monkeypatch, tmp_path: Path):
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("default_format: text\n", encoding="utf-8")
    env_path = tmp_path / "env.yaml"
    env_path.write_text("default_format: json\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_load_config(*, project_root, global_config_path=None, env=None, cli_overrides=None):
        captured["global_config_path"] = global_config_path
        from skillinquisitor.models import ScanConfig

        return ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli.load_config", fake_load_config)
    monkeypatch.setattr("skillinquisitor.cli.list_llm_model_statuses", lambda config: [])

    result = runner.invoke(
        app,
        ["models", "list", "--config", str(explicit)],
        env={"SKILLINQUISITOR_CONFIG": str(env_path)},
    )

    assert result.exit_code == 0
    assert captured["global_config_path"] == explicit


