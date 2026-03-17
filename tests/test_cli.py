import asyncio
from importlib import import_module

import pytest
from typer.testing import CliRunner

from skillinquisitor.cli import app

runner = CliRunner()


def test_package_imports():
    module = import_module("skillinquisitor")
    assert getattr(module, "__version__")


def test_models_list_outputs_configured_model_statuses(monkeypatch):
    def fake_list_model_statuses(config):
        return [
            {
                "layer": "ml",
                "model_id": "patronus-studio/wolf-defender-prompt-injection",
                "status": "cached",
            },
            {
                "layer": "ml",
                "model_id": "vijil/vijil_dome_prompt_injection_detection",
                "status": "missing",
            },
        ]

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

    monkeypatch.setattr("skillinquisitor.cli.list_model_statuses", fake_list_model_statuses)
    monkeypatch.setattr("skillinquisitor.cli.list_llm_model_statuses", fake_list_llm_model_statuses)

    result = runner.invoke(app, ["models", "list"])

    assert result.exit_code == 0
    assert "wolf-defender-prompt-injection" in result.stdout
    assert "cached" in result.stdout
    assert "group=tiny" in result.stdout
    assert "Qwen3.5-0.8B-Q4_K_M.gguf" in result.stdout


def test_models_download_runs_configured_download(monkeypatch):
    def fake_download_configured_models(config):
        return [
            ("patronus-studio/wolf-defender-prompt-injection", "downloaded"),
            ("vijil/vijil_dome_prompt_injection_detection", "already-cached"),
        ]

    def fake_download_llm_models(config, requested_group=None):
        assert requested_group == "tiny"
        return [("unsloth/Qwen3.5-0.8B-GGUF", "downloaded")]

    monkeypatch.setattr("skillinquisitor.cli.download_configured_models", fake_download_configured_models)
    monkeypatch.setattr("skillinquisitor.cli.download_llm_models", fake_download_llm_models)

    result = runner.invoke(app, ["models", "download", "--llm-group", "tiny"])

    assert result.exit_code == 0
    assert "downloaded" in result.stdout
    assert "already-cached" in result.stdout


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
    async def fake_run_benchmark(config):
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
    async def fake_run_benchmark(config):
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
    assert '"findings": []' in result.stdout


def test_build_config_overrides_can_force_llm_group():
    from skillinquisitor.cli import _build_config_overrides

    overrides = _build_config_overrides(output_format="text", severity=None, llm_group="balanced")

    assert overrides["layers"]["llm"]["default_group"] == "balanced"
    assert overrides["layers"]["llm"]["auto_select_group"] is False


def test_scan_command_accepts_workers_option(monkeypatch):
    async def fake_run_scan(*, target, output_format, config_path, cli_overrides, workers):
        assert workers == 2
        from skillinquisitor.models import ScanConfig, ScanResult

        return ScanResult(skills=[], findings=[]), ScanConfig()

    monkeypatch.setattr("skillinquisitor.cli._run_scan", fake_run_scan)

    result = runner.invoke(app, ["scan", "tests/fixtures/local/basic-skill", "--workers", "2"])

    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_run_scan_parallelizes_multi_skill_targets_with_shared_runtime(monkeypatch):
    from skillinquisitor.cli import _run_scan
    from skillinquisitor.models import ScanConfig, ScanResult, Skill

    skills = [
        Skill(path="skill-a", name="a"),
        Skill(path="skill-b", name="b"),
    ]
    max_inflight = 0
    inflight = 0
    seen_runtime_ids: set[int] = set()

    monkeypatch.setattr("skillinquisitor.cli.load_config", lambda **kwargs: ScanConfig())

    async def fake_resolve_input(target):
        assert target == "multi-skill"
        return skills

    async def fake_run_pipeline(*, skills, config, runtime=None):
        nonlocal inflight, max_inflight
        seen_runtime_ids.add(id(runtime))
        inflight += 1
        max_inflight = max(max_inflight, inflight)
        if skills[0].path == "skill-a":
            await asyncio.sleep(0.05)
        else:
            await asyncio.sleep(0.01)
        inflight -= 1
        return ScanResult(skills=skills, findings=[])

    monkeypatch.setattr("skillinquisitor.cli.resolve_input", fake_resolve_input)
    monkeypatch.setattr("skillinquisitor.cli.run_pipeline", fake_run_pipeline)

    result, _ = await _run_scan(
        target="multi-skill",
        output_format="console",
        config_path=None,
        cli_overrides={},
        workers=2,
    )

    assert max_inflight >= 2
    assert len(seen_runtime_ids) == 1
    assert [skill.path for skill in result.skills] == ["skill-a", "skill-b"]
