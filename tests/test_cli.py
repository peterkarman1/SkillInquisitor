from importlib import import_module

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

    monkeypatch.setattr("skillinquisitor.cli.list_model_statuses", fake_list_model_statuses)

    result = runner.invoke(app, ["models", "list"])

    assert result.exit_code == 0
    assert "wolf-defender-prompt-injection" in result.stdout
    assert "cached" in result.stdout


def test_models_download_runs_configured_download(monkeypatch):
    def fake_download_configured_models(config):
        return [
            ("patronus-studio/wolf-defender-prompt-injection", "downloaded"),
            ("vijil/vijil_dome_prompt_injection_detection", "already-cached"),
        ]

    monkeypatch.setattr("skillinquisitor.cli.download_configured_models", fake_download_configured_models)

    result = runner.invoke(app, ["models", "download"])

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


def test_benchmark_subcommand_is_stubbed():
    result = runner.invoke(app, ["benchmark", "run"])
    assert result.exit_code == 2
    assert "not implemented" in result.stdout.lower()


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
