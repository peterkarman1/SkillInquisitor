from importlib import import_module

from typer.testing import CliRunner

from skillinquisitor.cli import app

runner = CliRunner()


def test_package_imports():
    module = import_module("skillinquisitor")
    assert getattr(module, "__version__")


def test_models_subcommand_is_stubbed():
    result = runner.invoke(app, ["models", "list"])
    assert result.exit_code == 2
    assert "not implemented" in result.stdout.lower()


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


def test_rules_test_runs_single_rule_against_normalized_file():
    result = runner.invoke(
        app,
        ["rules", "test", "D-1B", "tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md"],
    )

    assert result.exit_code == 1
    assert "D-1B" in result.stdout


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
