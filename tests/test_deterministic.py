from pathlib import Path

import pytest
import yaml
from skillinquisitor.models import Category, DetectionLayer, Finding, Location, Severity


def test_fixture_manifest_exists():
    manifest_path = Path("tests/fixtures/manifest.yaml")
    assert manifest_path.exists()


def test_manifest_has_five_active_safe_baselines():
    manifest = yaml.safe_load(Path("tests/fixtures/manifest.yaml").read_text(encoding="utf-8"))
    safe_fixtures = [
        entry
        for entry in manifest["fixtures"]
        if entry["status"] == "active" and "safe" in entry["tags"]
    ]
    assert len(safe_fixtures) >= 5


def test_template_fixture_is_indexed():
    manifest = yaml.safe_load(Path("tests/fixtures/manifest.yaml").read_text(encoding="utf-8"))
    assert any(entry["status"] == "template" for entry in manifest["fixtures"])


def test_load_active_fixture_specs(load_active_fixture_specs):
    specs = load_active_fixture_specs("deterministic")
    assert len(specs) >= 5
    assert all(spec.status == "active" for spec in specs)


def test_validate_fixture_expectation_schema(load_fixture_expectation):
    expectation = load_fixture_expectation("safe/simple-formatter")
    assert expectation.schema_version == 1
    assert expectation.match_mode == "exact"
    assert expectation.findings == []


def test_safe_fixture_matches_expected_contract(run_fixture_scan, assert_scan_matches_expected):
    result = run_fixture_scan("safe/simple-formatter")
    assert_scan_matches_expected("safe/simple-formatter", result)


def test_unexpected_in_scope_findings_fail(
    build_expectation,
    assert_scan_matches_expected,
    empty_scan_result,
):
    expectation = build_expectation(
        verdict="SAFE",
        findings=[],
    )
    result = empty_scan_result.model_copy(
        update={
            "findings": [
                Finding(
                    rule_id="D-1",
                    layer=DetectionLayer.DETERMINISTIC,
                    category=Category.STEGANOGRAPHY,
                    severity=Severity.LOW,
                    message="unexpected",
                    location=Location(file_path="SKILL.md", start_line=1, end_line=1),
                )
            ]
        }
    )

    try:
        assert_scan_matches_expected(expectation, result)
    except AssertionError:
        return

    raise AssertionError("expected assertion failure for unexpected in-scope findings")


def test_scoped_matching_ignores_out_of_scope_findings(
    build_expectation,
    assert_scan_matches_expected,
    empty_scan_result,
):
    expectation = build_expectation(
        verdict="SAFE",
        scope={"layers": ["deterministic"], "checks": ["D-1"]},
        findings=[],
    )
    result = empty_scan_result.model_copy(
        update={
            "findings": [
                Finding(
                    rule_id="ML-1",
                    layer=DetectionLayer.ML_ENSEMBLE,
                    category=Category.PROMPT_INJECTION,
                    severity=Severity.LOW,
                    message="out of scope",
                    location=Location(file_path="SKILL.md", start_line=1, end_line=1),
                )
            ]
        }
    )

    assert_scan_matches_expected(expectation, result)


def test_action_flag_assertions_match_selected_finding(
    build_expectation,
    assert_scan_matches_expected,
    empty_scan_result,
):
    expectation = build_expectation(
        verdict="SAFE",
        findings=[
            {
                "rule_id": "D-12A",
                "layer": "deterministic",
                "category": "suppression",
                "severity": "medium",
                "message": "suppression",
                "location": {"file_path": "SKILL.md", "start_line": 4, "end_line": 4},
            }
        ],
        action_flags_contains=[
            {
                "selector": {
                    "rule_id": "D-12A",
                    "file_path": "SKILL.md",
                    "start_line": 4,
                },
                "flags": ["SUPPRESSION_PRESENT", "SUPPRESS_DISCLOSURE"],
            }
        ],
    )
    result = empty_scan_result.model_copy(
        update={
            "findings": [
                Finding(
                    rule_id="D-12A",
                    layer=DetectionLayer.DETERMINISTIC,
                    category=Category.SUPPRESSION,
                    severity=Severity.MEDIUM,
                    message="suppression",
                    location=Location(file_path="SKILL.md", start_line=4, end_line=4),
                    action_flags=["SUPPRESSION_PRESENT", "SUPPRESS_DISCLOSURE"],
                )
            ]
        }
    )

    assert_scan_matches_expected(expectation, result)


def test_details_assertions_match_selected_finding(
    build_expectation,
    assert_scan_matches_expected,
    empty_scan_result,
):
    expectation = build_expectation(
        verdict="SAFE",
        findings=[
            {
                "rule_id": "D-12A",
                "layer": "deterministic",
                "category": "suppression",
                "severity": "medium",
                "message": "suppression",
                "location": {"file_path": "SKILL.md", "start_line": 4, "end_line": 4},
            }
        ],
        details_contains=[
            {
                "selector": {
                    "rule_id": "D-12A",
                    "file_path": "SKILL.md",
                    "start_line": 4,
                },
                "values": {"amplifier_eligible": True, "suppression_kind": "disclosure"},
            }
        ],
    )
    result = empty_scan_result.model_copy(
        update={
            "findings": [
                Finding(
                    rule_id="D-12A",
                    layer=DetectionLayer.DETERMINISTIC,
                    category=Category.SUPPRESSION,
                    severity=Severity.MEDIUM,
                    message="suppression",
                    location=Location(file_path="SKILL.md", start_line=4, end_line=4),
                    details={"amplifier_eligible": True, "suppression_kind": "disclosure"},
                )
            ]
        }
    )

    assert_scan_matches_expected(expectation, result)


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/unicode/D-1A-unicode-tags",
        "deterministic/unicode/D-1B-zero-width",
        "deterministic/unicode/D-1C-variation-selector",
        "deterministic/unicode/D-1D-rtlo",
        "deterministic/unicode/D-2A-homoglyph-command",
        "deterministic/unicode/D-6A-split-keyword",
        "deterministic/unicode/NC-3A-normalization-delta",
        "deterministic/unicode/safe-mixed-language-prose",
        "deterministic/unicode/safe-ascii-skill",
        "deterministic/unicode/safe-code-like-words",
    ],
)
def test_unicode_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)


def test_unicode_suite_indexes_positive_and_negative_epic3_fixtures(load_active_fixture_specs):
    specs = load_active_fixture_specs("deterministic")
    unicode_specs = [spec for spec in specs if spec.path.startswith("deterministic/unicode/")]

    assert {
        "deterministic/unicode/D-1A-unicode-tags",
        "deterministic/unicode/D-1B-zero-width",
        "deterministic/unicode/D-1C-variation-selector",
        "deterministic/unicode/D-1D-rtlo",
        "deterministic/unicode/D-2A-homoglyph-command",
        "deterministic/unicode/D-6A-split-keyword",
        "deterministic/unicode/NC-3A-normalization-delta",
        "deterministic/unicode/safe-ascii-skill",
        "deterministic/unicode/safe-mixed-language-prose",
        "deterministic/unicode/safe-code-like-words",
    }.issubset({spec.path for spec in unicode_specs})


def test_encoding_suite_indexes_positive_and_negative_epic4_fixtures(load_active_fixture_specs):
    specs = load_active_fixture_specs("deterministic")
    encoding_specs = [spec for spec in specs if spec.path.startswith("deterministic/encoding/")]

    assert {
        "deterministic/encoding/D-3-base64",
        "deterministic/encoding/D-4-rot13",
        "deterministic/encoding/D-5-hex-xor",
        "deterministic/encoding/D-21-html-comments",
        "deterministic/encoding/D-22-code-fences",
        "deterministic/encoding/nested-encoding",
    }.issubset({spec.path for spec in encoding_specs})


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/encoding/D-3-base64",
        "deterministic/encoding/D-4-rot13",
        "deterministic/encoding/D-5-hex-xor",
        "deterministic/encoding/D-21-html-comments",
        "deterministic/encoding/D-22-code-fences",
        "deterministic/encoding/nested-encoding",
        "deterministic/encoding/safe-benign-comments",
        "deterministic/encoding/safe-benign-fences",
        "deterministic/encoding/safe-base64-looking-text",
        "deterministic/encoding/safe-hex-looking-text",
    ],
)
def test_encoding_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/secrets/D-7-sensitive-files",
        "deterministic/secrets/D-7-metadata-endpoints",
        "deterministic/secrets/D-8-known-secret-vars",
        "deterministic/secrets/D-8-generic-env-enum",
        "deterministic/secrets/safe-docs-env-mention",
        "deterministic/secrets/safe-env-config",
    ],
)
def test_secrets_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/secrets/D-9-network-send",
        "deterministic/secrets/D-10-dynamic-exec",
        "deterministic/secrets/safe-health-check",
    ],
)
def test_behavioral_component_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/secrets/D-19-read-send-chain",
        "deterministic/secrets/D-19-read-exec-chain",
        "deterministic/secrets/D-19-metadata-send-chain",
    ],
)
def test_behavior_chain_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/injection/D-11A-instruction-override",
        "deterministic/injection/D-12A-nondisclosure",
        "deterministic/injection/D-13E-description-injection",
        "deterministic/injection/safe-ci-noninteractive",
    ],
)
def test_injection_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/structural/D-14-structure-validation",
        "deterministic/structural/D-15-actionable-url",
        "deterministic/structural/D-15-allowlisted-url",
        "deterministic/structural/D-20-typosquat",
        "deterministic/structural/safe-allowlisted-github-url",
    ],
)
def test_structural_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/temporal/D-16-time-bomb",
        "deterministic/temporal/D-17-persistence-write",
        "deterministic/temporal/D-18-cross-agent-target",
        "deterministic/temporal/D-18-auto-invocation",
        "deterministic/temporal/safe-datetime-logging",
    ],
)
def test_temporal_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)
