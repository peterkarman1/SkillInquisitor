"""Tests for SARIF 2.1.0 formatter."""

from __future__ import annotations

import json

import pytest

from skillinquisitor.formatters.sarif import format_sarif
from skillinquisitor.models import (
    AdjudicationResult,
    Category,
    DetectionLayer,
    Finding,
    Location,
    RiskLabel,
    ScanResult,
    Severity,
    Skill,
)

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)


def _make_result(
    findings: list[Finding] | None = None,
    risk_score: int = 0,
    verdict: str = "LOW RISK",
) -> ScanResult:
    risk_label = (
        RiskLabel.CRITICAL if verdict == "CRITICAL"
        else RiskLabel.HIGH if verdict == "HIGH RISK"
        else RiskLabel.MEDIUM if verdict == "MEDIUM RISK"
        else RiskLabel.LOW
    )
    return ScanResult(
        skills=[Skill(path="test-skill", name="test-skill")],
        findings=findings or [],
        risk_score=risk_score,
        verdict=verdict,
        risk_label=risk_label,
        binary_label="malicious" if risk_label in {RiskLabel.HIGH, RiskLabel.CRITICAL} else "not_malicious",
        adjudication=AdjudicationResult(
            risk_label=risk_label,
            summary="sarif test summary",
            rationale="sarif test rationale",
        ).model_dump(mode="python"),
    )


class TestSARIFFormatter:
    def test_valid_sarif_structure(self):
        """Has $schema, version '2.1.0', runs array with 1 element."""
        result = _make_result()
        output = format_sarif(result)
        sarif = json.loads(output)

        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == "2.1.0"
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

    def test_tool_driver_info(self):
        """driver.name == 'SkillInquisitor'."""
        result = _make_result()
        sarif = json.loads(format_sarif(result))

        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "SkillInquisitor"
        assert "informationUri" in driver
        assert isinstance(driver["rules"], list)

    def test_findings_map_to_results(self):
        """1 HIGH finding maps to 1 result with ruleId and level 'error'."""
        finding = Finding(
            severity=Severity.HIGH,
            category=Category.DATA_EXFILTRATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-9A",
            message="Network send detected",
            location=Location(file_path="scripts/send.py", start_line=5, end_line=5),
        )
        result = _make_result(findings=[finding], risk_score=20, verdict="HIGH RISK")
        sarif = json.loads(format_sarif(result))

        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "D-9A"
        assert results[0]["level"] == "error"
        assert results[0]["message"]["text"] == "Network send detected"

    def test_severity_to_level_mapping(self):
        """CRITICAL->error, HIGH->error, MEDIUM->warning, LOW->note, INFO->note."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        for severity, expected_level in mapping.items():
            finding = Finding(
                severity=severity,
                category=Category.STRUCTURAL,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id=f"TEST-{severity.value}",
                message=f"Test {severity.value}",
                location=Location(file_path="test.md"),
            )
            result = _make_result(findings=[finding])
            sarif = json.loads(format_sarif(result))
            actual_level = sarif["runs"][0]["results"][0]["level"]
            assert actual_level == expected_level, (
                f"Severity {severity.value} should map to level '{expected_level}', "
                f"got '{actual_level}'"
            )

    def test_chain_includes_related_locations(self):
        """Chain finding with references includes relatedLocations array."""
        read_finding = Finding(
            severity=Severity.HIGH,
            category=Category.CREDENTIAL_THEFT,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-7A",
            message="Sensitive file read",
            location=Location(file_path="scripts/read.py", start_line=3, end_line=3),
        )
        send_finding = Finding(
            severity=Severity.MEDIUM,
            category=Category.DATA_EXFILTRATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-9A",
            message="Network send",
            location=Location(file_path="scripts/send.py", start_line=10, end_line=10),
        )
        chain_finding = Finding(
            severity=Severity.CRITICAL,
            category=Category.DATA_EXFILTRATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-19A",
            message="Behavior chain detected: Data Exfiltration",
            location=Location(file_path="SKILL.md", start_line=1, end_line=1),
            references=[read_finding.id, send_finding.id],
        )
        result = _make_result(
            findings=[read_finding, send_finding, chain_finding],
            risk_score=39,
            verdict="HIGH RISK",
        )
        sarif = json.loads(format_sarif(result))

        chain_result = [
            r for r in sarif["runs"][0]["results"] if r["ruleId"] == "D-19A"
        ][0]
        assert "relatedLocations" in chain_result
        related = chain_result["relatedLocations"]
        assert len(related) == 2
        # Each related location should have an id and physicalLocation
        for loc in related:
            assert "id" in loc
            assert "physicalLocation" in loc

    def test_rules_array_populated(self):
        """Unique rule_ids produce rules array in driver."""
        findings = [
            Finding(
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_THEFT,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-7A",
                message="Sensitive file read",
                location=Location(file_path="scripts/read.py", start_line=3),
            ),
            Finding(
                severity=Severity.MEDIUM,
                category=Category.DATA_EXFILTRATION,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-9A",
                message="Network send",
                location=Location(file_path="scripts/send.py", start_line=10),
            ),
            Finding(
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_THEFT,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-7A",
                message="Another sensitive file read",
                location=Location(file_path="scripts/read2.py", start_line=1),
            ),
        ]
        result = _make_result(findings=findings)
        sarif = json.loads(format_sarif(result))

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        # Should have 2 unique rules, not 3
        assert len(rules) == 2
        assert "D-7A" in rule_ids
        assert "D-9A" in rule_ids

    def test_empty_findings(self):
        """0 findings produces empty results array, still valid SARIF."""
        result = _make_result(findings=[], risk_score=0, verdict="LOW RISK")
        sarif = json.loads(format_sarif(result))

        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_invocation_properties(self):
        """invocations[0].properties has verdict and risk_score."""
        result = _make_result(risk_score=42, verdict="HIGH RISK")
        sarif = json.loads(format_sarif(result))

        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
        props = invocations[0]["properties"]["skillinquisitor"]
        assert props["risk_label"] == "HIGH"
        assert props["binary_label"] == "malicious"
        assert props["verdict"] == "HIGH RISK"
        assert props["risk_score"] == 42

    def test_location_region_fields(self):
        """Region includes startLine, endLine, startColumn, endColumn when present."""
        finding = Finding(
            severity=Severity.MEDIUM,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-5A",
            message="Obfuscation detected",
            location=Location(
                file_path="test.py",
                start_line=10,
                end_line=15,
                start_col=5,
                end_col=20,
            ),
        )
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))

        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 10
        assert region["endLine"] == 15
        assert region["startColumn"] == 5
        assert region["endColumn"] == 20

    def test_location_region_omits_none_fields(self):
        """Region fields that are None are not emitted."""
        finding = Finding(
            severity=Severity.LOW,
            category=Category.STRUCTURAL,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-1A",
            message="Structural issue",
            location=Location(file_path="test.md", start_line=3),
        )
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))

        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 3
        assert "endLine" not in region
        assert "startColumn" not in region
        assert "endColumn" not in region

    def test_confidence_maps_to_rank(self):
        """confidence maps to rank property as confidence * 100."""
        finding = Finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-1",
            message="Prompt injection detected",
            location=Location(file_path="SKILL.md", start_line=1),
            confidence=0.87,
        )
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))

        sarif_result = sarif["runs"][0]["results"][0]
        assert sarif_result["rank"] == 87.0

    def test_no_confidence_omits_rank(self):
        """When confidence is None, rank is not emitted."""
        finding = Finding(
            severity=Severity.HIGH,
            category=Category.STRUCTURAL,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-1A",
            message="Test",
            location=Location(file_path="test.md"),
        )
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))

        sarif_result = sarif["runs"][0]["results"][0]
        assert "rank" not in sarif_result

    def test_properties_include_layer_and_details(self):
        """Result properties include severity, category, layer, and details."""
        finding = Finding(
            severity=Severity.HIGH,
            category=Category.DATA_EXFILTRATION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-1",
            message="Exfil detected",
            location=Location(file_path="SKILL.md", start_line=1),
            action_flags=["NETWORK_SEND"],
            details={"model_scores": {"model_a": 0.9}},
        )
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))

        props = sarif["runs"][0]["results"][0]["properties"]["skillinquisitor"]
        assert props["severity"] == "high"
        assert props["category"] == "data_exfiltration"
        assert props["layer"] == "ml_ensemble"
        assert props["action_flags"] == ["NETWORK_SEND"]

    def test_rule_default_configuration_level(self):
        """Rules have correct defaultConfiguration level matching severity."""
        finding = Finding(
            severity=Severity.CRITICAL,
            category=Category.DATA_EXFILTRATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-19A",
            message="Chain detected",
            location=Location(file_path="SKILL.md"),
        )
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "D-19A"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["skillinquisitor"]["category"] == "data_exfiltration"
        assert rule["properties"]["skillinquisitor"]["severity"] == "critical"

    def test_output_is_valid_json_string(self):
        """format_sarif returns a valid JSON string."""
        result = _make_result()
        output = format_sarif(result)
        assert isinstance(output, str)
        # Should not raise
        parsed = json.loads(output)
        assert isinstance(parsed, dict)
