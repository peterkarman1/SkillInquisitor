"""Tests for output formatters (Epic 11)."""

from __future__ import annotations

import json

import pytest

from skillinquisitor.formatters.console import format_console
from skillinquisitor.formatters.json import format_json
from skillinquisitor.models import (
    AdjudicationResult,
    Artifact,
    Category,
    DetectionLayer,
    Finding,
    Location,
    RiskLabel,
    ScanResult,
    Segment,
    SegmentType,
    Severity,
    Skill,
)


# -- Helpers ----------------------------------------------------------------


def _make_finding(
    *,
    rule_id: str = "D-TEST",
    severity: Severity = Severity.MEDIUM,
    category: Category = Category.STRUCTURAL,
    layer: DetectionLayer = DetectionLayer.DETERMINISTIC,
    message: str = "test finding",
    file_path: str = "SKILL.md",
    start_line: int | None = 1,
    action_flags: list[str] | None = None,
    references: list[str] | None = None,
    finding_id: str | None = None,
    confidence: float | None = None,
    details: dict | None = None,
) -> Finding:
    kwargs: dict = dict(
        rule_id=rule_id,
        severity=severity,
        category=category,
        layer=layer,
        message=message,
        location=Location(file_path=file_path, start_line=start_line, end_line=start_line),
        action_flags=action_flags or [],
        references=references or [],
        confidence=confidence,
        details=details or {},
    )
    if finding_id is not None:
        kwargs["id"] = finding_id
    return Finding(**kwargs)


def _make_result(
    *,
    findings: list[Finding] | None = None,
    skills: list[Skill] | None = None,
    risk_label: RiskLabel = RiskLabel.LOW,
    binary_label: str = "not_malicious",
    layer_metadata: dict | None = None,
    total_timing: float = 1.23,
) -> ScanResult:
    return ScanResult(
        skills=skills or [Skill(path="/tmp/test-skill", name="test-skill")],
        findings=findings or [],
        risk_label=risk_label,
        binary_label=binary_label,
        adjudication=AdjudicationResult(
            risk_label=risk_label,
            summary="formatter test summary",
            rationale="formatter test rationale",
        ).model_dump(mode="python"),
        layer_metadata=layer_metadata or {},
        total_timing=total_timing,
    )


def _make_scan_result_with_findings() -> ScanResult:
    """Build a ScanResult that contains artifacts/segments/raw content and findings."""
    skill = Skill(
        path="/tmp/test-skill",
        name="data-helper",
        artifacts=[
            Artifact(
                path="SKILL.md",
                raw_content="# This is raw markdown content\nDo bad things.",
                normalized_content="# This is normalized content",
                segments=[
                    Segment(
                        id="seg-1",
                        content="segment body",
                        segment_type=SegmentType.ORIGINAL,
                    )
                ],
            )
        ],
    )
    finding = Finding(
        id="f-001",
        severity=Severity.CRITICAL,
        category=Category.DATA_EXFILTRATION,
        layer=DetectionLayer.DETERMINISTIC,
        rule_id="D-19A",
        message="Behavior chain detected: Data Exfiltration",
        location=Location(file_path="SKILL.md", start_line=1, end_line=1),
        confidence=1.0,
        action_flags=["READ_SENSITIVE", "NETWORK_SEND"],
        references=["https://example.com/threat"],
        details={"chain_name": "Data Exfiltration"},
    )
    return ScanResult(
        skills=[skill],
        findings=[finding],
        risk_label=RiskLabel.HIGH,
        binary_label="malicious",
        adjudication=AdjudicationResult(
            risk_label=RiskLabel.HIGH,
            summary="high risk summary",
            rationale="high risk rationale",
        ).model_dump(mode="python"),
        layer_metadata={"deterministic": {"enabled": True, "findings": 1}},
        total_timing=1.23,
    )


# -- Console Formatter Tests ------------------------------------------------


class TestConsoleFormatter:
    def test_empty_findings_shows_low_risk_label(self):
        result = _make_result()
        output = format_console(result)
        assert "Risk label: LOW" in output
        assert "Binary label: not_malicious" in output
        assert "No findings" in output

    def test_findings_grouped_by_file(self):
        findings = [
            _make_finding(rule_id="D-1A", file_path="SKILL.md", start_line=1, message="unicode issue"),
            _make_finding(rule_id="D-1B", file_path="SKILL.md", start_line=5, message="another unicode issue"),
            _make_finding(rule_id="D-9A", file_path="scripts/run.py", start_line=3, message="network send"),
        ]
        result = _make_result(findings=findings, risk_label=RiskLabel.HIGH, binary_label="malicious")
        output = format_console(result)
        skill_pos = output.index("SKILL.md")
        scripts_pos = output.index("scripts/run.py")
        assert skill_pos < scripts_pos

    def test_severity_sorted_within_file(self):
        findings = [
            _make_finding(rule_id="D-LOW", severity=Severity.LOW, file_path="SKILL.md", start_line=10, message="low severity"),
            _make_finding(rule_id="D-CRIT", severity=Severity.CRITICAL, file_path="SKILL.md", start_line=5, message="critical severity"),
        ]
        result = _make_result(findings=findings, risk_label=RiskLabel.CRITICAL, binary_label="malicious")
        output = format_console(result)
        lines = output.split("\n")
        finding_lines = [line for line in lines if "D-LOW" in line or "D-CRIT" in line]
        assert len(finding_lines) == 2
        assert finding_lines[0].find("D-CRIT") >= 0
        assert finding_lines[1].find("D-LOW") >= 0

    def test_summary_section_present(self):
        findings = [
            _make_finding(severity=Severity.HIGH, message="high one"),
            _make_finding(severity=Severity.HIGH, message="high two"),
            _make_finding(severity=Severity.LOW, message="low one"),
        ]
        result = _make_result(findings=findings, risk_label=RiskLabel.HIGH, binary_label="malicious")
        output = format_console(result)
        lower = output.lower()
        assert "summary" in lower

    def test_chain_cross_references_shown(self):
        ref_finding = _make_finding(finding_id="ref-1", rule_id="D-8A", message="sensitive file read")
        chain_finding = _make_finding(
            rule_id="D-19A", severity=Severity.CRITICAL, message="data exfiltration chain",
            references=["ref-1"],
        )
        result = _make_result(findings=[ref_finding, chain_finding], risk_label=RiskLabel.CRITICAL, binary_label="malicious")
        output = format_console(result)
        assert "D-8A" in output
        assert any(c in output for c in ["├─", "└─"])

    def test_absorbed_finding_annotated(self):
        ref_finding = _make_finding(finding_id="absorbed-id", rule_id="D-8A", message="sensitive file read")
        chain_finding = _make_finding(
            rule_id="D-19A", severity=Severity.CRITICAL, message="data exfiltration chain",
            references=["absorbed-id"],
        )
        result = _make_result(findings=[ref_finding, chain_finding], risk_label=RiskLabel.CRITICAL, binary_label="malicious")
        output = format_console(result)
        assert "Absorbed by chain" in output

    def test_suppression_indicator(self):
        finding = _make_finding(
            rule_id="D-12A", severity=Severity.HIGH, message="nondisclosure",
            action_flags=["SUPPRESSION_PRESENT"],
        )
        result = _make_result(findings=[finding], risk_label=RiskLabel.HIGH, binary_label="malicious")
        output = format_console(result)
        assert "Suppression" in output

    def test_verbose_no_longer_differs(self):
        """After removing legacy scoring details, verbose produces same output."""
        result = _make_result(
            findings=[_make_finding(severity=Severity.HIGH, message="high one")],
            risk_label=RiskLabel.HIGH,
            binary_label="malicious",
        )
        output_normal = format_console(result)
        output_verbose = format_console(result, verbose=True)
        assert output_verbose == output_normal


# -- JSON Formatter Tests ---------------------------------------------------


class TestJSONFormatter:
    def test_valid_json_output(self):
        result = _make_scan_result_with_findings()
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["risk_label"] == "HIGH"
        assert parsed["binary_label"] == "malicious"
        assert "verdict" not in parsed
        assert "risk_score" not in parsed

    def test_includes_summary(self):
        result = _make_scan_result_with_findings()
        parsed = json.loads(format_json(result))
        summary = parsed["summary"]
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 0
        assert summary["by_layer"]["deterministic"] == 1
        assert summary["by_category"]["data_exfiltration"] == 1

    def test_no_raw_content_in_output(self):
        result = _make_scan_result_with_findings()
        output = format_json(result)
        assert "raw_content" not in output
        assert "normalized_content" not in output
        assert "segments" not in output

    def test_skills_have_path_and_name_only(self):
        result = _make_scan_result_with_findings()
        parsed = json.loads(format_json(result))
        for skill in parsed["skills"]:
            assert set(skill.keys()) == {"path", "name"}

    def test_version_field_present(self):
        parsed = json.loads(format_json(_make_scan_result_with_findings()))
        assert parsed["version"] == "1.0"

    def test_findings_include_all_fields(self):
        parsed = json.loads(format_json(_make_scan_result_with_findings()))
        required_keys = {"id", "severity", "category", "layer", "rule_id", "message",
                         "location", "confidence", "action_flags", "references", "details"}
        for finding in parsed["findings"]:
            assert required_keys.issubset(set(finding.keys()))

    def test_empty_findings_still_has_summary(self):
        result = _make_result()
        parsed = json.loads(format_json(result))
        assert parsed["findings"] == []
        assert all(v == 0 for v in parsed["summary"]["by_severity"].values())

    def test_finding_severity_is_string_value(self):
        parsed = json.loads(format_json(_make_scan_result_with_findings()))
        assert parsed["findings"][0]["severity"] == "critical"
        assert parsed["findings"][0]["layer"] == "deterministic"
