from __future__ import annotations

import pytest

from skillinquisitor.formatters.console import format_console
from skillinquisitor.models import (
    Category,
    DetectionLayer,
    Finding,
    Location,
    ScanResult,
    Severity,
    Skill,
)


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
) -> Finding:
    kwargs: dict = dict(
        rule_id=rule_id,
        severity=severity,
        category=category,
        layer=layer,
        message=message,
        location=Location(file_path=file_path, start_line=start_line),
        action_flags=action_flags or [],
        references=references or [],
    )
    if finding_id is not None:
        kwargs["id"] = finding_id
    return Finding(**kwargs)


def _make_result(
    *,
    findings: list[Finding] | None = None,
    skills: list[Skill] | None = None,
    risk_score: int = 100,
    verdict: str = "SAFE",
    layer_metadata: dict | None = None,
) -> ScanResult:
    return ScanResult(
        skills=skills or [],
        findings=findings or [],
        risk_score=risk_score,
        verdict=verdict,
        layer_metadata=layer_metadata or {},
    )


class TestConsoleFormatter:
    def test_empty_findings_shows_safe(self):
        result = _make_result(
            verdict="SAFE",
            risk_score=100,
        )
        output = format_console(result)
        assert "SAFE" in output
        assert "100" in output
        assert "No findings" in output
        assert "0 findings" in output.lower()

    def test_findings_grouped_by_file(self):
        findings = [
            _make_finding(
                rule_id="D-1A",
                file_path="SKILL.md",
                start_line=1,
                message="unicode issue",
            ),
            _make_finding(
                rule_id="D-1B",
                file_path="SKILL.md",
                start_line=5,
                message="another unicode issue",
            ),
            _make_finding(
                rule_id="D-9A",
                file_path="scripts/run.py",
                start_line=3,
                message="network send",
            ),
        ]
        result = _make_result(
            findings=findings,
            verdict="HIGH RISK",
            risk_score=40,
        )
        output = format_console(result)
        # SKILL.md comes before scripts/run.py alphabetically
        skill_pos = output.index("SKILL.md")
        scripts_pos = output.index("scripts/run.py")
        assert skill_pos < scripts_pos

    def test_severity_sorted_within_file(self):
        findings = [
            _make_finding(
                rule_id="D-LOW",
                severity=Severity.LOW,
                file_path="SKILL.md",
                start_line=10,
                message="low severity",
            ),
            _make_finding(
                rule_id="D-CRIT",
                severity=Severity.CRITICAL,
                file_path="SKILL.md",
                start_line=5,
                message="critical severity",
            ),
        ]
        result = _make_result(findings=findings, verdict="CRITICAL RISK", risk_score=10)
        output = format_console(result)
        crit_pos = output.index("CRITICAL")
        # Find LOW after the header area (skip verdict line)
        lines = output.split("\n")
        finding_lines = [line for line in lines if "D-LOW" in line or "D-CRIT" in line]
        assert len(finding_lines) == 2
        # CRITICAL finding should come first
        assert finding_lines[0].find("D-CRIT") >= 0
        assert finding_lines[1].find("D-LOW") >= 0

    def test_summary_section_present(self):
        findings = [
            _make_finding(severity=Severity.HIGH, message="high one"),
            _make_finding(severity=Severity.HIGH, message="high two"),
            _make_finding(severity=Severity.LOW, message="low one"),
        ]
        result = _make_result(findings=findings, verdict="HIGH RISK", risk_score=50)
        output = format_console(result)
        lower = output.lower()
        assert "summary" in lower
        assert "high" in lower
        assert "low" in lower

    def test_chain_cross_references_shown(self):
        ref_finding = _make_finding(
            finding_id="ref-finding-1",
            rule_id="D-8A",
            file_path="SKILL.md",
            start_line=1,
            message="sensitive file read",
        )
        chain_finding = _make_finding(
            rule_id="D-19A",
            severity=Severity.CRITICAL,
            file_path="SKILL.md",
            start_line=1,
            message="data exfiltration chain",
            references=["ref-finding-1"],
        )
        result = _make_result(
            findings=[ref_finding, chain_finding],
            verdict="CRITICAL RISK",
            risk_score=5,
        )
        output = format_console(result)
        # The chain finding should show the referenced rule_id underneath
        assert "D-8A" in output
        # Tree connectors should appear
        assert any(c in output for c in ["├─", "└─"])

    def test_absorbed_finding_annotated(self):
        ref_finding = _make_finding(
            finding_id="absorbed-id",
            rule_id="D-8A",
            file_path="SKILL.md",
            start_line=1,
            message="sensitive file read",
        )
        chain_finding = _make_finding(
            rule_id="D-19A",
            severity=Severity.CRITICAL,
            file_path="SKILL.md",
            start_line=1,
            message="data exfiltration chain",
            references=["absorbed-id"],
        )
        result = _make_result(
            findings=[ref_finding, chain_finding],
            verdict="CRITICAL RISK",
            risk_score=5,
        )
        output = format_console(result)
        assert "Absorbed by chain" in output
        assert "D-19A" in output

    def test_suppression_indicator(self):
        finding = _make_finding(
            rule_id="D-12A",
            severity=Severity.HIGH,
            message="nondisclosure detected",
            action_flags=["SUPPRESSION_PRESENT", "SUPPRESS_DISCLOSURE"],
        )
        result = _make_result(findings=[finding], verdict="HIGH RISK", risk_score=30)
        output = format_console(result)
        assert "Suppression" in output

    def test_verbose_adds_scoring_details(self):
        result = _make_result(
            findings=[
                _make_finding(severity=Severity.HIGH, message="high one"),
            ],
            verdict="HIGH RISK",
            risk_score=80,
            layer_metadata={
                "scoring": {
                    "base_penalty": 20,
                    "suppression_multiplier": 1.0,
                    "absorbed_ids": [],
                    "final_score": 80,
                },
            },
        )
        output_normal = format_console(result)
        output_verbose = format_console(result, verbose=True)
        # verbose output should have scoring details that non-verbose does not
        assert "base_penalty" in output_verbose or "Scoring" in output_verbose
        # Normal output should not contain verbose scoring detail
        assert len(output_verbose) > len(output_normal)

    def test_header_shows_skill_names(self):
        skills = [Skill(path="/skills/helper", name="helper")]
        result = _make_result(skills=skills, verdict="SAFE", risk_score=100)
        output = format_console(result)
        assert "helper" in output

    def test_header_shows_file_count(self):
        skills = [Skill(path="/skills/helper", name="helper")]
        result = _make_result(
            skills=skills,
            findings=[_make_finding()],
            verdict="MEDIUM RISK",
            risk_score=70,
        )
        output = format_console(result)
        assert "1 finding" in output.lower()

    def test_finding_line_contains_line_number(self):
        finding = _make_finding(
            rule_id="D-1A",
            severity=Severity.HIGH,
            file_path="SKILL.md",
            start_line=42,
            message="test issue",
        )
        result = _make_result(findings=[finding], verdict="HIGH RISK", risk_score=60)
        output = format_console(result)
        assert ":42" in output

    def test_summary_counts_by_layer(self):
        findings = [
            _make_finding(
                layer=DetectionLayer.DETERMINISTIC,
                message="det finding",
            ),
            _make_finding(
                layer=DetectionLayer.ML_ENSEMBLE,
                message="ml finding",
            ),
        ]
        result = _make_result(findings=findings, verdict="HIGH RISK", risk_score=60)
        output = format_console(result)
        lower = output.lower()
        assert "deterministic" in lower
        assert "ml_ensemble" in lower

    def test_summary_counts_by_category(self):
        findings = [
            _make_finding(
                category=Category.PROMPT_INJECTION,
                message="pi finding",
            ),
            _make_finding(
                category=Category.DATA_EXFILTRATION,
                message="exfil finding",
            ),
        ]
        result = _make_result(findings=findings, verdict="HIGH RISK", risk_score=60)
        output = format_console(result)
        lower = output.lower()
        assert "prompt_injection" in lower
        assert "data_exfiltration" in lower
