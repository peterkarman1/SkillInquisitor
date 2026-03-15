from __future__ import annotations

import re

from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import (
    Artifact,
    Category,
    DetectionLayer,
    Finding,
    Location,
    ScanConfig,
    Segment,
    Severity,
    Skill,
)


NETWORK_SEND_PATTERNS = [
    re.compile(r"requests\.(post|put|patch)\s*\(", re.IGNORECASE),
    re.compile(r"fetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|PATCH)[\"']", re.IGNORECASE),
    re.compile(r"\bcurl\b[^\n]*(?:\s-\w*d|\s--data|\s--form)", re.IGNORECASE),
    re.compile(r"\bwget\b[^\n]*--post-data", re.IGNORECASE),
    re.compile(r"socket\.send(?:all)?\s*\(", re.IGNORECASE),
]
EXEC_PATTERNS = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\bcompile\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\.", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"\bpopen\s*\(", re.IGNORECASE),
    re.compile(r"\bbash\s+-c\b", re.IGNORECASE),
    re.compile(r"\bsh\s+-c\b", re.IGNORECASE),
    re.compile(r"`[^`\n]+`"),
]


def register_behavioral_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-9A",
        family_id="D-9",
        scope="segment",
        category=Category.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        description="Outbound network send behavior detected",
        evaluator=_detect_network_send,
    )
    registry.register(
        rule_id="D-10A",
        family_id="D-10",
        scope="segment",
        category=Category.BEHAVIORAL,
        severity=Severity.HIGH,
        description="Dynamic or shell execution behavior detected",
        evaluator=_detect_exec_dynamic,
    )
    registry.register(
        rule_id="D-19A",
        family_id="D-19",
        scope="segment",
        category=Category.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        description="Behavior chain detected: Data Exfiltration",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-19B",
        family_id="D-19",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.CRITICAL,
        description="Behavior chain detected: Credential Theft",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-19C",
        family_id="D-19",
        scope="segment",
        category=Category.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        description="Behavior chain detected: Cloud Metadata SSRF",
        evaluator=_noop_segment_rule,
    )


def _noop_segment_rule(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    return []


def _detect_network_send(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    for pattern in NETWORK_SEND_PATTERNS:
        for match in pattern.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=Category.DATA_EXFILTRATION,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-9A",
                    message="Outbound network send behavior detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["NETWORK_SEND"],
                    details={"target": match.group(0)},
                )
            )
    return findings


def _detect_exec_dynamic(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    for pattern in EXEC_PATTERNS:
        for match in pattern.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.BEHAVIORAL,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-10A",
                    message="Dynamic or shell execution behavior detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["EXEC_DYNAMIC"],
                    details={"target": match.group(0)},
                )
            )
    return findings


def run_behavioral_postprocessors(
    skills: list[Skill],
    findings: list[Finding],
    config: ScanConfig,
    only_rule_id: str | None = None,
) -> list[Finding]:
    return []


def _location_for_span(segment: Segment, start: int, end: int) -> Location:
    content = segment.content
    start_line = content.count("\n", 0, start) + 1
    end_line = content.count("\n", 0, end + 1) + 1
    start_offset = content.rfind("\n", 0, start)
    end_offset = content.rfind("\n", 0, end + 1)
    start_col = start + 1 if start_offset == -1 else start - start_offset
    end_col = end + 1 if end_offset == -1 else end - end_offset
    return segment.location.model_copy(
        update={
            "start_line": start_line,
            "end_line": end_line,
            "start_col": start_col,
            "end_col": end_col,
        }
    )
