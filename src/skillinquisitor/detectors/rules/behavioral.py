from __future__ import annotations

import re

from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import (
    Artifact,
    Category,
    DetectionLayer,
    FileType,
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
MARKDOWN_SEND_PATTERN = re.compile(r"\b(send|post|upload|exfiltrate)\b.*https?://", re.IGNORECASE)
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
]
CHAIN_RULE_IDS = {"D-19A", "D-19B", "D-19C"}
CHAIN_MESSAGES = {
    "Data Exfiltration": "Behavior chain detected: Data Exfiltration",
    "Credential Theft": "Behavior chain detected: Credential Theft",
    "Cloud Metadata SSRF": "Behavior chain detected: Cloud Metadata SSRF",
}
CHAIN_RULE_IDS_BY_NAME = {
    "Data Exfiltration": "D-19A",
    "Credential Theft": "D-19B",
    "Cloud Metadata SSRF": "D-19C",
}
CHAIN_CATEGORIES = {
    "D-19A": Category.DATA_EXFILTRATION,
    "D-19B": Category.CREDENTIAL_THEFT,
    "D-19C": Category.DATA_EXFILTRATION,
}


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
        soft=True,
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
    if artifact.file_type == FileType.MARKDOWN:
        for match in MARKDOWN_SEND_PATTERN.finditer(segment.content):
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
                    details={"target": match.group(0), "source_kind": "markdown"},
                )
            )
        return findings

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
                    details={"target": match.group(0), "source_kind": _source_kind(artifact)},
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
                    details={"target": match.group(0), "source_kind": _source_kind(artifact)},
                )
            )
    return findings


def run_behavioral_postprocessors(
    skills: list[Skill],
    findings: list[Finding],
    config: ScanConfig,
    only_rule_id: str | None = None,
) -> list[Finding]:
    chain_findings: list[Finding] = []
    for skill in skills:
        component_findings = [
            finding for finding in findings if _finding_belongs_to_skill(finding, skill)
        ]
        for chain in config.chains:
            rule_id = CHAIN_RULE_IDS_BY_NAME.get(chain.name)
            if rule_id is None:
                continue
            if only_rule_id is not None and rule_id != only_rule_id:
                continue
            matched = _select_component_evidence(component_findings, chain.required)
            if matched is None:
                continue
            chain_findings.append(_build_chain_finding(skill, chain.name, rule_id, chain.severity, matched))
    return chain_findings


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


def _select_component_evidence(
    findings: list[Finding],
    required_flags: list[str],
) -> list[Finding] | None:
    matched: list[Finding] = []
    for required_flag in required_flags:
        candidate = next(
            (finding for finding in findings if required_flag in finding.action_flags),
            None,
        )
        if candidate is None:
            return None
        matched.append(candidate)
    return matched


def _build_chain_finding(
    skill: Skill,
    chain_name: str,
    rule_id: str,
    default_severity: Severity,
    component_findings: list[Finding],
) -> Finding:
    source_kinds = [str(finding.details.get("source_kind", "code")) for finding in component_findings]
    severity = Severity.HIGH if all(kind == "markdown" for kind in source_kinds) else default_severity
    anchor = _skill_anchor_location(skill)

    return Finding(
        severity=severity,
        category=CHAIN_CATEGORIES[rule_id],
        layer=DetectionLayer.DETERMINISTIC,
        rule_id=rule_id,
        message=CHAIN_MESSAGES[chain_name],
        location=anchor,
        references=[finding.id for finding in component_findings],
        details={
            "source_kinds": source_kinds,
            "files": sorted({finding.location.file_path for finding in component_findings}),
            "actions": sorted({flag for finding in component_findings for flag in finding.action_flags}),
        },
    )


def _skill_anchor_location(skill: Skill) -> Location:
    skill_md_artifact = next(
        (artifact for artifact in skill.artifacts if artifact.path.endswith("SKILL.md") and artifact.segments),
        None,
    )
    if skill_md_artifact is not None:
        return skill_md_artifact.segments[0].location.model_copy(
            update={"start_line": 1, "end_line": 1, "start_col": 1, "end_col": 1}
        )

    if skill.artifacts and skill.artifacts[0].segments:
        return skill.artifacts[0].segments[0].location

    return Location(file_path=skill.path, start_line=1, end_line=1)


def _finding_belongs_to_skill(finding: Finding, skill: Skill) -> bool:
    file_path = finding.location.file_path
    if not file_path:
        return False
    return file_path.startswith(skill.path)


def _source_kind(artifact: Artifact) -> str:
    if artifact.file_type == FileType.MARKDOWN:
        return "markdown"
    return "code"
