from __future__ import annotations

from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import Artifact, Category, Finding, ScanConfig, Segment, Severity, Skill


def register_behavioral_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-9A",
        family_id="D-9",
        scope="segment",
        category=Category.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        description="Outbound network send behavior detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-10A",
        family_id="D-10",
        scope="segment",
        category=Category.BEHAVIORAL,
        severity=Severity.HIGH,
        description="Dynamic or shell execution behavior detected",
        evaluator=_noop_segment_rule,
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


def run_behavioral_postprocessors(
    skills: list[Skill],
    findings: list[Finding],
    config: ScanConfig,
    only_rule_id: str | None = None,
) -> list[Finding]:
    return []
