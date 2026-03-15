from __future__ import annotations

from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import Artifact, Category, ScanConfig, Segment, Severity, Skill


def register_secrets_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-7A",
        family_id="D-7",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Sensitive credential path reference detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-7B",
        family_id="D-7",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Cloud metadata endpoint reference or access detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-8A",
        family_id="D-8",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Known secret environment variable reference detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-8B",
        family_id="D-8",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.MEDIUM,
        description="Suspicious environment access or enumeration detected",
        evaluator=_noop_segment_rule,
    )


def _noop_segment_rule(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    return []
