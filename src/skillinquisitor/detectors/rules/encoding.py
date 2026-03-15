from __future__ import annotations

from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import Artifact, Category, Finding, ScanConfig, Segment, Severity, Skill


def register_encoding_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-3A",
        family_id="D-3",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="Suspicious Base64 payload detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-4A",
        family_id="D-4",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
        description="Explicit ROT13 reference detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-4B",
        family_id="D-4",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="ROT13-transformed content revealed suspicious patterns",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-5A",
        family_id="D-5",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="Suspicious hex payload detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-5B",
        family_id="D-5",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="XOR decode construct detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-5C",
        family_id="D-5",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="Multi-layer encoding chain detected",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-21A",
        family_id="D-21",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
        description="Suspicious content originated from an HTML comment",
        evaluator=_noop_segment_rule,
    )
    registry.register(
        rule_id="D-22A",
        family_id="D-22",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
        description="Suspicious content originated from a code fence",
        evaluator=_noop_segment_rule,
    )


def _noop_segment_rule(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    return []
