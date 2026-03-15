from __future__ import annotations

import re

from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import (
    Artifact,
    Category,
    DetectionLayer,
    Finding,
    ScanConfig,
    Segment,
    SegmentType,
    Severity,
    Skill,
)


ROT13_REFERENCE_PATTERN = re.compile(r"\brot(?:_|)13\b", re.IGNORECASE)
HEX_PATTERN = re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE)
XOR_PATTERN = re.compile(r"chr\s*\(\s*ord\s*\(\s*\w+\s*\)\s*\^\s*\d+\s*\)", re.IGNORECASE)
SUSPICIOUS_PATTERN = re.compile(
    r"ignore previous instructions|eval|exec|subprocess|curl|wget|requests|urllib",
    re.IGNORECASE,
)


def register_encoding_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-3A",
        family_id="D-3",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="Suspicious Base64 payload detected",
        evaluator=_detect_base64_payload,
    )
    registry.register(
        rule_id="D-4A",
        family_id="D-4",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
        description="Explicit ROT13 reference detected",
        evaluator=_detect_rot13_reference,
    )
    registry.register(
        rule_id="D-4B",
        family_id="D-4",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="ROT13-transformed content revealed suspicious patterns",
        evaluator=_detect_rot13_suspicious_content,
    )
    registry.register(
        rule_id="D-5A",
        family_id="D-5",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="Suspicious hex payload detected",
        evaluator=_detect_hex_payload,
    )
    registry.register(
        rule_id="D-5B",
        family_id="D-5",
        scope="segment",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="XOR decode construct detected",
        evaluator=_detect_xor_construct,
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


def _detect_base64_payload(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    if segment.segment_type != SegmentType.BASE64_DECODE:
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-3A",
            message="Suspicious Base64 payload detected",
            location=segment.location,
            segment_id=segment.id,
            details=segment.details,
        )
    ]


def _detect_rot13_reference(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    if ROT13_REFERENCE_PATTERN.search(segment.content) is None:
        return []
    return [
        Finding(
            severity=Severity.MEDIUM,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-4A",
            message="Explicit ROT13 reference detected",
            location=segment.location,
            segment_id=segment.id,
        )
    ]


def _detect_rot13_suspicious_content(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    content = segment.normalized_content or segment.content
    if segment.segment_type != SegmentType.ROT13_TRANSFORM or SUSPICIOUS_PATTERN.search(content) is None:
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-4B",
            message="ROT13-transformed content revealed suspicious patterns",
            location=segment.location,
            segment_id=segment.id,
        )
    ]


def _detect_hex_payload(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    content = segment.content if segment.segment_type != SegmentType.HEX_DECODE else segment.details.get("source_preview", "")
    if segment.segment_type != SegmentType.HEX_DECODE and HEX_PATTERN.search(content) is None:
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-5A",
            message="Suspicious hex payload detected",
            location=segment.location,
            segment_id=segment.id,
        )
    ]


def _detect_xor_construct(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    if XOR_PATTERN.search(segment.content) is None:
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-5B",
            message="XOR decode construct detected",
            location=segment.location,
            segment_id=segment.id,
        )
    ]
