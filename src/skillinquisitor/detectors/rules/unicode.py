from __future__ import annotations

import re

from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import (
    Artifact,
    Category,
    DetectionLayer,
    Finding,
    Location,
    NormalizationType,
    ScanConfig,
    Segment,
    Severity,
    Skill,
)
from skillinquisitor.normalize import (
    BIDI_OVERRIDE_CHARS,
    VARIATION_SELECTORS,
    ZERO_WIDTH_CHARS,
)


UNICODE_TAG_RANGE = range(0xE0000, 0xE0080)
TOKEN_PATTERN = re.compile(r"\S+")


def register_unicode_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-1A",
        family_id="D-1",
        scope="segment",
        category=Category.STEGANOGRAPHY,
        severity=Severity.CRITICAL,
        description="Unicode tag characters detected",
        evaluator=_detect_unicode_tags,
        llm_verification_prompt="Unicode tag characters (U+E0000 range) were detected. These are invisible and almost always used for steganographic attacks. MALICIOUS in virtually all cases.",
    )
    registry.register(
        rule_id="D-1B",
        family_id="D-1",
        scope="segment",
        category=Category.STEGANOGRAPHY,
        severity=Severity.HIGH,
        description="Zero-width or invisible control characters detected",
        evaluator=_detect_zero_width,
        llm_verification_prompt="Zero-width characters were found splitting text. MALICIOUS if splitting dangerous keywords. SAFE if natural word-joiner in certain scripts.",
    )
    registry.register(
        rule_id="D-1C",
        family_id="D-1",
        scope="segment",
        category=Category.STEGANOGRAPHY,
        severity=Severity.HIGH,
        description="Variation selectors detected",
        evaluator=_detect_variation_selectors,
        llm_verification_prompt=(
            "Unicode variation selectors were detected.\n"
            "MALICIOUS if: used to split or disguise dangerous keywords\n"
            "SAFE if: natural occurrence in emoji sequences or font rendering hints"
        ),
    )
    registry.register(
        rule_id="D-1D",
        family_id="D-1",
        scope="segment",
        category=Category.STEGANOGRAPHY,
        severity=Severity.CRITICAL,
        description="Right-to-left or bidi override characters detected",
        evaluator=_detect_bidi_overrides,
        llm_verification_prompt="Right-to-left override character detected. MALICIOUS in virtually all cases — used to disguise file extensions.",
    )
    registry.register(
        rule_id="D-2A",
        family_id="D-2",
        scope="segment",
        category=Category.STEGANOGRAPHY,
        severity=Severity.HIGH,
        description="Mixed-script homoglyph pattern detected",
        evaluator=_detect_homoglyphs,
        llm_verification_prompt=(
            "Mixed-script characters were detected (e.g., Cyrillic letters in Latin text).\n"
            "MALICIOUS if: characters disguise package names (typosquatting) or hide commands\n"
            "SAFE if: text is legitimately multilingual (Russian, Greek, etc.)"
        ),
    )
    registry.register(
        rule_id="D-6A",
        family_id="D-6",
        scope="artifact",
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
        description="Dangerous keyword splitting detected",
        evaluator=_detect_keyword_splitting,
        llm_verification_prompt="Dangerous keyword splitting detected (e.g., e.v.a.l). MALICIOUS if the split word reconstructs a dangerous function name. SAFE if it's a natural abbreviation or domain name.",
    )
    registry.register(
        rule_id="NC-3A",
        family_id="NC-3",
        scope="artifact",
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
        description="Security-relevant normalization changed artifact content",
        evaluator=_detect_normalization_delta,
        llm_verification_prompt=(
            "Security-relevant normalization changed the content.\n"
            "MALICIOUS if: normalization revealed hidden content (invisible characters removed)\n"
            "SAFE if: minor formatting differences with no security impact"
        ),
    )


def _char_findings(
    segment: Segment,
    chars: set[str] | None,
    range_match: range | None,
    rule_id: str,
    severity: Severity,
    category: Category,
    message: str,
) -> list[Finding]:
    matched_indices: list[int] = []
    codepoints: list[str] = []
    for index, char in enumerate(segment.content):
        matches = char in chars if chars is not None else ord(char) in range_match  # type: ignore[arg-type]
        if not matches:
            continue
        matched_indices.append(index)
        codepoints.append(f"U+{ord(char):04X}")

    if not matched_indices:
        return []

    return [
        Finding(
            severity=severity,
            category=category,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id=rule_id,
            message=message,
            location=_location_for_index(segment, matched_indices[0]),
            details={"codepoints": codepoints, "count": len(matched_indices)},
        )
    ]


def _detect_unicode_tags(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    return _char_findings(
        segment,
        chars=None,
        range_match=UNICODE_TAG_RANGE,
        rule_id="D-1A",
        severity=Severity.CRITICAL,
        category=Category.STEGANOGRAPHY,
        message="Unicode tag characters detected",
    )


def _detect_zero_width(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    return _char_findings(
        segment,
        chars=ZERO_WIDTH_CHARS,
        range_match=None,
        rule_id="D-1B",
        severity=Severity.HIGH,
        category=Category.STEGANOGRAPHY,
        message="Zero-width or invisible control characters detected",
    )


def _detect_variation_selectors(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    return _char_findings(
        segment,
        chars=VARIATION_SELECTORS,
        range_match=None,
        rule_id="D-1C",
        severity=Severity.HIGH,
        category=Category.STEGANOGRAPHY,
        message="Variation selectors detected",
    )


def _detect_bidi_overrides(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    return _char_findings(
        segment,
        chars=BIDI_OVERRIDE_CHARS,
        range_match=None,
        rule_id="D-1D",
        severity=Severity.CRITICAL,
        category=Category.STEGANOGRAPHY,
        message="Right-to-left or bidi override characters detected",
    )


def _detect_homoglyphs(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for match in TOKEN_PATTERN.finditer(segment.content):
        token = match.group(0)
        if not any(_is_identifierish_char(char) for char in token):
            continue
        scripts = {_script_group(char) for char in token if _script_group(char) is not None}
        if len(scripts) < 2:
            continue
        if "latin" not in scripts and "fullwidth" not in scripts:
            continue
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=Category.STEGANOGRAPHY,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-2A",
                message="Mixed-script homoglyph pattern detected",
                location=_location_for_span(segment, match.start(), match.end() - 1),
                details={"token": token, "scripts": sorted(scripts)},
            )
        )
    return findings


def _detect_keyword_splitting(artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for transformation in artifact.normalization_transformations:
        if transformation.transformation_type != NormalizationType.KEYWORD_SPLITTER_COLLAPSE:
            continue
        keyword = str(transformation.details.get("keyword", transformation.normalized_snippet))
        family = str(transformation.details.get("family", "unknown"))
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=Category.OBFUSCATION,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-6A",
                message=f"Dangerous keyword splitting detected for {keyword}",
                location=transformation.location or _artifact_location(artifact),
                details={"family": family, "keyword": keyword},
            )
        )
    return findings


def _detect_normalization_delta(artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    relevant = [
        transformation
        for transformation in artifact.normalization_transformations
        if transformation.transformation_type
        in {
            NormalizationType.UNICODE_TAG,
            NormalizationType.ZERO_WIDTH_REMOVAL,
            NormalizationType.VARIATION_SELECTOR,
            NormalizationType.BIDI_OVERRIDE,
            NormalizationType.HOMOGLYPH_FOLD,
            NormalizationType.KEYWORD_SPLITTER_COLLAPSE,
        }
    ]
    if not relevant:
        return []

    return [
        Finding(
            severity=Severity.MEDIUM,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="NC-3A",
            message="Security-relevant normalization changed artifact content",
            location=_artifact_location(artifact),
            details={"transformations": [item.transformation_type.value for item in relevant]},
        )
    ]


def _artifact_location(artifact: Artifact):
    return artifact.segments[0].location if artifact.segments else Location(file_path=artifact.path)


def _location_for_index(segment: Segment, index: int):
    return _location_for_span(segment, index, index)


def _location_for_span(segment: Segment, start: int, end: int):
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


def _is_identifierish_char(char: str) -> bool:
    return char.isalnum() or char in "._-/\\:"


def _script_group(char: str) -> str | None:
    codepoint = ord(char)
    if char.isascii() and char.isalpha():
        return "latin"
    if 0x0400 <= codepoint <= 0x04FF:
        return "cyrillic"
    if 0x0370 <= codepoint <= 0x03FF:
        return "greek"
    if 0xFF01 <= codepoint <= 0xFF5E:
        return "fullwidth"
    return None
