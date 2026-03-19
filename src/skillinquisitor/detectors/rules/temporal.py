from __future__ import annotations

import re

from skillinquisitor.detectors.rules.context import (
    classify_segment_context,
    is_environment_bootstrap,
    is_reference_example,
)
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
    SegmentType,
    Severity,
    Skill,
)


TIME_CONDITIONAL_PATTERNS = [
    re.compile(r"\bif\b[^\n]*(?:datetime\.now\(\)|date\.today\(\)|time\.time\(\)|weekday\(\))", re.IGNORECASE),
    re.compile(r"\b(?:when|if)\b[^\n]*(?:today|weekend|weekday|saturday|sunday|monday|tuesday|wednesday|thursday|friday)\b", re.IGNORECASE),
]
ENV_CONDITIONAL_PATTERNS = [
    re.compile(r"\bif\b[^\n]*\b(?:CI|GITHUB_ACTIONS|SANDBOX)\b", re.IGNORECASE),
    re.compile(r"os\.getenv\([\"'](?:CI|GITHUB_ACTIONS|SANDBOX)[\"']\)", re.IGNORECASE),
]
COUNTER_STATE_PATTERNS = [
    re.compile(r"\bif\b[^\n]*\b(?:run_count|counter|invocation_count|marker_file|state_file)\b", re.IGNORECASE),
    re.compile(r"\b(?:write|append|touch|open)\b[^\n]*(?:\.state|\.stamp|\.count|marker)", re.IGNORECASE),
]

WRITE_VERBS = r"(?:write|append|install|replace|save|drop|update|tee|echo|cat >|touch)"
CROSS_AGENT_VERBS = r"(?:write|append|install|replace|save|drop|update|tee|echo|cat >|touch|copy|sync|mirror|replicate|clone)"
WRITE_SPAN = r"[\s\S]{0,240}?"
PERSISTENCE_TARGET_PATTERNS = [
    re.compile(rf"{WRITE_VERBS}{WRITE_SPAN}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|settings\.json)", re.IGNORECASE),
    re.compile(r"\bcreate\b[^\n]{0,120}(?:~|/|\$HOME|\.\/|\.\./)[^\n]{0,120}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|settings\.json)", re.IGNORECASE),
    re.compile(rf"{WRITE_VERBS}{WRITE_SPAN}(?:\.bashrc|\.profile|\.zshrc|crontab|/etc/cron|launchd|systemd|\.git/hooks)", re.IGNORECASE),
    re.compile(rf"(?:Path|open)\({WRITE_SPAN}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|settings\.json|\.bashrc|\.profile|\.zshrc|\.git/hooks)", re.IGNORECASE),
]

CROSS_AGENT_TARGET_PATTERNS = [
    re.compile(rf"{CROSS_AGENT_VERBS}{WRITE_SPAN}(?:\.claude|\.gemini|\.cursor|\.copilot|\.codex|\.agents|\.windsurf|\.clinerules)", re.IGNORECASE),
    re.compile(r"\bcreate\b[^\n]{0,120}(?:~|/|\$HOME|\.\/|\.\./)[^\n]{0,120}(?:\.claude|\.gemini|\.cursor|\.copilot|\.codex|\.agents|\.windsurf|\.clinerules)", re.IGNORECASE),
    re.compile(rf"(?:Path|open)\({WRITE_SPAN}(?:\.claude|\.gemini|\.cursor|\.copilot|\.codex|\.agents|\.windsurf|\.clinerules)", re.IGNORECASE),
]
GENERIC_DESCRIPTION_TERMS = {"help", "assist", "answer", "write", "build", "code", "debug", "review", "analyze", "explain", "create", "fix"}
BROAD_SCOPE_PATTERNS = [
    re.compile(r"\b(?:any|almost any|all)\s+(?:request|requests|task|tasks|problem|problems)\b", re.IGNORECASE),
    re.compile(r"\bacross the workspace\b", re.IGNORECASE),
    re.compile(r"\bfor any task\b", re.IGNORECASE),
]


def register_temporal_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-16A",
        family_id="D-16",
        scope="segment",
        category=Category.PERSISTENCE,
        severity=Severity.HIGH,
        description="Time-based conditional behavior detected",
        evaluator=_detect_time_bomb_conditionals,
        llm_verification_prompt=(
            "Time-based or environment-gated conditional detected.\n"
            "MALICIOUS if: activates different behavior based on date/environment (time bomb, CI-only payload)\n"
            "SAFE if: legitimate scheduling or environment-specific configuration"
        ),
    )
    registry.register(
        rule_id="D-16B",
        family_id="D-16",
        scope="segment",
        category=Category.PERSISTENCE,
        severity=Severity.MEDIUM,
        description="Environment-conditional behavior detected",
        evaluator=_detect_environment_conditionals,
        llm_verification_prompt=(
            "Time-based or environment-gated conditional detected.\n"
            "MALICIOUS if: activates different behavior based on date/environment (time bomb, CI-only payload)\n"
            "SAFE if: legitimate scheduling or environment-specific configuration"
        ),
    )
    registry.register(
        rule_id="D-16C",
        family_id="D-16",
        scope="segment",
        category=Category.PERSISTENCE,
        severity=Severity.MEDIUM,
        description="Invocation counter or state-gated behavior detected",
        evaluator=_detect_counter_state_conditionals,
        llm_verification_prompt=(
            "Time-based or environment-gated conditional detected.\n"
            "MALICIOUS if: activates different behavior based on date/environment (time bomb, CI-only payload)\n"
            "SAFE if: legitimate scheduling or environment-specific configuration"
        ),
    )
    registry.register(
        rule_id="D-17A",
        family_id="D-17",
        scope="segment",
        category=Category.PERSISTENCE,
        severity=Severity.HIGH,
        description="Persistence target write detected",
        evaluator=_detect_persistence_targets,
        llm_verification_prompt=(
            "Write to a persistence target detected (crontab, .bashrc, git hooks).\n"
            "MALICIOUS if: secretly plants recurring callbacks or exfiltration\n"
            "SAFE if: the skill's PURPOSE is managing cron jobs, shell config, or git hooks"
        ),
    )
    registry.register(
        rule_id="D-18A",
        family_id="D-18",
        scope="segment",
        category=Category.CROSS_AGENT,
        severity=Severity.HIGH,
        description="Cross-agent targeting detected",
        evaluator=_detect_cross_agent_targeting,
        llm_verification_prompt=(
            "Cross-agent targeting detected (writes to other agent config dirs).\n"
            "MALICIOUS if: plants skills or config in other agent directories without permission\n"
            "SAFE if: legitimately managing multi-agent setups as documented"
        ),
    )
    registry.register(
        rule_id="D-18C",
        family_id="D-18",
        scope="artifact",
        category=Category.BEHAVIORAL,
        severity=Severity.MEDIUM,
        description="Overly broad auto-invocation description detected",
        evaluator=_detect_auto_invocation_abuse,
        soft=True,
        llm_verification_prompt=(
            "Overly broad auto-invocation description.\n"
            "MALICIOUS if: designed to intercept ALL user requests\n"
            "SAFE if: legitimately broad-scoped tool with honest description"
        ),
    )


def _detect_time_bomb_conditionals(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    return _match_patterns(
        segment=segment,
        artifact=artifact,
        patterns=TIME_CONDITIONAL_PATTERNS,
        rule_id="D-16A",
        message="Time-based conditional behavior detected",
        category=Category.PERSISTENCE,
        severity=Severity.HIGH,
        action_flags=["TEMPORAL_TRIGGER"],
        signal_family="time_conditional",
    )


def _detect_environment_conditionals(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    return _match_patterns(
        segment=segment,
        artifact=artifact,
        patterns=ENV_CONDITIONAL_PATTERNS,
        rule_id="D-16B",
        message="Environment-conditional behavior detected",
        category=Category.PERSISTENCE,
        severity=Severity.MEDIUM,
        action_flags=["TEMPORAL_TRIGGER"],
        signal_family="environment_conditional",
    )


def _detect_counter_state_conditionals(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    return _match_patterns(
        segment=segment,
        artifact=artifact,
        patterns=COUNTER_STATE_PATTERNS,
        rule_id="D-16C",
        message="Invocation counter or state-gated behavior detected",
        category=Category.PERSISTENCE,
        severity=Severity.MEDIUM,
        action_flags=["TEMPORAL_TRIGGER"],
        signal_family="state_gated_behavior",
    )


def _detect_persistence_targets(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    return _match_patterns(
        segment=segment,
        artifact=artifact,
        patterns=PERSISTENCE_TARGET_PATTERNS,
        rule_id="D-17A",
        message="Persistence target write detected",
        category=Category.PERSISTENCE,
        severity=Severity.HIGH,
        action_flags=["WRITE_SYSTEM"],
        signal_family="persistence_write",
    )


def _detect_cross_agent_targeting(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    findings = _match_patterns(
        segment=segment,
        artifact=artifact,
        patterns=CROSS_AGENT_TARGET_PATTERNS,
        rule_id="D-18A",
        message="Cross-agent targeting detected",
        category=Category.CROSS_AGENT,
        severity=Severity.HIGH,
        action_flags=["CROSS_AGENT"],
        signal_family="cross_agent_write",
    )
    filtered: list[Finding] = []
    for finding in findings:
        target_text = str(finding.details.get("target", "")).lower()
        if ".github" in target_text and not any(token in target_text for token in {"copilot", "settings.json", "skill.md"}):
            continue
        filtered.append(finding)
    return filtered


def _detect_auto_invocation_abuse(artifact: Artifact, skill: Skill, config: ScanConfig):
    if not artifact.path.endswith("SKILL.md"):
        return []
    description = artifact.frontmatter.get("description")
    if not isinstance(description, str):
        return []
    if artifact.frontmatter.get("disable-model-invocation") is True:
        return []
    words = re.findall(r"[A-Za-z][A-Za-z-]+", description.lower())
    generic_hits = sum(1 for word in words if word in GENERIC_DESCRIPTION_TERMS)
    has_broad_scope = any(pattern.search(description) for pattern in BROAD_SCOPE_PATTERNS)
    if len(words) < 18 and generic_hits < 5:
        return []
    if not has_broad_scope and generic_hits < 8:
        return []
    location = artifact.frontmatter_fields.get("description") or Location(file_path=artifact.path, start_line=1, end_line=1)
    return [
        Finding(
            severity=Severity.MEDIUM,
            category=Category.BEHAVIORAL,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-18C",
            message="Overly broad auto-invocation description detected",
            location=location,
            details={"word_count": len(words), "generic_hits": generic_hits, "broad_scope": has_broad_scope},
        )
    ]


def _match_patterns(
    *,
    segment: Segment,
    artifact: Artifact,
    patterns: list[re.Pattern[str]],
    rule_id: str,
    message: str,
    category: Category,
    severity: Severity,
    action_flags: list[str],
    signal_family: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_locations: set[tuple[str, int | None, int | None]] = set()
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    environment_bootstrap = is_environment_bootstrap(segment, artifact)
    for pattern in patterns:
        for match in pattern.finditer(segment.content):
            if rule_id == "D-17A" and _is_template_source_copy(match.group(0)):
                continue
            location = _location_for_span(segment, match.start(), match.end() - 1)
            location_key = (location.file_path, location.start_line, location.start_col)
            if location_key in seen_locations:
                continue
            seen_locations.add(location_key)
            findings.append(
                Finding(
                    severity=severity,
                    category=category,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id=rule_id,
                    message=message,
                    location=location,
                    segment_id=segment.id,
                    action_flags=action_flags,
                    details={
                        "target": match.group(0),
                        "signal_family": signal_family,
                        "source_kind": _source_kind(artifact, segment),
                        "context": context,
                        "reference_example": reference_example,
                        "environment_bootstrap": environment_bootstrap,
                    },
                )
            )
    return findings


def _source_kind(artifact: Artifact, segment: Segment) -> str:
    if segment.segment_type == SegmentType.FRONTMATTER_DESCRIPTION:
        return "frontmatter_description"
    if artifact.file_type == FileType.MARKDOWN:
        return "markdown"
    return "code"


def _is_template_source_copy(target: str) -> bool:
    lowered = target.lower()
    if not re.search(r"\b(?:cp|copy)\b", lowered):
        return False
    return bool(re.search(r"(?:\$script_dir|/resources/|(?:^|[\s\"'])\.(?:bashrc|profile|zshrc)\b)", lowered))


def _location_for_span(segment: Segment, start: int, end: int) -> Location:
    content = segment.content
    start_line = (segment.location.start_line or 1) + content.count("\n", 0, start)
    end_line = (segment.location.start_line or 1) + content.count("\n", 0, end + 1)
    start_offset = content.rfind("\n", 0, start)
    end_offset = content.rfind("\n", 0, end + 1)
    if start_offset == -1:
        start_col = (segment.location.start_col or 1) + start
    else:
        start_col = start - start_offset
    if end_offset == -1:
        end_col = (segment.location.start_col or 1) + end
    else:
        end_col = end - end_offset
    return Location(
        file_path=segment.location.file_path,
        start_line=start_line,
        end_line=end_line,
        start_col=start_col,
        end_col=end_col,
    )
