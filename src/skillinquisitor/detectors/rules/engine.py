from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

from skillinquisitor.models import (
    Artifact,
    Category,
    CustomRuleConfig,
    DetectionLayer,
    Finding,
    Location,
    ScanConfig,
    Segment,
    Severity,
    Skill,
)


SegmentRuleEvaluator = Callable[[Segment, Artifact, Skill, ScanConfig], list[Finding]]
ArtifactRuleEvaluator = Callable[[Artifact, Skill, ScanConfig], list[Finding]]
SkillRuleEvaluator = Callable[[Skill, ScanConfig], list[Finding]]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    scope: str
    category: Category
    severity: Severity
    description: str
    evaluator: SegmentRuleEvaluator | ArtifactRuleEvaluator | SkillRuleEvaluator
    family_id: str | None = None
    enabled_by_default: bool = True
    origin: str = "builtin"
    soft: bool = False
    soft_fallback_confidence: float = 0.0
    llm_verification_prompt: str = ""  # Per-rule LLM prompt context for targeted verification


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def register(self, **kwargs) -> None:
        evaluator = kwargs.get("evaluator", lambda *args, **inner_kwargs: [])
        rule = RuleDefinition(
            rule_id=kwargs["rule_id"],
            scope=kwargs["scope"],
            category=_coerce_category(kwargs["category"]),
            severity=_coerce_severity(kwargs.get("severity", Severity.LOW)),
            description=kwargs.get("description", ""),
            evaluator=evaluator,
            family_id=kwargs.get("family_id"),
            enabled_by_default=kwargs.get("enabled_by_default", True),
            origin=kwargs.get("origin", "builtin"),
            soft=kwargs.get("soft", False),
            soft_fallback_confidence=kwargs.get("soft_fallback_confidence", 0.0),
            llm_verification_prompt=kwargs.get("llm_verification_prompt", ""),
        )
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> RuleDefinition | None:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[RuleDefinition]:
        return [self._rules[key] for key in sorted(self._rules)]


def _coerce_category(value: Category | str) -> Category:
    if isinstance(value, Category):
        return value
    try:
        return Category(str(value).lower())
    except ValueError:
        return Category.CUSTOM


def _coerce_severity(value: Severity | str) -> Severity:
    if isinstance(value, Severity):
        return value
    return Severity(str(value).lower())


def _rule_is_enabled(rule: RuleDefinition, config: ScanConfig, only_rule_id: str | None) -> bool:
    if only_rule_id is not None:
        return rule.rule_id == only_rule_id
    if not rule.enabled_by_default:
        return False

    checks = config.layers.deterministic.checks
    if rule.rule_id in checks:
        return checks[rule.rule_id]

    categories = config.layers.deterministic.categories
    category_key = rule.category.value
    if category_key in categories:
        return categories[category_key]

    return True


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            finding.location.file_path,
            finding.location.start_line or 0,
            finding.location.start_col or 0,
            finding.rule_id,
            finding.message,
        ),
    )


def build_custom_rule(rule_config: CustomRuleConfig) -> RuleDefinition:
    pattern = re.compile(rule_config.pattern, re.IGNORECASE)

    def evaluator(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for match in pattern.finditer(segment.content):
            location = _location_from_match(segment, match.start(), match.end() - 1)
            findings.append(
                Finding(
                    severity=rule_config.severity,
                    category=_coerce_category(rule_config.category),
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id=rule_config.id,
                    message=rule_config.message,
                    location=location,
                )
            )
        return findings

    return RuleDefinition(
        rule_id=rule_config.id,
        family_id=None,
        scope="segment",
        category=_coerce_category(rule_config.category),
        severity=rule_config.severity,
        description=rule_config.message,
        evaluator=evaluator,
        origin="custom",
    )


def build_rule_registry(config: ScanConfig) -> RuleRegistry:
    from skillinquisitor.detectors.rules.behavioral import register_behavioral_rules
    from skillinquisitor.detectors.rules.encoding import register_encoding_rules
    from skillinquisitor.detectors.rules.secrets import register_secrets_rules
    from skillinquisitor.detectors.rules.unicode import register_unicode_rules
    try:
        from skillinquisitor.detectors.rules.injection import register_injection_rules
    except ImportError:  # pragma: no cover - epic 6 lands later
        register_injection_rules = None
    try:
        from skillinquisitor.detectors.rules.structural import register_structural_rules
    except ImportError:  # pragma: no cover - epic 7 lands later
        register_structural_rules = None
    try:
        from skillinquisitor.detectors.rules.temporal import register_temporal_rules
    except ImportError:  # pragma: no cover - epic 8 lands later
        register_temporal_rules = None

    registry = RuleRegistry()
    register_unicode_rules(registry)
    register_encoding_rules(registry)
    register_secrets_rules(registry)
    register_behavioral_rules(registry)
    if register_injection_rules is not None:
        register_injection_rules(registry)
    if register_structural_rules is not None:
        register_structural_rules(registry)
    if register_temporal_rules is not None:
        register_temporal_rules(registry)
    for rule_config in config.custom_rules:
        registry.register(**build_custom_rule(rule_config).__dict__)
    return registry


def _tag_soft_findings(findings: list[Finding], registry: RuleRegistry, config: ScanConfig) -> None:
    """Tag findings from soft rules.

    The config ``soft_rules`` list is the authoritative source. Builtin
    ``rule.soft`` flags serve as defaults that populate the config list.
    An empty config list means no rules are soft (explicit override).
    """
    soft_rule_ids = set(config.layers.deterministic.soft_rules)
    for finding in findings:
        if finding.rule_id in soft_rule_ids:
            finding.details["soft"] = True
            finding.details["soft_status"] = "pending"


def run_registered_rules(
    skills: list[Skill],
    config: ScanConfig,
    registry: RuleRegistry,
    only_rule_id: str | None = None,
) -> list[Finding]:
    if not config.layers.deterministic.enabled:
        return []

    chain_only_rule = only_rule_id in {"D-19A", "D-19B", "D-19C"}
    findings: list[Finding] = []
    if chain_only_rule:
        active_rules = [
            rule
            for rule in registry.list_rules()
            if rule.rule_id not in {"D-19A", "D-19B", "D-19C"} and _rule_is_enabled(rule, config, None)
        ]
    else:
        active_rules = [rule for rule in registry.list_rules() if _rule_is_enabled(rule, config, only_rule_id)]

    for skill in skills:
        for rule in active_rules:
            if rule.scope == "skill":
                findings.extend(rule.evaluator(skill, config))  # type: ignore[arg-type]
        for artifact in skill.artifacts:
            for rule in active_rules:
                if rule.scope == "artifact":
                    findings.extend(rule.evaluator(artifact, skill, config))  # type: ignore[arg-type]
                    continue
                if rule.scope in {"artifact", "skill"}:
                    continue
                if rule.scope != "segment":
                    continue
                for segment in artifact.segments:
                    findings.extend(rule.evaluator(segment, artifact, skill, config))  # type: ignore[arg-type]

    from skillinquisitor.detectors.rules.behavioral import run_behavioral_postprocessors
    from skillinquisitor.detectors.rules.encoding import run_encoding_postprocessors

    if only_rule_id is None:
        findings.extend(run_encoding_postprocessors(skills, findings))

    behavioral_findings = run_behavioral_postprocessors(skills, findings, config, only_rule_id=only_rule_id)
    if chain_only_rule:
        return _sort_findings(behavioral_findings)

    findings.extend(behavioral_findings)

    _tag_soft_findings(findings, registry, config)
    return _sort_findings(findings)


def _location_from_match(segment: Segment, start: int, end: int) -> Location:
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
