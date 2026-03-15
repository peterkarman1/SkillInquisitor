from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

from skillinquisitor.models import CustomRuleConfig, ScanConfig


RuleEvaluator = Callable[..., object]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    scope: str
    category: str
    family_id: str | None = None
    severity: str = "low"
    description: str = ""
    evaluator: RuleEvaluator | None = None
    enabled_by_default: bool = True
    origin: str = "builtin"


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def register(self, **kwargs) -> None:
        rule = RuleDefinition(**kwargs)
        self._rules[rule.rule_id] = rule

    def list_rules(self) -> list[RuleDefinition]:
        return [self._rules[key] for key in sorted(self._rules)]


def build_custom_rule(rule_config: CustomRuleConfig) -> RuleDefinition:
    pattern = re.compile(rule_config.pattern, re.IGNORECASE)

    def evaluator(*args, **kwargs) -> object:
        return pattern

    return RuleDefinition(
        rule_id=rule_config.id,
        scope="segment",
        category=str(rule_config.category),
        family_id=None,
        severity=rule_config.severity.value,
        description=rule_config.message,
        evaluator=evaluator,
        origin="custom",
    )


def build_rule_registry(config: ScanConfig) -> RuleRegistry:
    registry = RuleRegistry()
    for rule_config in config.custom_rules:
        registry.register(**build_custom_rule(rule_config).__dict__)
    return registry
