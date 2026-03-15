from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


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
