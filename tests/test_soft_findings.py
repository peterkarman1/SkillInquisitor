"""Tests for soft finding tagging and configuration."""
from __future__ import annotations

from skillinquisitor.detectors.rules.engine import RuleDefinition, RuleRegistry
from skillinquisitor.models import Category, CheckConfig, ScanConfig, ScoringConfig, Severity


class TestRuleDefinitionSoftFlag:
    def test_default_not_soft(self):
        rule = RuleDefinition(
            rule_id="TEST", scope="segment", category=Category.STRUCTURAL,
            severity=Severity.LOW, description="test",
            evaluator=lambda *a, **k: [],
        )
        assert rule.soft is False
        assert rule.soft_fallback_confidence == 0.0

    def test_soft_rule(self):
        rule = RuleDefinition(
            rule_id="TEST", scope="segment", category=Category.STRUCTURAL,
            severity=Severity.LOW, description="test",
            evaluator=lambda *a, **k: [],
            soft=True, soft_fallback_confidence=0.15,
        )
        assert rule.soft is True
        assert rule.soft_fallback_confidence == 0.15

    def test_registry_accepts_soft(self):
        registry = RuleRegistry()
        registry.register(
            rule_id="SOFT-TEST", scope="segment", category="structural",
            severity="low", description="test", soft=True,
        )
        rule = registry.get("SOFT-TEST")
        assert rule is not None
        assert rule.soft is True

    def test_registry_default_not_soft(self):
        registry = RuleRegistry()
        registry.register(
            rule_id="HARD-TEST", scope="segment", category="structural",
            severity="low", description="test",
        )
        rule = registry.get("HARD-TEST")
        assert rule is not None
        assert rule.soft is False


class TestCheckConfigSoftRules:
    def test_default_soft_rules(self):
        config = CheckConfig()
        expected_soft = [
            "D-14C", "D-14D", "D-15E", "D-15G", "D-15C",
            "D-18C", "D-22A", "D-5A", "D-2A", "D-12C", "D-8B",
            "D-1C", "NC-3A",
        ]
        for rule_id in expected_soft:
            assert rule_id in config.soft_rules, f"{rule_id} should be in default soft_rules"
        assert len(config.soft_rules) == len(expected_soft)

    def test_default_fallback_confidence(self):
        config = CheckConfig()
        assert config.soft_fallback_confidence == 0.0

    def test_custom_soft_rules(self):
        config = CheckConfig(soft_rules=["D-1A", "D-2A"])
        assert config.soft_rules == ["D-1A", "D-2A"]

    def test_soft_overrides(self):
        config = CheckConfig(soft_overrides={"D-10A": {"soft_fallback_confidence": 0.15}})
        assert config.soft_overrides["D-10A"]["soft_fallback_confidence"] == 0.15


class TestScoringConfigSoftFields:
    def test_defaults(self):
        config = ScoringConfig()
        assert config.soft_confirmed_boost == 1.5
        assert config.soft_confirmation_threshold == 0.75

    def test_custom_values(self):
        config = ScoringConfig(soft_confirmed_boost=2.0, soft_confirmation_threshold=0.5)
        assert config.soft_confirmed_boost == 2.0
        assert config.soft_confirmation_threshold == 0.5


class TestBuiltinSoftRuleRegistration:
    def test_d10a_registered_as_soft(self):
        config = ScanConfig()
        from skillinquisitor.detectors.rules.engine import build_rule_registry
        registry = build_rule_registry(config)
        rule = registry.get("D-10A")
        assert rule is not None
        assert rule.soft is True

    def test_d18c_registered_as_soft(self):
        config = ScanConfig()
        from skillinquisitor.detectors.rules.engine import build_rule_registry
        registry = build_rule_registry(config)
        rule = registry.get("D-18C")
        assert rule is not None
        assert rule.soft is True

    def test_d1a_not_soft(self):
        config = ScanConfig()
        from skillinquisitor.detectors.rules.engine import build_rule_registry
        registry = build_rule_registry(config)
        rule = registry.get("D-1A")
        assert rule is not None
        assert rule.soft is False
