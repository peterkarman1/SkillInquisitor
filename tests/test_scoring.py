"""Comprehensive tests for the risk scoring engine (Epic 11, Task 2)."""

from __future__ import annotations

import pytest

from skillinquisitor.models import (
    Category,
    DetectionLayer,
    Finding,
    Location,
    ScanConfig,
    Severity,
)
from skillinquisitor.scoring import ScoredResult, compute_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config(**overrides) -> ScanConfig:
    """Build a ScanConfig with optional scoring overrides."""
    config = ScanConfig()
    if overrides:
        scoring_dict = config.scoring.model_dump()
        for key, value in overrides.items():
            if key == "weights":
                weights_dict = scoring_dict["weights"]
                weights_dict.update(value)
                scoring_dict["weights"] = weights_dict
            else:
                scoring_dict[key] = value
        from skillinquisitor.models import ScoringConfig
        config = config.model_copy(update={"scoring": ScoringConfig.model_validate(scoring_dict)})
    return config


def _finding(
    *,
    severity: Severity = Severity.MEDIUM,
    category: Category = Category.STRUCTURAL,
    layer: DetectionLayer = DetectionLayer.DETERMINISTIC,
    rule_id: str = "TEST-1",
    confidence: float | None = None,
    segment_id: str | None = None,
    action_flags: list[str] | None = None,
    references: list[str] | None = None,
    details: dict | None = None,
    finding_id: str | None = None,
) -> Finding:
    """Create a Finding with sensible defaults."""
    f = Finding(
        severity=severity,
        category=category,
        layer=layer,
        rule_id=rule_id,
        message=f"Test finding {rule_id}",
        location=Location(file_path="test.md", start_line=1),
        confidence=confidence,
        segment_id=segment_id,
        action_flags=action_flags or [],
        references=references or [],
        details=details or {},
    )
    if finding_id is not None:
        f = f.model_copy(update={"id": finding_id})
    return f


# =========================================================================
# Basic scoring
# =========================================================================

class TestBasicScoring:
    """Test fundamental scoring behavior with single findings."""

    def test_no_findings_returns_100_safe(self):
        result = compute_score([], _config())
        assert result.risk_score == 100
        assert result.verdict == "SAFE"

    def test_single_low_finding(self):
        """1 LOW finding: deduction = 5 * 1.0 * 0.7^0 * 1.0 = 5 → score = 95."""
        findings = [_finding(severity=Severity.LOW)]
        result = compute_score(findings, _config())
        assert result.risk_score == 95
        assert result.verdict == "SAFE"

    def test_single_medium_finding(self):
        """1 MEDIUM finding: deduction = 10 * 1.0 * 0.7^0 * 1.0 = 10 → score = 90."""
        findings = [_finding(severity=Severity.MEDIUM)]
        result = compute_score(findings, _config())
        assert result.risk_score == 90
        assert result.verdict == "SAFE"

    def test_single_info_finding(self):
        """INFO has weight 0 → no deduction → score = 100."""
        findings = [_finding(severity=Severity.INFO)]
        result = compute_score(findings, _config())
        assert result.risk_score == 100
        assert result.verdict == "SAFE"

    def test_single_critical_finding_floored(self):
        """1 CRITICAL: deduction = 30 → raw = 70, but floor at 39 → score = 39."""
        findings = [_finding(severity=Severity.CRITICAL)]
        result = compute_score(findings, _config())
        assert result.risk_score == 39
        assert result.verdict == "HIGH RISK"
        assert result.scoring_details["severity_floor_applied"] is True

    def test_single_high_finding_floored(self):
        """1 HIGH: deduction = 20 → raw = 80, but floor at 59 → score = 59."""
        findings = [_finding(severity=Severity.HIGH)]
        result = compute_score(findings, _config())
        assert result.risk_score == 59
        assert result.verdict == "MEDIUM RISK"
        assert result.scoring_details["severity_floor_applied"] is True


# =========================================================================
# Diminishing returns
# =========================================================================

class TestDiminishingReturns:
    """Test geometric decay within severity tiers."""

    def test_two_criticals(self):
        """2 CRITICALs: first=30, second=30*0.7=21 → deduction=51, raw=49, floored to 39."""
        findings = [
            _finding(severity=Severity.CRITICAL, rule_id="C-1"),
            _finding(severity=Severity.CRITICAL, rule_id="C-2"),
        ]
        result = compute_score(findings, _config())
        assert result.scoring_details["raw_score"] == 49
        # Floor caps it to 39
        assert result.risk_score == 39
        assert result.verdict == "HIGH RISK"

    def test_twenty_low_findings_stay_safe(self):
        """20 LOW findings with geometric decay: sum = 5 * sum(0.7^n for n=0..19).
        Geometric sum = 5 * (1 - 0.7^20) / (1 - 0.7) ≈ 5 * 3.325 = 16.62
        Score = 100 - 17 = 83 → SAFE.
        """
        findings = [
            _finding(severity=Severity.LOW, rule_id=f"L-{i}")
            for i in range(20)
        ]
        result = compute_score(findings, _config())
        assert result.risk_score >= 80
        assert result.verdict == "SAFE"

    def test_fifty_info_findings_no_deduction(self):
        """50 INFO findings → no deduction → score = 100."""
        findings = [
            _finding(severity=Severity.INFO, rule_id=f"I-{i}")
            for i in range(50)
        ]
        result = compute_score(findings, _config())
        assert result.risk_score == 100
        assert result.verdict == "SAFE"

    def test_diminishing_returns_ordering_by_confidence(self):
        """Higher confidence findings should be deducted first (full weight)."""
        f_high_conf = _finding(severity=Severity.MEDIUM, rule_id="M-1", confidence=0.9)
        f_low_conf = _finding(severity=Severity.MEDIUM, rule_id="M-2", confidence=0.3)
        findings = [f_low_conf, f_high_conf]  # order shouldn't matter
        result = compute_score(findings, _config())
        # First deduction: 10 * 0.9 * 0.7^0 = 9
        # Second deduction: 10 * 0.3 * 0.7^1 = 2.1
        # Total = 11.1, score = 89
        assert result.risk_score == 89


# =========================================================================
# Chain absorption
# =========================================================================

class TestChainAbsorption:
    """Test that component findings referenced by chain findings are absorbed."""

    def test_chain_absorbs_components(self):
        """Chain finding (CRITICAL, references two MEDIUM components) → only chain deducts."""
        comp_a = _finding(severity=Severity.MEDIUM, rule_id="D-7A", finding_id="comp-a")
        comp_b = _finding(severity=Severity.MEDIUM, rule_id="D-9A", finding_id="comp-b")
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=["comp-a", "comp-b"],
        )
        findings = [comp_a, comp_b, chain]
        result = compute_score(findings, _config())
        assert result.scoring_details["absorbed_count"] == 2
        assert result.scoring_details["effective_finding_count"] == 1
        # Only chain deducts: 30 * 1.0 = 30, raw = 70, floored to 39
        assert result.risk_score == 39

    def test_chain_absorption_disabled(self):
        """With chain_absorption=False → all three deduct (score is worse)."""
        comp_a = _finding(severity=Severity.MEDIUM, rule_id="D-7A", finding_id="comp-a")
        comp_b = _finding(severity=Severity.MEDIUM, rule_id="D-9A", finding_id="comp-b")
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=["comp-a", "comp-b"],
        )
        findings = [comp_a, comp_b, chain]
        result = compute_score(findings, _config(chain_absorption=False))
        assert result.scoring_details["absorbed_count"] == 0
        assert result.scoring_details["effective_finding_count"] == 3
        # Chain CRITICAL: 30
        # Medium-1: 10 * 0.7^0 = 10
        # Medium-2: 10 * 0.7^1 = 7
        # Total = 47, raw = 53, floored to 39
        assert result.risk_score == 39

    def test_chain_absorption_disabled_raw_score_worse(self):
        """Raw score should be worse when absorption is disabled."""
        comp_a = _finding(severity=Severity.MEDIUM, rule_id="D-7A", finding_id="comp-a")
        comp_b = _finding(severity=Severity.MEDIUM, rule_id="D-9A", finding_id="comp-b")
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=["comp-a", "comp-b"],
        )
        findings = [comp_a, comp_b, chain]

        result_with = compute_score(findings, _config())
        result_without = compute_score(findings, _config(chain_absorption=False))

        # Raw score without absorption should be lower (worse)
        assert result_without.scoring_details["raw_score"] < result_with.scoring_details["raw_score"]


# =========================================================================
# Suppression amplifier
# =========================================================================

class TestSuppressionAmplifier:
    """Test that suppression findings amplify other deductions."""

    def test_suppression_amplifies_other_findings(self):
        """D-12 (MEDIUM, SUPPRESSION_PRESENT) + D-7 (MEDIUM) → D-7 amplified by 1.5x."""
        suppression = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-12A",
            action_flags=["SUPPRESSION_PRESENT"],
        )
        other = _finding(severity=Severity.MEDIUM, rule_id="D-7A")
        findings = [suppression, other]
        result = compute_score(findings, _config())

        # Suppression finding itself: 10 * 1.0 * 0.7^0 = 10 (NOT amplified)
        # Other finding: 10 * 1.0 * 0.7^1 * 1.5 = 10.5
        # Total deduction = 20.5, raw = 80, score = 80
        assert result.scoring_details["suppression_active"] is True

        # Compare with D-7 alone
        result_alone = compute_score([other], _config())
        # D-7 alone: deduction = 10, score = 90
        assert result.risk_score < result_alone.risk_score

    def test_suppression_finding_alone(self):
        """Suppression finding alone → 100 - 10 = 90, its own deduction is NOT amplified."""
        suppression = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-12A",
            action_flags=["SUPPRESSION_PRESENT"],
        )
        result = compute_score([suppression], _config())
        assert result.risk_score == 90
        assert result.scoring_details["suppression_active"] is True

    def test_no_suppression_no_amplification(self):
        """Without suppression findings, no amplification occurs."""
        findings = [_finding(severity=Severity.MEDIUM)]
        result = compute_score(findings, _config())
        assert result.scoring_details["suppression_active"] is False


# =========================================================================
# LLM adjustment
# =========================================================================

class TestLLMDispute:
    """Test LLM dispute findings that reduce confidence of referenced findings."""

    def test_dispute_lifts_critical_floor(self):
        """CRITICAL det finding + LLM dispute (conf=0.90) → CRITICAL floor lifted, score > 39."""
        det = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-11A",
            finding_id="det-1",
        )
        dispute = _finding(
            severity=Severity.INFO,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-DISPUTE",
            confidence=0.90,
            references=["det-1"],
            details={"disposition": "dispute"},
        )
        findings = [det, dispute]
        result = compute_score(findings, _config())
        # det effective confidence = 1.0 * (1 - 0.5 * 0.90) = 1.0 * 0.55 = 0.55
        # deduction = 30 * 0.55 = 16.5, raw = 84
        # Critical floor does NOT apply because det-1 is disputed
        assert result.risk_score > 39
        assert result.scoring_details["disputed_count"] == 1
        assert result.scoring_details["severity_floor_applied"] is False

    def test_dispute_reduces_deduction(self):
        """Disputed CRITICAL det finding deducts less than undisputed."""
        det = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-11A",
            finding_id="det-1",
        )
        dispute = _finding(
            severity=Severity.INFO,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-DISPUTE",
            confidence=0.90,
            references=["det-1"],
            details={"disposition": "dispute"},
        )
        result_disputed = compute_score([det, dispute], _config())
        result_undisputed = compute_score([det], _config())

        # Both get floored but raw score differs
        assert result_disputed.scoring_details["raw_score"] > result_undisputed.scoring_details["raw_score"]


class TestLLMConfirm:
    """Test LLM confirm findings that boost deduction of referenced findings."""

    def test_confirm_increases_deduction(self):
        """HIGH det finding + LLM confirm (conf=0.85) → score worse than HIGH alone."""
        det = _finding(
            severity=Severity.HIGH,
            rule_id="D-9A",
            finding_id="det-1",
        )
        confirm = _finding(
            severity=Severity.INFO,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-CONFIRM",
            confidence=0.85,
            references=["det-1"],
            details={"disposition": "confirm"},
        )
        result_confirmed = compute_score([det, confirm], _config())
        result_alone = compute_score([det], _config())

        # Confirm multiplier = 1 + 0.15 * 0.85 = 1.1275
        # Confirmed deduction: 20 * 1.0 * 1.1275 = 22.55, raw = 77
        # Unconfirmed deduction: 20 * 1.0 = 20, raw = 80
        # Both floored to 59 in final score, but raw score should differ
        assert result_confirmed.scoring_details["raw_score"] < result_alone.scoring_details["raw_score"]


class TestLLMSemanticFindings:
    """Test that semantic LLM findings can score as direct evidence."""

    def test_targeted_semantic_confirm_scores_as_direct_finding(self):
        det = _finding(
            severity=Severity.HIGH,
            rule_id="D-19A",
            finding_id="det-1",
        )
        semantic = _finding(
            severity=Severity.CRITICAL,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-TGT-EXFIL",
            confidence=0.90,
            references=["det-1"],
            details={"disposition": "confirm"},
        )

        result = compute_score([det, semantic], _config())

        assert result.scoring_details["effective_finding_count"] == 2
        assert result.scoring_details["absorbed_count"] == 0
        assert result.scoring_details["raw_score"] < compute_score([det], _config()).scoring_details["raw_score"]

    def test_confirm_does_not_prevent_floor(self):
        """Confirming a HIGH finding should still trigger the HIGH floor."""
        det = _finding(
            severity=Severity.HIGH,
            rule_id="D-9A",
            finding_id="det-1",
        )
        confirm = _finding(
            severity=Severity.INFO,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-CONFIRM",
            confidence=0.85,
            references=["det-1"],
            details={"disposition": "confirm"},
        )
        result = compute_score([det, confirm], _config())
        assert result.risk_score <= 59
        assert result.scoring_details["severity_floor_applied"] is True


# =========================================================================
# Cross-layer dedup
# =========================================================================

class TestCrossLayerDedup:
    """Test dedup of findings from different layers on the same segment+category."""

    def test_deterministic_and_ml_same_segment_deduped(self):
        """D-11A (deterministic) + ML-INJ (ml_ensemble) same segment → single deduction."""
        det = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-11A",
            segment_id="seg-1",
            confidence=0.75,
        )
        ml = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-INJ",
            segment_id="seg-1",
            confidence=0.85,
        )
        findings = [det, ml]
        result = compute_score(findings, _config())
        assert result.scoring_details["deduped_count"] == 1
        assert result.scoring_details["effective_finding_count"] == 1

    def test_dedup_keeps_higher_confidence(self):
        """Dedup should keep the finding with higher confidence."""
        det = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-11A",
            segment_id="seg-1",
            confidence=0.75,
        )
        ml = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-INJ",
            segment_id="seg-1",
            confidence=0.85,
        )
        findings = [det, ml]
        result = compute_score(findings, _config())
        # ML has higher confidence (0.85 vs 0.75) → ML kept
        # Deduction = 20 * 0.85 = 17, raw = 83, floored to 59
        assert result.risk_score == 59

    def test_different_segments_not_deduped(self):
        """Findings on different segments are not deduped."""
        det = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-11A",
            segment_id="seg-1",
        )
        ml = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-INJ",
            segment_id="seg-2",
        )
        findings = [det, ml]
        result = compute_score(findings, _config())
        assert result.scoring_details["deduped_count"] == 0
        assert result.scoring_details["effective_finding_count"] == 2

    def test_different_categories_not_deduped(self):
        """Findings with different categories on same segment are not deduped."""
        f1 = _finding(
            severity=Severity.MEDIUM,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-11A",
            segment_id="seg-1",
        )
        f2 = _finding(
            severity=Severity.MEDIUM,
            category=Category.OBFUSCATION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-OBF",
            segment_id="seg-1",
        )
        findings = [f1, f2]
        result = compute_score(findings, _config())
        assert result.scoring_details["deduped_count"] == 0
        assert result.scoring_details["effective_finding_count"] == 2

    def test_null_segment_ids_not_deduped(self):
        """Findings without segment_id should not be deduped against each other."""
        f1 = _finding(
            severity=Severity.MEDIUM,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-11A",
            segment_id=None,
        )
        f2 = _finding(
            severity=Severity.MEDIUM,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-INJ",
            segment_id=None,
        )
        findings = [f1, f2]
        result = compute_score(findings, _config())
        assert result.scoring_details["deduped_count"] == 0
        assert result.scoring_details["effective_finding_count"] == 2


# =========================================================================
# Verdict boundaries
# =========================================================================

class TestVerdictBoundaries:
    """Test score-to-verdict mapping at all boundaries."""

    @pytest.mark.parametrize(
        "score, expected_verdict",
        [
            (100, "SAFE"),
            (80, "SAFE"),
            (79, "LOW RISK"),
            (60, "LOW RISK"),
            (59, "MEDIUM RISK"),
            (40, "MEDIUM RISK"),
            (39, "HIGH RISK"),
            (20, "HIGH RISK"),
            (19, "CRITICAL"),
            (0, "CRITICAL"),
        ],
    )
    def test_verdict_for_score(self, score, expected_verdict):
        """Verify the score-to-verdict mapping at boundary values."""
        from skillinquisitor.scoring import _score_to_verdict
        assert _score_to_verdict(score) == expected_verdict


# =========================================================================
# Scoring details
# =========================================================================

class TestScoringDetails:
    """Test that scoring_details dict is populated correctly."""

    def test_empty_findings_details(self):
        result = compute_score([], _config())
        # Empty findings should still produce an empty scoring_details
        # (the implementation returns early with a minimal ScoredResult)
        assert result.risk_score == 100

    def test_details_populated(self):
        findings = [_finding(severity=Severity.MEDIUM)]
        result = compute_score(findings, _config())
        details = result.scoring_details
        assert "raw_score" in details
        assert "total_deduction" in details
        assert "absorbed_count" in details
        assert "deduped_count" in details
        assert "disputed_count" in details
        assert "suppression_active" in details
        assert "severity_floor_applied" in details
        assert "effective_finding_count" in details
        assert details["absorbed_count"] == 0
        assert details["deduped_count"] == 0
        assert details["disputed_count"] == 0
        assert details["suppression_active"] is False
        assert details["severity_floor_applied"] is False
        assert details["effective_finding_count"] == 1

    def test_total_deduction_rounded(self):
        """Total deduction should be rounded to 2 decimal places."""
        findings = [
            _finding(severity=Severity.MEDIUM, confidence=0.33, rule_id="M-1"),
        ]
        result = compute_score(findings, _config())
        total = result.scoring_details["total_deduction"]
        assert total == round(total, 2)


# =========================================================================
# Edge cases
# =========================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_confidence_none_treated_as_1(self):
        """Finding with confidence=None should be treated as 1.0."""
        f_none = _finding(severity=Severity.MEDIUM, confidence=None, rule_id="M-1")
        f_one = _finding(severity=Severity.MEDIUM, confidence=1.0, rule_id="M-2")
        result_none = compute_score([f_none], _config())
        result_one = compute_score([f_one], _config())
        assert result_none.risk_score == result_one.risk_score

    def test_score_clamped_to_zero(self):
        """Many severe findings should clamp to 0, not go negative."""
        findings = [
            _finding(severity=Severity.CRITICAL, rule_id=f"C-{i}")
            for i in range(20)
        ]
        result = compute_score(findings, _config())
        assert result.risk_score >= 0

    def test_mixed_severities(self):
        """Mix of severities: each tier decays independently."""
        findings = [
            _finding(severity=Severity.CRITICAL, rule_id="C-1"),
            _finding(severity=Severity.HIGH, rule_id="H-1"),
            _finding(severity=Severity.MEDIUM, rule_id="M-1"),
            _finding(severity=Severity.LOW, rule_id="L-1"),
        ]
        result = compute_score(findings, _config())
        # Critical: 30, High: 20, Medium: 10, Low: 5 = total 65
        # raw = 35, floored to 39 (critical floor is higher)
        # Actually floor caps score at min(39, raw)... wait, floor says
        # if score > floor_value, cap at floor_value.  raw=35 < 39, so no capping.
        assert result.scoring_details["raw_score"] == 35
        assert result.risk_score == 35
        assert result.verdict == "HIGH RISK"

    def test_severity_floor_only_applied_when_score_above(self):
        """Floor is only applied when raw score exceeds the floor threshold."""
        # 1 CRITICAL: deduction 30, raw 70 > 39 → floor applies → 39
        result = compute_score(
            [_finding(severity=Severity.CRITICAL)], _config()
        )
        assert result.risk_score == 39
        assert result.scoring_details["severity_floor_applied"] is True

        # Many CRITICALs: raw < 39 → floor does not apply (score is already below)
        result2 = compute_score(
            [_finding(severity=Severity.CRITICAL, rule_id=f"C-{i}") for i in range(10)],
            _config(),
        )
        assert result2.risk_score <= 39
        # If raw_score is already <= 39, floor should not apply
        if result2.scoring_details["raw_score"] <= 39:
            assert result2.scoring_details["severity_floor_applied"] is False

    def test_llm_dispute_does_not_deduct_itself(self):
        """LLM dispute findings should not contribute their own deduction."""
        det = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-11A",
            finding_id="det-1",
        )
        dispute = _finding(
            severity=Severity.INFO,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-DISPUTE",
            confidence=0.90,
            references=["det-1"],
            details={"disposition": "dispute"},
        )
        result = compute_score([det, dispute], _config())
        assert result.scoring_details["effective_finding_count"] == 1

    def test_llm_confirm_does_not_deduct_itself(self):
        """LLM confirm findings should not contribute their own deduction."""
        det = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-11A",
            finding_id="det-1",
        )
        confirm = _finding(
            severity=Severity.INFO,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-CONFIRM",
            confidence=0.85,
            references=["det-1"],
            details={"disposition": "confirm"},
        )
        result = compute_score([det, confirm], _config())
        assert result.scoring_details["effective_finding_count"] == 1

    def test_suppression_with_multiple_non_suppression_findings(self):
        """Suppression amplifier applies to all non-suppression findings."""
        suppression = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-12A",
            action_flags=["SUPPRESSION_PRESENT"],
        )
        f1 = _finding(severity=Severity.MEDIUM, rule_id="D-7A")
        f2 = _finding(severity=Severity.MEDIUM, rule_id="D-9A")
        findings = [suppression, f1, f2]
        result = compute_score(findings, _config())
        assert result.scoring_details["suppression_active"] is True
        # Suppression: 10 * 0.7^0 = 10 (not amplified)
        # D-7A: 10 * 0.7^1 * 1.5 = 10.5
        # D-9A: 10 * 0.7^2 * 1.5 = 7.35
        # Total = 27.85, raw = 72
        assert result.risk_score == 72

    def test_absorbed_findings_not_in_cross_layer_dedup(self):
        """Absorbed findings should not participate in cross-layer dedup."""
        comp = _finding(
            severity=Severity.MEDIUM,
            category=Category.DATA_EXFILTRATION,
            rule_id="D-7A",
            finding_id="comp-1",
            segment_id="seg-1",
        )
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=["comp-1"],
        )
        # ML finding on same segment+category as comp
        ml = _finding(
            severity=Severity.MEDIUM,
            category=Category.DATA_EXFILTRATION,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-EXFIL",
            segment_id="seg-1",
            confidence=0.9,
        )
        findings = [comp, chain, ml]
        result = compute_score(findings, _config())
        # comp is absorbed by chain, ML finding should not be deduped against comp
        assert result.scoring_details["absorbed_count"] == 1

    def test_semantic_llm_findings_do_not_absorb_referenced_deterministic_evidence(self):
        det = _finding(
            severity=Severity.HIGH,
            category=Category.SUPPRESSION,
            rule_id="D-12A",
            finding_id="det-1",
            action_flags=["SUPPRESSION_PRESENT"],
        )
        llm = _finding(
            severity=Severity.INFO,
            category=Category.SUPPRESSION,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-TGT-VERIFY",
            finding_id="llm-1",
            references=["det-1"],
            details={"disposition": "escalate"},
        )

        result = compute_score([det, llm], _config())

        assert result.scoring_details["absorbed_count"] == 0
        assert result.risk_score == 59

    def test_same_layer_findings_do_not_cross_layer_dedup_each_other(self):
        f1 = _finding(
            severity=Severity.HIGH,
            category=Category.SUPPRESSION,
            rule_id="D-12A",
            segment_id="seg-1",
            action_flags=["SUPPRESSION_PRESENT"],
        )
        f2 = _finding(
            severity=Severity.MEDIUM,
            category=Category.SUPPRESSION,
            rule_id="D-12B",
            segment_id="seg-1",
            action_flags=["SUPPRESSION_PRESENT", "SUPPRESS_OUTPUT"],
        )

        result = compute_score([f1, f2], _config())

        assert result.scoring_details["deduped_count"] == 0
        assert result.risk_score == 59
