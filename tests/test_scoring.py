"""Tests for the finding preparation engine (prepare_findings)."""

from __future__ import annotations

import pytest

from skillinquisitor.models import (
    Category,
    DetectionLayer,
    Finding,
    FindingPolicyConfig,
    Location,
    ScanConfig,
    Severity,
)
from skillinquisitor.scoring import prepare_findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config(**overrides) -> ScanConfig:
    """Build a ScanConfig with optional scoring overrides."""
    config = ScanConfig()
    if overrides:
        scoring_dict = config.scoring.model_dump()
        for key, value in overrides.items():
            scoring_dict[key] = value
        config = config.model_copy(update={"scoring": FindingPolicyConfig.model_validate(scoring_dict)})
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
# Basic behavior
# =========================================================================

class TestPrepareFindings:
    """Test fundamental prepare_findings behavior."""

    def test_empty_findings(self):
        result = prepare_findings([], _config())
        assert result == []

    def test_single_finding_unchanged(self):
        findings = [_finding(severity=Severity.LOW)]
        result = prepare_findings(findings, _config())
        assert len(result) == 1
        assert result[0].severity == Severity.LOW


# =========================================================================
# Chain absorption
# =========================================================================

class TestChainAbsorption:
    """Test that component findings referenced by chain findings are annotated as absorbed."""

    def test_chain_absorbs_components(self):
        comp_a = _finding(severity=Severity.MEDIUM, rule_id="D-7A", finding_id="comp-a")
        comp_b = _finding(severity=Severity.MEDIUM, rule_id="D-9A", finding_id="comp-b")
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=["comp-a", "comp-b"],
        )
        findings = [comp_a, comp_b, chain]
        prepare_findings(findings, _config())
        assert comp_a.details.get("absorbed_by") == "D-19A"
        assert comp_b.details.get("absorbed_by") == "D-19A"
        assert "absorbed_by" not in chain.details

    def test_chain_absorption_disabled(self):
        comp_a = _finding(severity=Severity.MEDIUM, rule_id="D-7A", finding_id="comp-a")
        comp_b = _finding(severity=Severity.MEDIUM, rule_id="D-9A", finding_id="comp-b")
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=["comp-a", "comp-b"],
        )
        findings = [comp_a, comp_b, chain]
        prepare_findings(findings, _config(chain_absorption=False))
        assert "absorbed_by" not in comp_a.details
        assert "absorbed_by" not in comp_b.details


# =========================================================================
# Cross-layer dedup
# =========================================================================

class TestCrossLayerDedup:
    """Test dedup of findings from different layers on the same segment+category."""

    def test_deterministic_and_llm_same_segment_deduped(self):
        det = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-11A",
            segment_id="seg-1",
            confidence=0.75,
        )
        llm = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-INJ",
            segment_id="seg-1",
            confidence=0.85,
        )
        findings = [det, llm]
        prepare_findings(findings, _config())
        # Lower confidence det should be marked deduped
        assert det.details.get("deduped") is True
        assert "deduped" not in llm.details

    def test_different_segments_not_deduped(self):
        det = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-11A",
            segment_id="seg-1",
        )
        llm = _finding(
            severity=Severity.HIGH,
            category=Category.PROMPT_INJECTION,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-INJ",
            segment_id="seg-2",
        )
        findings = [det, llm]
        prepare_findings(findings, _config())
        assert "deduped" not in det.details
        assert "deduped" not in llm.details

    def test_different_categories_not_deduped(self):
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
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-OBF",
            segment_id="seg-1",
        )
        findings = [f1, f2]
        prepare_findings(findings, _config())
        assert "deduped" not in f1.details
        assert "deduped" not in f2.details

    def test_null_segment_ids_not_deduped(self):
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
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-INJ",
            segment_id=None,
        )
        findings = [f1, f2]
        prepare_findings(findings, _config())
        assert "deduped" not in f1.details
        assert "deduped" not in f2.details


# =========================================================================
# Soft finding gate
# =========================================================================

class TestSoftFindingGate:
    """Test soft finding filtering based on LLM confirmation status."""

    def test_soft_confirmed_annotated(self):
        f = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-10A",
            details={"soft": True, "soft_status": "confirmed"},
        )
        prepare_findings([f], _config())
        assert f.details["soft_status"] == "confirmed"

    def test_soft_rejected_annotated(self):
        f = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-10A",
            details={"soft": True, "soft_status": "rejected"},
        )
        prepare_findings([f], _config())
        assert f.details["soft_status"] == "rejected"

    def test_soft_pending_llm_disabled_rejected(self):
        """With LLM disabled and soft_fallback_confidence=0.0, pending soft findings are rejected."""
        config = _config()
        config.layers.llm.enabled = False
        f = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-10A",
            details={"soft": True, "soft_status": "pending"},
        )
        prepare_findings([f], config)
        assert f.details["soft_status"] == "rejected"

    def test_soft_pending_llm_disabled_with_fallback(self):
        """With LLM disabled but soft_fallback_confidence > 0, confidence is set."""
        config = _config()
        config.layers.llm.enabled = False
        config.layers.deterministic.soft_fallback_confidence = 0.3
        f = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-10A",
            details={"soft": True, "soft_status": "pending"},
        )
        prepare_findings([f], config)
        assert f.confidence == 0.3


# =========================================================================
# LLM dispute/confirm adjustments
# =========================================================================

class TestLLMDispute:
    """Test LLM dispute findings that reduce confidence of referenced findings."""

    def test_dispute_reduces_confidence(self):
        det = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-11A",
            finding_id="det-1",
            confidence=1.0,
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
        prepare_findings(findings, _config())
        # det effective confidence = 1.0 * (1 - 0.5 * 0.90) = 0.55
        assert det.confidence == pytest.approx(0.55, abs=0.01)
        assert det.details["llm_disposition"] == "dispute"


class TestLLMConfirm:
    """Test LLM confirm findings that annotate confirmed findings."""

    def test_confirm_annotates_finding(self):
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
        findings = [det, confirm]
        prepare_findings(findings, _config())
        assert det.details["llm_disposition"] == "confirm"


# =========================================================================
# LLM adjustment findings are not chain parents
# =========================================================================

class TestLLMAdjustmentNotChainParent:
    """LLM adjustment findings should not absorb their referenced findings."""

    def test_llm_dispute_does_not_absorb(self):
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
        prepare_findings([det, dispute], _config())
        assert "absorbed_by" not in det.details

    def test_llm_confirm_does_not_absorb(self):
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
        prepare_findings([det, confirm], _config())
        assert "absorbed_by" not in det.details


# =========================================================================
# Absorbed findings not in cross-layer dedup
# =========================================================================

class TestAbsorbedNotDeduped:
    """Absorbed findings should not participate in cross-layer dedup."""

    def test_absorbed_findings_not_deduped_against_llm(self):
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
        llm = _finding(
            severity=Severity.MEDIUM,
            category=Category.DATA_EXFILTRATION,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-EXFIL",
            segment_id="seg-1",
            confidence=0.9,
        )
        findings = [comp, chain, llm]
        prepare_findings(findings, _config())
        # comp is absorbed, llm should NOT be deduped
        assert comp.details.get("absorbed_by") == "D-19A"
        assert "deduped" not in llm.details


# =========================================================================
# Semantic LLM findings do not absorb referenced deterministic evidence
# =========================================================================

class TestSemanticLLMNotAbsorbing:
    """Semantic LLM findings (non-dispute, non-confirm) do not absorb."""

    def test_semantic_llm_does_not_absorb(self):
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
        prepare_findings([det, llm], _config())
        assert "absorbed_by" not in det.details
