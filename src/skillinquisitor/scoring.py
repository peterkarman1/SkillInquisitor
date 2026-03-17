"""Risk scoring engine.

Implements: subtractive scoring with diminishing returns, confidence weighting,
chain absorption, cross-layer dedup, LLM adjustment, suppression amplification,
and severity floors.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from skillinquisitor.models import (
    DetectionLayer,
    Finding,
    ScanConfig,
    Severity,
)

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEVERITY_WEIGHT_ATTR = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: None,
}


@dataclass(frozen=True)
class ScoredResult:
    risk_score: int
    verdict: str
    scoring_details: dict[str, object] = field(default_factory=dict)


def compute_score(findings: list[Finding], config: ScanConfig) -> ScoredResult:
    """Compute a 0-100 risk score and verdict from a list of findings.

    Algorithm:
    1. Start at 100.
    2. Chain absorption: component findings referenced by chain findings
       don't contribute their own deduction.
    3. LLM adjustments: dispute reduces effective confidence and lifts
       severity floors; confirm multiplies deduction.
    4. Cross-layer dedup: same segment_id + category across layers keeps
       only the higher-confidence finding.
    5. Build effective findings (minus absorbed, deduped, LLM adjustments).
    6. Group by severity tier, sort by confidence descending.
    7. Diminishing returns via geometric decay within each tier.
    8. Suppression amplifier on non-suppression findings when any finding
       carries SUPPRESSION_PRESENT.
    9. Clamp to [0, 100] and round.
    10. Severity floors cap the score for undisputed critical/high findings.
    11. Map score to verdict.
    """
    if not findings:
        return ScoredResult(risk_score=100, verdict="SAFE")

    scoring = config.scoring
    weights = scoring.weights

    def _weight_for(severity: Severity) -> int:
        attr = SEVERITY_WEIGHT_ATTR.get(severity)
        return getattr(weights, attr) if attr else 0

    # Step 1: identify LLM adjustment findings (must come before absorption)
    llm_adjustments: dict[str, Finding] = {}  # referenced_id -> LLM finding
    llm_adjustment_ids: set[str] = set()
    for f in findings:
        if _is_llm_adjustment(f):
            llm_adjustment_ids.add(f.id)
            for ref_id in f.references:
                llm_adjustments[ref_id] = f

    # Step 2: identify chain component IDs for absorption
    # LLM adjustment findings are not chain parents — their references
    # point to findings they adjust, not to component findings.
    absorbed_ids: set[str] = set()
    if scoring.chain_absorption:
        for f in findings:
            if f.references and f.id not in llm_adjustment_ids:
                absorbed_ids.update(f.references)

    # Step 3: cross-layer dedup by segment_id + category overlap
    seen_segments: dict[tuple[str, str], Finding] = {}  # (segment_id, category) -> best finding
    dedup_ids: set[str] = set()
    for f in findings:
        if f.id in absorbed_ids:
            continue
        if _is_llm_adjustment(f):
            continue  # LLM adjustment findings don't participate in dedup
        if f.segment_id:
            key = (f.segment_id, f.category.value)
            if key in seen_segments:
                existing = seen_segments[key]
                existing_conf = existing.confidence if existing.confidence is not None else 1.0
                new_conf = f.confidence if f.confidence is not None else 1.0
                if new_conf > existing_conf:
                    dedup_ids.add(existing.id)
                    seen_segments[key] = f
                else:
                    dedup_ids.add(f.id)
            else:
                seen_segments[key] = f

    # Step 3.5: filter soft findings based on LLM confirmation status
    llm_enabled = config.layers.llm.enabled
    soft_fallback = config.layers.deterministic.soft_fallback_confidence
    soft_rejected_ids: set[str] = set()
    soft_confirmed_ids: set[str] = set()
    for f in findings:
        if not f.details.get("soft", False):
            continue
        status = f.details.get("soft_status", "pending")
        if status == "confirmed":
            soft_confirmed_ids.add(f.id)
        elif status == "rejected":
            soft_rejected_ids.add(f.id)
        elif status == "pending" and llm_enabled:
            # LLM ran but didn't evaluate this finding (no matching target)
            # Treat as rejected — no LLM confirmation means no confidence
            rule_override = config.layers.deterministic.soft_overrides.get(f.rule_id, {})
            fallback = rule_override.get("soft_fallback_confidence", soft_fallback)
            if fallback > 0.0:
                f.confidence = fallback
            else:
                soft_rejected_ids.add(f.id)
        elif not llm_enabled:
            rule_override = config.layers.deterministic.soft_overrides.get(f.rule_id, {})
            fallback = rule_override.get("soft_fallback_confidence", soft_fallback)
            if fallback > 0.0:
                f.confidence = fallback
            else:
                soft_rejected_ids.add(f.id)

    # Step 4: build effective findings list
    effective: list[Finding] = []
    disputed_ids: set[str] = set()
    for f in findings:
        if f.id in absorbed_ids or f.id in dedup_ids or f.id in soft_rejected_ids:
            continue
        if _is_llm_adjustment(f):
            continue
        effective.append(f)

    # Step 5: compute per-finding effective confidence with LLM adjustments
    effective_confidences: dict[str, float] = {}
    effective_deduction_multipliers: dict[str, float] = {}
    for f in effective:
        base_conf = f.confidence if f.confidence is not None else 1.0
        mult = 1.0
        if f.id in llm_adjustments:
            adj = llm_adjustments[f.id]
            adj_conf = adj.confidence if adj.confidence is not None else 0.5
            if adj.details.get("disposition") == "dispute":
                base_conf = base_conf * (1.0 - scoring.llm_dispute_factor * adj_conf)
                disputed_ids.add(f.id)
            elif adj.details.get("disposition") == "confirm":
                mult = 1.0 + scoring.llm_confirm_factor * adj_conf
        effective_confidences[f.id] = max(0.0, base_conf)
        effective_deduction_multipliers[f.id] = mult

    # Step 6: check for suppression
    has_suppression = any("SUPPRESSION_PRESENT" in f.action_flags for f in findings)
    is_suppression_finding = {
        f.id for f in effective if "SUPPRESSION_PRESENT" in f.action_flags
    }

    # Step 7: group by severity tier, sort by confidence desc within tier
    tiers: dict[Severity, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in effective:
        tiers[f.severity].append(f)
    for tier_findings in tiers.values():
        tier_findings.sort(key=lambda f: -(effective_confidences.get(f.id, 1.0)))

    # Step 8: compute deductions with diminishing returns
    total_deduction = 0.0
    decay = scoring.decay_factor
    for severity in SEVERITY_ORDER:
        base_weight = _weight_for(severity)
        if base_weight == 0:
            continue
        for position, f in enumerate(tiers[severity]):
            conf = effective_confidences.get(f.id, 1.0)
            mult = effective_deduction_multipliers.get(f.id, 1.0)
            deduction = base_weight * conf * (decay ** position) * mult
            # Apply soft-confirmed boost
            if f.id in soft_confirmed_ids:
                deduction *= scoring.soft_confirmed_boost
            # Apply suppression amplifier to non-suppression findings
            if has_suppression and f.id not in is_suppression_finding:
                deduction *= scoring.suppression_multiplier
            total_deduction += deduction

    # Step 9: compute raw score
    raw_score = max(0, min(100, round(100.0 - total_deduction)))

    # Step 10: apply severity floors (only for undisputed findings)
    score = raw_score
    worst_undisputed = _worst_undisputed_severity(effective, disputed_ids)
    if worst_undisputed is not None:
        floor_key = worst_undisputed.value
        if floor_key in scoring.severity_floors:
            floor_value = scoring.severity_floors[floor_key]
            if score > floor_value:
                score = floor_value

    verdict = _score_to_verdict(score)
    return ScoredResult(
        risk_score=score,
        verdict=verdict,
        scoring_details={
            "raw_score": raw_score,
            "total_deduction": round(total_deduction, 2),
            "absorbed_count": len(absorbed_ids),
            "deduped_count": len(dedup_ids),
            "disputed_count": len(disputed_ids),
            "suppression_active": has_suppression,
            "severity_floor_applied": score != raw_score,
            "effective_finding_count": len(effective),
            "soft_confirmed_count": len(soft_confirmed_ids),
            "soft_rejected_count": len(soft_rejected_ids),
        },
    )


def _worst_undisputed_severity(
    effective: list[Finding], disputed_ids: set[str]
) -> Severity | None:
    """Return the worst (most severe) severity among undisputed effective findings."""
    for severity in SEVERITY_ORDER:
        for f in effective:
            if f.severity == severity and f.id not in disputed_ids:
                return severity
    return None


def _score_to_verdict(score: int) -> str:
    """Map a 0-100 risk score to a verdict string."""
    if score >= 80:
        return "SAFE"
    if score >= 60:
        return "LOW RISK"
    if score >= 40:
        return "MEDIUM RISK"
    if score >= 20:
        return "HIGH RISK"
    return "CRITICAL"


def _is_llm_adjustment(finding: Finding) -> bool:
    if finding.layer != DetectionLayer.LLM_ANALYSIS or not finding.references:
        return False
    disposition = finding.details.get("disposition")
    if disposition not in ("dispute", "confirm"):
        return False
    return finding.rule_id in {"LLM-DISPUTE", "LLM-CONFIRM", "LLM-TGT-VERIFY"}
