"""Finding preparation engine.

Implements: chain absorption, cross-layer dedup, LLM adjustment annotation,
soft finding gate, and finding enrichment for downstream consumers.
"""
from __future__ import annotations

from skillinquisitor.models import (
    DetectionLayer,
    Finding,
    ScanConfig,
)


def prepare_findings(findings: list[Finding], config: ScanConfig) -> list[Finding]:
    """Annotate findings with chain absorption, soft status, dedup, and LLM adjustments.

    Returns the same findings list with details dicts enriched:
    - absorbed_by: rule_id of the chain that absorbed this finding
    - soft_status: "confirmed" or "rejected"
    - deduped: True if a higher-confidence finding exists for same segment+category
    - llm_disposition: "dispute" or "confirm" with adjusted confidence
    """
    if not findings:
        return findings

    scoring = config.scoring

    # Step 1: identify LLM adjustment findings
    llm_adjustments: dict[str, Finding] = {}  # referenced_id -> LLM finding
    llm_adjustment_ids: set[str] = set()
    for f in findings:
        if _is_llm_adjustment(f):
            llm_adjustment_ids.add(f.id)
            for ref_id in f.references:
                llm_adjustments[ref_id] = f

    # Step 2: chain absorption — mark component findings absorbed by D-19 chains
    absorbed_ids: set[str] = set()
    absorbing_chains: dict[str, str] = {}  # absorbed_id -> chain rule_id
    if scoring.chain_absorption:
        for f in findings:
            if _is_absorbing_chain_finding(f, llm_adjustment_ids):
                for ref_id in f.references:
                    absorbed_ids.add(ref_id)
                    absorbing_chains[ref_id] = f.rule_id

    # Step 3: cross-layer dedup by segment_id + category
    seen_segments: dict[tuple[str, str], Finding] = {}
    dedup_ids: set[str] = set()
    for f in findings:
        if f.id in absorbed_ids:
            continue
        if _is_llm_adjustment(f):
            continue
        if f.segment_id:
            key = (f.segment_id, f.category.value)
            if key in seen_segments:
                existing = seen_segments[key]
                existing_conf = existing.confidence if existing.confidence is not None else 1.0
                new_conf = f.confidence if f.confidence is not None else 1.0
                if existing.layer == f.layer:
                    if new_conf > existing_conf:
                        seen_segments[key] = f
                else:
                    if new_conf > existing_conf:
                        dedup_ids.add(existing.id)
                        seen_segments[key] = f
                    else:
                        dedup_ids.add(f.id)
            else:
                seen_segments[key] = f

    # Step 4: soft finding gate
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

    # Step 5: annotate LLM dispute/confirm adjustments
    for f in findings:
        if _is_llm_adjustment(f):
            continue
        if f.id in llm_adjustments:
            adj = llm_adjustments[f.id]
            disposition = adj.details.get("disposition")
            adj_conf = adj.confidence if adj.confidence is not None else 0.5
            if disposition == "dispute":
                base_conf = f.confidence if f.confidence is not None else 1.0
                f.confidence = max(0.0, base_conf * (1.0 - scoring.llm_dispute_factor * adj_conf))
                f.details["llm_disposition"] = "dispute"
            elif disposition == "confirm":
                f.details["llm_disposition"] = "confirm"

    # Step 6: write annotations into details dicts
    for f in findings:
        if f.id in absorbed_ids:
            f.details["absorbed_by"] = absorbing_chains.get(f.id, "")
        if f.id in dedup_ids:
            f.details["deduped"] = True
        if f.id in soft_rejected_ids:
            f.details["soft_status"] = "rejected"
        if f.id in soft_confirmed_ids:
            f.details["soft_status"] = "confirmed"

    return findings


def _is_llm_adjustment(finding: Finding) -> bool:
    if finding.layer != DetectionLayer.LLM_ANALYSIS or not finding.references:
        return False
    disposition = finding.details.get("disposition")
    if disposition not in ("dispute", "confirm"):
        return False
    return finding.rule_id in {"LLM-DISPUTE", "LLM-CONFIRM", "LLM-TGT-VERIFY"}


def _is_absorbing_chain_finding(finding: Finding, llm_adjustment_ids: set[str]) -> bool:
    if not finding.references or finding.id in llm_adjustment_ids:
        return False
    return finding.rule_id.startswith("D-19")
