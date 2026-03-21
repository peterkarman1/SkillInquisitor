from __future__ import annotations

import asyncio
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path

from skillinquisitor.detectors.llm.download import _expand_cache_dir, resolve_model_file
from skillinquisitor.detectors.llm.parsing import coerce_confidence
from skillinquisitor.detectors.llm.models import (
    CodeAnalysisModel,
    build_code_analysis_model,
    detect_hardware_profile,
    resolve_group_models,
)
from skillinquisitor.models import (
    AdjudicationResult,
    ArtifactEvidenceSummary,
    Category,
    DetectionLayer,
    EvidenceDriver,
    EvidencePacket,
    Finding,
    RiskLabel,
    ScanConfig,
    Severity,
)
from skillinquisitor.runtime import ScanRuntime


RISK_LABEL_ORDER = {
    RiskLabel.LOW: 0,
    RiskLabel.MEDIUM: 1,
    RiskLabel.HIGH: 2,
    RiskLabel.CRITICAL: 3,
}

SEVERITY_TO_RISK_LABEL = {
    Severity.INFO: RiskLabel.LOW,
    Severity.LOW: RiskLabel.LOW,
    Severity.MEDIUM: RiskLabel.MEDIUM,
    Severity.HIGH: RiskLabel.HIGH,
    Severity.CRITICAL: RiskLabel.CRITICAL,
}

DANGEROUS_PROMOTION_CATEGORIES = {
    Category.CREDENTIAL_THEFT,
    Category.DATA_EXFILTRATION,
    Category.BEHAVIORAL,
    Category.PROMPT_INJECTION,
    Category.PERSISTENCE,
    Category.JAILBREAK,
}

EXPLICIT_HIGH_SIGNAL_RULE_IDS = {
    "D-10B",
    "D-10C",
    "D-10D",
    "D-20G",
    "D-20H",
    "D-19A",
    "D-19B",
    "D-19C",
    "D-11A",
    "D-11C",
    "D-11D",
}

DECISIVE_NON_LLM_OBFUSCATION_RULE_IDS = {
    "D-1C",
    "D-3A",
    "D-4B",
    "D-5A",
    "D-5B",
    "D-5C",
}

DECISIVE_NON_LLM_BEHAVIOR_RULE_IDS = {
    "D-10A",
    "D-10D",
    "D-12D",
    "D-17A",
    "D-18A",
}

DECISIVE_NON_LLM_EXFIL_RULE_IDS = {
    "D-9A",
    "D-15C",
    "D-15D",
}

DECISIVE_NON_LLM_CREDENTIAL_RULE_IDS = {
    "D-8A",
    "D-8D",
}

PROMOTABLE_CONTEXTS = {
    "actionable_instruction",
    "executable_snippet",
    "code",
    "frontmatter_description",
}


def map_risk_label_to_binary(risk_label: RiskLabel, cutoff: RiskLabel) -> str:
    if RISK_LABEL_ORDER[risk_label] >= RISK_LABEL_ORDER[cutoff]:
        return "malicious"
    return "not_malicious"


def risk_label_to_legacy_verdict(risk_label: RiskLabel) -> str:
    if risk_label == RiskLabel.LOW:
        return "LOW RISK"
    if risk_label == RiskLabel.MEDIUM:
        return "MEDIUM RISK"
    if risk_label == RiskLabel.HIGH:
        return "HIGH RISK"
    return "CRITICAL"


def build_evidence_packet(findings: list[Finding], config: ScanConfig) -> EvidencePacket:
    del config
    confirmed_categories: set[Category] = set()
    disputed_categories: set[Category] = set()
    high_signal_findings: list[EvidenceDriver] = []
    chain_findings: list[EvidenceDriver] = []
    ml_signals: list[EvidenceDriver] = []
    llm_confirmations: list[EvidenceDriver] = []
    llm_disputes: list[EvidenceDriver] = []

    per_artifact_categories: dict[str, set[Category]] = defaultdict(set)
    per_artifact_count: dict[str, int] = defaultdict(int)
    per_artifact_severity: dict[str, Severity] = {}

    for finding in findings:
        file_path = finding.location.file_path
        if file_path:
            per_artifact_count[file_path] += 1
            per_artifact_categories[file_path].add(finding.category)
            existing = per_artifact_severity.get(file_path)
            if existing is None or RISK_LABEL_ORDER[SEVERITY_TO_RISK_LABEL[finding.severity]] > RISK_LABEL_ORDER[SEVERITY_TO_RISK_LABEL[existing]]:
                per_artifact_severity[file_path] = finding.severity

        driver = EvidenceDriver(
            rule_ids=[finding.rule_id] if finding.rule_id else [],
            categories=[finding.category],
            file_path=file_path,
            segment_ids=[finding.segment_id] if finding.segment_id else [],
            explanation=finding.message,
        )

        disposition = finding.details.get("disposition")
        soft_status = finding.details.get("soft_status")
        if disposition == "confirm" or soft_status == "confirmed":
            confirmed_categories.add(finding.category)
            llm_confirmations.append(driver)
        elif disposition == "dispute" or soft_status == "rejected":
            disputed_categories.add(finding.category)
            llm_disputes.append(driver)

        if finding.layer == DetectionLayer.ML_ENSEMBLE:
            ml_signals.append(driver)
        if finding.rule_id.startswith("D-19"):
            chain_findings.append(driver)
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
            high_signal_findings.append(driver)

    artifact_summary = [
        ArtifactEvidenceSummary(
            file_path=file_path,
            categories=sorted(categories, key=lambda category: category.value),
            finding_count=per_artifact_count[file_path],
            strongest_severity=per_artifact_severity.get(file_path),
        )
        for file_path, categories in sorted(per_artifact_categories.items())
    ]

    return EvidencePacket(
        confirmed_categories=sorted(confirmed_categories, key=lambda category: category.value),
        disputed_categories=sorted(disputed_categories, key=lambda category: category.value),
        high_signal_findings=high_signal_findings,
        chain_findings=chain_findings,
        ml_signals=ml_signals,
        llm_confirmations=llm_confirmations,
        llm_disputes=llm_disputes,
        artifact_summary=artifact_summary,
    )


def determine_guardrail_floor(
    packet: EvidencePacket,
    findings: list[Finding],
    config: ScanConfig,
) -> tuple[RiskLabel | None, list[str]]:
    matched: list[str] = []
    floor: RiskLabel | None = None
    finding_rule_ids = {finding.rule_id for finding in findings}
    finding_categories = {finding.category for finding in findings}
    confirmed_categories = set(packet.confirmed_categories)

    for rule in config.decision_policy.hard_guardrails:
        when = rule.when
        rule_id_match = not when.rule_ids or bool(finding_rule_ids.intersection(when.rule_ids))
        category_match = not when.categories or bool(finding_categories.intersection(when.categories))
        confirmed_match = not when.confirmed_categories or set(when.confirmed_categories).issubset(confirmed_categories)
        if rule_id_match and category_match and confirmed_match:
            matched.append(
                f"minimum {rule.minimum_label.value} from "
                f"rules={when.rule_ids or '-'} categories={[category.value for category in when.categories] or '-'} "
                f"confirmed={[category.value for category in when.confirmed_categories] or '-'}"
            )
            if floor is None or RISK_LABEL_ORDER[rule.minimum_label] > RISK_LABEL_ORDER[floor]:
                floor = rule.minimum_label

    return floor, matched


def heuristic_adjudicate(
    findings: list[Finding],
    packet: EvidencePacket,
    config: ScanConfig,
) -> AdjudicationResult:
    floor, guardrails = determine_guardrail_floor(packet, findings, config)
    packet.highest_guardrail_floor = floor

    if not findings:
        return AdjudicationResult(
            risk_label=RiskLabel.LOW,
            summary="No findings were produced by the active layers.",
            rationale="The scan produced no structured evidence of malicious behavior, so the skill defaults to the lowest non-safe label.",
            drivers=[],
            categories=[],
            guardrails_triggered=[],
            adjudicator="heuristic",
            confidence=0.6,
        )

    confirmed_categories = set(packet.confirmed_categories)
    all_categories = sorted({finding.category for finding in findings}, key=lambda category: category.value)
    active_findings = [
        finding
        for finding in findings
        if not (finding.details.get("soft") and finding.details.get("soft_status", "pending") == "rejected")
        and not _finding_is_uncorroborated_general_llm(finding, findings)
        and not _finding_is_weak_markdown_llm_target(finding, findings)
    ]
    corroborating_findings = [
        finding
        for finding in active_findings
        if not (finding.details.get("soft") and finding.details.get("soft_status", "pending") == "pending")
    ]
    unique_active_findings = _dedupe_findings_for_policy(active_findings)
    unique_corroborating_findings = _dedupe_findings_for_policy(corroborating_findings)
    corroborating_categories = {finding.category for finding in unique_corroborating_findings}
    corroborating_llm_confirmations = [
        finding
        for finding in unique_corroborating_findings
        if finding.layer == DetectionLayer.LLM_ANALYSIS and str(finding.details.get("disposition", "")) == "confirm"
    ]
    chain_count = len(packet.chain_findings)
    unique_non_reference_corroborating_findings = [
        finding for finding in unique_corroborating_findings if not _finding_is_reference_example(finding)
    ]
    substantive_corroborating_findings = [
        finding for finding in unique_non_reference_corroborating_findings if not _finding_is_benign_bootstrap_signal(finding)
    ]
    substantive_corroborating_categories = {finding.category for finding in substantive_corroborating_findings}
    high_signal_count = sum(
        1
        for finding in substantive_corroborating_findings
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}
    )
    has_substantive_ml_signal = any(
        finding.layer == DetectionLayer.ML_ENSEMBLE and not _finding_is_reference_example(finding)
        and _finding_has_non_ml_corroboration(finding, unique_corroborating_findings)
        for finding in unique_corroborating_findings
    )
    confirm_count = len(corroborating_llm_confirmations)
    has_high_or_critical_finding = any(
        finding.severity in {Severity.HIGH, Severity.CRITICAL}
        for finding in substantive_corroborating_findings
    )
    has_benign_bootstrap_finding = any(_finding_is_benign_bootstrap_signal(finding) for finding in unique_corroborating_findings)
    has_medium_dangerous_signal = any(
        finding.severity == Severity.MEDIUM
        and finding.category in DANGEROUS_PROMOTION_CATEGORIES
        and not _finding_is_reference_example(finding)
        and not _finding_is_benign_bootstrap_signal(finding)
        and (
            str(finding.details.get("context", "")) in PROMOTABLE_CONTEXTS
            or str(finding.details.get("source_kind", "")) in {"code", "frontmatter_description"}
            or (
                not str(finding.details.get("context", ""))
                and not str(finding.details.get("source_kind", ""))
            )
        )
        for finding in unique_corroborating_findings
    )
    has_high_credential_or_persistence = any(
        finding.severity in {Severity.HIGH, Severity.CRITICAL}
        and finding.category in {Category.CREDENTIAL_THEFT, Category.PERSISTENCE}
        and _finding_supports_dangerous_promotion(finding)
        for finding in unique_corroborating_findings
    )
    has_paired_high_obfuscation = sum(
        1
        for finding in unique_active_findings
        if finding.category == Category.OBFUSCATION
        and finding.severity in {Severity.HIGH, Severity.CRITICAL}
        and not _finding_is_reference_example(finding)
    ) >= 2
    has_dangerous_medium_signal = any(_finding_supports_dangerous_promotion(finding) for finding in unique_corroborating_findings)
    has_prompt_suppression_combo = (
        any(
            finding.category == Category.PROMPT_INJECTION and not _finding_is_reference_example(finding)
            for finding in unique_active_findings
        )
        and any(
            finding.category == Category.SUPPRESSION and not _finding_is_reference_example(finding)
            for finding in substantive_corroborating_findings
        )
    )
    has_explicit_high_signal_rule = any(
        finding.rule_id in EXPLICIT_HIGH_SIGNAL_RULE_IDS and not _finding_is_benign_bootstrap_signal(finding)
        for finding in unique_corroborating_findings
    )
    has_encoded_remote_bootstrap_combo = _has_encoded_remote_bootstrap_combo(unique_active_findings)
    has_critical_finding = any(finding.severity == Severity.CRITICAL for finding in unique_active_findings)

    risk_label = RiskLabel.LOW
    if (
        has_high_or_critical_finding
        or has_benign_bootstrap_finding
        or has_medium_dangerous_signal
        or len(substantive_corroborating_findings) >= 2
        or has_substantive_ml_signal
        or confirm_count >= 1
    ):
        risk_label = RiskLabel.MEDIUM
    if (
        has_critical_finding
        or chain_count >= 1
        or high_signal_count >= 2
        or confirm_count >= 2
        or has_high_credential_or_persistence
        or has_paired_high_obfuscation
        or has_dangerous_medium_signal
        or has_prompt_suppression_combo
        or has_explicit_high_signal_rule
        or has_encoded_remote_bootstrap_combo
    ):
        risk_label = RiskLabel.HIGH
    if (
        {Category.CREDENTIAL_THEFT, Category.DATA_EXFILTRATION}.issubset(confirmed_categories)
        or chain_count >= 2
    ):
        risk_label = RiskLabel.CRITICAL
    elif (
        any(
            finding.category == Category.SUPPRESSION and not _finding_is_reference_example(finding)
            for finding in substantive_corroborating_findings
        )
        or (
            Category.CROSS_AGENT in substantive_corroborating_categories
            and bool(
                substantive_corroborating_categories.intersection(
                    {
                        Category.PERSISTENCE,
                        Category.BEHAVIORAL,
                        Category.JAILBREAK,
                        Category.CREDENTIAL_THEFT,
                        Category.DATA_EXFILTRATION,
                    }
                )
            )
        )
    ):
        risk_label = max_risk_label(risk_label, RiskLabel.HIGH)

    if floor is not None:
        risk_label = max_risk_label(risk_label, floor)

    drivers = packet.high_signal_findings[:3] or packet.chain_findings[:3] or packet.ml_signals[:3]
    if not drivers and findings:
        first = findings[0]
        drivers = [
            EvidenceDriver(
                rule_ids=[first.rule_id] if first.rule_id else [],
                categories=[first.category],
                file_path=first.location.file_path,
                segment_ids=[first.segment_id] if first.segment_id else [],
                explanation=first.message,
            )
        ]

    summary = _heuristic_summary(risk_label, all_categories, guardrails)
    rationale = _heuristic_rationale(packet=packet, guardrails=guardrails, finding_count=len(findings))
    return AdjudicationResult(
        risk_label=risk_label,
        summary=summary,
        rationale=rationale,
        drivers=drivers,
        categories=all_categories,
        guardrails_triggered=guardrails,
        adjudicator="heuristic",
        confidence=0.7 if guardrails or confirm_count else 0.58,
    )


def final_adjudicate(findings: list[Finding], config: ScanConfig) -> AdjudicationResult:
    packet = build_evidence_packet(findings, config)
    return heuristic_adjudicate(findings, packet, config)


async def run_final_adjudication(
    findings: list[Finding],
    config: ScanConfig,
    *,
    runtime: ScanRuntime | None = None,
    models: list[CodeAnalysisModel] | None = None,
) -> AdjudicationResult:
    packet = build_evidence_packet(findings, config)
    baseline = heuristic_adjudicate(findings, packet, config)
    if not findings:
        return baseline
    if not config.layers.llm.enabled or not config.layers.llm.final_adjudicator.enabled:
        return baseline
    if RISK_LABEL_ORDER[baseline.risk_label] < RISK_LABEL_ORDER[RiskLabel.HIGH]:
        return baseline
    if _final_adjudication_is_redundant(baseline, packet, findings):
        return baseline
    if runtime is not None:
        async with runtime.llm_section():
            return await runtime.to_thread(
                _run_final_adjudication_sync,
                findings,
                packet,
                config,
                baseline,
                runtime,
                models,
            )
    return await asyncio.to_thread(
        _run_final_adjudication_sync,
        findings,
        packet,
        config,
        baseline,
        None,
        models,
    )


def _final_adjudication_is_redundant(
    baseline: AdjudicationResult,
    packet: EvidencePacket,
    findings: list[Finding],
) -> bool:
    if baseline.risk_label not in {RiskLabel.HIGH, RiskLabel.CRITICAL}:
        return False
    if has_decisive_non_llm_combo(findings):
        return True
    finding_rule_ids = {
        rule_id
        for driver in packet.chain_findings
        for rule_id in driver.rule_ids
    }
    finding_rule_ids.update(
        rule_id
        for driver in packet.high_signal_findings
        for rule_id in driver.rule_ids
    )
    finding_rule_ids.update(
        rule_id
        for driver in packet.llm_confirmations
        for rule_id in driver.rule_ids
    )
    if any(rule_id in {"D-19A", "D-19B", "D-19C"} for rule_id in finding_rule_ids):
        return True
    return _has_decisive_non_llm_combo_from_rule_ids(finding_rule_ids)


def has_decisive_non_llm_combo(findings: list[Finding]) -> bool:
    raw_relevant_findings = [
        finding
        for finding in findings
        if not _finding_is_reference_example(finding)
        and not _finding_is_benign_bootstrap_signal(finding)
    ]
    relevant_findings = _dedupe_findings_for_policy(raw_relevant_findings)
    if _has_encoded_remote_bootstrap_combo(raw_relevant_findings):
        return True

    high_rule_ids = {
        finding.rule_id
        for finding in relevant_findings
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}
    }
    medium_or_higher_rule_ids = {
        finding.rule_id
        for finding in relevant_findings
        if finding.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
    }

    remote_host_count = len(
        {
            str(finding.details.get("host", ""))
            for finding in raw_relevant_findings
            if finding.rule_id == "D-15E"
            and finding.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
            and str(finding.details.get("host", ""))
        }
    )
    obfuscation_signal_count = sum(
        1
        for finding in raw_relevant_findings
        if finding.rule_id in DECISIVE_NON_LLM_OBFUSCATION_RULE_IDS
        and finding.severity in {Severity.HIGH, Severity.CRITICAL}
    )
    if _has_decisive_non_llm_combo_from_rule_ids(
        high_rule_ids | medium_or_higher_rule_ids,
        remote_host_count=remote_host_count,
        obfuscation_signal_count=obfuscation_signal_count,
    ):
        return True

    has_high_credential = bool(high_rule_ids.intersection(DECISIVE_NON_LLM_CREDENTIAL_RULE_IDS))
    has_behavioral_or_exfil = bool(
        high_rule_ids.intersection(DECISIVE_NON_LLM_BEHAVIOR_RULE_IDS)
        or medium_or_higher_rule_ids.intersection(DECISIVE_NON_LLM_EXFIL_RULE_IDS)
    )
    has_obfuscation = bool(
        high_rule_ids.intersection(DECISIVE_NON_LLM_OBFUSCATION_RULE_IDS)
        or "NC-3A" in medium_or_higher_rule_ids
    )
    return has_high_credential and has_behavioral_or_exfil and has_obfuscation


def _has_decisive_non_llm_combo_from_rule_ids(
    rule_ids: set[str],
    remote_host_count: int = 0,
    obfuscation_signal_count: int = 0,
) -> bool:
    if rule_ids.intersection({"D-19A", "D-19B", "D-19C"}):
        return True
    if "D-20H" not in rule_ids:
        return False
    has_high_behavioral = bool(rule_ids.intersection(DECISIVE_NON_LLM_BEHAVIOR_RULE_IDS))
    has_high_credential = bool(rule_ids.intersection(DECISIVE_NON_LLM_CREDENTIAL_RULE_IDS))
    has_obfuscation_or_stego = bool(rule_ids.intersection(DECISIVE_NON_LLM_OBFUSCATION_RULE_IDS))
    distinct_obfuscation_rule_count = len(rule_ids.intersection(DECISIVE_NON_LLM_OBFUSCATION_RULE_IDS))
    has_remote_or_exfil = remote_host_count >= 3 or bool(rule_ids.intersection(DECISIVE_NON_LLM_EXFIL_RULE_IDS))
    return (
        has_high_behavioral
        or has_high_credential
        or obfuscation_signal_count >= 2
        or distinct_obfuscation_rule_count >= 2
        or (has_obfuscation_or_stego and has_remote_or_exfil)
    )


def max_risk_label(left: RiskLabel, right: RiskLabel) -> RiskLabel:
    if RISK_LABEL_ORDER[left] >= RISK_LABEL_ORDER[right]:
        return left
    return right


def _dedupe_findings_for_policy(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str | None]] = set()
    for finding in findings:
        key = (finding.rule_id, finding.category.value, finding.location.file_path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _finding_supports_dangerous_promotion(finding: Finding) -> bool:
    if _finding_is_benign_bootstrap_signal(finding):
        return False
    if finding.rule_id == "D-9A" and finding.severity == Severity.MEDIUM:
        return False
    if finding.category not in DANGEROUS_PROMOTION_CATEGORIES:
        return False
    if finding.severity not in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}:
        return False
    if finding.rule_id in EXPLICIT_HIGH_SIGNAL_RULE_IDS:
        return True
    source_kind = str(finding.details.get("source_kind", ""))
    if _finding_is_reference_example(finding):
        return False
    if finding.layer == DetectionLayer.LLM_ANALYSIS:
        return True
    if finding.layer == DetectionLayer.ML_ENSEMBLE:
        return False

    context = str(finding.details.get("context", ""))
    if context in PROMOTABLE_CONTEXTS:
        return True
    if context == "documentation":
        return False
    if source_kind in {"code", "frontmatter_description"}:
        return True
    if source_kind == "markdown":
        return False
    return True


def _finding_is_reference_example(finding: Finding) -> bool:
    return bool(finding.details.get("reference_example")) and str(finding.details.get("source_kind", "")) == "markdown"


def _finding_is_uncorroborated_general_llm(finding: Finding, findings: list[Finding]) -> bool:
    if finding.layer != DetectionLayer.LLM_ANALYSIS:
        return False
    if finding.rule_id != "LLM-GEN" and str(finding.details.get("analysis_scope", "")) != "general":
        return False
    return not _finding_has_substantive_non_llm_corroboration(finding, findings)


def _finding_has_non_llm_corroboration(finding: Finding, findings: list[Finding]) -> bool:
    file_path = finding.location.file_path or ""
    return any(
        other.id != finding.id
        and other.layer != DetectionLayer.LLM_ANALYSIS
        and not _finding_is_reference_example(other)
        and (other.location.file_path or "") == file_path
        for other in findings
    )


def _finding_has_substantive_non_llm_corroboration(finding: Finding, findings: list[Finding]) -> bool:
    file_path = finding.location.file_path or ""
    return any(
        other.id != finding.id
        and other.layer != DetectionLayer.LLM_ANALYSIS
        and not _finding_is_reference_example(other)
        and (other.location.file_path or "") == file_path
        and (
            other.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
            or other.category != Category.STRUCTURAL
        )
        for other in findings
    )


def _finding_has_high_non_llm_corroboration(finding: Finding, findings: list[Finding]) -> bool:
    file_path = finding.location.file_path or ""
    return any(
        other.id != finding.id
        and other.layer != DetectionLayer.LLM_ANALYSIS
        and not _finding_is_reference_example(other)
        and (other.location.file_path or "") == file_path
        and other.severity in {Severity.HIGH, Severity.CRITICAL}
        for other in findings
    )


def _finding_is_weak_markdown_llm_target(finding: Finding, findings: list[Finding]) -> bool:
    if finding.layer != DetectionLayer.LLM_ANALYSIS:
        return False
    if finding.rule_id == "LLM-GEN" or str(finding.details.get("analysis_scope", "")) == "general":
        return False
    if finding.severity != Severity.MEDIUM:
        return False
    file_path = finding.location.file_path or ""
    source_kind = str(finding.details.get("source_kind", ""))
    if source_kind != "markdown" and Path(file_path).suffix.lower() != ".md":
        return False
    return not _finding_has_high_non_llm_corroboration(finding, findings)


def _finding_has_non_ml_corroboration(finding: Finding, findings: list[Finding]) -> bool:
    file_path = finding.location.file_path or ""
    return any(
        other.id != finding.id
        and other.layer != DetectionLayer.ML_ENSEMBLE
        and not _finding_is_reference_example(other)
        and (other.location.file_path or "") == file_path
        for other in findings
    )


def _finding_is_benign_bootstrap_signal(finding: Finding) -> bool:
    if not bool(finding.details.get("environment_bootstrap")):
        return False
    if finding.category in {Category.PERSISTENCE, Category.CROSS_AGENT}:
        return True
    return finding.rule_id in {"D-10A", "D-10D"}


def _has_encoded_remote_bootstrap_combo(findings: list[Finding]) -> bool:
    relevant_findings = [
        finding
        for finding in findings
        if not _finding_is_reference_example(finding) and not _finding_is_benign_bootstrap_signal(finding)
    ]
    has_encoded_payload = any(
        finding.rule_id in {"D-3A", "D-4B", "D-5A", "D-5B", "D-5C"}
        and finding.severity in {Severity.HIGH, Severity.CRITICAL}
        for finding in relevant_findings
    )
    has_execution = any(
        finding.rule_id in {"D-10A", "D-10D"}
        and str(finding.details.get("context", "")) in PROMOTABLE_CONTEXTS
        for finding in relevant_findings
    )
    has_remote_target = any(
        finding.rule_id in {"D-15C", "D-15D"}
        or (
            finding.rule_id == "D-15E"
            and str(finding.details.get("context", "")) in {"actionable_instruction", "executable_snippet"}
        )
        for finding in relevant_findings
    )
    return has_encoded_payload and has_execution and has_remote_target


def _heuristic_summary(
    risk_label: RiskLabel,
    categories: list[Category],
    guardrails: list[str],
) -> str:
    category_labels = ", ".join(category.value for category in categories[:4]) or "no categories"
    if guardrails:
        return f"{risk_label.value} risk based on guardrail-triggering evidence in {category_labels}."
    return f"{risk_label.value} risk based on combined evidence in {category_labels}."


def _heuristic_rationale(
    *,
    packet: EvidencePacket,
    guardrails: list[str],
    finding_count: int,
) -> str:
    parts = [f"{finding_count} findings contributed to the decision."]
    if packet.chain_findings:
        parts.append(f"{len(packet.chain_findings)} chained behavior findings increased severity.")
    if packet.llm_confirmations:
        parts.append(f"{len(packet.llm_confirmations)} findings were semantically confirmed.")
    if packet.llm_disputes:
        parts.append(f"{len(packet.llm_disputes)} findings were disputed or rejected.")
    if guardrails:
        parts.append("Guardrails prevented the final label from being downgraded.")
    return " ".join(parts)


def _run_final_adjudication_sync(
    findings: list[Finding],
    packet: EvidencePacket,
    config: ScanConfig,
    baseline: AdjudicationResult,
    runtime: ScanRuntime | None,
    models: list[CodeAnalysisModel] | None,
) -> AdjudicationResult:
    prompt = _build_final_adjudication_prompt(packet, baseline)
    llm_lease = None
    owned_models: list[CodeAnalysisModel] = []
    active_models = models
    if active_models is None and runtime is not None and config.runtime.llm_lifecycle == "command":
        llm_lease = runtime.lease_llm_models(
            config,
            requested_group=config.layers.llm.final_adjudicator.model_group,
        )
        active_models = llm_lease.models
    elif active_models is None:
        active_models = _build_final_adjudication_models(config)
        owned_models = list(active_models)

    responses: list[dict[str, object]] = []
    try:
        responses = _execute_final_adjudicator_models(
            models=active_models or [],
            prompt=prompt,
            max_tokens=config.layers.llm.final_adjudicator.max_tokens,
            max_workers=max(1, config.runtime.llm_server_parallel_requests),
        )
    finally:
        if llm_lease is not None:
            llm_lease.release()

    if not responses:
        return baseline.model_copy(update={"adjudicator": "heuristic_fallback"})

    voted_label = _majority_risk_label(responses)
    if packet.highest_guardrail_floor is not None:
        voted_label = max_risk_label(voted_label, packet.highest_guardrail_floor)
    chosen = max(
        (response for response in responses if response["risk_label"] == voted_label),
        key=lambda response: coerce_confidence(response.get("confidence", 0.0)),
        default=max(responses, key=lambda response: coerce_confidence(response.get("confidence", 0.0))),
    )

    drivers = baseline.drivers
    if chosen.get("driver_rule_ids"):
        candidate_drivers = [
            driver for driver in baseline.drivers if set(driver.rule_ids).intersection(chosen["driver_rule_ids"])
        ]
        if candidate_drivers:
            drivers = candidate_drivers

    return baseline.model_copy(
        update={
            "risk_label": voted_label,
            "summary": str(chosen.get("summary") or baseline.summary),
            "rationale": str(chosen.get("rationale") or baseline.rationale),
            "drivers": drivers,
            "adjudicator": "llm",
            "confidence": _mean_confidence(responses),
            "guardrails_triggered": baseline.guardrails_triggered,
        }
    )


def _execute_final_adjudicator_models(
    *,
    models: list[CodeAnalysisModel],
    prompt: str,
    max_tokens: int,
    max_workers: int,
) -> list[dict[str, object]]:
    if max_workers <= 1 or len(models) <= 1:
        return [
            response
            for model in models
            if (response := _run_final_adjudicator_model(model, prompt, max_tokens)) is not None
        ]

    responses: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(models))) as executor:
        futures = [executor.submit(_run_final_adjudicator_model, model, prompt, max_tokens) for model in models]
        for future in as_completed(futures):
            response = future.result()
            if response is not None:
                responses.append(response)
    return responses


def _run_final_adjudicator_model(
    model: CodeAnalysisModel,
    prompt: str,
    max_tokens: int,
) -> dict[str, object] | None:
    try:
        model.load()
        response = model.generate_structured(prompt, max_tokens=max_tokens)
        return _parse_final_adjudication_response(response, model.model_id)
    except Exception:
        return None
    finally:
        model.unload()


def _build_final_adjudication_models(config: ScanConfig) -> list[CodeAnalysisModel]:
    hardware = detect_hardware_profile(config.layers.llm.device_policy or config.device)
    _, model_configs = resolve_group_models(
        config,
        requested_group=config.layers.llm.final_adjudicator.model_group,
        hardware=hardware,
    )
    cache_dir = _expand_cache_dir(config)
    cache_dir.mkdir(parents=True, exist_ok=True)
    models: list[CodeAnalysisModel] = []
    for model_config in model_configs:
        model_path = None
        if model_config.runtime.lower() != "heuristic":
            model_path = resolve_model_file(
                model_config,
                cache_dir=cache_dir,
                auto_download=config.layers.llm.auto_download,
            )
        models.append(
            build_code_analysis_model(
                model=model_config,
                model_path=model_path,
                hardware=hardware,
                parallel_requests=max(1, config.runtime.llm_server_parallel_requests),
                server_threads=max(1, config.runtime.llm_server_threads),
            )
        )
    return models


def _build_final_adjudication_prompt(packet: EvidencePacket, baseline: AdjudicationResult) -> str:
    packet_json = json.dumps(packet.model_dump(mode="json"), indent=2, sort_keys=True)
    return (
        "You are the final risk adjudicator for an AI agent skill security scan.\n\n"
        "You will receive a structured evidence packet produced by deterministic rules, ML classifiers, "
        "and targeted/repo LLM analysis. Choose the final overall risk label for the skill.\n\n"
        "RULES:\n"
        "- Choose exactly one risk_label from LOW, MEDIUM, HIGH, CRITICAL.\n"
        "- Do not output a binary label.\n"
        "- Use the evidence packet only; do not invent evidence.\n"
        "- If the evidence packet suggests clear malicious behavior, prefer the stronger label.\n"
        "- If the heuristic baseline is already severe due to hard evidence, do not downplay it.\n\n"
        "Return ONLY valid JSON with keys:\n"
        '- "risk_label"\n'
        '- "summary"\n'
        '- "rationale"\n'
        '- "driver_rule_ids" (list of rule ids that most influenced the decision)\n'
        '- "confidence" (0.0-1.0)\n\n'
        f"Heuristic baseline: {baseline.risk_label.value}\n"
        f"Heuristic summary: {baseline.summary}\n\n"
        "Evidence packet:\n"
        "```json\n"
        f"{packet_json}\n"
        "```"
    )


def _parse_final_adjudication_response(
    response: dict[str, object],
    model_id: str,
) -> dict[str, object] | None:
    risk_label = str(response.get("risk_label", "")).upper()
    if risk_label not in {label.value for label in RiskLabel}:
        return None
    summary = str(response.get("summary", "")).strip()
    rationale = str(response.get("rationale", "")).strip()
    confidence = coerce_confidence(response.get("confidence", 0.0))
    driver_rule_ids = [str(item) for item in response.get("driver_rule_ids", []) if item]
    return {
        "risk_label": RiskLabel(risk_label),
        "summary": summary,
        "rationale": rationale,
        "confidence": confidence,
        "driver_rule_ids": driver_rule_ids,
        "model_id": model_id,
    }


def _majority_risk_label(responses: list[dict[str, object]]) -> RiskLabel:
    counts: dict[RiskLabel, int] = defaultdict(int)
    for response in responses:
        counts[response["risk_label"]] += 1
    return max(
        counts,
        key=lambda label: (counts[label], _mean_confidence([r for r in responses if r["risk_label"] == label]), RISK_LABEL_ORDER[label]),
    )


def _mean_confidence(responses: list[dict[str, object]]) -> float:
    if not responses:
        return 0.0
    return round(sum(coerce_confidence(response.get("confidence", 0.0)) for response in responses) / len(responses), 4)
