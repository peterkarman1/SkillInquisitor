from skillinquisitor.adjudication import (
    _parse_final_adjudication_response,
    build_evidence_packet,
    final_adjudicate,
    has_decisive_non_llm_combo,
    map_risk_label_to_binary,
    risk_label_to_legacy_verdict,
)
from skillinquisitor.models import (
    Category,
    DetectionLayer,
    Finding,
    Location,
    RiskLabel,
    ScanConfig,
    Severity,
)


def _finding(
    *,
    rule_id: str,
    category: Category,
    severity: Severity,
    layer: DetectionLayer = DetectionLayer.DETERMINISTIC,
    file_path: str = "skill/SKILL.md",
    details: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        layer=layer,
        category=category,
        severity=severity,
        message=rule_id,
        location=Location(file_path=file_path, start_line=1, end_line=1),
        details=details or {},
    )


def test_build_evidence_packet_tracks_confirmed_disputed_and_artifact_summaries():
    findings = [
        _finding(
            rule_id="D-19A",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            file_path="skill/scripts/exfil.py",
            details={"soft_status": "confirmed"},
        ),
        _finding(
            rule_id="ML-PI",
            category=Category.PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            layer=DetectionLayer.ML_ENSEMBLE,
            file_path="skill/SKILL.md",
        ),
        _finding(
            rule_id="LLM-TGT-EXFIL",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/scripts/exfil.py",
            details={"disposition": "confirm"},
        ),
        _finding(
            rule_id="LLM-TGT-BENIGN",
            category=Category.BEHAVIORAL,
            severity=Severity.LOW,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/scripts/health.py",
            details={"disposition": "dispute"},
        ),
    ]

    packet = build_evidence_packet(findings, ScanConfig())

    assert [category.value for category in packet.confirmed_categories] == ["data_exfiltration"]
    assert [category.value for category in packet.disputed_categories] == ["behavioral"]
    assert [driver.rule_ids[0] for driver in packet.chain_findings] == ["D-19A"]
    assert [driver.rule_ids[0] for driver in packet.ml_signals] == ["ML-PI"]
    assert len(packet.artifact_summary) == 3


def test_final_adjudicate_promotes_single_confirmed_exfiltration_to_high():
    findings = [
        _finding(
            rule_id="LLM-TGT-EXFIL",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/scripts/exfil.py",
            details={"disposition": "confirm"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_parse_final_adjudication_response_coerces_qualitative_confidence():
    parsed = _parse_final_adjudication_response(
        {
            "risk_label": "high",
            "summary": "malicious bootstrap flow",
            "rationale": "encoded remote installer plus execution",
            "confidence": "high",
            "driver_rule_ids": ["D-10D", "D-20H"],
        },
        "fixture://model",
    )

    assert parsed is not None
    assert parsed["risk_label"] == RiskLabel.HIGH
    assert parsed["confidence"] > 0.0


def test_parse_final_adjudication_response_defaults_invalid_confidence_to_zero():
    parsed = _parse_final_adjudication_response(
        {
            "risk_label": "medium",
            "summary": "uncertain review",
            "rationale": "model returned malformed confidence",
            "confidence": {"value": "oops"},
            "driver_rule_ids": [],
        },
        "fixture://model",
    )

    assert parsed is not None
    assert parsed["risk_label"] == RiskLabel.MEDIUM
    assert parsed["confidence"] == 0.0


def test_has_decisive_non_llm_combo_for_fake_prerequisite_obfuscation_and_remote_delivery():
    findings = [
        _finding(
            rule_id="D-20H",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH,
        ),
        _finding(
            rule_id="D-1C",
            category=Category.STEGANOGRAPHY,
            severity=Severity.HIGH,
        ),
        _finding(
            rule_id="D-5A",
            category=Category.OBFUSCATION,
            severity=Severity.HIGH,
        ),
        _finding(
            rule_id="D-15E",
            category=Category.STRUCTURAL,
            severity=Severity.MEDIUM,
            details={"host": "example.invalid"},
        ),
        _finding(
            rule_id="D-15E",
            category=Category.STRUCTURAL,
            severity=Severity.MEDIUM,
            details={"host": "cdn.invalid"},
            file_path="skill/README.md",
        ),
        _finding(
            rule_id="D-15E",
            category=Category.STRUCTURAL,
            severity=Severity.MEDIUM,
            details={"host": "api.invalid"},
            file_path="skill/docs.md",
        ),
    ]

    assert has_decisive_non_llm_combo(findings) is True


def test_final_adjudicate_promotes_single_medium_credential_signal_to_high():
    findings = [
        _finding(
            rule_id="D-8B",
            category=Category.CREDENTIAL_THEFT,
            severity=Severity.MEDIUM,
            file_path="skill/scripts/env_dump.py",
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_single_medium_dangerous_signal_at_medium():
    findings = [
        _finding(
            rule_id="D-9A",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            file_path="skill/scripts/send.py",
            details={"context": "actionable_instruction"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_medium_dangerous_signal_at_medium_even_with_pending_soft_corroborator():
    findings = [
        _finding(
            rule_id="D-9A",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            file_path="skill/scripts/send.py",
        ),
        _finding(
            rule_id="D-15E",
            category=Category.STRUCTURAL,
            severity=Severity.MEDIUM,
            file_path="skill/scripts/send.py",
            details={"soft": True, "soft_status": "pending"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_promotes_single_behavioral_signal_even_after_deduping():
    findings = [
        _finding(
            rule_id="D-10A",
            category=Category.BEHAVIORAL,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"context": "executable_snippet"},
        ),
        _finding(
            rule_id="D-10A",
            category=Category.BEHAVIORAL,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"context": "executable_snippet"},
        ),
        _finding(
            rule_id="D-22A",
            category=Category.OBFUSCATION,
            severity=Severity.MEDIUM,
            file_path="skill/SKILL.md",
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_documentation_only_behavioral_signal_at_medium():
    findings = [
        _finding(
            rule_id="D-10A",
            category=Category.BEHAVIORAL,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"context": "documentation", "source_kind": "markdown"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_downgrades_documentation_only_persistence_signal_to_low():
    findings = [
        _finding(
            rule_id="D-16B",
            category=Category.PERSISTENCE,
            severity=Severity.MEDIUM,
            file_path="skill/SKILL.md",
            details={"context": "documentation", "source_kind": "markdown"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_lone_ml_prompt_injection_signal_at_medium():
    findings = [
        _finding(
            rule_id="D-14C",
            category=Category.STRUCTURAL,
            severity=Severity.LOW,
            file_path="skill/SKILL.md",
        ),
        _finding(
            rule_id="ML-PI",
            category=Category.PROMPT_INJECTION,
            severity=Severity.HIGH,
            layer=DetectionLayer.ML_ENSEMBLE,
            file_path="skill/SKILL.md",
            details={"context": "actionable_instruction", "source_kind": "markdown"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_lone_ml_prompt_injection_code_signal_at_medium():
    findings = [
        _finding(
            rule_id="ML-PI",
            category=Category.PROMPT_INJECTION,
            severity=Severity.HIGH,
            layer=DetectionLayer.ML_ENSEMBLE,
            file_path="skill/scripts/worker.py",
            details={"context": "code", "source_kind": "code"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_uncorroborated_general_llm_on_skill_manifest():
    findings = [
        _finding(
            rule_id="LLM-GEN",
            category=Category.BEHAVIORAL,
            severity=Severity.CRITICAL,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/SKILL.md",
            details={"analysis_scope": "general", "disposition": "confirm"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_uncorroborated_general_llm_on_non_manifest_artifact():
    findings = [
        _finding(
            rule_id="LLM-GEN",
            category=Category.BEHAVIORAL,
            severity=Severity.CRITICAL,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/scripts/helper.js",
            details={"analysis_scope": "general", "disposition": "confirm"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_treat_low_structural_noise_as_general_llm_corroboration():
    findings = [
        _finding(
            rule_id="LLM-GEN",
            category=Category.BEHAVIORAL,
            severity=Severity.CRITICAL,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/SKILL.md",
            details={"analysis_scope": "general", "disposition": "confirm"},
        ),
        _finding(
            rule_id="D-13A",
            category=Category.STRUCTURAL,
            severity=Severity.LOW,
            file_path="skill/SKILL.md",
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_allows_general_llm_when_non_llm_finding_corroborates_same_manifest():
    findings = [
        _finding(
            rule_id="LLM-GEN",
            category=Category.BEHAVIORAL,
            severity=Severity.HIGH,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/SKILL.md",
            details={"analysis_scope": "general", "disposition": "confirm"},
        ),
        _finding(
            rule_id="D-10A",
            category=Category.BEHAVIORAL,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"context": "actionable_instruction", "source_kind": "markdown"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_medium_targeted_llm_on_markdown_without_high_non_llm_support():
    findings = [
        _finding(
            rule_id="D-9A",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            file_path="skill/SKILL.md",
            details={"context": "documentation", "source_kind": "markdown"},
        ),
        _finding(
            rule_id="LLM-TGT-EXFIL",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/SKILL.md",
            details={"disposition": "confirm", "source_kind": "markdown"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_allows_medium_targeted_llm_on_markdown_with_high_non_llm_support():
    findings = [
        _finding(
            rule_id="D-20H",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"context": "actionable_instruction", "source_kind": "markdown"},
        ),
        _finding(
            rule_id="LLM-TGT-EXFIL",
            category=Category.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            layer=DetectionLayer.LLM_ANALYSIS,
            file_path="skill/SKILL.md",
            details={"disposition": "confirm", "source_kind": "markdown"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_bootstrap_persistence_and_cross_agent_to_high():
    findings = [
        _finding(
            rule_id="D-17A",
            category=Category.PERSISTENCE,
            severity=Severity.HIGH,
            file_path="skill/resources/Dockerfile",
            details={"context": "code", "source_kind": "code", "environment_bootstrap": True},
        ),
        _finding(
            rule_id="D-18A",
            category=Category.CROSS_AGENT,
            severity=Severity.HIGH,
            file_path="skill/resources/devcontainer.json",
            details={"context": "code", "source_kind": "code", "environment_bootstrap": True},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_environment_bootstrap_remote_installer_to_high():
    findings = [
        _finding(
            rule_id="D-10D",
            category=Category.BEHAVIORAL,
            severity=Severity.HIGH,
            file_path="skill/resources/Dockerfile",
            details={"context": "code", "source_kind": "code", "environment_bootstrap": True},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_lone_cross_agent_signal_to_high():
    findings = [
        _finding(
            rule_id="D-18A",
            category=Category.CROSS_AGENT,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"context": "actionable_instruction", "source_kind": "markdown"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_reference_example_ml_signal_to_high():
    findings = [
        _finding(
            rule_id="ML-PI",
            category=Category.PROMPT_INJECTION,
            severity=Severity.HIGH,
            layer=DetectionLayer.ML_ENSEMBLE,
            file_path="skill/references/runbook.md",
            details={"reference_example": True, "context": "executable_snippet", "source_kind": "markdown"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_does_not_promote_reference_example_secret_signal_to_high():
    findings = [
        _finding(
            rule_id="D-8A",
            category=Category.CREDENTIAL_THEFT,
            severity=Severity.HIGH,
            file_path="skill/references/guide.md",
            details={"reference_example": True, "context": "documentation", "source_kind": "markdown"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_promotes_prompt_injection_plus_suppression_combo_to_high():
    findings = [
        _finding(
            rule_id="ML-PI",
            category=Category.PROMPT_INJECTION,
            severity=Severity.HIGH,
            layer=DetectionLayer.ML_ENSEMBLE,
            file_path="skill/SKILL.md",
            details={"context": "actionable_instruction", "source_kind": "markdown"},
        ),
        _finding(
            rule_id="D-12C",
            category=Category.SUPPRESSION,
            severity=Severity.MEDIUM,
            file_path="skill/SKILL.md",
            details={"context": "actionable_instruction", "source_kind": "markdown"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_reference_example_prompt_injection_plus_suppression_combo_at_medium():
    findings = [
        _finding(
            rule_id="ML-PI",
            category=Category.PROMPT_INJECTION,
            severity=Severity.HIGH,
            layer=DetectionLayer.ML_ENSEMBLE,
            file_path="skill/references/runbook.md",
            details={"reference_example": True, "context": "documentation", "source_kind": "markdown"},
        ),
        _finding(
            rule_id="D-12C",
            category=Category.SUPPRESSION,
            severity=Severity.MEDIUM,
            file_path="skill/references/runbook.md",
            details={"reference_example": True, "context": "documentation", "source_kind": "markdown"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_promotes_instruction_override_to_high():
    findings = [
        _finding(
            rule_id="D-11A",
            category=Category.PROMPT_INJECTION,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_promotes_reverse_shell_signal_to_high():
    findings = [
        _finding(
            rule_id="D-10B",
            category=Category.BEHAVIORAL,
            severity=Severity.HIGH,
            file_path="skill/scripts/worker.py",
            details={"context": "code", "source_kind": "code"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_promotes_global_workflow_capture_to_high():
    findings = [
        _finding(
            rule_id="D-11G",
            category=Category.PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            file_path="skill/SKILL.md",
            details={"context": "actionable_instruction", "source_kind": "markdown"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_promotes_single_high_credential_theft_signal_to_high():
    findings = [
        _finding(
            rule_id="D-7A",
            category=Category.CREDENTIAL_THEFT,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
        ),
        _finding(
            rule_id="D-14C",
            category=Category.STRUCTURAL,
            severity=Severity.LOW,
            file_path="skill/SKILL.md",
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_documented_high_credential_signal_at_medium():
    findings = [
        _finding(
            rule_id="D-8A",
            category=Category.CREDENTIAL_THEFT,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"context": "documentation", "source_kind": "markdown"},
        )
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.MEDIUM
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_multiple_reference_example_credential_signals_at_low():
    findings = [
        _finding(
            rule_id="D-8A",
            category=Category.CREDENTIAL_THEFT,
            severity=Severity.HIGH,
            file_path="skill/README.md",
            details={"context": "documentation", "source_kind": "markdown", "reference_example": True},
        ),
        _finding(
            rule_id="D-8D",
            category=Category.CREDENTIAL_THEFT,
            severity=Severity.HIGH,
            file_path="skill/README.md",
            details={"context": "actionable_instruction", "source_kind": "markdown", "reference_example": True},
        ),
        _finding(
            rule_id="D-8B",
            category=Category.CREDENTIAL_THEFT,
            severity=Severity.MEDIUM,
            file_path="skill/README.md",
            details={"context": "actionable_instruction", "source_kind": "markdown", "reference_example": True},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_keeps_reference_example_cross_agent_and_persistence_signals_at_low():
    findings = [
        _finding(
            rule_id="D-17A",
            category=Category.PERSISTENCE,
            severity=Severity.HIGH,
            file_path="skill/references/guide.md",
            details={"context": "actionable_instruction", "source_kind": "markdown", "reference_example": True},
        ),
        _finding(
            rule_id="D-18A",
            category=Category.CROSS_AGENT,
            severity=Severity.HIGH,
            file_path="skill/references/guide.md",
            details={"context": "actionable_instruction", "source_kind": "markdown", "reference_example": True},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_final_adjudicate_promotes_paired_high_obfuscation_signals_to_high():
    findings = [
        _finding(
            rule_id="D-5A",
            category=Category.OBFUSCATION,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"soft": True, "soft_status": "pending"},
        ),
        _finding(
            rule_id="D-5B",
            category=Category.OBFUSCATION,
            severity=Severity.HIGH,
            file_path="skill/SKILL.md",
            details={"soft": True, "soft_status": "pending"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.HIGH
    assert result.guardrails_triggered == []


def test_final_adjudicate_ignores_rejected_soft_suppression_for_high_promotion():
    findings = [
        _finding(
            rule_id="D-12C",
            category=Category.SUPPRESSION,
            severity=Severity.MEDIUM,
            file_path="skill/SKILL.md",
            details={"soft": True, "soft_status": "rejected"},
        ),
        _finding(
            rule_id="D-22A",
            category=Category.OBFUSCATION,
            severity=Severity.MEDIUM,
            file_path="skill/SKILL.md",
            details={"soft": True, "soft_status": "rejected"},
        ),
    ]

    result = final_adjudicate(findings, ScanConfig())

    assert result.risk_label == RiskLabel.LOW
    assert result.guardrails_triggered == []


def test_binary_label_mapping_uses_cutoff_policy():
    assert map_risk_label_to_binary(RiskLabel.MEDIUM, RiskLabel.HIGH) == "not_malicious"
    assert map_risk_label_to_binary(RiskLabel.HIGH, RiskLabel.HIGH) == "malicious"
    assert map_risk_label_to_binary(RiskLabel.MEDIUM, RiskLabel.MEDIUM) == "malicious"


def test_risk_label_to_legacy_verdict_matches_new_labels():
    assert risk_label_to_legacy_verdict(RiskLabel.LOW) == "LOW RISK"
    assert risk_label_to_legacy_verdict(RiskLabel.MEDIUM) == "MEDIUM RISK"
    assert risk_label_to_legacy_verdict(RiskLabel.HIGH) == "HIGH RISK"
    assert risk_label_to_legacy_verdict(RiskLabel.CRITICAL) == "CRITICAL"
