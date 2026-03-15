from __future__ import annotations

from skillinquisitor.detectors.rules import build_rule_registry, run_registered_rules
from skillinquisitor.models import ScanConfig, ScanResult, Skill
from skillinquisitor.normalize import normalize_artifact


def normalize_skills(skills: list[Skill]) -> list[Skill]:
    normalized_skills: list[Skill] = []
    for skill in skills:
        normalized_skills.append(
            skill.model_copy(
                update={
                    "artifacts": [normalize_artifact(artifact) for artifact in skill.artifacts],
                }
            )
        )
    return normalized_skills


async def run_pipeline(skills: list[Skill], config: ScanConfig) -> ScanResult:
    normalized_skills = normalize_skills(skills)
    rule_registry = build_rule_registry(config)
    findings = run_registered_rules(normalized_skills, config, rule_registry)

    return ScanResult(
        skills=normalized_skills,
        findings=findings,
        risk_score=100,
        verdict="SAFE" if not findings else "MEDIUM RISK",
        layer_metadata={
            "deterministic": {"enabled": config.layers.deterministic.enabled, "findings": len(findings)},
            "ml": {"enabled": config.layers.ml.enabled, "findings": 0},
            "llm": {"enabled": config.layers.llm.enabled, "findings": 0},
        },
        total_timing=0.0,
    )
