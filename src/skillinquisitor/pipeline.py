from __future__ import annotations

from skillinquisitor.models import ScanConfig, ScanResult, Skill
from skillinquisitor.normalize import normalize_artifact


async def run_pipeline(skills: list[Skill], config: ScanConfig) -> ScanResult:
    normalized_skills: list[Skill] = []
    for skill in skills:
        normalized_skills.append(
            skill.model_copy(
                update={
                    "artifacts": [normalize_artifact(artifact) for artifact in skill.artifacts],
                }
            )
        )

    return ScanResult(
        skills=normalized_skills,
        findings=[],
        risk_score=100,
        verdict="SAFE",
        layer_metadata={
            "deterministic": {"enabled": config.layers.deterministic.enabled, "findings": 0},
            "ml": {"enabled": config.layers.ml.enabled, "findings": 0},
            "llm": {"enabled": config.layers.llm.enabled, "findings": 0},
        },
        total_timing=0.0,
    )
