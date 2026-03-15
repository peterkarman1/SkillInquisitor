from __future__ import annotations

from skillinquisitor.detectors.rules import build_rule_registry, run_registered_rules
from skillinquisitor.models import ScanConfig, ScanResult, Skill
from skillinquisitor.normalize import normalize_artifact


def normalize_skills(skills: list[Skill], config: ScanConfig) -> list[Skill]:
    normalized_skills: list[Skill] = []
    for skill in skills:
        normalized_artifacts = [normalize_artifact(artifact, config=config) for artifact in skill.artifacts]
        normalized_skills.append(
            skill.model_copy(
                update={
                    "artifacts": normalized_artifacts,
                }
            )
        )
    return normalized_skills


def _update_skill_names_from_frontmatter(skills: list[Skill]) -> list[Skill]:
    updated: list[Skill] = []
    for skill in skills:
        next_name = skill.name
        for artifact in skill.artifacts:
            if not artifact.path.endswith("SKILL.md"):
                continue
            duplicate_name_observations = [
                observation
                for observation in artifact.frontmatter_observations
                if observation.get("kind") == "duplicate_key" and observation.get("key") == "name"
            ]
            parsed_name = artifact.frontmatter.get("name")
            if isinstance(parsed_name, str) and not duplicate_name_observations and "name" in artifact.frontmatter_fields:
                next_name = parsed_name
            break
        updated.append(skill.model_copy(update={"name": next_name}))
    return updated


async def run_pipeline(skills: list[Skill], config: ScanConfig) -> ScanResult:
    normalized_skills = normalize_skills(skills, config=config)
    normalized_skills = _update_skill_names_from_frontmatter(normalized_skills)
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
