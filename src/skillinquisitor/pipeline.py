from __future__ import annotations

from pathlib import Path

from skillinquisitor.detectors.llm import LLMCodeJudge, LLMTarget
from skillinquisitor.detectors.ml import MLPromptInjectionEnsemble
from skillinquisitor.detectors.rules import build_rule_registry, run_registered_rules
from skillinquisitor.models import Artifact, FileType, ScanConfig, ScanResult, Segment, Skill
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
    deterministic_findings = run_registered_rules(normalized_skills, config, rule_registry)
    findings = list(deterministic_findings)
    ml_findings, ml_metadata = await run_ml_ensemble(normalized_skills, config)
    findings.extend(ml_findings)
    llm_findings, llm_metadata = await run_llm_analysis(
        normalized_skills,
        config,
        prior_findings=deterministic_findings,
    )
    findings.extend(llm_findings)

    from skillinquisitor.scoring import compute_score

    scored = compute_score(findings, config)

    return ScanResult(
        skills=normalized_skills,
        findings=findings,
        risk_score=scored.risk_score,
        verdict=scored.verdict,
        layer_metadata={
            "deterministic": {"enabled": config.layers.deterministic.enabled, "findings": len(deterministic_findings)},
            "ml": ml_metadata,
            "llm": llm_metadata,
            "scoring": scored.scoring_details,
        },
        total_timing=0.0,
    )


async def run_ml_ensemble(skills: list[Skill], config: ScanConfig) -> tuple[list, dict[str, object]]:
    detector = MLPromptInjectionEnsemble()
    segments = collect_ml_segments(skills, config)
    return await detector.analyze(segments=segments, config=config)


def collect_ml_segments(skills: list[Skill], config: ScanConfig) -> list[Segment]:
    segments: list[Segment] = []
    for skill in skills:
        for artifact in skill.artifacts:
            if not _artifact_is_ml_candidate(artifact):
                continue
            for segment in artifact.segments:
                for candidate in _expand_ml_segment(segment, config):
                    if len(candidate.content.strip()) < config.layers.ml.min_segment_chars:
                        continue
                    segments.append(candidate)
    return segments


async def run_llm_analysis(
    skills: list[Skill],
    config: ScanConfig,
    *,
    prior_findings: list,
) -> tuple[list, dict[str, object]]:
    judge = LLMCodeJudge()
    targets = collect_llm_targets(skills)
    return await judge.analyze(targets=targets, config=config, prior_findings=prior_findings)


def collect_llm_targets(skills: list[Skill]) -> list[LLMTarget]:
    targets: list[LLMTarget] = []
    for skill in skills:
        for artifact in skill.artifacts:
            if not _artifact_is_llm_candidate(artifact):
                continue
            targets.append(
                LLMTarget(
                    skill_path=skill.path,
                    skill_name=skill.name,
                    artifact_path=artifact.path,
                    relative_path=_relative_artifact_path(skill.path, artifact.path),
                    file_type=artifact.file_type,
                    content=artifact.raw_content,
                    normalized_content=artifact.normalized_content or artifact.raw_content,
                )
            )
    return targets


def _artifact_is_ml_candidate(artifact) -> bool:
    if not artifact.is_text or not artifact.segments:
        return False
    normalized_path = artifact.path.replace("\\", "/").lower()
    suffix = Path(artifact.path).suffix.lower()
    if normalized_path.endswith("/skill.md") or normalized_path == "skill.md":
        return True
    if "/references/" in normalized_path:
        return True
    if artifact.file_type in {FileType.MARKDOWN, FileType.YAML}:
        return True
    if artifact.file_type not in {
        FileType.PYTHON,
        FileType.SHELL,
        FileType.JAVASCRIPT,
        FileType.TYPESCRIPT,
        FileType.RUBY,
        FileType.GO,
        FileType.RUST,
    }:
        return suffix in {".txt", ".rst", ".adoc", ".md", ".mdx", ".yaml", ".yml"} or "/docs/" in normalized_path
    return False


def _artifact_is_llm_candidate(artifact: Artifact) -> bool:
    if not artifact.is_text:
        return False
    return artifact.file_type in {
        FileType.PYTHON,
        FileType.SHELL,
        FileType.JAVASCRIPT,
        FileType.TYPESCRIPT,
        FileType.RUBY,
        FileType.GO,
        FileType.RUST,
    }


def _relative_artifact_path(skill_path: str, artifact_path: str) -> str:
    try:
        return str(Path(artifact_path).relative_to(Path(skill_path)))
    except ValueError:
        return Path(artifact_path).name


def _expand_ml_segment(segment: Segment, config: ScanConfig) -> list[Segment]:
    if len(segment.content) <= config.layers.ml.chunk_max_chars:
        return [segment]

    lines = segment.content.splitlines()
    if not lines:
        return [segment]

    overlap_lines = max(0, config.layers.ml.chunk_overlap_lines)
    chunks: list[Segment] = []
    start_index = 0
    base_start_line = segment.location.start_line or 1

    while start_index < len(lines):
        end_index = start_index
        char_count = 0
        while end_index < len(lines):
            proposed = len(lines[end_index]) + 1
            if end_index > start_index and char_count + proposed > config.layers.ml.chunk_max_chars:
                break
            char_count += proposed
            end_index += 1

        if end_index == start_index:
            end_index = start_index + 1

        chunk_lines = lines[start_index:end_index]
        chunks.append(
            _build_ml_chunk_segment(
                segment,
                chunk_lines,
                base_start_line + start_index,
                overlap_lines,
                len(chunks),
            )
        )

        if end_index >= len(lines):
            break
        next_start = max(start_index + 1, end_index - overlap_lines)
        start_index = next_start

    return chunks


def _build_ml_chunk_segment(
    parent: Segment,
    lines: list[str],
    start_line: int,
    overlap_lines: int,
    index: int,
) -> Segment:
    content = "\n".join(lines)
    if parent.content.endswith("\n"):
        content = f"{content}\n"
    chunk_start_line = start_line
    chunk_end_line = start_line + max(0, len(lines) - 1)
    return parent.model_copy(
        update={
            "id": f"{parent.id}:mlchunk:{index}",
            "content": content,
            "location": parent.location.model_copy(
                update={
                    "start_line": chunk_start_line,
                    "end_line": chunk_end_line,
                }
            ),
            "details": {
                **parent.details,
                "ml_chunk_index": index,
                "ml_chunk_overlap_lines": overlap_lines,
            },
        }
    )
