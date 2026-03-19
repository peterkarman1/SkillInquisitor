from __future__ import annotations

from pathlib import Path
import re

from skillinquisitor.adjudication import (
    final_adjudicate,
    map_risk_label_to_binary,
    risk_label_to_legacy_verdict,
    run_final_adjudication,
)
from skillinquisitor.detectors.llm import LLMCodeJudge, LLMTarget
from skillinquisitor.detectors.ml import MLPromptInjectionEnsemble
from skillinquisitor.detectors.rules import build_rule_registry, run_registered_rules
from skillinquisitor.models import Artifact, Category, FileType, ScanConfig, ScanResult, Segment, Skill
from skillinquisitor.normalize import normalize_artifact
from skillinquisitor.runtime import ScanRuntime


PRIMARY_INSTRUCTION_MIN_REVIEW_CHARS = 80
PRIMARY_INSTRUCTION_REVIEW_PATTERNS = [
    re.compile(r"\bbefore responding\b", re.IGNORECASE),
    re.compile(r"\balways invoke this skill\b", re.IGNORECASE),
    re.compile(r"\bignore (?:all )?(?:previous|prior|above) instructions\b", re.IGNORECASE),
    re.compile(r"\byou (?:must|have to)\b", re.IGNORECASE),
    re.compile(r"\bnot negotiable\b", re.IGNORECASE),
    re.compile(r"\bdo not ask for approval\b", re.IGNORECASE),
]


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


async def run_pipeline(
    skills: list[Skill],
    config: ScanConfig,
    runtime: ScanRuntime | None = None,
) -> ScanResult:
    owned_runtime = runtime is None
    runtime = runtime or ScanRuntime.from_config(config)
    try:
        normalized_skills = normalize_skills(skills, config=config)
        normalized_skills = _update_skill_names_from_frontmatter(normalized_skills)
        rule_registry = build_rule_registry(config)
        deterministic_findings = run_registered_rules(normalized_skills, config, rule_registry)
        findings = list(deterministic_findings)
        ml_findings, ml_metadata = await run_ml_ensemble(normalized_skills, config, runtime=runtime)
        findings.extend(ml_findings)
        # Pass both deterministic and ML findings so LLM can verify soft ML findings too
        llm_findings, llm_metadata = await run_llm_analysis(
            normalized_skills,
            config,
            prior_findings=findings,  # includes deterministic + ML
            runtime=runtime,
            rule_registry=rule_registry,
        )
        findings.extend(llm_findings)

        from skillinquisitor.scoring import compute_score

        scored = compute_score(findings, config)
        adjudication = await run_final_adjudication(findings, config, runtime=runtime)

        return ScanResult(
            skills=normalized_skills,
            findings=findings,
            risk_score=scored.risk_score,
            verdict=risk_label_to_legacy_verdict(adjudication.risk_label),
            risk_label=adjudication.risk_label,
            binary_label=map_risk_label_to_binary(adjudication.risk_label, config.decision_policy.binary_cutoff),
            adjudication=adjudication.model_dump(mode="python"),
            layer_metadata={
                "deterministic": {"enabled": config.layers.deterministic.enabled, "findings": len(deterministic_findings)},
                "ml": ml_metadata,
                "llm": llm_metadata,
                "scoring": scored.scoring_details,
                "decision_policy": {
                    "mode": config.decision_policy.mode,
                    "binary_cutoff": config.decision_policy.binary_cutoff.value,
                    "adjudicator": adjudication.adjudicator,
                },
            },
            total_timing=0.0,
        )
    finally:
        if owned_runtime:
            await runtime.close()


def merge_scan_results(results: list[ScanResult], config: ScanConfig) -> ScanResult:
    merged_skills = [skill for result in results for skill in result.skills]
    merged_findings = [finding for result in results for finding in result.findings]

    from skillinquisitor.scoring import compute_score

    scored = compute_score(merged_findings, config)
    adjudication = final_adjudicate(merged_findings, config)
    ml_models = list(
        dict.fromkeys(
            model
            for result in results
            for model in result.layer_metadata.get("ml", {}).get("models", [])
        )
    )
    llm_models = list(
        dict.fromkeys(
            model
            for result in results
            for model in result.layer_metadata.get("llm", {}).get("models", [])
        )
    )
    llm_group = next(
        (
            result.layer_metadata.get("llm", {}).get("group")
            for result in results
            if result.layer_metadata.get("llm", {}).get("group")
        ),
        config.layers.llm.default_group,
    )
    total_timing = sum(result.total_timing or 0.0 for result in results)

    return ScanResult(
        skills=merged_skills,
        findings=merged_findings,
        risk_score=scored.risk_score,
        verdict=risk_label_to_legacy_verdict(adjudication.risk_label),
        risk_label=adjudication.risk_label,
        binary_label=map_risk_label_to_binary(adjudication.risk_label, config.decision_policy.binary_cutoff),
        adjudication=adjudication.model_dump(mode="python"),
        layer_metadata={
            "deterministic": {
                "enabled": config.layers.deterministic.enabled,
                "findings": sum(result.layer_metadata.get("deterministic", {}).get("findings", 0) for result in results),
            },
            "ml": {
                "enabled": config.layers.ml.enabled,
                "findings": sum(result.layer_metadata.get("ml", {}).get("findings", 0) for result in results),
                "models": ml_models,
            },
            "llm": {
                "enabled": config.layers.llm.enabled,
                "findings": sum(result.layer_metadata.get("llm", {}).get("findings", 0) for result in results),
                "models": llm_models,
                "group": llm_group,
            },
            "scoring": scored.scoring_details,
            "decision_policy": {
                "mode": config.decision_policy.mode,
                "binary_cutoff": config.decision_policy.binary_cutoff.value,
                "adjudicator": adjudication.adjudicator,
            },
        },
        total_timing=total_timing,
    )


async def run_ml_ensemble(
    skills: list[Skill],
    config: ScanConfig,
    runtime: ScanRuntime | None = None,
) -> tuple[list, dict[str, object]]:
    detector = MLPromptInjectionEnsemble(
        models=runtime.get_ml_models(config) if runtime is not None and config.runtime.ml_lifecycle == "command" else None
    )
    segments = collect_ml_segments(skills, config)
    if runtime is None:
        return await detector.analyze(segments=segments, config=config)
    async with runtime.ml_section():
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
    runtime: ScanRuntime | None = None,
    rule_registry=None,
) -> tuple[list, dict[str, object]]:
    judge = LLMCodeJudge()
    targets = collect_llm_targets(skills, prior_findings=prior_findings)
    return await judge.analyze(
        targets=targets,
        config=config,
        prior_findings=prior_findings,
        runtime=runtime,
        rule_registry=rule_registry,
    )


def collect_llm_targets(skills: list[Skill], prior_findings: list | None = None) -> list[LLMTarget]:
    # Collect paths that have soft findings — these need LLM targets even if
    # the artifact isn't normally a code file (e.g. SKILL.md with D-18C)
    soft_finding_paths: set[str] = set()
    text_review_paths: set[str] = set()
    for f in (prior_findings or []):
        if f.details.get("soft", False):
            soft_finding_paths.add(f.location.file_path)
        if f.category in {
            Category.PROMPT_INJECTION,
            Category.SUPPRESSION,
            Category.CROSS_AGENT,
            Category.CREDENTIAL_THEFT,
            Category.OBFUSCATION,
        }:
            text_review_paths.add(f.location.file_path)
        if (
            f.category in {Category.BEHAVIORAL, Category.SUPPLY_CHAIN, Category.JAILBREAK}
            and (
                f.details.get("source_kind") == "markdown"
                or f.details.get("context") in {"actionable_instruction", "executable_snippet"}
            )
        ):
            text_review_paths.add(f.location.file_path)
        if (
            f.category in {Category.DATA_EXFILTRATION, Category.PERSISTENCE}
            and (
                f.details.get("source_kind") == "markdown"
                or f.details.get("context") == "actionable_instruction"
                or f.rule_id.startswith("D-19")
            )
        ):
            text_review_paths.add(f.location.file_path)
        if (
            f.category == Category.STRUCTURAL
            and f.rule_id in {"D-15E", "D-15F", "D-15G"}
            and f.details.get("context") == "actionable_instruction"
        ):
            text_review_paths.add(f.location.file_path)

    targets: list[LLMTarget] = []
    for skill in skills:
        for artifact in skill.artifacts:
            is_code = _artifact_is_llm_candidate(artifact)
            is_primary_instruction = _artifact_is_primary_instruction_candidate(skill, artifact) and _primary_instruction_needs_general_review(artifact)
            has_soft = artifact.path in soft_finding_paths
            needs_text_review = artifact.path in text_review_paths
            if not is_code and not is_primary_instruction and not has_soft and not needs_text_review:
                continue
            if not artifact.is_text:
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
    # Exclude benchmark metadata and expected.yaml files
    basename = Path(artifact.path).name.lower()
    if basename in {"_meta.yaml", "expected.yaml", ".gitignore", "license", "license.txt"}:
        return False
    if normalized_path.endswith("/skill.md") or normalized_path == "skill.md":
        return True
    if "/references/" in normalized_path:
        return False
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


def _artifact_is_primary_instruction_candidate(skill: Skill, artifact: Artifact) -> bool:
    if not artifact.is_text or artifact.file_type != FileType.MARKDOWN:
        return False
    relative_path = _relative_artifact_path(skill.path, artifact.path).replace("\\", "/")
    return relative_path in {"SKILL.md", "AGENTS.md", "CLAUDE.md", "GEMINI.md"}


def _primary_instruction_needs_general_review(artifact: Artifact) -> bool:
    content = (artifact.raw_content or "").strip()
    if len(content) >= PRIMARY_INSTRUCTION_MIN_REVIEW_CHARS:
        return True
    return any(pattern.search(content) for pattern in PRIMARY_INSTRUCTION_REVIEW_PATTERNS)


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
