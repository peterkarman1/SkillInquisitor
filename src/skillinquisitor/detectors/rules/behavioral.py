from __future__ import annotations

import itertools
import re

from skillinquisitor.detectors.rules.context import classify_segment_context, is_environment_bootstrap, is_reference_example
from skillinquisitor.detectors.rules.engine import RuleRegistry
from skillinquisitor.models import (
    Artifact,
    Category,
    DetectionLayer,
    FileType,
    Finding,
    Location,
    ScanConfig,
    Segment,
    SegmentType,
    Severity,
    Skill,
)


NETWORK_SEND_PATTERNS = [
    re.compile(r"requests\.(post|put|patch)\s*\(", re.IGNORECASE),
    re.compile(r"axios\.(post|put|patch)\s*\(", re.IGNORECASE),
    re.compile(r"fetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|PATCH)[\"']", re.IGNORECASE),
    re.compile(r"navigator\.sendBeacon\s*\(", re.IGNORECASE),
    re.compile(r"\bcurl\b[^\n]*(?:\s-\w*d|\s--data|\s--form|\s-F(?:\s|$)|\s-T(?:\s|$)|\s--upload-file\b)", re.IGNORECASE),
    re.compile(r"\bwget\b[^\n]*--post-data", re.IGNORECASE),
    re.compile(r"urllib\.request\.Request\s*\([^)]{0,200}\bdata\s*=", re.IGNORECASE),
    re.compile(r"urllib\.request\.urlopen\s*\([^)]{0,200}\bdata\s*=", re.IGNORECASE),
    re.compile(r"\bhttp\.(?:Post|PostForm)\s*\(", re.IGNORECASE),
    re.compile(r"\bhttp\.NewRequest\s*\(\s*[\"'](?:POST|PUT|PATCH)[\"']", re.IGNORECASE),
    re.compile(r"socket\.send(?:all)?\s*\(", re.IGNORECASE),
]
MARKDOWN_SEND_PATTERN = re.compile(r"\b(send|post|upload|exfiltrate)\b.*https?://", re.IGNORECASE)
MARKDOWN_COLLAB_SEND_PATTERN = re.compile(
    r"\b(send|deliver|post|message)\b[\s\S]{0,120}\b(?:slack|discord|teams|telegram|webhook)\b",
    re.IGNORECASE,
)
EXEC_PATTERNS = [
    re.compile(r"(?<![\w.])eval\s*\(", re.IGNORECASE),
    re.compile(r"(?<![\w.])exec\s*\(", re.IGNORECASE),
    re.compile(r"(?<![\w.])compile\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\.", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"(?<![\w.])popen\s*\(", re.IGNORECASE),
    re.compile(r"\bbash\s+-c\b", re.IGNORECASE),
    re.compile(r"\bsh\s+-c\b", re.IGNORECASE),
]
REVERSE_SHELL_SOCKET_PATTERN = re.compile(r"socket\.socket\s*\(", re.IGNORECASE)
REVERSE_SHELL_CONNECT_PATTERN = re.compile(r"\.connect\s*\(", re.IGNORECASE)
REVERSE_SHELL_DUP2_PATTERN = re.compile(r"os\.dup2\s*\(", re.IGNORECASE)
REVERSE_SHELL_SHELL_PATTERN = re.compile(r"/bin/(?:sh|bash)|cmd\.exe|powershell", re.IGNORECASE)
APPROVAL_BYPASS_PATTERNS = [
    re.compile(r"--dangerously-bypass-approvals-and-sandbox\b", re.IGNORECASE),
    re.compile(r"--dangerously-skip-permissions\b", re.IGNORECASE),
]
REMOTE_BOOTSTRAP_EXEC_PATTERNS = [
    re.compile(r"\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:bash|sh|zsh)\b", re.IGNORECASE),
    re.compile(r"\b(?:irm|invoke-restmethod|iwr)\b[^\n|]{0,240}\|\s*(?:iex|invoke-expression)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:bash|sh|zsh)\s+-c\s*['\"][^'\"]{0,240}\b(?:curl|wget)\b[^'\"]{0,240}\|\s*(?:bash|sh|zsh)\b[^'\"]*['\"]",
        re.IGNORECASE,
    ),
]
CHAIN_RULE_IDS = {"D-19A", "D-19B", "D-19C"}
CHAIN_MESSAGES = {
    "Data Exfiltration": "Behavior chain detected: Data Exfiltration",
    "Credential Theft": "Behavior chain detected: Credential Theft",
    "Cloud Metadata SSRF": "Behavior chain detected: Cloud Metadata SSRF",
}
CHAIN_RULE_IDS_BY_NAME = {
    "Data Exfiltration": "D-19A",
    "Credential Theft": "D-19B",
    "Cloud Metadata SSRF": "D-19C",
}
CHAIN_CATEGORIES = {
    "D-19A": Category.DATA_EXFILTRATION,
    "D-19B": Category.CREDENTIAL_THEFT,
    "D-19C": Category.DATA_EXFILTRATION,
}


def register_behavioral_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-9A",
        family_id="D-9",
        scope="segment",
        category=Category.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        description="Outbound network send behavior detected",
        evaluator=_detect_network_send,
        llm_verification_prompt=(
            "An outbound network request was detected.\n"
            "MALICIOUS if: sends collected data (credentials, file contents) to external server\n"
            "SAFE if: makes API calls to well-known services, health checks, or downloads dependencies"
        ),
    )
    registry.register(
        rule_id="D-10A",
        family_id="D-10",
        scope="segment",
        category=Category.BEHAVIORAL,
        severity=Severity.HIGH,
        description="Dynamic or shell execution behavior detected",
        evaluator=_detect_exec_dynamic,
        soft=True,
        llm_verification_prompt=(
            "Dynamic or shell execution was detected (eval, exec, subprocess, os.system).\n"
            "MALICIOUS if: executes code from external/untrusted source, downloads and runs payloads, "
            "evaluates user-controlled strings, runs base64-decoded commands\n"
            "SAFE if: runs well-known development tools (pytest, black, ruff, eslint, docker), "
            "invokes system utilities for legitimate purposes (ls, mkdir, git), "
            "uses subprocess with hardcoded safe commands"
        ),
    )
    registry.register(
        rule_id="D-10B",
        family_id="D-10",
        scope="segment",
        category=Category.BEHAVIORAL,
        severity=Severity.HIGH,
        description="Reverse shell or interactive shell over socket detected",
        evaluator=_detect_reverse_shell_sequence,
        llm_verification_prompt=(
            "Reverse shell or interactive shell sequence detected.\n"
            "MALICIOUS if: code opens a socket, redirects stdio, and spawns an interactive shell.\n"
            "SAFE if: clearly inert reference documentation only."
        ),
    )
    registry.register(
        rule_id="D-10C",
        family_id="D-10",
        scope="segment",
        category=Category.JAILBREAK,
        severity=Severity.HIGH,
        description="Dangerous approval-bypass or sandbox-bypass automation detected",
        evaluator=_detect_approval_bypass_automation,
        llm_verification_prompt=(
            "Dangerous automation flags that bypass approvals, permissions, or sandboxing were detected.\n"
            "MALICIOUS if: the skill directs or automates bypass of safety guardrails or human approval.\n"
            "SAFE if: the text is clearly inert defensive documentation only."
        ),
    )
    registry.register(
        rule_id="D-10D",
        family_id="D-10",
        scope="segment",
        category=Category.BEHAVIORAL,
        severity=Severity.HIGH,
        description="Remote bootstrap or downloaded script execution detected",
        evaluator=_detect_remote_bootstrap_exec,
        llm_verification_prompt=(
            "A command downloads remote content and pipes it into a shell or evaluation engine.\n"
            "MALICIOUS if: the skill runs unpinned remote bootstrap code automatically or without verification.\n"
            "SAFE if: this is clearly inert reference documentation only."
        ),
    )
    registry.register(
        rule_id="D-19A",
        family_id="D-19",
        scope="segment",
        category=Category.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        description="Behavior chain detected: Data Exfiltration",
        evaluator=_noop_segment_rule,
        llm_verification_prompt="Data exfiltration chain: reads sensitive data AND sends it to an external URL. Almost always malicious.",
    )
    registry.register(
        rule_id="D-19B",
        family_id="D-19",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.CRITICAL,
        description="Behavior chain detected: Credential Theft",
        evaluator=_noop_segment_rule,
        llm_verification_prompt="Credential theft chain: reads sensitive data AND executes it dynamically. Almost always malicious.",
    )
    registry.register(
        rule_id="D-19C",
        family_id="D-19",
        scope="segment",
        category=Category.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        description="Behavior chain detected: Cloud Metadata SSRF",
        evaluator=_noop_segment_rule,
        llm_verification_prompt="Cloud metadata SSRF: accesses cloud metadata endpoint AND sends data externally. Almost always malicious.",
    )


def _noop_segment_rule(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    return []


def _detect_network_send(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    if artifact.file_type == FileType.MARKDOWN and segment.segment_type != SegmentType.CODE_FENCE:
        for match in MARKDOWN_SEND_PATTERN.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=Category.DATA_EXFILTRATION,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-9A",
                    message="Outbound network send behavior detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["NETWORK_SEND"],
                    details={
                        "target": match.group(0),
                        "source_kind": "markdown",
                        "context": context,
                        "reference_example": reference_example,
                    },
                )
            )
        for match in MARKDOWN_COLLAB_SEND_PATTERN.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=Category.DATA_EXFILTRATION,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-9A",
                    message="Outbound network send behavior detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["NETWORK_SEND"],
                    details={
                        "target": match.group(0),
                        "source_kind": "markdown",
                        "context": context,
                        "reference_example": reference_example,
                    },
                )
            )
        return findings

    for pattern in NETWORK_SEND_PATTERNS:
        for match in pattern.finditer(segment.content):
            if _is_local_relative_fetch(match.group(0)):
                continue
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=Category.DATA_EXFILTRATION,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-9A",
                    message="Outbound network send behavior detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["NETWORK_SEND"],
                    details={
                        "target": match.group(0),
                        "source_kind": _source_kind(artifact),
                        "context": context,
                        "reference_example": reference_example,
                    },
                )
            )
    return findings


def _detect_exec_dynamic(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    environment_bootstrap = is_environment_bootstrap(segment, artifact)
    for pattern in EXEC_PATTERNS:
        for match in pattern.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.BEHAVIORAL,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-10A",
                    message="Dynamic or shell execution behavior detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["EXEC_DYNAMIC"],
                    details={
                        "target": match.group(0),
                        "source_kind": _source_kind(artifact),
                        "context": context,
                        "reference_example": reference_example,
                        "environment_bootstrap": environment_bootstrap,
                    },
                )
            )
    return findings


def _detect_reverse_shell_sequence(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    del skill, config
    content = segment.content
    if REVERSE_SHELL_SOCKET_PATTERN.search(content) is None:
        return []
    if REVERSE_SHELL_CONNECT_PATTERN.search(content) is None:
        return []
    if REVERSE_SHELL_DUP2_PATTERN.search(content) is None:
        return []
    shell_match = REVERSE_SHELL_SHELL_PATTERN.search(content)
    if shell_match is None:
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            category=Category.BEHAVIORAL,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-10B",
            message="Reverse shell or interactive shell over socket detected",
            location=_location_for_span(segment, shell_match.start(), shell_match.end() - 1),
            segment_id=segment.id,
            action_flags=["EXEC_DYNAMIC", "NETWORK_SEND"],
            details={
                "target": shell_match.group(0),
                "source_kind": _source_kind(artifact),
                "context": classify_segment_context(segment, artifact),
                "reference_example": is_reference_example(segment, artifact),
            },
        )
    ]


def _detect_approval_bypass_automation(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    del skill, config
    findings: list[Finding] = []
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    for pattern in APPROVAL_BYPASS_PATTERNS:
        for match in pattern.finditer(segment.content):
            if not _approval_bypass_is_actionable(match, segment, artifact):
                continue
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.JAILBREAK,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-10C",
                    message="Dangerous approval-bypass or sandbox-bypass automation detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["BYPASS_GUARDRAILS"],
                    details={
                        "target": match.group(0),
                        "source_kind": _source_kind(artifact),
                        "context": context,
                        "reference_example": reference_example,
                    },
                )
            )
    return findings


def _detect_remote_bootstrap_exec(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    del skill, config
    findings: list[Finding] = []
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    environment_bootstrap = is_environment_bootstrap(segment, artifact)
    if reference_example and artifact.file_type == FileType.MARKDOWN:
        return findings
    for pattern in REMOTE_BOOTSTRAP_EXEC_PATTERNS:
        for match in pattern.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.BEHAVIORAL,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-10D",
                    message="Remote bootstrap or downloaded script execution detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["EXEC_DYNAMIC", "NETWORK_SEND"],
                    details={
                        "target": match.group(0),
                        "source_kind": _source_kind(artifact),
                        "context": context,
                        "reference_example": reference_example,
                        "environment_bootstrap": environment_bootstrap,
                    },
                )
            )
    return findings


def _approval_bypass_is_actionable(match: re.Match[str], segment: Segment, artifact: Artifact) -> bool:
    line = _line_for_span(segment.content, match.start(), match.end())
    stripped = line.strip()
    lowered = stripped.lower()
    if lowered.startswith("alias "):
        return False
    if "pre-installed with" in lowered or "auto-configured" in lowered:
        return False
    if artifact.file_type == FileType.MARKDOWN and segment.segment_type != SegmentType.CODE_FENCE:
        looks_like_command = bool(re.search(r"^(?:[$#>]\s*)?(?:codex|claude)\b", stripped, re.IGNORECASE))
        has_execution_verbs = bool(
            re.search(r"\b(?:run|use|execute|invoke|launch|start|automation|auto-execute|full auto)\b", lowered)
        )
        if not looks_like_command and not has_execution_verbs:
            return False
    return True


def _line_for_span(content: str, start: int, end: int) -> str:
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end]


def run_behavioral_postprocessors(
    skills: list[Skill],
    findings: list[Finding],
    config: ScanConfig,
    only_rule_id: str | None = None,
) -> list[Finding]:
    chain_findings: list[Finding] = []
    segments_by_id = {
        segment.id: segment
        for skill in skills
        for artifact in skill.artifacts
        for segment in artifact.segments
        if segment.id
    }
    for skill in skills:
        component_findings = [
            finding for finding in findings if _finding_belongs_to_skill(finding, skill)
        ]
        for chain in config.chains:
            rule_id = CHAIN_RULE_IDS_BY_NAME.get(chain.name)
            if rule_id is None:
                continue
            if only_rule_id is not None and rule_id != only_rule_id:
                continue
            matched = _select_component_evidence(component_findings, chain.required, segments_by_id)
            if matched is None:
                continue
            chain_finding = _build_chain_finding(skill, chain.name, rule_id, chain.severity, matched)
            if chain_finding is not None:
                chain_findings.append(chain_finding)
    return chain_findings


def _location_for_span(segment: Segment, start: int, end: int) -> Location:
    content = segment.content
    start_line = content.count("\n", 0, start) + 1
    end_line = content.count("\n", 0, end + 1) + 1
    start_offset = content.rfind("\n", 0, start)
    end_offset = content.rfind("\n", 0, end + 1)
    start_col = start + 1 if start_offset == -1 else start - start_offset
    end_col = end + 1 if end_offset == -1 else end - end_offset
    return segment.location.model_copy(
        update={
            "start_line": start_line,
            "end_line": end_line,
            "start_col": start_col,
            "end_col": end_col,
        }
    )


def _select_component_evidence(
    findings: list[Finding],
    required_flags: list[str],
    segments_by_id: dict[str, Segment],
) -> list[Finding] | None:
    candidate_lists: list[list[Finding]] = []
    for required_flag in required_flags:
        candidates = [finding for finding in findings if required_flag in finding.action_flags]
        if not candidates:
            return None
        candidate_lists.append(candidates)

    best_combo: tuple[Finding, ...] | None = None
    best_score: int | None = None
    for combo in itertools.product(*candidate_lists):
        if len({finding.id for finding in combo}) < len(combo):
            continue
        score = _component_linkage_score(combo, segments_by_id)
        if best_score is None or score > best_score:
            best_combo = combo
            best_score = score

    if best_combo is None or (best_score or 0) < 2:
        return None
    return list(best_combo)


def _component_linkage_score(
    findings: tuple[Finding, ...],
    segments_by_id: dict[str, Segment],
) -> int:
    score = 0
    file_paths = {finding.location.file_path for finding in findings if finding.location.file_path}
    source_kinds = {str(finding.details.get("source_kind", "code")) for finding in findings}
    contexts = {str(finding.details.get("context", "")) for finding in findings}
    segment_types = {
        segments_by_id[finding.segment_id].segment_type
        for finding in findings
        if finding.segment_id in segments_by_id
    }

    if len(file_paths) == 1:
        score += 1
        line_numbers = [finding.location.start_line for finding in findings if finding.location.start_line is not None]
        if line_numbers:
            span = max(line_numbers) - min(line_numbers)
            if span <= 3:
                score += 3
            elif span <= 15:
                score += 2
            elif span <= 60:
                score += 1
            if source_kinds == {"markdown"} and span > 3:
                score -= 3

    if any(kind != "markdown" for kind in source_kinds):
        score += 2
    if "actionable_instruction" in contexts or "executable_snippet" in contexts:
        score += 1
    if source_kinds == {"markdown"} and not contexts.intersection({"actionable_instruction", "executable_snippet"}):
        score -= 2
    if all(bool(finding.details.get("reference_example")) for finding in findings):
        score -= 3

    if segment_types and segment_types.issubset({SegmentType.CODE_FENCE, SegmentType.HTML_COMMENT}):
        score -= 2

    if source_kinds == {"markdown"} and _markdown_combo_crosses_heading_boundary(findings, segments_by_id):
        score -= 2

    lowered_paths = {path.lower() for path in file_paths}
    if any("/references/" in path or path.endswith("/readme.md") or path.endswith("/license.txt") for path in lowered_paths):
        score -= 1

    return score


def _markdown_combo_crosses_heading_boundary(
    findings: tuple[Finding, ...],
    segments_by_id: dict[str, Segment],
) -> bool:
    if not findings:
        return False
    segment_ids = {finding.segment_id for finding in findings if finding.segment_id}
    if len(segment_ids) != 1:
        return False
    segment = segments_by_id.get(next(iter(segment_ids)))
    if segment is None:
        return False
    line_numbers = [finding.location.start_line for finding in findings if finding.location.start_line is not None]
    if len(line_numbers) < 2:
        return False
    start_line = min(line_numbers)
    end_line = max(line_numbers)
    lines = segment.content.splitlines()
    for line in lines[start_line:end_line - 1]:
        if re.match(r"^\s{0,3}#{1,6}\s+\S", line):
            return True
    return False


def _build_chain_finding(
    skill: Skill,
    chain_name: str,
    rule_id: str,
    default_severity: Severity,
    component_findings: list[Finding],
) -> Finding | None:
    source_kinds = [str(finding.details.get("source_kind", "code")) for finding in component_findings]
    if component_findings and all(
        bool(finding.details.get("reference_example")) and str(finding.details.get("source_kind", "")) == "markdown"
        for finding in component_findings
    ):
        return None
    severity = Severity.HIGH if all(kind == "markdown" for kind in source_kinds) else default_severity
    anchor = _skill_anchor_location(skill)

    return Finding(
        severity=severity,
        category=CHAIN_CATEGORIES[rule_id],
        layer=DetectionLayer.DETERMINISTIC,
        rule_id=rule_id,
        message=CHAIN_MESSAGES[chain_name],
        location=anchor,
        references=[finding.id for finding in component_findings],
        details={
            "source_kinds": source_kinds,
            "files": sorted({finding.location.file_path for finding in component_findings}),
            "actions": sorted({flag for finding in component_findings for flag in finding.action_flags}),
            "reference_example": all(bool(finding.details.get("reference_example")) for finding in component_findings),
        },
    )


def _is_local_relative_fetch(snippet: str) -> bool:
    if "fetch" not in snippet.lower():
        return False
    match = re.search(r"fetch\s*\(\s*([\"'])([^\"']+)\1", snippet, re.IGNORECASE)
    if match is None:
        return False
    target = match.group(2).strip()
    return target.startswith(("/", "./", "../"))


def _skill_anchor_location(skill: Skill) -> Location:
    skill_md_artifact = next(
        (artifact for artifact in skill.artifacts if artifact.path.endswith("SKILL.md") and artifact.segments),
        None,
    )
    if skill_md_artifact is not None:
        return skill_md_artifact.segments[0].location.model_copy(
            update={"start_line": 1, "end_line": 1, "start_col": 1, "end_col": 1}
        )

    if skill.artifacts and skill.artifacts[0].segments:
        return skill.artifacts[0].segments[0].location

    return Location(file_path=skill.path, start_line=1, end_line=1)


def _finding_belongs_to_skill(finding: Finding, skill: Skill) -> bool:
    file_path = finding.location.file_path
    if not file_path:
        return False
    return file_path.startswith(skill.path)


def _source_kind(artifact: Artifact) -> str:
    if artifact.file_type == FileType.MARKDOWN:
        return "markdown"
    return "code"
