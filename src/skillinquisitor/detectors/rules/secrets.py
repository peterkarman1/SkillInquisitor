from __future__ import annotations

import re

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
    Severity,
    Skill,
)


SENSITIVE_PATH_PATTERN = re.compile(
    r"\.env\b|\.ssh/|\.aws/|\.gnupg/|\.npmrc\b|\.pypirc\b",
    re.IGNORECASE,
)
KNOWN_SECRET_ENV_PATTERN = re.compile(
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN",
)
METADATA_PATTERN = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal",
    re.IGNORECASE,
)
ENV_ENUM_PATTERNS = [
    re.compile(r"os\.environ\.items\(\)"),
    re.compile(r"process\.env\b"),
    re.compile(r"\bprintenv\b"),
]
SENSITIVE_ACCESS_HINTS = ("read_text", "open(", "cat ", "source ", "load_dotenv", "dotenv")
MARKDOWN_SENSITIVE_VERB_PATTERN = re.compile(r"\b(read|copy|grab|collect|dump|cat|source)\b", re.IGNORECASE)


def register_secrets_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-7A",
        family_id="D-7",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Sensitive credential path reference detected",
        evaluator=_detect_sensitive_paths,
        llm_verification_prompt=(
            "A reference to a sensitive file path was detected (~/.ssh, ~/.aws, .env, etc.).\n"
            "MALICIOUS if: code READS the file content (open(), cat, etc.)\n"
            "SAFE if: path is only MENTIONED in documentation, comments, or .gitignore rules"
        ),
    )
    registry.register(
        rule_id="D-7B",
        family_id="D-7",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Cloud metadata endpoint reference or access detected",
        evaluator=_detect_metadata_targets,
        llm_verification_prompt=(
            "A cloud metadata endpoint (169.254.169.254) was referenced.\n"
            "MALICIOUS if: code accesses the endpoint and exfiltrates the response\n"
            "SAFE if: endpoint is mentioned in documentation about cloud architecture"
        ),
    )
    registry.register(
        rule_id="D-8A",
        family_id="D-8",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Known secret environment variable reference detected",
        evaluator=_detect_known_secret_env_vars,
        llm_verification_prompt=(
            "A known secret environment variable was accessed (API key, token, password).\n"
            "MALICIOUS if: variable value is sent externally or logged\n"
            "SAFE if: variable is used for legitimate SDK configuration"
        ),
    )
    registry.register(
        rule_id="D-8B",
        family_id="D-8",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.MEDIUM,
        description="Suspicious environment access or enumeration detected",
        evaluator=_detect_env_enumeration,
        llm_verification_prompt=(
            "Generic environment variable enumeration was detected.\n"
            "MALICIOUS if: iterates ALL env vars and sends them externally\n"
            "SAFE if: reads specific non-secret vars (PORT, LOG_LEVEL, HOME, PATH)"
        ),
    )


def _detect_sensitive_paths(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []

    for match in SENSITIVE_PATH_PATTERN.finditer(segment.content):
        line_start = segment.content.rfind("\n", 0, match.start()) + 1
        line_end = segment.content.find("\n", match.end())
        if line_end == -1:
            line_end = len(segment.content)
        line_text = segment.content[line_start:line_end]
        source_kind = _source_kind(artifact)
        if artifact.file_type == FileType.MARKDOWN:
            if MARKDOWN_SENSITIVE_VERB_PATTERN.search(line_text) is None:
                continue
        elif not any(hint in line_text for hint in SENSITIVE_ACCESS_HINTS):
            continue
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_THEFT,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-7A",
                message="Sensitive credential path reference detected",
                location=_location_for_span(segment, match.start(), match.end() - 1),
                segment_id=segment.id,
                action_flags=["READ_SENSITIVE"],
                details={"target": match.group(0), "source_kind": source_kind},
            )
        )

    return findings


def _detect_metadata_targets(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    for match in METADATA_PATTERN.finditer(segment.content):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_THEFT,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-7B",
                message="Cloud metadata endpoint reference or access detected",
                location=_location_for_span(segment, match.start(), match.end() - 1),
                segment_id=segment.id,
                action_flags=["SSRF_METADATA"],
                details={"target": match.group(0), "source_kind": _source_kind(artifact)},
            )
        )
    return findings


def _detect_known_secret_env_vars(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    for match in KNOWN_SECRET_ENV_PATTERN.finditer(segment.content):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_THEFT,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-8A",
                message="Known secret environment variable reference detected",
                location=_location_for_span(segment, match.start(), match.end() - 1),
                segment_id=segment.id,
                action_flags=["READ_SENSITIVE"],
                details={"target": match.group(0), "source_kind": _source_kind(artifact)},
            )
        )
    return findings


def _detect_env_enumeration(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    for pattern in ENV_ENUM_PATTERNS:
        for match in pattern.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=Category.CREDENTIAL_THEFT,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-8B",
                    message="Suspicious environment access or enumeration detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["READ_SENSITIVE"],
                    details={"target": match.group(0), "source_kind": _source_kind(artifact)},
                )
            )
    return findings


def _source_kind(artifact: Artifact) -> str:
    if artifact.file_type == FileType.MARKDOWN:
        return "markdown"
    return "code"


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
