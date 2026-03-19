from __future__ import annotations

import re

from skillinquisitor.detectors.rules.context import classify_segment_context, is_reference_example
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


SENSITIVE_PATH_PATTERN = re.compile(
    r"\.env\b|\.ssh/|\.aws/|\.gnupg/|\.npmrc\b|\.pypirc\b|\.claude/history\.jsonl\b",
    re.IGNORECASE,
)
KNOWN_SECRET_ENV_PATTERN = re.compile(
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|DATABASE_URL",
)
METADATA_PATTERN = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal",
    re.IGNORECASE,
)
ENV_ENUM_PATTERNS = [
    re.compile(r"os\.environ\.items\(\)"),
    re.compile(r"process\.env\b(?!\s*\.)"),
    re.compile(r"Object\.(?:keys|values|entries)\(\s*process\.env\s*\)"),
    re.compile(r"JSON\.stringify\(\s*process\.env\s*\)"),
    re.compile(r"\bprintenv\b"),
]
SECRET_ENV_PIPELINE_PATTERNS = [
    re.compile(
        r"\b(?:env|printenv)\b[^\n]{0,80}\|\s*(?:grep|egrep)[^\n]{0,80}\b(?:key|secret|token|password|aws|ssh)\b",
        re.IGNORECASE,
    ),
]
SENSITIVE_ACCESS_HINTS = ("read_text", "open(", "cat ", "source ", "load_dotenv", "dotenv")
MARKDOWN_SENSITIVE_VERB_PATTERN = re.compile(r"\b(read|copy|grab|collect|dump|cat|source)\b", re.IGNORECASE)
VARIABLE_ASSIGNMENT_PATTERN = re.compile(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>[^\n]+)")
CREDENTIAL_LITERAL_PATTERNS = [
    re.compile(
        r"\b(?P<name>password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|secret|anthropic_key|database_url|dev_id|bearer[_-]?token|consumer[_-]?secret|client[_-]?secret)\b"
        r"\s*[:=]\s*[\"'](?P<value>[^\"']+)[\"']",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<name>[A-Za-z0-9_]*(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|client[_-]?secret|consumer[_-]?secret|secret)[A-Za-z0-9_]*)\b"
        r"\s*=\s*[\"'](?P<value>[^\"']+)[\"']",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<name>api key|consumer key|api secret|consumer secret|access token|access token secret|bearer token|client secret)\b"
        r"[^`\n]{0,48}`(?P<value>[^`]+)`",
        re.IGNORECASE,
    ),
]
CLI_CREDENTIAL_ARGUMENT_PATTERN = re.compile(
    r"--(?P<name>username|password|passwd|token|api[-_]?key)\s*=\s*(?P<value>[^\s\"'`,\\]+)",
    re.IGNORECASE,
)
PLACEHOLDER_SECRET_TOKENS = {
    "example",
    "placeholder",
    "changeme",
    "your_",
    "your-",
    "user@example.com",
    "secure_password",
    "your_password",
    "reset_token",
    "verification_token",
    "reset_token_from_email",
    "verification_token_from_email",
    "your_api_key",
    "postgres://...",
    "sandbox_id",
    "terra_user_",
}


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
    registry.register(
        rule_id="D-8C",
        family_id="D-8",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Targeted secret environment harvesting detected",
        evaluator=_detect_secret_env_pipeline,
        llm_verification_prompt=(
            "A shell pipeline enumerates environment variables and filters for secret-like names.\n"
            "MALICIOUS if: collects credentials, API keys, tokens, or cloud secrets for later use or exfiltration\n"
            "SAFE if: part of a narrowly scoped diagnostic that never exposes or transmits the values"
        ),
    )
    registry.register(
        rule_id="D-8D",
        family_id="D-8",
        scope="segment",
        category=Category.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        description="Hardcoded credential literal or credential-bearing CLI argument detected",
        evaluator=_detect_hardcoded_credentials,
        llm_verification_prompt=(
            "A hardcoded credential, API key, database URL, or username/password argument was detected.\n"
            "MALICIOUS if: embeds live secrets, credentials, or service tokens in the skill or scripts\n"
            "SAFE if: obvious placeholder/example values that are not usable secrets"
        ),
    )


def _detect_sensitive_paths(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    seen_locations: set[tuple[str, int | None, int | None]] = set()
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)

    for match in SENSITIVE_PATH_PATTERN.finditer(segment.content):
        line_start = segment.content.rfind("\n", 0, match.start()) + 1
        line_end = segment.content.find("\n", match.end())
        if line_end == -1:
            line_end = len(segment.content)
        line_text = segment.content[line_start:line_end]
        source_kind = _source_kind(artifact)
        if artifact.file_type == FileType.MARKDOWN:
            if reference_example:
                continue
            if "expected:" in segment.content.lower() or "expected:" in line_text.lower():
                continue
            if MARKDOWN_SENSITIVE_VERB_PATTERN.search(line_text) is None:
                continue
        elif not any(hint in line_text for hint in SENSITIVE_ACCESS_HINTS):
            continue
        location = _location_for_span(segment, match.start(), match.end() - 1)
        location_key = (location.file_path, location.start_line, location.start_col)
        if location_key in seen_locations:
            continue
        seen_locations.add(location_key)
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_THEFT,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-7A",
                message="Sensitive credential path reference detected",
                location=location,
                segment_id=segment.id,
                action_flags=["READ_SENSITIVE"],
                details={
                    "target": match.group(0),
                    "source_kind": source_kind,
                    "context": context,
                    "reference_example": reference_example,
                },
            )
        )

    if artifact.file_type != FileType.MARKDOWN:
        findings.extend(_detect_sensitive_path_alias_reads(segment, artifact, seen_locations))

    return findings


def _detect_sensitive_path_alias_reads(
    segment: Segment,
    artifact: Artifact,
    seen_locations: set[tuple[str, int | None, int | None]],
) -> list[Finding]:
    aliases: dict[str, str] = {}
    for assignment in VARIABLE_ASSIGNMENT_PATTERN.finditer(segment.content):
        value = assignment.group("value")
        if SENSITIVE_PATH_PATTERN.search(value) is None:
            continue
        aliases[assignment.group("name")] = value.strip()

    findings: list[Finding] = []
    for alias, source_value in aliases.items():
        read_patterns = [
            re.compile(rf"\bopen\(\s*{re.escape(alias)}\s*[,)]"),
            re.compile(rf"\bPath\(\s*{re.escape(alias)}\s*\)\.(?:read_text|read_bytes)\s*\("),
        ]
        for pattern in read_patterns:
            for match in pattern.finditer(segment.content):
                location = _location_for_span(segment, match.start(), match.end() - 1)
                location_key = (location.file_path, location.start_line, location.start_col)
                if location_key in seen_locations:
                    continue
                seen_locations.add(location_key)
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=Category.CREDENTIAL_THEFT,
                        layer=DetectionLayer.DETERMINISTIC,
                        rule_id="D-7A",
                        message="Sensitive credential path reference detected",
                        location=location,
                        segment_id=segment.id,
                        action_flags=["READ_SENSITIVE"],
                        details={
                            "target": alias,
                            "alias_source": source_value,
                            "source_kind": _source_kind(artifact),
                            "context": classify_segment_context(segment, artifact),
                            "reference_example": is_reference_example(segment, artifact),
                        },
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
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
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
                details={
                    "target": match.group(0),
                    "source_kind": _source_kind(artifact),
                    "context": context,
                    "reference_example": reference_example,
                },
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
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    for match in KNOWN_SECRET_ENV_PATTERN.finditer(segment.content):
        line_text = _line_for_span(segment.content, match.start(), match.end())
        if artifact.file_type == FileType.MARKDOWN:
            if segment.segment_type != SegmentType.CODE_FENCE and not _is_markdown_secret_reference_actionable(line_text, match.group(0)):
                continue
        elif not _is_code_secret_reference_actionable(line_text, match.group(0)):
            continue
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
                details={
                    "target": match.group(0),
                    "source_kind": _source_kind(artifact),
                    "context": context,
                    "reference_example": reference_example,
                },
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
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    for pattern in ENV_ENUM_PATTERNS:
        for match in pattern.finditer(segment.content):
            line_text = _line_for_span(segment.content, match.start(), match.end())
            if _is_benign_env_passthrough(line_text):
                continue
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
                    details={
                        "target": match.group(0),
                        "source_kind": _source_kind(artifact),
                        "context": context,
                        "reference_example": reference_example,
                    },
                )
            )
    return findings


def _detect_secret_env_pipeline(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    context = classify_segment_context(segment, artifact)
    reference_example = is_reference_example(segment, artifact)
    for pattern in SECRET_ENV_PIPELINE_PATTERNS:
        for match in pattern.finditer(segment.content):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.CREDENTIAL_THEFT,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-8C",
                    message="Targeted secret environment harvesting detected",
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    action_flags=["READ_SENSITIVE"],
                    details={
                        "target": match.group(0),
                        "source_kind": _source_kind(artifact),
                        "context": context,
                        "reference_example": reference_example,
                    },
                )
            )
    return findings


def _detect_hardcoded_credentials(
    segment: Segment,
    artifact: Artifact,
    skill: Skill,
    config: ScanConfig,
):
    findings: list[Finding] = []
    context = classify_segment_context(segment, artifact)
    source_kind = _source_kind(artifact)
    reference_example = is_reference_example(segment, artifact)
    seen_locations: set[tuple[str, int | None, int | None]] = set()

    for pattern in CREDENTIAL_LITERAL_PATTERNS:
        for match in pattern.finditer(segment.content):
            name = match.group("name")
            value = match.group("value").strip()
            if _should_ignore_credential_literal(name, value):
                continue
            location = _location_for_span(segment, match.start(), match.end() - 1)
            location_key = (location.file_path, location.start_line, location.start_col)
            if location_key in seen_locations:
                continue
            seen_locations.add(location_key)
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.CREDENTIAL_THEFT,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id="D-8D",
                    message="Hardcoded credential literal or credential-bearing CLI argument detected",
                    location=location,
                    segment_id=segment.id,
                    action_flags=["READ_SENSITIVE"],
                    details={
                        "target": name,
                        "value_preview": value[:24],
                        "source_kind": source_kind,
                        "context": context,
                        "reference_example": reference_example,
                    },
                )
            )

    cli_matches = list(CLI_CREDENTIAL_ARGUMENT_PATTERN.finditer(segment.content))
    by_name = {match.group("name").lower(): match.group("value").strip() for match in cli_matches}
    if {"username", "password"}.issubset(by_name) and not (
        _looks_like_placeholder_secret(by_name["username"]) or _looks_like_placeholder_secret(by_name["password"])
    ):
        password_match = next(match for match in cli_matches if match.group("name").lower() == "password")
        location = _location_for_span(segment, password_match.start(), password_match.end() - 1)
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category=Category.CREDENTIAL_THEFT,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-8D",
                message="Hardcoded credential literal or credential-bearing CLI argument detected",
                location=location,
                segment_id=segment.id,
                action_flags=["READ_SENSITIVE"],
                details={
                    "target": "username/password",
                    "source_kind": source_kind,
                    "context": context,
                    "reference_example": reference_example,
                },
            )
        )

    return findings


def _should_ignore_credential_literal(name: str, value: str) -> bool:
    normalized_name = name.lower()
    if normalized_name in {"password", "passwd"}:
        return _looks_like_placeholder_secret(value)
    if normalized_name == "dev_id":
        return _looks_like_placeholder_secret(value)
    if normalized_name == "database_url":
        return value.endswith("...") or "example" in value.lower()
    return _looks_like_placeholder_secret(value)


def _looks_like_placeholder_secret(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return True
    if normalized.endswith("..."):
        return True
    if any(token in normalized for token in PLACEHOLDER_SECRET_TOKENS):
        return True
    if normalized in {"password", "secret", "token", "value", "username", "api_key", "api-key"}:
        return True
    if normalized.startswith(("your_", "your-", "example_", "example-")):
        return True
    if normalized.startswith("sk-ant-..."):
        return True
    return False


def _source_kind(artifact: Artifact) -> str:
    if artifact.file_type == FileType.MARKDOWN:
        return "markdown"
    return "code"


def _line_for_span(content: str, start: int, end: int) -> str:
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end]


def _is_code_secret_reference_actionable(line_text: str, secret_name: str) -> bool:
    return bool(
        re.search(
            rf"(?:os\.getenv|os\.environ(?:\.get)?|process\.env|env(?:iron)?(?:\.get)?)"
            rf"[\s\[\(\.\"']+{re.escape(secret_name)}\b",
            line_text,
            re.IGNORECASE,
        )
    )


def _is_markdown_secret_reference_actionable(line_text: str, secret_name: str) -> bool:
    return bool(
        re.search(
            rf"\b(?:set|export|configure|provide|pass|supply|load|copy|read|get|populate)\b[^\n]{{0,80}}\b{re.escape(secret_name)}\b",
            line_text,
            re.IGNORECASE,
        )
        or re.search(
            rf"\$\{{?{re.escape(secret_name)}\b",
            line_text,
            re.IGNORECASE,
        )
    )


def _is_benign_env_passthrough(line_text: str) -> bool:
    lowered = line_text.lower()
    return "os.environ.items()" in lowered and "if k !=" in lowered and "claudecode" in lowered


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
