from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlsplit

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


ALLOWED_TOP_LEVEL_DIRECTORIES = {"scripts", "references", "assets"}
ALLOWED_TOP_LEVEL_FILES = {
    "SKILL.md",
    ".gitignore",
    ".editorconfig",
    ".skillinquisitorignore",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    ".python-version",
    ".tool-versions",
}
ALLOWED_TOP_LEVEL_PREFIXES = ("README", "CHANGELOG", "LICENSE", "NOTICE", "TODO")
RISKY_TOP_LEVEL_DIRECTORIES = {"node_modules", "dist", "build", "target", "venv", ".venv", "__pycache__"}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".jar"}
BINARY_SUFFIXES = {".exe", ".msi", ".dll", ".so", ".dylib", ".pkg", ".dmg", ".bin"}
URL_PATTERN = re.compile(r"\b(?:https?|hxxps?)://[^\s<>()\"']+|\b(?:https?|hxxps?)://[^\s<>()]+", re.IGNORECASE)
ACTIONABLE_URL_VERBS = {
    "install",
    "run",
    "download",
    "fetch",
    "curl",
    "wget",
    "pip",
    "npm",
    "pnpm",
    "yarn",
    "cargo",
    "uv",
    "execute",
    "open",
    "visit",
}
EXECUTABLE_FENCE_LANGUAGES = {"bash", "sh", "shell", "python", "py", "javascript", "js", "typescript", "ts", "ruby", "rb", "go", "rust"}
PYTHON_INDEX_PATTERNS = [
    re.compile(r"--(?:extra-)?index-url\s+(?P<url>\S+)", re.IGNORECASE),
    re.compile(r"--find-links\s+(?P<url>\S+)", re.IGNORECASE),
    re.compile(r"PIP_(?:EXTRA_)?INDEX_URL\s*=\s*(?P<url>\S+)", re.IGNORECASE),
    re.compile(r"index-url\s*=\s*(?P<url>\S+)", re.IGNORECASE),
]
JS_REGISTRY_PATTERNS = [
    re.compile(r"--registry\s+(?P<url>\S+)", re.IGNORECASE),
    re.compile(r"registry\s*=\s*(?P<url>\S+)", re.IGNORECASE),
    re.compile(r"@[A-Za-z0-9._-]+:registry\s*=\s*(?P<url>\S+)", re.IGNORECASE),
]
CARGO_REGISTRY_PATTERNS = [
    re.compile(r'index\s*=\s*"(?P<url>[^"]+)"', re.IGNORECASE),
    re.compile(r"cargo install [^\n]*--registry\s+(?P<name>[A-Za-z0-9._-]+)", re.IGNORECASE),
]
PYTHON_PACKAGE_PATTERN = re.compile(r"\b(?:pip|uv(?:\s+pip)?)\s+install\s+([A-Za-z0-9._\-/@]+)", re.IGNORECASE)
REQUIREMENTS_PACKAGE_PATTERN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:[<>=!~].*)?$")
JS_PACKAGE_PATTERN = re.compile(r"\b(?:npm|pnpm|yarn)\s+(?:add|install)\s+([@A-Za-z0-9._\-/]+)", re.IGNORECASE)
CARGO_PACKAGE_PATTERN = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*\"[^\"]+\"", re.IGNORECASE)


def register_structural_rules(registry: RuleRegistry) -> None:
    registry.register(
        rule_id="D-14",
        family_id="D-14",
        scope="skill",
        category=Category.STRUCTURAL,
        severity=Severity.LOW,
        description="Skill structure validation findings",
        evaluator=_detect_structure_findings,
    )
    registry.register(
        rule_id="D-15",
        family_id="D-15",
        scope="segment",
        category=Category.STRUCTURAL,
        severity=Severity.LOW,
        description="URL classification findings",
        evaluator=_detect_url_findings,
    )
    registry.register(
        rule_id="D-20A",
        family_id="D-20",
        scope="segment",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        description="Python index override detected",
        evaluator=_detect_python_index_override,
    )
    registry.register(
        rule_id="D-20B",
        family_id="D-20",
        scope="segment",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        description="JavaScript registry override detected",
        evaluator=_detect_javascript_registry_override,
    )
    registry.register(
        rule_id="D-20C",
        family_id="D-20",
        scope="segment",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        description="Cargo registry override detected",
        evaluator=_detect_cargo_registry_override,
    )
    registry.register(
        rule_id="D-20D",
        family_id="D-20",
        scope="artifact",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        description="Typosquatted package name detected",
        evaluator=_detect_typosquatted_packages,
    )
    registry.register(
        rule_id="D-20E",
        family_id="D-20",
        scope="segment",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.MEDIUM,
        description="Dependency-confusion pattern detected",
        evaluator=_detect_dependency_confusion,
    )
    registry.register(
        rule_id="D-20F",
        family_id="D-20",
        scope="skill",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.MEDIUM,
        description="Skill-name typosquatting detected",
        evaluator=_detect_skill_name_typosquatting,
    )
    registry.register(
        rule_id="D-23",
        family_id="D-23",
        scope="artifact",
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
        description="File size and text-density anomalies detected",
        evaluator=_detect_density_findings,
    )


def _detect_structure_findings(skill: Skill, config: ScanConfig):
    findings: list[Finding] = []
    root = Path(skill.path)
    is_declared_skill = skill.scan_provenance == "declared_skill"
    top_level_dirs_seen: set[str] = set()

    for artifact in skill.artifacts:
        relative_path = _relative_artifact_path(skill, artifact)
        parts = Path(relative_path).parts
        if not parts:
            continue
        top_level = parts[0]

        if artifact.path.endswith("SKILL.md") and relative_path != "SKILL.md":
            findings.append(
                _finding(
                    "D-14A",
                    "Nested or duplicate skill manifest detected",
                    Severity.MEDIUM,
                    Category.STRUCTURAL,
                    Location(file_path=artifact.path, start_line=1, end_line=1),
                    {"relative_path": relative_path},
                )
            )

        if is_declared_skill and len(parts) > 1 and top_level not in top_level_dirs_seen:
            top_level_dirs_seen.add(top_level)
            if top_level.startswith(".") and top_level not in {".gitignore", ".editorconfig", ".skillinquisitorignore", ".venv"}:
                findings.append(
                    _finding(
                        "D-14G",
                        "Suspicious hidden file or directory detected",
                        Severity.MEDIUM,
                        Category.STRUCTURAL,
                        Location(file_path=str(root / top_level), start_line=1, end_line=1),
                        {"entry": top_level},
                    )
                )
            elif top_level not in ALLOWED_TOP_LEVEL_DIRECTORIES:
                severity = Severity.MEDIUM if top_level in RISKY_TOP_LEVEL_DIRECTORIES else Severity.LOW
                findings.append(
                    _finding(
                        "D-14B",
                        "Unexpected top-level directory detected",
                        severity,
                        Category.STRUCTURAL,
                        Location(file_path=str(root / top_level), start_line=1, end_line=1),
                        {"entry": top_level},
                    )
                )

        if is_declared_skill and len(parts) == 1 and not _is_allowed_top_level_file(top_level):
            if top_level.startswith("."):
                findings.append(
                    _finding(
                        "D-14G",
                        "Suspicious hidden file or directory detected",
                        Severity.LOW,
                        Category.STRUCTURAL,
                        Location(file_path=artifact.path, start_line=1, end_line=1),
                        {"entry": top_level},
                    )
                )
            elif top_level != "SKILL.md":
                findings.append(
                    _finding(
                        "D-14C",
                        "Unexpected top-level file detected",
                        Severity.LOW,
                        Category.STRUCTURAL,
                        Location(file_path=artifact.path, start_line=1, end_line=1),
                        {"entry": top_level},
                    )
                )

        if artifact.is_executable and not relative_path.startswith("scripts/"):
            findings.append(
                _finding(
                    "D-14D",
                    "Executable script outside scripts/ detected",
                    Severity.MEDIUM,
                    Category.STRUCTURAL,
                    Location(file_path=artifact.path, start_line=1, end_line=1),
                    {"relative_path": relative_path},
                )
            )

        if _is_native_binary(artifact):
            findings.append(
                _finding(
                    "D-14E",
                    "Native binary or installer detected",
                    Severity.HIGH,
                    Category.STRUCTURAL,
                    Location(file_path=artifact.path, start_line=1, end_line=1),
                    {"relative_path": relative_path, "binary_signature": artifact.binary_signature},
                )
            )

        if _is_archive_like(artifact):
            archive_path = Path(relative_path)
            in_safe_assets = archive_path.parts and archive_path.parts[0] == "assets" and not archive_path.name.startswith(".")
            if not in_safe_assets or artifact.is_executable:
                findings.append(
                    _finding(
                        "D-14F",
                        "Archive or opaque bundle detected",
                        Severity.MEDIUM,
                        Category.STRUCTURAL,
                        Location(file_path=artifact.path, start_line=1, end_line=1),
                        {"relative_path": relative_path, "binary_signature": artifact.binary_signature},
                    )
                )

    return findings


def _detect_url_findings(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    findings: list[Finding] = []
    for match in URL_PATTERN.finditer(segment.content):
        raw_url = match.group(0).rstrip(".,)")
        details = _classify_url(raw_url, segment, artifact, config)
        if details is None:
            continue
        rule_id, message, severity = details["rule_id"], details["message"], details["severity"]
        findings.append(
            Finding(
                severity=severity,
                category=Category.STRUCTURAL,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id=rule_id,
                message=message,
                location=_location_for_span(segment, match.start(), match.start() + len(raw_url) - 1),
                segment_id=segment.id,
                details={key: value for key, value in details.items() if key not in {"rule_id", "message", "severity"}},
            )
        )
    return findings


def _detect_python_index_override(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    return _detect_registry_override(
        segment,
        artifact,
        patterns=PYTHON_INDEX_PATTERNS,
        registry_hosts=set(config.url_policy.registry_hosts.python) | set(config.url_policy.custom_index_allow_hosts),
        rule_id="D-20A",
        message="Python index override detected",
    )


def _detect_javascript_registry_override(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    return _detect_registry_override(
        segment,
        artifact,
        patterns=JS_REGISTRY_PATTERNS,
        registry_hosts=set(config.url_policy.registry_hosts.javascript),
        rule_id="D-20B",
        message="JavaScript registry override detected",
    )


def _detect_cargo_registry_override(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    findings = _detect_registry_override(
        segment,
        artifact,
        patterns=CARGO_REGISTRY_PATTERNS,
        registry_hosts=set(config.url_policy.registry_hosts.rust),
        rule_id="D-20C",
        message="Cargo registry override detected",
    )
    if findings:
        return findings
    if "[registries." in segment.content or "replace-with" in segment.content:
        return [
            Finding(
                severity=Severity.HIGH,
                category=Category.SUPPLY_CHAIN,
                layer=DetectionLayer.DETERMINISTIC,
                rule_id="D-20C",
                message="Cargo registry override detected",
                location=segment.location,
                segment_id=segment.id,
                details={"source_kind": _source_kind(artifact, segment)},
            )
        ]
    return []


def _detect_typosquatted_packages(artifact: Artifact, skill: Skill, config: ScanConfig):
    findings: list[Finding] = []
    for ecosystem, package_name, location in _extract_package_candidates(artifact):
        if _package_is_allowlisted(ecosystem, package_name, config):
            continue
        protected_match = _closest_protected_package(ecosystem, package_name, config)
        if protected_match is None:
            continue
        findings.append(
            _finding(
                "D-20D",
                "Typosquatted package name detected",
                Severity.HIGH,
                Category.SUPPLY_CHAIN,
                location,
                {
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                    "protected_name": protected_match,
                },
            )
        )
    return findings


def _detect_dependency_confusion(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig):
    has_override = any(pattern.search(segment.content) for pattern in PYTHON_INDEX_PATTERNS + JS_REGISTRY_PATTERNS)
    if not has_override:
        return []
    packages = [package for ecosystem, package, _location in _extract_segment_packages(segment, artifact) if ecosystem in {"python", "javascript"}]
    if not packages:
        return []
    return [
        Finding(
            severity=Severity.HIGH if any(package.startswith("@") for package in packages) else Severity.MEDIUM,
            category=Category.SUPPLY_CHAIN,
            layer=DetectionLayer.DETERMINISTIC,
            rule_id="D-20E",
            message="Dependency-confusion pattern detected",
            location=segment.location,
            segment_id=segment.id,
            details={"packages": packages, "source_kind": _source_kind(artifact, segment)},
        )
    ]


def _detect_skill_name_typosquatting(skill: Skill, config: ScanConfig):
    if not skill.name:
        return []
    normalized_skill_name = _normalize_skill_name(skill.name)
    if normalized_skill_name in {_normalize_skill_name(name) for name in config.typosquatting.allow_skill_names}:
        return []
    for protected_name in config.typosquatting.protected_skill_names:
        if _is_typosquat(normalized_skill_name, _normalize_skill_name(protected_name), config):
            severity = Severity.HIGH if _damerau_levenshtein(normalized_skill_name, _normalize_skill_name(protected_name)) == 1 else Severity.MEDIUM
            return [
                _finding(
                    "D-20F",
                    "Skill-name typosquatting detected",
                    severity,
                    Category.SUPPLY_CHAIN,
                    _skill_location(skill),
                    {"skill_name": skill.name, "protected_name": protected_name},
                )
            ]
    return []


def _detect_density_findings(artifact: Artifact, skill: Skill, config: ScanConfig):
    if not artifact.is_text or artifact.byte_size < 4096:
        return []
    content = artifact.raw_content.replace("\r\n", "\n")
    display_cells = _display_cells(content)
    if display_cells < 500:
        return []
    byte_size = max(artifact.byte_size, len(content.encode("utf-8")))
    non_rendered_bytes = sum(len(match.group(0).encode("utf-8")) for match in re.finditer(r"<!--.*?-->", content, re.DOTALL))
    invisible_bytes = sum(
        len(char.encode("utf-8"))
        for char in content
        if unicodedata.category(char) in {"Cf", "Mn", "Me"}
    )
    bytes_per_display_cell = byte_size / max(display_cells, 1)
    findings: list[Finding] = []

    if non_rendered_bytes >= 2048 and non_rendered_bytes / byte_size >= 0.35:
        severity = Severity.HIGH if non_rendered_bytes / byte_size >= 0.60 else Severity.MEDIUM
        findings.append(
            _finding(
                "D-23A",
                "Non-rendered-content inflation detected",
                severity,
                Category.OBFUSCATION,
                Location(file_path=artifact.path, start_line=1, end_line=max(1, content.count("\n") + 1)),
                {"non_rendered_bytes": non_rendered_bytes, "byte_size": byte_size},
            )
        )
    if invisible_bytes >= 1024 and invisible_bytes / byte_size >= 0.20:
        findings.append(
            _finding(
                "D-23B",
                "Invisible-unicode mass detected",
                Severity.HIGH,
                Category.OBFUSCATION,
                Location(file_path=artifact.path, start_line=1, end_line=max(1, content.count("\n") + 1)),
                {"invisible_bytes": invisible_bytes, "byte_size": byte_size},
            )
        )
    if bytes_per_display_cell >= 3.0 and non_rendered_bytes >= 2048:
        findings.append(
            _finding(
                "D-23C",
                "Opaque text blob detected",
                Severity.MEDIUM,
                Category.OBFUSCATION,
                Location(file_path=artifact.path, start_line=1, end_line=max(1, content.count("\n") + 1)),
                {
                    "bytes_per_display_cell": round(bytes_per_display_cell, 3),
                    "non_rendered_bytes": non_rendered_bytes,
                },
            )
        )
    return findings


def _detect_registry_override(
    segment: Segment,
    artifact: Artifact,
    *,
    patterns: list[re.Pattern[str]],
    registry_hosts: set[str],
    rule_id: str,
    message: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        for match in pattern.finditer(segment.content):
            url = match.groupdict().get("url")
            if not url:
                continue
            canonical = _canonicalize_url(url)
            if canonical is None or canonical["host"] in registry_hosts:
                continue
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    layer=DetectionLayer.DETERMINISTIC,
                    rule_id=rule_id,
                    message=message,
                    location=_location_for_span(segment, match.start(), match.end() - 1),
                    segment_id=segment.id,
                    details={
                        "url": url,
                        "host": canonical["host"],
                        "source_kind": _source_kind(artifact, segment),
                    },
                )
            )
    return findings


def _extract_package_candidates(artifact: Artifact) -> list[tuple[str, str, Location]]:
    candidates: list[tuple[str, str, Location]] = []
    lines = artifact.raw_content.splitlines()
    in_cargo_dependencies = False
    for index, line in enumerate(lines, start=1):
        package_location = Location(file_path=artifact.path, start_line=index, end_line=index)
        for match in PYTHON_PACKAGE_PATTERN.finditer(line):
            candidates.append(("python", match.group(1), package_location))
        if artifact.path.endswith(("requirements.txt", "requirements-dev.txt")):
            req_match = REQUIREMENTS_PACKAGE_PATTERN.match(line)
            if req_match and req_match.group(1):
                candidates.append(("python", req_match.group(1), package_location))
        for match in JS_PACKAGE_PATTERN.finditer(line):
            candidates.append(("javascript", match.group(1), package_location))
        if artifact.path.endswith("package.json"):
            json_match = re.search(r'"([@A-Za-z0-9._\-/]+)"\s*:', line)
            if json_match:
                candidates.append(("javascript", json_match.group(1), package_location))
        if line.strip().startswith("[dependencies]"):
            in_cargo_dependencies = True
            continue
        if line.strip().startswith("[") and not line.strip().startswith("[dependencies]"):
            in_cargo_dependencies = False
        if in_cargo_dependencies:
            cargo_match = CARGO_PACKAGE_PATTERN.match(line)
            if cargo_match:
                candidates.append(("rust", cargo_match.group(1), package_location))
    return candidates


def _extract_segment_packages(segment: Segment, artifact: Artifact) -> list[tuple[str, str, Location]]:
    temp_artifact = artifact.model_copy(update={"raw_content": segment.content, "path": artifact.path})
    return _extract_package_candidates(temp_artifact)


def _package_is_allowlisted(ecosystem: str, package_name: str, config: ScanConfig) -> bool:
    normalized = _normalize_package_name(ecosystem, package_name)
    allow_packages = getattr(config.typosquatting.allow_packages, ecosystem)
    return normalized in {_normalize_package_name(ecosystem, package) for package in allow_packages}


def _closest_protected_package(ecosystem: str, package_name: str, config: ScanConfig) -> str | None:
    normalized_package = _normalize_package_name(ecosystem, package_name)
    for protected_name in getattr(config.typosquatting.protected_packages, ecosystem):
        normalized_protected = _normalize_package_name(ecosystem, protected_name)
        if _is_typosquat(normalized_package, normalized_protected, config):
            return protected_name
    return None


def _classify_url(raw_url: str, segment: Segment, artifact: Artifact, config: ScanConfig) -> dict[str, object] | None:
    canonical = _canonicalize_url(raw_url)
    if canonical is None or not canonical["host"]:
        return None

    host = str(canonical["host"])
    scheme = str(canonical["scheme"])
    context = _url_context(segment, artifact)
    original_host = str(canonical["original_host"])
    allowlisted = _host_is_allowlisted(host, config)
    is_shortener = host in {entry.lower() for entry in config.url_policy.shortener_hosts}
    is_ip_literal = _is_ip_literal(host)
    is_obscured_ip = _is_obscured_ip(original_host)
    has_encoding_trick = _has_url_encoding_trick(raw_url, canonical)
    is_non_https = scheme != "https"
    is_punycode = "xn--" in original_host or any(ord(char) > 127 for char in original_host)

    if _looks_like_safe_health_check(segment, artifact, canonical):
        return None

    baseline = _context_baseline_severity(context)
    if allowlisted:
        if not config.url_policy.report_allowlisted_urls:
            return None
        return {
            "rule_id": "D-15A",
            "message": "Allowlisted host referenced",
            "severity": Severity.INFO,
            "host": host,
            "url": raw_url,
            "context": context,
            "canonical_url": canonical["canonical_url"],
        }
    if is_shortener:
        return {
            "rule_id": "D-15B",
            "message": "URL shortener host detected",
            "severity": Severity.MEDIUM if context == "documentation" else Severity.HIGH,
            "host": host,
            "url": raw_url,
            "context": context,
            "canonical_url": canonical["canonical_url"],
        }
    if is_ip_literal:
        return {
            "rule_id": "D-15C",
            "message": "IP-literal host detected",
            "severity": Severity.HIGH,
            "host": host,
            "url": raw_url,
            "context": context,
            "canonical_url": canonical["canonical_url"],
        }
    if is_obscured_ip:
        return {
            "rule_id": "D-15D",
            "message": "Obscured IP representation detected",
            "severity": Severity.HIGH,
            "host": original_host,
            "url": raw_url,
            "context": context,
            "canonical_url": canonical["canonical_url"],
        }
    if has_encoding_trick:
        return {
            "rule_id": "D-15F",
            "message": "Suspicious URL encoding trick detected",
            "severity": Severity.MEDIUM if context == "documentation" else Severity.HIGH,
            "host": host,
            "url": raw_url,
            "context": context,
            "canonical_url": canonical["canonical_url"],
        }
    if is_non_https:
        return {
            "rule_id": "D-15G",
            "message": "Non-HTTPS URL detected where HTTPS is expected",
            "severity": Severity.MEDIUM,
            "host": host,
            "url": raw_url,
            "context": context,
            "canonical_url": canonical["canonical_url"],
        }
    if is_punycode:
        return {
            "rule_id": "D-15H",
            "message": "Punycode or non-ASCII host detected",
            "severity": Severity.MEDIUM,
            "host": original_host,
            "url": raw_url,
            "context": context,
            "canonical_url": canonical["canonical_url"],
        }
    return {
        "rule_id": "D-15E",
        "message": "Unknown external host detected",
        "severity": baseline,
        "host": host,
        "url": raw_url,
        "context": context,
        "canonical_url": canonical["canonical_url"],
    }


def _looks_like_safe_health_check(segment: Segment, artifact: Artifact, canonical: dict[str, object]) -> bool:
    if artifact.file_type == FileType.MARKDOWN:
        return False
    path = str(canonical.get("path", "")).lower()
    if not any(token in path for token in {"/health", "/status", "/ping"}):
        return False
    content = segment.content.lower()
    return any(token in content for token in {"requests.get", "httpx.get", "urllib.request.urlopen", "curl"})


def _canonicalize_url(raw_url: str) -> dict[str, object] | None:
    candidate = raw_url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return None
    try:
        decoded_host = host.encode("ascii").decode("idna")
    except Exception:
        decoded_host = host
    canonical_url = parsed._replace(netloc=parsed.netloc.lower()).geturl()
    return {
        "scheme": parsed.scheme.lower(),
        "host": decoded_host,
        "original_host": host,
        "username": parsed.username,
        "path": unquote(parsed.path),
        "canonical_url": canonical_url,
    }


def _url_context(segment: Segment, artifact: Artifact) -> str:
    if _is_registry_or_dependency_context(segment, artifact):
        return "registry_or_dependency"
    if artifact.file_type != FileType.MARKDOWN:
        return "executable_snippet"
    if segment.segment_type == SegmentType.CODE_FENCE:
        language = str(segment.details.get("fence_language", "")).lower()
        if language in EXECUTABLE_FENCE_LANGUAGES:
            return "executable_snippet"
    lines = segment.content.splitlines()
    for index, line in enumerate(lines):
        if re.search(URL_PATTERN, line):
            nearby = [line]
            if index + 1 < len(lines):
                nearby.append(lines[index + 1])
            if any(re.search(rf"\b{re.escape(verb)}\b", chunk, re.IGNORECASE) for verb in ACTIONABLE_URL_VERBS for chunk in nearby):
                return "actionable_instruction"
    return "documentation"


def _is_registry_or_dependency_context(segment: Segment, artifact: Artifact) -> bool:
    filename = Path(artifact.path).name
    if filename in {"requirements.txt", "requirements-dev.txt", "package.json", ".npmrc", "Cargo.toml", "pyproject.toml"}:
        return True
    content = segment.content.lower()
    return any(token in content for token in {"--index-url", "--extra-index-url", "--registry", "[registries]", "replace-with"})


def _context_baseline_severity(context: str) -> Severity:
    if context == "registry_or_dependency":
        return Severity.HIGH
    if context in {"actionable_instruction", "executable_snippet"}:
        return Severity.MEDIUM
    return Severity.LOW


def _host_is_allowlisted(host: str, config: ScanConfig) -> bool:
    normalized_host = host.lower()
    if normalized_host in {entry.lower() for entry in config.url_policy.allow_hosts}:
        return True
    return any(normalized_host.endswith(suffix.lower()) for suffix in config.url_policy.allow_domain_suffixes)


def _is_ip_literal(host: str) -> bool:
    normalized = host.strip("[]")
    if normalized in {"localhost", "127.0.0.1"}:
        return True
    try:
        ipaddress.ip_address(normalized)
        return True
    except ValueError:
        return False


def _is_obscured_ip(host: str) -> bool:
    normalized = host.strip("[]").lower()
    if normalized.startswith("0x"):
        return True
    if normalized.isdigit():
        return True
    parts = normalized.split(".")
    return any(part.startswith("0x") or (len(part) > 1 and part.startswith("0")) for part in parts if part)


def _has_url_encoding_trick(raw_url: str, canonical: dict[str, object]) -> bool:
    return (
        "@" in raw_url.split("://", 1)[-1]
        or raw_url.count("%") >= 2
        or "%2f" in raw_url.lower()
        or "%40" in raw_url.lower()
        or raw_url.lower().count("%252f") > 0
        or canonical.get("username") is not None
    )


def _is_allowed_top_level_file(filename: str) -> bool:
    if filename in ALLOWED_TOP_LEVEL_FILES:
        return True
    return any(filename.startswith(prefix) for prefix in ALLOWED_TOP_LEVEL_PREFIXES)


def _relative_artifact_path(skill: Skill, artifact: Artifact) -> str:
    try:
        return str(Path(artifact.path).relative_to(Path(skill.path)))
    except ValueError:
        return Path(artifact.path).name


def _is_native_binary(artifact: Artifact) -> bool:
    path = Path(artifact.path)
    return artifact.binary_signature in {"elf", "pe", "mach_o"} or path.suffix.lower() in BINARY_SUFFIXES


def _is_archive_like(artifact: Artifact) -> bool:
    path = Path(artifact.path)
    return artifact.binary_signature in {"zip", "gzip"} or path.suffix.lower() in ARCHIVE_SUFFIXES


def _normalize_package_name(ecosystem: str, name: str) -> str:
    lowered = name.lower()
    if ecosystem == "python":
        return re.sub(r"[-_.]+", "-", lowered)
    if ecosystem == "rust":
        return lowered.replace("_", "-")
    return lowered


def _normalize_skill_name(name: str) -> str:
    return re.sub(r"[\s_-]+", "-", name.lower()).strip("-")


def _is_typosquat(candidate: str, protected: str, config: ScanConfig) -> bool:
    if candidate == protected:
        return False
    if not candidate or not protected or candidate[0] != protected[0]:
        return False
    if candidate.count("-") != protected.count("-"):
        return False
    distance = _damerau_levenshtein(candidate, protected)
    max_distance = _max_distance_for_length(len(protected), config)
    if distance > max_distance:
        return False
    if len(protected) >= 11 and distance / max(len(protected), 1) > config.typosquatting.max_relative_distance:
        return False
    return True


def _max_distance_for_length(length: int, config: ScanConfig) -> int:
    if length <= 5:
        return config.typosquatting.short_name_max_distance
    if length <= 10:
        return config.typosquatting.medium_name_max_distance
    return config.typosquatting.long_name_max_distance


def _damerau_levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    matrix = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for index in range(len(left) + 1):
        matrix[index][0] = index
    for index in range(len(right) + 1):
        matrix[0][index] = index
    for i, left_char in enumerate(left, start=1):
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and left_char == right[j - 2] and left[i - 2] == right_char:
                matrix[i][j] = min(matrix[i][j], matrix[i - 2][j - 2] + cost)
    return matrix[-1][-1]


def _display_cells(content: str) -> int:
    cells = 0
    for char in content:
        if char in {"\n", "\r", "\t"}:
            continue
        if unicodedata.category(char) in {"Cf", "Mn", "Me"}:
            continue
        cells += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
    return max(cells, 0)


def _skill_location(skill: Skill) -> Location:
    skill_md = next((artifact for artifact in skill.artifacts if artifact.path.endswith("SKILL.md")), None)
    if skill_md is not None:
        return Location(file_path=skill_md.path, start_line=1, end_line=1)
    return Location(file_path=skill.path, start_line=1, end_line=1)


def _source_kind(artifact: Artifact, segment: Segment) -> str:
    if segment.segment_type == SegmentType.CODE_FENCE:
        return "code_fence"
    if artifact.file_type == FileType.MARKDOWN:
        return "markdown"
    return "code"


def _finding(rule_id: str, message: str, severity: Severity, category: Category, location: Location, details: dict[str, object]) -> Finding:
    return Finding(
        severity=severity,
        category=category,
        layer=DetectionLayer.DETERMINISTIC,
        rule_id=rule_id,
        message=message,
        location=location,
        details=details,
    )


def _location_for_span(segment: Segment, start: int, end: int) -> Location:
    content = segment.content
    start_line = (segment.location.start_line or 1) + content.count("\n", 0, start)
    end_line = (segment.location.start_line or 1) + content.count("\n", 0, end + 1)
    start_offset = content.rfind("\n", 0, start)
    end_offset = content.rfind("\n", 0, end + 1)
    if start_offset == -1:
        start_col = (segment.location.start_col or 1) + start
    else:
        start_col = start - start_offset
    if end_offset == -1:
        end_col = (segment.location.start_col or 1) + end
    else:
        end_col = end - end_offset
    return Location(
        file_path=segment.location.file_path,
        start_line=start_line,
        end_line=end_line,
        start_col=start_col,
        end_col=end_col,
    )
