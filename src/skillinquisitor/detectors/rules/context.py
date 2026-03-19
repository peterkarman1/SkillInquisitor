from __future__ import annotations

import re

from skillinquisitor.models import Artifact, FileType, Segment, SegmentType


ACTIONABLE_SECTION_HEADERS = {
    "prerequisites",
    "installation",
    "install",
    "setup",
    "usage",
    "quick start",
    "quickstart",
    "getting started",
}

ACTIONABLE_CONTEXT_VERBS = {
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
    "post",
    "upload",
    "send",
    "use",
    "follow",
    "respond",
}

EXECUTABLE_FENCE_LANGUAGES = {
    "bash",
    "sh",
    "shell",
    "python",
    "py",
    "javascript",
    "js",
    "typescript",
    "ts",
    "ruby",
    "rb",
    "go",
    "rust",
}

REFERENCE_EXAMPLE_PATH_HINTS = {
    "/references/",
    "/reference/",
    "/examples/",
    "/example/",
    "best-practices",
    "quick-reference",
    "cheatsheet",
    "handbook",
    "playbook",
    "troubleshooting",
    "tutorial",
    "workflow",
    "runbook",
    "guide",
}
REFERENCE_EXAMPLE_PATTERNS = [
    re.compile(r"\bfor example\b", re.IGNORECASE),
    re.compile(r"\bdefensive example\b", re.IGNORECASE),
    re.compile(r"\bquoted example\b", re.IGNORECASE),
    re.compile(r"\bexample attack\b", re.IGNORECASE),
    re.compile(r"\bdo not execute\b", re.IGNORECASE),
    re.compile(r"\bexpected:\b", re.IGNORECASE),
    re.compile(r"\bfor training\b", re.IGNORECASE),
    re.compile(r"\bfor detection\b", re.IGNORECASE),
    re.compile(r"\bsecurity guide\b", re.IGNORECASE),
    re.compile(r"\btaint mode\b", re.IGNORECASE),
    re.compile(r"^\s*(?:bad|good|safe|unsafe|vulnerable)\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*pattern\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*ruleid\s*:", re.IGNORECASE | re.MULTILINE),
]
SECURITY_REFERENCE_PATTERNS = [
    re.compile(r"\bsecurity skill for detecting\b", re.IGNORECASE),
    re.compile(r"\bhelps identify security vulnerabilities\b", re.IGNORECASE),
    re.compile(r"\bvulnerability categories\b", re.IGNORECASE),
    re.compile(r"\bcritical distinction\b", re.IGNORECASE),
    re.compile(r"\bthe skill identifies\b", re.IGNORECASE),
    re.compile(r"\bpit of success\b", re.IGNORECASE),
    re.compile(r"\byara(?:-x)?\b", re.IGNORECASE),
    re.compile(r"\bvirustotal\b", re.IGNORECASE),
    re.compile(r"\bgoodware\b", re.IGNORECASE),
    re.compile(r"\b(?:livehunt|retrohunt)\b", re.IGNORECASE),
    re.compile(r"\bmalware (?:analysis|detection)\b", re.IGNORECASE),
    re.compile(r"\bdetection engineering\b", re.IGNORECASE),
    re.compile(r"\brule authoring\b", re.IGNORECASE),
    re.compile(r"\b(?:audit|auditing|detect|detecting)\b[\s\S]{0,80}\b(?:security|vulnerabilit|misconfiguration|authentication|authorization|cryptographic|configuration)\b", re.IGNORECASE),
]
ENVIRONMENT_BOOTSTRAP_PATH_HINTS = {
    "/.devcontainer/",
    "/devcontainer/",
    "devcontainer.json",
    "/dockerfile",
    "/post_install.py",
}
ENVIRONMENT_BOOTSTRAP_PATTERNS = [
    re.compile(r"\bdevcontainer\b", re.IGNORECASE),
    re.compile(r"\bdockerfile\b", re.IGNORECASE),
    re.compile(r"\bpost(?:-|_|\s)?install\b", re.IGNORECASE),
    re.compile(r"\bcontainer\b", re.IGNORECASE),
    re.compile(r"\bworkspace(?:mount|folder)?\b", re.IGNORECASE),
    re.compile(r"\btype=volume\b", re.IGNORECASE),
    re.compile(r"\bpath configuration\b", re.IGNORECASE),
    re.compile(r"\badd (?:it|them) to your path\b", re.IGNORECASE),
]


def classify_segment_context(
    segment: Segment,
    artifact: Artifact,
    *,
    extra_verbs: set[str] | None = None,
) -> str:
    if segment.segment_type == SegmentType.FRONTMATTER_DESCRIPTION:
        return "frontmatter_description"
    if artifact.file_type != FileType.MARKDOWN:
        return "code"
    if segment.segment_type == SegmentType.CODE_FENCE:
        language = str(segment.details.get("fence_language", "")).lower()
        if language in EXECUTABLE_FENCE_LANGUAGES:
            return "executable_snippet"

    verbs = ACTIONABLE_CONTEXT_VERBS | (extra_verbs or set())
    lines = segment.content.splitlines()
    if not lines:
        return "documentation"

    for index, line in enumerate(lines):
        prior_lines = lines[max(0, index - 3):index]
        nearby = [line]
        if index + 1 < len(lines):
            nearby.append(lines[index + 1])
        nearby.extend(prior_lines)
        if any(re.search(rf"\b{re.escape(verb)}\b", chunk, re.IGNORECASE) for verb in verbs for chunk in nearby):
            return "actionable_instruction"
        if any(_line_has_actionable_heading(chunk) for chunk in prior_lines):
            return "actionable_instruction"

    return "documentation"


def _line_has_actionable_heading(line: str) -> bool:
    stripped = line.strip().lstrip("#").strip().rstrip(":")
    return stripped.lower() in ACTIONABLE_SECTION_HEADERS


def is_reference_example(segment: Segment, artifact: Artifact) -> bool:
    path_lower = (artifact.path or "").replace("\\", "/").lower()
    if any(hint in path_lower for hint in REFERENCE_EXAMPLE_PATH_HINTS):
        return True
    if artifact.file_type != FileType.MARKDOWN:
        return False
    if any(pattern.search(segment.content) for pattern in SECURITY_REFERENCE_PATTERNS):
        return True
    return any(pattern.search(segment.content) for pattern in REFERENCE_EXAMPLE_PATTERNS)


def is_environment_bootstrap(segment: Segment, artifact: Artifact) -> bool:
    path_lower = (artifact.path or "").replace("\\", "/").lower()
    if any(hint in path_lower for hint in ENVIRONMENT_BOOTSTRAP_PATH_HINTS):
        return True
    return any(pattern.search(segment.content) for pattern in ENVIRONMENT_BOOTSTRAP_PATTERNS)
