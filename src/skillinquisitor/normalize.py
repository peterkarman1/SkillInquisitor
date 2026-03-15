from __future__ import annotations

import base64
import codecs
import hashlib
import re

from skillinquisitor.models import (
    Artifact,
    FileType,
    Location,
    NormalizationTransformation,
    NormalizationType,
    ProvenanceStep,
    ScanConfig,
    Segment,
    SegmentType,
)


ZERO_WIDTH_CHARS = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
}
VARIATION_SELECTORS = {chr(codepoint) for codepoint in range(0xFE00, 0xFE10)}
BIDI_OVERRIDE_CHARS = {
    "\u202a",
    "\u202b",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}
UNICODE_TAG_RANGE = range(0xE0000, 0xE0080)

HOMOGLYPH_MAP = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "α": "a",
    "β": "b",
    "γ": "y",
    "ι": "i",
    "κ": "k",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "ａ": "a",
    "ｂ": "b",
    "ｃ": "c",
    "ｄ": "d",
    "ｅ": "e",
    "ｆ": "f",
    "ｇ": "g",
    "ｈ": "h",
    "ｉ": "i",
    "ｊ": "j",
    "ｋ": "k",
    "ｌ": "l",
    "ｍ": "m",
    "ｎ": "n",
    "ｏ": "o",
    "ｐ": "p",
    "ｑ": "q",
    "ｒ": "r",
    "ｓ": "s",
    "ｔ": "t",
    "ｕ": "u",
    "ｖ": "v",
    "ｗ": "w",
    "ｘ": "x",
    "ｙ": "y",
    "ｚ": "z",
}
TOKEN_PATTERN = re.compile(r"\S+")
HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
CODE_FENCE_PATTERN = re.compile(r"```([^\n`]*)\n(.*?)\n```", re.DOTALL)
BASE64_CANDIDATE_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")

DANGEROUS_KEYWORD_FAMILIES = {
    "execution": ["eval", "exec", "compile", "subprocess", "os.system"],
    "network": ["curl", "wget", "fetch", "requests", "urllib", "socket"],
    "secrets": ["os.environ", "process.env", "getenv", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
    "encoding": ["base64", "b64decode", "fromhex"],
}


def _build_original_segment(artifact: Artifact) -> Segment:
    location = Location(
        file_path=artifact.path,
        start_line=1,
        end_line=max(1, artifact.raw_content.count("\n") + 1),
        start_col=1,
        end_col=1,
    )
    return Segment(
        id=_segment_id(artifact.path, "original", "0", str(len(artifact.raw_content))),
        content=artifact.raw_content,
        segment_type=SegmentType.ORIGINAL,
        location=location,
        provenance_chain=[
            ProvenanceStep(
                segment_type=SegmentType.ORIGINAL,
                source_location=location,
                description="Original artifact content",
            )
        ],
    )


def _segment_id(*parts: str) -> str:
    digest = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def _location_for_span(content: str, path: str, start: int, end: int) -> Location:
    start_line = content.count("\n", 0, start) + 1
    end_line = content.count("\n", 0, end) + 1
    start_line_offset = content.rfind("\n", 0, start)
    end_line_offset = content.rfind("\n", 0, end)
    start_col = start + 1 if start_line_offset == -1 else start - start_line_offset
    end_col = end + 1 if end_line_offset == -1 else end - end_line_offset
    return Location(
        file_path=path,
        start_line=start_line,
        end_line=end_line,
        start_col=start_col,
        end_col=end_col,
    )


def _location_for_child_span(parent: Segment, start: int, end: int) -> Location:
    content = parent.content
    start_line_offset = content.count("\n", 0, start)
    end_line_offset = content.count("\n", 0, end + 1)
    start_line = (parent.location.start_line or 1) + start_line_offset
    end_line = (parent.location.start_line or 1) + end_line_offset

    last_start_newline = content.rfind("\n", 0, start)
    last_end_newline = content.rfind("\n", 0, end + 1)

    if last_start_newline == -1:
        start_col = (parent.location.start_col or 1) + start
    else:
        start_col = start - last_start_newline

    if last_end_newline == -1:
        end_col = (parent.location.start_col or 1) + end
    else:
        end_col = end - last_end_newline

    return Location(
        file_path=parent.location.file_path,
        start_line=start_line,
        end_line=end_line,
        start_col=start_col,
        end_col=end_col,
    )


def _record_char_removals(
    content: str,
    path: str,
    chars: set[str],
    transformation_type: NormalizationType,
) -> tuple[str, list[NormalizationTransformation]]:
    transformations: list[NormalizationTransformation] = []
    kept: list[str] = []

    for index, char in enumerate(content):
        if char in chars:
            transformations.append(
                NormalizationTransformation(
                    transformation_type=transformation_type,
                    original_snippet=char,
                    normalized_snippet="",
                    location=_location_for_span(content, path, index, index),
                    details={"codepoint": f"U+{ord(char):04X}"},
                )
            )
            continue
        kept.append(char)

    return "".join(kept), transformations


def _remove_unicode_tags(content: str, path: str) -> tuple[str, list[NormalizationTransformation]]:
    transformations: list[NormalizationTransformation] = []
    kept: list[str] = []

    for index, char in enumerate(content):
        if ord(char) in UNICODE_TAG_RANGE:
            transformations.append(
                NormalizationTransformation(
                    transformation_type=NormalizationType.UNICODE_TAG,
                    original_snippet=char,
                    normalized_snippet="",
                    location=_location_for_span(content, path, index, index),
                    details={"codepoint": f"U+{ord(char):05X}"},
                )
            )
            continue
        kept.append(char)

    return "".join(kept), transformations


def _fold_homoglyphs(content: str, path: str) -> tuple[str, list[NormalizationTransformation]]:
    transformed: list[NormalizationTransformation] = []
    chars = list(content)

    for match in TOKEN_PATTERN.finditer(content):
        token = match.group(0)
        scripts = {_script_group(char) for char in token if _script_group(char) is not None}
        if len(scripts) < 2:
            continue
        if "latin" not in scripts and "fullwidth" not in scripts:
            continue
        for offset, char in enumerate(token):
            replacement = HOMOGLYPH_MAP.get(char)
            if replacement is None:
                continue
            absolute_index = match.start() + offset
            transformed.append(
                NormalizationTransformation(
                    transformation_type=NormalizationType.HOMOGLYPH_FOLD,
                    original_snippet=char,
                    normalized_snippet=replacement,
                    location=_location_for_span(content, path, absolute_index, absolute_index),
                    details={"codepoint": f"U+{ord(char):04X}"},
                )
            )
            chars[absolute_index] = replacement

    return "".join(chars), transformed


def _iter_dangerous_keywords() -> list[tuple[str, str]]:
    return [
        (family, keyword)
        for family, keywords in DANGEROUS_KEYWORD_FAMILIES.items()
        for keyword in keywords
    ]


def _build_splitter_pattern(keyword: str) -> re.Pattern[str]:
    parts = [re.escape(char) for char in keyword]
    separator = r"(?:[\.\-_ \t\r\n\u200b\u200c\u200d\u2060]+)"
    pattern = separator.join(parts)
    return re.compile(pattern, re.IGNORECASE)


def _collapse_keyword_splitters(content: str, path: str) -> tuple[str, list[NormalizationTransformation]]:
    updated = content
    transformations: list[NormalizationTransformation] = []

    for family, keyword in _iter_dangerous_keywords():
        pattern = _build_splitter_pattern(keyword)
        while True:
            match = pattern.search(updated)
            if match is None:
                break
            original = match.group(0)
            collapsed = keyword
            transformations.append(
                NormalizationTransformation(
                    transformation_type=NormalizationType.KEYWORD_SPLITTER_COLLAPSE,
                    original_snippet=original,
                    normalized_snippet=collapsed,
                    location=_location_for_span(updated, path, match.start(), match.end() - 1),
                    details={"keyword": keyword, "family": family},
                )
            )
            updated = f"{updated[:match.start()]}{collapsed}{updated[match.end():]}"

    return updated, transformations

def _normalize_segment_text(content: str, path: str) -> tuple[str, list[NormalizationTransformation]]:
    normalized_content = content
    transformations: list[NormalizationTransformation] = []

    for transform in (
        _remove_unicode_tags,
        lambda content, path: _record_char_removals(content, path, ZERO_WIDTH_CHARS, NormalizationType.ZERO_WIDTH_REMOVAL),
        lambda content, path: _record_char_removals(content, path, VARIATION_SELECTORS, NormalizationType.VARIATION_SELECTOR),
        lambda content, path: _record_char_removals(content, path, BIDI_OVERRIDE_CHARS, NormalizationType.BIDI_OVERRIDE),
        _fold_homoglyphs,
        _collapse_keyword_splitters,
    ):
        normalized_content, new_transformations = transform(normalized_content, path)
        transformations.extend(new_transformations)

    return normalized_content, transformations


def _build_child_segment(
    *,
    artifact: Artifact,
    parent: Segment,
    segment_type: SegmentType,
    content: str,
    start_offset: int,
    end_offset: int,
    description: str,
    details: dict[str, object] | None = None,
) -> Segment:
    normalized_content, _ = _normalize_segment_text(content, artifact.path)
    location = _location_for_child_span(parent, start_offset, end_offset)
    return Segment(
        id=_segment_id(
            artifact.path,
            parent.id,
            segment_type.value,
            str(start_offset),
            str(end_offset),
            content,
        ),
        content=content,
        normalized_content=normalized_content,
        segment_type=segment_type,
        location=location,
        provenance_chain=[
            *parent.provenance_chain,
            ProvenanceStep(
                segment_type=segment_type,
                source_location=location,
                description=description,
            ),
        ],
        depth=parent.depth + 1,
        parent_segment_id=parent.id,
        parent_start_offset=start_offset,
        parent_end_offset=end_offset,
        parent_segment_type=parent.segment_type,
        details=details or {},
    )


def _markdown_extraction_eligible(artifact: Artifact, segment: Segment) -> bool:
    return artifact.file_type == FileType.MARKDOWN and segment.segment_type in {
        SegmentType.ORIGINAL,
        SegmentType.HTML_COMMENT,
        SegmentType.CODE_FENCE,
    }


def _extract_code_fence_segments(parent: Segment, artifact: Artifact) -> tuple[list[Segment], list[tuple[int, int]]]:
    segments: list[Segment] = []
    blocked_ranges: list[tuple[int, int]] = []

    for match in CODE_FENCE_PATTERN.finditer(parent.content):
        body = match.group(2)
        body_start = match.start(2)
        body_end = match.end(2) - 1
        blocked_ranges.append((match.start(), match.end() - 1))
        segments.append(
            _build_child_segment(
                artifact=artifact,
                parent=parent,
                segment_type=SegmentType.CODE_FENCE,
                content=body,
                start_offset=body_start,
                end_offset=body_end,
                description="Extracted from markdown code fence",
                details={"fence_language": match.group(1).strip()},
            )
        )

    return segments, blocked_ranges


def _extract_html_comment_segments(
    parent: Segment,
    artifact: Artifact,
    blocked_ranges: list[tuple[int, int]],
) -> tuple[list[Segment], list[tuple[int, int]]]:
    segments: list[Segment] = []
    comment_ranges: list[tuple[int, int]] = []

    for match in HTML_COMMENT_PATTERN.finditer(parent.content):
        match_start = match.start()
        match_end = match.end() - 1
        if any(match_start >= blocked_start and match_end <= blocked_end for blocked_start, blocked_end in blocked_ranges):
            continue
        comment_ranges.append((match_start, match_end))
        segments.append(
            _build_child_segment(
                artifact=artifact,
                parent=parent,
                segment_type=SegmentType.HTML_COMMENT,
                content=match.group(1),
                start_offset=match.start(1),
                end_offset=match.end(1) - 1,
                description="Extracted from HTML comment",
            )
        )

    return segments, comment_ranges


def _decode_base64_segments(
    parent: Segment,
    artifact: Artifact,
    config: ScanConfig,
    blocked_ranges: list[tuple[int, int]],
) -> list[Segment]:
    segments: list[Segment] = []
    accepted_candidates = 0

    for match in BASE64_CANDIDATE_PATTERN.finditer(parent.content):
        if accepted_candidates >= config.layers.deterministic.max_decode_candidates_per_segment:
            break
        match_start = match.start(1)
        match_end = match.end(1) - 1
        if any(match_start >= blocked_start and match_end <= blocked_end for blocked_start, blocked_end in blocked_ranges):
            continue
        candidate = match.group(1)
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            if len(decoded_bytes) > config.layers.deterministic.max_decoded_bytes:
                continue
            decoded_text = decoded_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue

        segments.append(
            _build_child_segment(
                artifact=artifact,
                parent=parent,
                segment_type=SegmentType.BASE64_DECODE,
                content=decoded_text,
                start_offset=match_start,
                end_offset=match_end,
                description="Decoded from Base64 payload",
                details={"decoder": "base64", "source_preview": candidate[:24]},
            )
        )
        accepted_candidates += 1

    return segments


def _derive_rot13_segment(parent: Segment, artifact: Artifact, config: ScanConfig) -> list[Segment]:
    if parent.segment_type == SegmentType.ROT13_TRANSFORM:
        return []
    if config.layers.deterministic.require_rot13_signal and (
        "rot13" not in parent.content.lower() and "rot_13" not in parent.content.lower()
    ):
        return []

    return [
        _build_child_segment(
            artifact=artifact,
            parent=parent,
            segment_type=SegmentType.ROT13_TRANSFORM,
            content=codecs.encode(parent.content, "rot_13"),
            start_offset=0,
            end_offset=max(0, len(parent.content) - 1),
            description="ROT13-transformed content derived from explicit signal",
            details={"decoder": "rot13"},
        )
    ]


def _expand_segments(parent: Segment, artifact: Artifact, config: ScanConfig, state: dict[str, int]) -> list[Segment]:
    if not _markdown_extraction_eligible(artifact, parent):
        return []
    if parent.depth >= config.layers.deterministic.max_derived_depth:
        return []

    code_fence_segments, blocked_ranges = _extract_code_fence_segments(parent, artifact)
    comment_segments, comment_ranges = _extract_html_comment_segments(parent, artifact, blocked_ranges)
    excluded_ranges = [*blocked_ranges, *comment_ranges]
    base64_segments = _decode_base64_segments(parent, artifact, config, excluded_ranges)
    rot13_segments = _derive_rot13_segment(parent, artifact, config)

    children = [*code_fence_segments, *comment_segments, *base64_segments, *rot13_segments]
    expanded: list[Segment] = []
    for child in children:
        if state["derived_segments"] >= config.layers.deterministic.max_derived_segments_per_artifact:
            break
        state["derived_segments"] += 1
        expanded.append(child)
        expanded.extend(_expand_segments(child, artifact, config, state))
    return expanded


def normalize_artifact(artifact: Artifact, config: ScanConfig | None = None) -> Artifact:
    effective_config = config or ScanConfig()
    normalized_content, transformations = _normalize_segment_text(artifact.raw_content, artifact.path)
    original_segment = _build_original_segment(artifact).model_copy(
        update={"normalized_content": normalized_content}
    )
    derived_segments = _expand_segments(
        original_segment,
        artifact,
        effective_config,
        state={"derived_segments": 0},
    )

    return artifact.model_copy(
        update={
            "normalized_content": normalized_content,
            "normalization_transformations": transformations,
            "segments": [original_segment, *derived_segments],
        }
    )


def _script_group(char: str) -> str | None:
    codepoint = ord(char)
    if char.isascii() and char.isalpha():
        return "latin"
    if 0x0400 <= codepoint <= 0x04FF:
        return "cyrillic"
    if 0x0370 <= codepoint <= 0x03FF:
        return "greek"
    if 0xFF01 <= codepoint <= 0xFF5E:
        return "fullwidth"
    return None
