from __future__ import annotations

import re

from skillinquisitor.models import (
    Artifact,
    Location,
    NormalizationTransformation,
    NormalizationType,
    ProvenanceStep,
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


def normalize_artifact(artifact: Artifact) -> Artifact:
    normalized_content = artifact.raw_content
    transformations: list[NormalizationTransformation] = []

    for transform in (
        _remove_unicode_tags,
        lambda content, path: _record_char_removals(content, path, ZERO_WIDTH_CHARS, NormalizationType.ZERO_WIDTH_REMOVAL),
        lambda content, path: _record_char_removals(content, path, VARIATION_SELECTORS, NormalizationType.VARIATION_SELECTOR),
        lambda content, path: _record_char_removals(content, path, BIDI_OVERRIDE_CHARS, NormalizationType.BIDI_OVERRIDE),
        _fold_homoglyphs,
        _collapse_keyword_splitters,
    ):
        normalized_content, new_transformations = transform(normalized_content, artifact.path)
        transformations.extend(new_transformations)

    return artifact.model_copy(
        update={
            "normalized_content": normalized_content,
            "normalization_transformations": transformations,
            "segments": [_build_original_segment(artifact)],
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
