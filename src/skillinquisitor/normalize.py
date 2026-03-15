from __future__ import annotations

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


def _build_original_segment(artifact: Artifact) -> Segment:
    location = Location(file_path=artifact.path)
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


def _location_for_index(content: str, path: str, index: int) -> Location:
    line = content.count("\n", 0, index) + 1
    last_newline = content.rfind("\n", 0, index)
    column = index + 1 if last_newline == -1 else index - last_newline
    return Location(file_path=path, start_line=line, end_line=line, start_col=column, end_col=column)


def _remove_zero_width(content: str, path: str) -> tuple[str, list[NormalizationTransformation]]:
    transformed: list[NormalizationTransformation] = []
    kept: list[str] = []

    for index, char in enumerate(content):
        if char in ZERO_WIDTH_CHARS:
            transformed.append(
                NormalizationTransformation(
                    transformation_type=NormalizationType.ZERO_WIDTH_REMOVAL,
                    original_snippet=char,
                    normalized_snippet="",
                    location=_location_for_index(content, path, index),
                )
            )
            continue
        kept.append(char)

    return "".join(kept), transformed


def normalize_artifact(artifact: Artifact) -> Artifact:
    normalized_content, transformations = _remove_zero_width(artifact.raw_content, artifact.path)
    return artifact.model_copy(
        update={
            "normalized_content": normalized_content,
            "normalization_transformations": transformations,
            "segments": [_build_original_segment(artifact)],
        }
    )
