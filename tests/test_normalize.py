from skillinquisitor.models import Artifact, FileType, NormalizationTransformation, NormalizationType
from skillinquisitor.normalize import normalize_artifact


def test_artifact_supports_typed_normalization_transformations():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="eval",
        normalization_transformations=[
            NormalizationTransformation(
                transformation_type=NormalizationType.KEYWORD_SPLITTER_COLLAPSE,
                original_snippet="e.v.a.l",
                normalized_snippet="eval",
            )
        ],
    )

    assert artifact.normalization_transformations[0].normalized_snippet == "eval"


def test_normalize_artifact_records_zero_width_removal():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="e\u200bv\u200ba\u200bl",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)

    assert normalized.normalized_content == "eval"
    assert normalized.normalization_transformations


def test_normalize_artifact_keeps_original_segment_as_canonical_source():
    artifact = Artifact(path="SKILL.md", raw_content="safe", file_type=FileType.MARKDOWN)

    normalized = normalize_artifact(artifact)

    assert len(normalized.segments) == 1
    assert normalized.segments[0].content == "safe"
