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


def test_segment_supports_parent_linkage_and_normalized_view():
    from skillinquisitor.models import Segment, SegmentType

    segment = Segment(
        id="seg-1",
        content="payload",
        normalized_content="payload",
        segment_type=SegmentType.BASE64_DECODE,
        parent_segment_id="seg-0",
        parent_start_offset=10,
        parent_end_offset=25,
        depth=1,
    )

    assert segment.parent_segment_id == "seg-0"
    assert segment.normalized_content == "payload"


def test_finding_supports_segment_id_reference():
    from skillinquisitor.models import Finding

    finding = Finding(rule_id="D-3A", message="base64", segment_id="seg-1")

    assert finding.segment_id == "seg-1"


def test_original_segment_receives_normalized_view():
    from skillinquisitor.models import SegmentType

    artifact = Artifact(
        path="SKILL.md",
        raw_content="e\u200bv\u200ba\u200bl",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)

    assert normalized.segments[0].segment_type == SegmentType.ORIGINAL
    assert normalized.segments[0].normalized_content == "eval"


def test_original_segment_id_is_deterministic():
    artifact = Artifact(path="SKILL.md", raw_content="safe", file_type=FileType.MARKDOWN)

    first = normalize_artifact(artifact).segments[0].id
    second = normalize_artifact(artifact).segments[0].id

    assert first
    assert first == second


def test_markdown_comment_and_fence_content_become_child_segments():
    from skillinquisitor.models import SegmentType

    artifact = Artifact(
        path="SKILL.md",
        raw_content="<!-- hidden -->\n```python\nprint('safe')\n```",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)
    segment_types = [segment.segment_type for segment in normalized.segments]

    assert SegmentType.HTML_COMMENT in segment_types
    assert SegmentType.CODE_FENCE in segment_types


def test_parent_markdown_does_not_extract_comment_inside_code_fence_twice():
    from skillinquisitor.models import SegmentType

    artifact = Artifact(
        path="SKILL.md",
        raw_content="```md\n<!-- hidden -->\n```",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)
    comment_segments = [s for s in normalized.segments if s.segment_type == SegmentType.HTML_COMMENT]

    assert len(comment_segments) == 1
