from skillinquisitor.models import Artifact, FileType, SegmentType
from skillinquisitor.normalize import normalize_artifact


def test_normalize_artifact_creates_original_segment():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="# skill",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)

    assert len(normalized.segments) == 1
    assert normalized.segments[0].content == "# skill"
    assert normalized.segments[0].segment_type == SegmentType.ORIGINAL
