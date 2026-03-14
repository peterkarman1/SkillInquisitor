import pytest

from skillinquisitor.formatters.console import format_console
from skillinquisitor.formatters.json import format_json
from skillinquisitor.models import Artifact, FileType, SegmentType
from skillinquisitor.pipeline import run_pipeline
from skillinquisitor.models import ScanConfig
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


@pytest.mark.asyncio
async def test_empty_pipeline_returns_zero_findings():
    result = await run_pipeline(skills=[], config=ScanConfig())
    assert result.findings == []
    assert result.risk_score == 100
    assert result.verdict == "SAFE"


@pytest.mark.asyncio
async def test_console_formatter_handles_empty_result():
    result = await run_pipeline(skills=[], config=ScanConfig())
    output = format_console(result)
    assert "0 findings" in output.lower()


@pytest.mark.asyncio
async def test_json_formatter_serializes_findings():
    result = await run_pipeline(skills=[], config=ScanConfig())
    output = format_json(result)
    assert '"findings": []' in output
