from pathlib import Path

import pytest

from skillinquisitor.input import resolve_input


@pytest.mark.asyncio
async def test_single_file_input_creates_synthetic_skill(tmp_path: Path):
    file_path = tmp_path / "SKILL.md"
    file_path.write_text("# demo", encoding="utf-8")

    skills = await resolve_input(str(file_path))

    assert len(skills) == 1
    assert skills[0].name == file_path.parent.name
    assert len(skills[0].artifacts) == 1


@pytest.mark.asyncio
async def test_directory_input_collects_all_artifacts_for_skill_fixture():
    skills = await resolve_input("tests/fixtures/local/nested-skill")

    assert len(skills) == 1
    assert len(skills[0].artifacts) == 2


@pytest.mark.asyncio
async def test_stdin_input_creates_synthetic_skill():
    skills = await resolve_input("-", stdin_text="# piped")

    assert len(skills) == 1
    assert len(skills[0].artifacts) == 1
    assert skills[0].artifacts[0].raw_content == "# piped"
