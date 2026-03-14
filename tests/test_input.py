from pathlib import Path

import pytest

from skillinquisitor.input import parse_github_url, resolve_input


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


def test_parse_github_repo_url():
    parsed = parse_github_url("https://github.com/openai/example")
    assert parsed.owner == "openai"
    assert parsed.repo == "example"
    assert parsed.ref is None
    assert parsed.subpath is None


def test_parse_github_tree_url():
    parsed = parse_github_url("https://github.com/openai/example/tree/main/src")
    assert parsed.owner == "openai"
    assert parsed.repo == "example"
    assert parsed.ref == "main"
    assert parsed.subpath == Path("src")


def test_parse_github_url_rejects_non_github_host():
    with pytest.raises(ValueError):
        parse_github_url("https://gitlab.com/openai/example")


@pytest.mark.asyncio
async def test_resolve_input_uses_github_clone(monkeypatch: pytest.MonkeyPatch):
    async def fake_clone(target, destination):
        return Path("tests/fixtures/local/nested-skill")

    monkeypatch.setattr("skillinquisitor.input.clone_github_repo", fake_clone)

    skills = await resolve_input("https://github.com/openai/example")

    assert len(skills) == 1
    assert len(skills[0].artifacts) == 2
