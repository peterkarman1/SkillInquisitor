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
    async def fake_clone(target, destination, event_sink=None):
        return Path("tests/fixtures/local/nested-skill")

    monkeypatch.setattr("skillinquisitor.input.clone_github_repo", fake_clone)

    skills = await resolve_input("https://github.com/openai/example")

    assert len(skills) == 1
    assert len(skills[0].artifacts) == 2


@pytest.mark.asyncio
async def test_directory_input_ignores_git_metadata(tmp_path: Path):
    skill_dir = tmp_path / "repo-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# skill", encoding="utf-8")
    git_dir = skill_dir / ".git"
    git_dir.mkdir()
    (git_dir / "index").write_bytes(b"\x92binary")

    skills = await resolve_input(str(skill_dir))

    assert len(skills) == 1
    assert [artifact.path for artifact in skills[0].artifacts] == [str(skill_dir / "SKILL.md")]


@pytest.mark.asyncio
async def test_directory_input_ignores_internal_metadata_files(tmp_path: Path):
    skill_dir = tmp_path / "meta-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# skill", encoding="utf-8")
    (skill_dir / "_meta.json").write_text('{"notes":"benchmark metadata"}\n', encoding="utf-8")
    (skill_dir / "_meta.yaml").write_text("notes: benchmark metadata\n", encoding="utf-8")
    (skill_dir / "expected.yaml").write_text("verdict: HIGH RISK\n", encoding="utf-8")

    skills = await resolve_input(str(skill_dir))

    assert len(skills) == 1
    assert [artifact.path for artifact in skills[0].artifacts] == [str(skill_dir / "SKILL.md")]


@pytest.mark.asyncio
async def test_directory_input_preserves_non_utf8_files_as_binary_artifacts(tmp_path: Path):
    skill_dir = tmp_path / "binary-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# skill", encoding="utf-8")
    (skill_dir / "payload.bin").write_bytes(b"\x92binary")

    skills = await resolve_input(str(skill_dir))

    assert len(skills) == 1
    assert [artifact.path for artifact in skills[0].artifacts] == [
        str(skill_dir / "SKILL.md"),
        str(skill_dir / "payload.bin"),
    ]
    payload = next(artifact for artifact in skills[0].artifacts if artifact.path.endswith("payload.bin"))
    assert payload.is_text is False
