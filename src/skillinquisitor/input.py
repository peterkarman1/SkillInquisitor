from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urlparse

from skillinquisitor.models import Artifact, FileType, Skill


async def resolve_input(target: str | None, stdin_text: str | None = None) -> list[Skill]:
    if _is_stdin_target(target):
        if stdin_text is None:
            raise ValueError("stdin_text is required when target is stdin")
        return [_build_synthetic_skill("stdin", stdin_text)]

    if target is None:
        raise ValueError("A scan target is required")

    if _looks_like_github_url(target):
        raise NotImplementedError("GitHub input is implemented in the next TDD step")

    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(target)
    if path.is_file():
        content = await asyncio.to_thread(path.read_text, encoding="utf-8")
        return [_build_synthetic_skill(str(path), content)]
    return await asyncio.to_thread(_resolve_directory, path)


def _resolve_directory(root: Path) -> list[Skill]:
    ignore_names = _load_ignore_patterns(root)
    if (root / "SKILL.md").exists():
        return [_build_skill_from_directory(root, ignore_names)]

    skill_dirs = sorted({path.parent for path in root.rglob("SKILL.md")})
    if skill_dirs:
        return [_build_skill_from_directory(skill_dir, ignore_names) for skill_dir in skill_dirs]

    artifacts = _collect_artifacts(root, ignore_names)
    synthetic_skill = Skill(path=str(root), name=root.name, artifacts=artifacts)
    return [synthetic_skill]


def _build_skill_from_directory(root: Path, ignore_names: set[str]) -> Skill:
    return Skill(path=str(root), name=root.name, artifacts=_collect_artifacts(root, ignore_names))


def _collect_artifacts(root: Path, ignore_names: set[str]) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in ignore_names for part in path.parts):
            continue
        artifacts.append(
            Artifact(
                path=str(path),
                raw_content=path.read_text(encoding="utf-8"),
                file_type=_infer_file_type(path),
            )
        )
    return artifacts


def _build_synthetic_skill(target: str, content: str) -> Skill:
    path = Path(target)
    return Skill(
        path=str(path),
        name=path.parent.name or path.name,
        artifacts=[
            Artifact(
                path=str(path),
                raw_content=content,
                file_type=_infer_file_type(path),
            )
        ],
    )


def _is_stdin_target(target: str | None) -> bool:
    return target in {None, "-"}


def _looks_like_github_url(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme == "https" and parsed.netloc == "github.com"


def _infer_file_type(path: Path) -> FileType:
    suffix = path.suffix.lower()
    return {
        ".md": FileType.MARKDOWN,
        ".py": FileType.PYTHON,
        ".sh": FileType.SHELL,
        ".js": FileType.JAVASCRIPT,
        ".ts": FileType.TYPESCRIPT,
        ".rb": FileType.RUBY,
        ".go": FileType.GO,
        ".rs": FileType.RUST,
        ".yaml": FileType.YAML,
        ".yml": FileType.YAML,
    }.get(suffix, FileType.UNKNOWN)


def _load_ignore_patterns(root: Path) -> set[str]:
    ignore_file = root / ".skillinquisitorignore"
    if not ignore_file.exists():
        return set()
    return {
        line.strip()
        for line in ignore_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
