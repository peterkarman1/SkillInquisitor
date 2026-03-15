from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import tempfile
from urllib.parse import urlparse

from skillinquisitor.models import Artifact, FileType, Skill


@dataclass(frozen=True)
class GitHubTarget:
    owner: str
    repo: str
    ref: str | None = None
    subpath: Path | None = None
    is_blob: bool = False


async def resolve_input(target: str | None, stdin_text: str | None = None) -> list[Skill]:
    if _is_stdin_target(target):
        if stdin_text is None:
            raise ValueError("stdin_text is required when target is stdin")
        return [_build_synthetic_skill("stdin", stdin_text, scan_provenance="stdin")]

    if target is None:
        raise ValueError("A scan target is required")

    if _looks_like_github_url(target):
        github_target = parse_github_url(target)
        with tempfile.TemporaryDirectory(prefix="skillinquisitor-") as temp_dir:
            resolved_root = await clone_github_repo(github_target, Path(temp_dir))
            if resolved_root.is_file():
                content = await asyncio.to_thread(resolved_root.read_text, encoding="utf-8")
                return [_build_synthetic_skill(str(resolved_root), content, scan_provenance="synthetic_file")]
            return await asyncio.to_thread(_resolve_directory, resolved_root)

    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(target)
    if path.is_file():
        content = await asyncio.to_thread(path.read_text, encoding="utf-8")
        return [_build_synthetic_skill(str(path), content, scan_provenance="synthetic_file")]
    return await asyncio.to_thread(_resolve_directory, path)


def _resolve_directory(root: Path) -> list[Skill]:
    ignore_names = _load_ignore_patterns(root)
    if (root / "SKILL.md").exists():
        return [_build_skill_from_directory(root, ignore_names)]

    skill_dirs = sorted({path.parent for path in root.rglob("SKILL.md")})
    if skill_dirs:
        return [_build_skill_from_directory(skill_dir, ignore_names) for skill_dir in skill_dirs]

    artifacts = _collect_artifacts(root, ignore_names)
    synthetic_skill = Skill(
        path=str(root),
        name=root.name,
        artifacts=artifacts,
        scan_provenance="synthetic_directory",
    )
    return [synthetic_skill]


def _build_skill_from_directory(root: Path, ignore_names: set[str]) -> Skill:
    return Skill(
        path=str(root),
        name=root.name,
        artifacts=_collect_artifacts(root, ignore_names),
        scan_provenance="declared_skill",
    )


def _collect_artifacts(root: Path, ignore_names: set[str]) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if ".git" in relative_parts:
            continue
        if any(part in ignore_names for part in relative_parts):
            continue
        byte_size = path.stat().st_size
        is_executable = os.access(path, os.X_OK) or _has_shebang(path)
        signature = _infer_binary_signature(path)
        try:
            raw_content = path.read_text(encoding="utf-8")
            is_text = True
            encoding = "utf-8"
        except UnicodeDecodeError:
            raw_content = ""
            is_text = False
            encoding = None
        if signature in {"elf", "pe", "mach_o", "zip", "gzip"} and path.suffix.lower() not in {".md", ".py", ".sh", ".js", ".ts", ".rb", ".go", ".rs", ".yaml", ".yml", ".txt"}:
            raw_content = ""
            is_text = False
            encoding = None
        artifacts.append(
            Artifact(
                path=str(path),
                raw_content=raw_content,
                file_type=_infer_file_type(path),
                byte_size=byte_size,
                is_text=is_text,
                encoding=encoding,
                is_executable=is_executable,
                binary_signature=signature,
            )
        )
    return artifacts


def _build_synthetic_skill(target: str, content: str, scan_provenance: str) -> Skill:
    path = Path(target)
    return Skill(
        path=str(path),
        name=path.parent.name or path.name,
        scan_provenance=scan_provenance,
        artifacts=[
            Artifact(
                path=str(path),
                raw_content=content,
                file_type=_infer_file_type(path),
                byte_size=len(content.encode("utf-8")),
                is_text=True,
                encoding="utf-8",
            )
        ],
    )


def _is_stdin_target(target: str | None) -> bool:
    return target in {None, "-"}


def parse_github_url(url: str) -> GitHubTarget:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError("Only https://github.com URLs are supported")

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repository")

    owner, repo = parts[0], parts[1]
    if len(parts) == 2:
        return GitHubTarget(owner=owner, repo=repo)
    if len(parts) >= 5 and parts[2] in {"tree", "blob"}:
        return GitHubTarget(
            owner=owner,
            repo=repo,
            ref=parts[3],
            subpath=Path(*parts[4:]),
            is_blob=parts[2] == "blob",
        )
    raise ValueError("Unsupported GitHub URL format")


def _looks_like_github_url(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme == "https" and parsed.netloc == "github.com"


async def clone_github_repo(target: GitHubTarget, destination: Path) -> Path:
    clone_target = destination / target.repo
    command = [
        "git",
        "clone",
        "--depth",
        "1",
    ]
    if target.ref is not None:
        command.extend(["--branch", target.ref])
    command.extend(
        [
            f"https://github.com/{target.owner}/{target.repo}",
            str(clone_target),
        ]
    )
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr.decode("utf-8").strip() or "git clone failed")

    if target.subpath is None:
        return clone_target

    resolved_path = clone_target / target.subpath
    if not resolved_path.exists():
        raise FileNotFoundError(f"GitHub path not found: {target.subpath}")
    return resolved_path


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


def _has_shebang(path: Path) -> bool:
    try:
        return path.read_bytes().startswith(b"#!")
    except OSError:
        return False


def _infer_binary_signature(path: Path) -> str | None:
    try:
        header = path.read_bytes()[:8]
    except OSError:
        return None

    if header.startswith(b"\x7fELF"):
        return "elf"
    if header.startswith(b"MZ"):
        return "pe"
    if header[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
        return "mach_o"
    if header.startswith(b"PK\x03\x04"):
        return "zip"
    if header.startswith(b"\x1f\x8b"):
        return "gzip"
    return None
