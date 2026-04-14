from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlparse

from skillinquisitor.models import Artifact, FileType, Skill
from skillinquisitor.progress import ProgressSink, emit_progress

DEFAULT_IGNORED_FILENAMES = {"_meta.json", "_meta.yaml", "expected.yaml"}
SCP_STYLE_GIT_REMOTE_RE = re.compile(r"^[^@\s]+@[^:\s]+:.+$")

@dataclass(frozen=True)
class GitRemoteTarget:
    remote_url: str
    clone_name: str
    ref: str | None = None
    subpath: Path | None = None
    is_blob: bool = False
    host: str | None = None
    owner: str | None = None
    repo: str | None = None


@dataclass
class ResolvedInput:
    skills: list[Skill]
    temp_dir: str | None = None

    def cleanup(self) -> None:
        if self.temp_dir is not None:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None


async def resolve_input(
    target: str | None,
    stdin_text: str | None = None,
    commit_sha: str | None = None,
    *,
    event_sink: ProgressSink | None = None,
) -> ResolvedInput:
    if _is_stdin_target(target):
        if stdin_text is None:
            raise ValueError("stdin_text is required when target is stdin")
        return ResolvedInput(skills=[_build_synthetic_skill("stdin", stdin_text, scan_provenance="stdin")])

    if target is None:
        raise ValueError("A scan target is required")

    if _looks_like_git_remote(target):
        remote_target = parse_git_remote_target(target)
        temp_dir = tempfile.mkdtemp(prefix="skillinquisitor-")
        try:
            resolved_root = await clone_git_repo(
                remote_target,
                Path(temp_dir),
                commit_sha=commit_sha,
                event_sink=event_sink,
            )
            if resolved_root.is_file():
                content = await asyncio.to_thread(resolved_root.read_text, encoding="utf-8")
                return ResolvedInput(
                    skills=[_build_synthetic_skill(str(resolved_root), content, scan_provenance="synthetic_file")],
                    temp_dir=temp_dir,
                )
            skills = await asyncio.to_thread(_resolve_directory, resolved_root, event_sink)
            return ResolvedInput(skills=skills, temp_dir=temp_dir)
        except Exception:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(target)
    if path.is_file():
        content = await asyncio.to_thread(path.read_text, encoding="utf-8")
        return ResolvedInput(skills=[_build_synthetic_skill(str(path), content, scan_provenance="synthetic_file")])
    return ResolvedInput(skills=await asyncio.to_thread(_resolve_directory, path, event_sink))


def _resolve_directory(root: Path, event_sink: ProgressSink | None = None) -> list[Skill]:
    ignore_names = _load_ignore_patterns(root)
    if (root / "SKILL.md").exists():
        skills = [_build_skill_from_directory(root, ignore_names)]
        emit_progress(event_sink, "input.discovered", root=str(root), skills=len(skills))
        return skills

    skill_dirs = sorted({path.parent for path in root.rglob("SKILL.md")})
    if skill_dirs:
        skills = [_build_skill_from_directory(skill_dir, ignore_names) for skill_dir in skill_dirs]
        emit_progress(event_sink, "input.discovered", root=str(root), skills=len(skills))
        return skills

    artifacts = _collect_artifacts(root, ignore_names)
    synthetic_skill = Skill(
        path=str(root),
        name=root.name,
        artifacts=artifacts,
        scan_provenance="synthetic_directory",
    )
    emit_progress(event_sink, "input.discovered", root=str(root), skills=1)
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
        if path.name in DEFAULT_IGNORED_FILENAMES:
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


def parse_github_url(url: str) -> GitRemoteTarget:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError("Only https://github.com URLs are supported")

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repository")

    owner, repo = parts[0], parts[1]
    remote_url = f"https://github.com/{owner}/{repo}"
    clone_name = _normalize_clone_name(repo)
    if len(parts) == 2:
        return GitRemoteTarget(
            remote_url=remote_url,
            clone_name=clone_name,
            host=parsed.netloc,
            owner=owner,
            repo=repo,
        )
    if len(parts) >= 5 and parts[2] in {"tree", "blob"}:
        return GitRemoteTarget(
            remote_url=remote_url,
            clone_name=clone_name,
            ref=parts[3],
            subpath=Path(*parts[4:]),
            is_blob=parts[2] == "blob",
            host=parsed.netloc,
            owner=owner,
            repo=repo,
        )
    raise ValueError("Unsupported GitHub URL format")


def parse_git_remote_target(target: str) -> GitRemoteTarget:
    if _looks_like_github_url(target):
        return parse_github_url(target)
    if _looks_like_standard_git_remote(target):
        parsed = urlparse(target)
        return GitRemoteTarget(
            remote_url=target,
            clone_name=_normalize_clone_name(Path(parsed.path).name),
            host=parsed.netloc or None,
        )
    if _looks_like_scp_git_remote(target):
        host = target.split("@", 1)[1].split(":", 1)[0]
        repo_path = target.rsplit(":", 1)[1]
        return GitRemoteTarget(
            remote_url=target,
            clone_name=_normalize_clone_name(Path(repo_path).name),
            host=host,
        )
    raise ValueError("Unsupported git remote URL format")


def _looks_like_github_url(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme == "https" and parsed.netloc == "github.com"


def _looks_like_git_remote(target: str) -> bool:
    return _looks_like_github_url(target) or _looks_like_standard_git_remote(target) or _looks_like_scp_git_remote(target)


def _looks_like_standard_git_remote(target: str) -> bool:
    parsed = urlparse(target)
    if parsed.scheme not in {"https", "ssh", "git", "file"}:
        return False
    if parsed.scheme != "file" and not parsed.netloc:
        return False
    path_parts = [part for part in parsed.path.split("/") if part]
    return len(path_parts) >= 2


def _looks_like_scp_git_remote(target: str) -> bool:
    return bool(SCP_STYLE_GIT_REMOTE_RE.match(target))


async def clone_git_repo(
    target: GitRemoteTarget,
    destination: Path,
    commit_sha: str | None = None,
    *,
    event_sink: ProgressSink | None = None,
) -> Path:
    clone_target = destination / target.clone_name
    emit_progress(
        event_sink,
        "input.git.clone.started",
        remote=target.remote_url,
        host=target.host,
        ref=target.ref,
        commit=commit_sha,
    )
    command = [
        "git",
        "clone",
    ]
    if commit_sha is None:
        command.extend(["--depth", "1"])
    if commit_sha is None and target.ref is not None:
        command.extend(["--branch", target.ref])
    command.extend(
        [
            target.remote_url,
            str(clone_target),
        ]
    )
    await _run_git_command(command, error_message="git clone failed")
    if commit_sha is not None:
        await _run_git_command(
            ["git", "-C", str(clone_target), "checkout", "--detach", commit_sha],
            error_message=f"git checkout failed for commit {commit_sha}",
        )
    emit_progress(event_sink, "input.git.clone.completed", path=str(clone_target))

    if target.subpath is None:
        return clone_target

    resolved_path = clone_target / target.subpath
    if not resolved_path.exists():
        raise FileNotFoundError(f"Git remote path not found: {target.subpath}")
    return resolved_path


async def _run_git_command(command: list[str], *, error_message: str) -> None:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr.decode("utf-8").strip() or error_message)


def _normalize_clone_name(name: str) -> str:
    normalized = name.removesuffix(".git")
    return normalized or "repo"


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
