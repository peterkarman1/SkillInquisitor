#!/usr/bin/env python3
"""Reset the benchmark dataset to safe GitHub skills from curated repos.

This script replaces benchmark/dataset and benchmark/manifest.yaml with a
github-only corpus sourced from:
- obra/superpowers
- trailofbits/skills
"""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_ROOT = PROJECT_ROOT / "benchmark"
DATASET_ROOT = BENCHMARK_ROOT / "dataset"
MANIFEST_PATH = BENCHMARK_ROOT / "manifest.yaml"


@dataclass(frozen=True)
class RepoSpec:
    slug_prefix: str
    repo: str
    license_id: str
    skill_roots: tuple[str, ...]


REPOS: tuple[RepoSpec, ...] = (
    RepoSpec(
        slug_prefix="obra",
        repo="obra/superpowers",
        license_id="MIT",
        skill_roots=("skills",),
    ),
    RepoSpec(
        slug_prefix="tob",
        repo="trailofbits/skills",
        license_id="Apache-2.0",
        skill_roots=(".codex/skills", "plugins"),
    ),
)


def run(cmd: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def clone_repo(repo: str, dest: Path) -> str:
    run(["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", str(dest)])
    return run(["git", "rev-parse", "HEAD"], cwd=dest)


def discover_skill_dirs(repo_dir: Path, roots: tuple[str, ...]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        root_dir = repo_dir / root
        if not root_dir.exists():
            continue
        for skill_md in sorted(root_dir.rglob("SKILL.md")):
            found.append(skill_md.parent)
    return found


def make_entry_id(prefix: str, repo_dir: Path, skill_dir: Path) -> str:
    relative = skill_dir.relative_to(repo_dir).as_posix()
    parts = [part for part in relative.split("/") if part not in {"skills", "plugins", ".codex"}]
    return f"{prefix}-{'-'.join(parts)}".replace("_", "-").lower()


def assign_tier(index: int) -> str:
    if index < 20:
        return "smoke"
    if index < 50:
        return "standard"
    return "full"


def write_meta(dest: Path, *, repo: str, commit_sha: str, relative_path: str, license_id: str, fetch_date: str) -> None:
    source_url = f"https://github.com/{repo}/tree/main/{relative_path}"
    content = {
        "source_type": "github",
        "provenance": {
            "source_url": source_url,
            "source_ref": commit_sha,
            "fetch_date": fetch_date,
            "license": license_id,
            "upstream_status": "active",
        },
    }
    (dest / "_meta.yaml").write_text(yaml.safe_dump(content, sort_keys=False), encoding="utf-8")


def build_manifest(entries: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_version": "3.0.0",
        "decision_policy": {"default_threshold": 60.0},
        "entries": entries,
    }


def main() -> int:
    if DATASET_ROOT.exists():
        shutil.rmtree(DATASET_ROOT)
    DATASET_ROOT.mkdir(parents=True, exist_ok=True)
    skills_root = DATASET_ROOT / "skills"
    skills_root.mkdir(parents=True, exist_ok=True)

    fetch_date = dt.date.today().isoformat()
    entries: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory(prefix="benchmark-safe-reset-") as tmp:
        temp_root = Path(tmp)
        discovered: list[tuple[RepoSpec, Path, str, Path]] = []
        for repo_spec in REPOS:
            repo_dir = temp_root / repo_spec.repo.split("/")[1]
            commit_sha = clone_repo(repo_spec.repo, repo_dir)
            for skill_dir in discover_skill_dirs(repo_dir, repo_spec.skill_roots):
                discovered.append((repo_spec, repo_dir, commit_sha, skill_dir))

        for index, (repo_spec, repo_dir, commit_sha, skill_dir) in enumerate(sorted(discovered, key=lambda item: make_entry_id(item[0].slug_prefix, item[1], item[3]))):
            entry_id = make_entry_id(repo_spec.slug_prefix, repo_dir, skill_dir)
            dest = skills_root / entry_id
            shutil.copytree(skill_dir, dest)
            relative_path = skill_dir.relative_to(repo_dir).as_posix()
            write_meta(
                dest,
                repo=repo_spec.repo,
                commit_sha=commit_sha,
                relative_path=relative_path,
                license_id=repo_spec.license_id,
                fetch_date=fetch_date,
            )
            entries.append(
                {
                    "id": entry_id,
                    "path": f"skills/{entry_id}",
                    "ground_truth": {
                        "verdict": "SAFE",
                        "attack_categories": [],
                        "severity": None,
                        "expected_rules": [],
                        "min_category_coverage": [],
                        "notes": f"Safe real-world skill snapshot from {repo_spec.repo}.",
                    },
                    "metadata": {
                        "tier": assign_tier(index),
                        "difficulty": "medium",
                        "source_type": "github",
                        "tags": ["safe", "real-world", repo_spec.slug_prefix],
                    },
                    "provenance": {
                        "source_url": f"https://github.com/{repo_spec.repo}/tree/main/{relative_path}",
                        "source_ref": commit_sha,
                        "fetch_date": fetch_date,
                        "license": repo_spec.license_id,
                        "upstream_status": "active",
                    },
                }
            )

    MANIFEST_PATH.write_text(yaml.safe_dump(build_manifest(entries), sort_keys=False), encoding="utf-8")
    print(f"Reset benchmark dataset with {len(entries)} safe skills.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
