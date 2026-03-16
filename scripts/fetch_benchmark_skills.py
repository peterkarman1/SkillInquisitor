#!/usr/bin/env python3
"""Fetch real-world safe skills from GitHub for the benchmark dataset.

Downloads skill directories from public GitHub repos using sparse checkout,
saves them as local snapshots, and generates _meta.yaml provenance files.

Usage:
    python scripts/fetch_benchmark_skills.py [--dry-run] [--limit N]
    python scripts/fetch_benchmark_skills.py --output-dir /tmp/test-safe --limit 3
"""

from __future__ import annotations

import argparse
import datetime
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Skill source registry
# ---------------------------------------------------------------------------

SKILL_SOURCES: list[dict[str, str]] = [
    # Trail of Bits (Apache-2.0)
    {"repo": "trailofbits/skills", "subpath": "plugins/semgrep-rule-creator", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/audit-context-building", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/insecure-defaults", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/property-based-testing", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/variant-analysis", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/static-analysis", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/modern-python", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/supply-chain-risk-auditor", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/yara-authoring", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/gh-cli", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/git-cleanup", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/devcontainer-setup", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/firebase-apk-scanner", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/zeroize-audit", "license": "Apache-2.0"},
    {"repo": "trailofbits/skills", "subpath": "plugins/sharp-edges", "license": "Apache-2.0"},
    # Anthropic Official
    {"repo": "anthropics/skills", "subpath": "skills/pdf", "license": "MIT"},
    {"repo": "anthropics/skills", "subpath": "skills/docx", "license": "MIT"},
    {"repo": "anthropics/skills", "subpath": "skills/mcp-builder", "license": "MIT"},
    {"repo": "anthropics/skills", "subpath": "skills/skill-creator", "license": "MIT"},
    {"repo": "anthropics/skills", "subpath": "skills/webapp-testing", "license": "MIT"},
    {"repo": "anthropics/skills", "subpath": "skills/frontend-design", "license": "MIT"},
    {"repo": "anthropics/skills", "subpath": "skills/algorithmic-art", "license": "MIT"},
    {"repo": "anthropics/skills", "subpath": "skills/slack-gif-creator", "license": "MIT"},
    # Cloudflare
    {"repo": "cloudflare/skills", "subpath": "skills/agents-sdk", "license": "Apache-2.0"},
    {"repo": "cloudflare/skills", "subpath": "skills/wrangler", "license": "Apache-2.0"},
    {"repo": "cloudflare/skills", "subpath": "skills/durable-objects", "license": "Apache-2.0"},
    # HashiCorp
    {"repo": "hashicorp/agent-skills", "subpath": "terraform/code-generation", "license": "MPL-2.0"},
    {"repo": "hashicorp/agent-skills", "subpath": "terraform/module-generation", "license": "MPL-2.0"},
    # Vercel
    {"repo": "vercel-labs/agent-skills", "subpath": "skills/react-best-practices", "license": "MIT"},
    {"repo": "vercel-labs/agent-skills", "subpath": "skills/composition-patterns", "license": "MIT"},
    # Stripe
    {"repo": "stripe/ai", "subpath": "skills/stripe-best-practices", "license": "MIT"},
    # Supabase
    {"repo": "supabase/agent-skills", "subpath": "skills/supabase-postgres-best-practices", "license": "Apache-2.0"},
    # Expo
    {"repo": "expo/skills", "subpath": "plugins/expo-app-design", "license": "MIT"},
    # HuggingFace
    {"repo": "huggingface/skills", "subpath": "skills/hugging-face-cli", "license": "Apache-2.0"},
    {"repo": "huggingface/skills", "subpath": "skills/hugging-face-datasets", "license": "Apache-2.0"},
]

# ---------------------------------------------------------------------------
# Slug generation
# ---------------------------------------------------------------------------

# Map repo org names to short prefixes for readable slugs.
_ORG_PREFIXES: dict[str, str] = {
    "trailofbits": "tob",
    "anthropics": "anthropic",
    "cloudflare": "cf",
    "hashicorp": "hc",
    "vercel-labs": "vercel",
    "stripe": "stripe",
    "supabase": "supabase",
    "expo": "expo",
    "huggingface": "hf",
}


def make_slug(repo: str, subpath: str) -> str:
    """Generate a short, filesystem-safe slug from repo + subpath.

    Examples:
        trailofbits/skills + plugins/semgrep-rule-creator -> tob-semgrep-rule-creator
        anthropics/skills  + skills/pdf                   -> anthropic-pdf
        hashicorp/agent-skills + terraform/code-generation -> hc-terraform-code-generation
    """
    org = repo.split("/")[0]
    prefix = _ORG_PREFIXES.get(org, org)

    # Use the last path component as the skill name.  For hashicorp where
    # the top-level directory is semantically meaningful (terraform/), keep
    # all components.
    parts = subpath.strip("/").split("/")
    # Drop leading directory if it's a generic container name.
    generic_dirs = {"plugins", "skills"}
    if parts[0] in generic_dirs and len(parts) > 1:
        parts = parts[1:]

    name = "-".join(parts)
    return f"{prefix}-{name}"


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    *,
    cwd: str | Path | None = None,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess, returning CompletedProcess.  Raises on non-zero exit."""
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=capture,
        text=True,
        check=True,
    )


def clone_sparse(
    repo: str,
    subpath: str,
    dest: Path,
) -> tuple[Path, str]:
    """Sparse-checkout *subpath* from *repo* into *dest*.

    Returns (path_to_skill_dir, commit_sha).
    """
    tmpdir = tempfile.mkdtemp(prefix="skillfetch-")
    try:
        # Shallow clone with blob filter (treeless clone).
        _run([
            "git", "clone",
            "--depth", "1",
            "--filter=blob:none",
            "--sparse",
            f"https://github.com/{repo}.git",
            tmpdir,
        ])

        # Enable sparse-checkout for the target subpath only.
        _run(["git", "sparse-checkout", "set", subpath], cwd=tmpdir)

        # Resolve the HEAD sha for provenance.
        result = _run(["git", "rev-parse", "HEAD"], cwd=tmpdir)
        commit_sha = result.stdout.strip()

        src = Path(tmpdir) / subpath
        if not src.is_dir():
            raise FileNotFoundError(
                f"Subpath '{subpath}' not found in {repo} after sparse checkout"
            )

        # Copy skill directory to destination.
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)

        return dest, commit_sha

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Meta-file generation
# ---------------------------------------------------------------------------


def write_meta(
    dest: Path,
    *,
    repo: str,
    subpath: str,
    commit_sha: str,
    license_id: str,
    fetch_date: str,
) -> None:
    """Write a _meta.yaml provenance sidecar into *dest*."""
    source_url = f"https://github.com/{repo}/tree/main/{subpath}"
    content = (
        f"source_type: github\n"
        f"provenance:\n"
        f'  source_url: "{source_url}"\n'
        f'  source_ref: "{commit_sha}"\n'
        f'  fetch_date: "{fetch_date}"\n'
        f'  license: "{license_id}"\n'
        f"  upstream_status: active\n"
    )
    (dest / "_meta.yaml").write_text(content)


# ---------------------------------------------------------------------------
# Manifest snippet generation
# ---------------------------------------------------------------------------


def manifest_entry(slug: str) -> str:
    """Return a YAML snippet suitable for appending to manifest.yaml."""
    return (
        f"  - id: {slug}\n"
        f"    path: real-world/safe/{slug}\n"
        f"    ground_truth:\n"
        f"      verdict: SAFE\n"
        f"      attack_categories: []\n"
        f"      severity: none\n"
        f"      expected_rules: []\n"
        f"      min_category_coverage: []\n"
        f'      notes: ""\n'
        f"    metadata:\n"
        f"      tier: real-world\n"
        f"      difficulty: baseline\n"
        f"      source_type: github\n"
        f"      tags:\n"
        f"        - safe\n"
        f"        - real-world\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch real-world safe skills from GitHub for the benchmark dataset.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be fetched without actually fetching.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Only fetch the first N skills (0 = all).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Override output directory (default: benchmark/dataset/real-world/safe).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Resolve project root relative to this script.
    project_root = Path(__file__).resolve().parent.parent
    output_dir: Path = args.output_dir or (
        project_root / "benchmark" / "dataset" / "real-world" / "safe"
    )

    sources = SKILL_SOURCES
    if args.limit > 0:
        sources = sources[: args.limit]

    total = len(sources)
    today = datetime.date.today().isoformat()
    manifest_snippets: list[str] = []
    ok_count = 0
    skip_count = 0

    print(f"Fetching {total} skill(s) -> {output_dir}")
    if args.dry_run:
        print("(dry-run mode -- no files will be written)\n")

    for idx, src in enumerate(sources, 1):
        repo = src["repo"]
        subpath = src["subpath"]
        license_id = src["license"]
        slug = make_slug(repo, subpath)
        dest = output_dir / slug

        tag = f"[{idx}/{total}]"

        if args.dry_run:
            print(f"{tag} {slug}  <-  {repo}:{subpath}  (dry-run, skipped)")
            manifest_snippets.append(manifest_entry(slug))
            ok_count += 1
            continue

        print(f"{tag} {slug}...", end=" ", flush=True)

        try:
            dest_path, commit_sha = clone_sparse(repo, subpath, dest)
            write_meta(
                dest_path,
                repo=repo,
                subpath=subpath,
                commit_sha=commit_sha,
                license_id=license_id,
                fetch_date=today,
            )
            manifest_snippets.append(manifest_entry(slug))
            ok_count += 1
            print("OK")
        except FileNotFoundError as exc:
            skip_count += 1
            print(f"SKIP ({exc})")
        except subprocess.CalledProcessError as exc:
            skip_count += 1
            stderr_preview = (exc.stderr or "")[:200].strip()
            print(f"FAIL (git error: {stderr_preview})")
        except Exception as exc:  # noqa: BLE001
            skip_count += 1
            print(f"FAIL ({exc})")

    # Summary
    print(f"\nDone: {ok_count} fetched, {skip_count} skipped out of {total}.")

    # Print manifest entries
    if manifest_snippets:
        print("\n# ---------------------------------------------------------------------------")
        print("# Append these entries to benchmark/manifest.yaml under 'entries:':")
        print("# ---------------------------------------------------------------------------\n")
        print(
            "  # ==========================================================================="
        )
        print(f"  # REAL-WORLD SAFE SKILLS ({ok_count})")
        print(
            "  # ===========================================================================\n"
        )
        for snippet in manifest_snippets:
            print(snippet)

    return 1 if skip_count == total and total > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
