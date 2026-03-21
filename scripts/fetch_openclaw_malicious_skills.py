#!/usr/bin/env python3
"""Build a real-world malicious benchmark slice from OpenClaw/ClawHub samples.

This script downloads the public `yoonholee/agent-skill-malware` dataset from
Hugging Face, keeps the malicious samples, writes them as benchmark skill
snapshots, and appends them to the benchmark manifest alongside the current
safe real-world corpus.

The malicious SKILL.md content is preserved verbatim. Benchmark scans only read
these files; they are never executed by this script.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict, deque
from datetime import date
from pathlib import Path
import subprocess
from urllib.request import urlopen

import yaml

DATASET_CARD_URL = "https://huggingface.co/datasets/yoonholee/agent-skill-malware"
DATASET_JSONL_URL = (
    "https://huggingface.co/datasets/yoonholee/agent-skill-malware/resolve/main/skills.jsonl?download=true"
)

DEFAULT_MANIFEST = Path("benchmark/manifest.yaml")
DEFAULT_DATASET_ROOT = Path("benchmark/dataset/skills")
DEFAULT_OPENCLAW_REPO = Path("benchmark/.cache/openclaw-skills.git")
OPENCLAW_REPO_URL = "https://github.com/openclaw/skills.git"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--openclaw-repo", type=Path, default=DEFAULT_OPENCLAW_REPO)
    parser.add_argument("--limit", type=int, default=0, help="Optional limit for debugging")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def _git_capture(repo: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=text,
    )
    return result.stdout


def ensure_openclaw_repo(repo: Path) -> None:
    if (repo / ".git").exists():
        subprocess.run(
            ["git", "-C", str(repo), "fetch", "--depth", "1", "origin", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "reset", "--hard", "FETCH_HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return

    repo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--no-checkout",
            OPENCLAW_REPO_URL,
            str(repo),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def build_upstream_skill_index(repo: Path) -> dict[str, list[str]]:
    paths = str(_git_capture(repo, "ls-tree", "-r", "--name-only", "HEAD", "skills")).splitlines()
    index: dict[str, list[str]] = defaultdict(list)
    for raw_path in paths:
        path = Path(raw_path)
        if path.name.lower() != "skill.md":
            continue
        index[path.parent.name.lower()].append(str(path.parent))
    return dict(index)


def find_upstream_skill_dir(
    repo: Path,
    skill_name: str,
    content: str,
    skill_index: dict[str, list[str]] | None = None,
) -> str | None:
    index = skill_index or build_upstream_skill_index(repo)
    candidates = index.get(skill_name.lower(), [])
    normalized_content = content.replace("\r\n", "\n").strip()
    for candidate in candidates:
        candidate_content = str(_git_capture(repo, "show", f"HEAD:{candidate}/SKILL.md")).replace("\r\n", "\n").strip()
        if candidate_content == normalized_content:
            return candidate
    return None


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _primary_name(skill_name: str) -> str:
    return re.sub(r"-[a-z0-9]{4,}$", "", skill_name.lower())


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(needle in lowered for needle in needles)


def infer_attack_categories(content: str) -> list[str]:
    categories: set[str] = set()
    lowered = content.lower()

    if _contains_any(lowered, ("openclaw-agent", "openclawcli", "openclaw-core", "glot.io/snippets", "setup-service.com", "install.app-distribution.net", "vercel.app", "base64")):
        categories.add("supply_chain")
    if _contains_any(lowered, ("webhook.site", "analytics", "~/.ssh", "~/.aws", "api key", "api_key", "token", "credential", "password", "private key", "seed phrase")):
        categories.update({"credential_theft", "data_exfiltration"})
    if _contains_any(lowered, ("do not ask", "don't ask", "without asking", "do not mention", "don't mention", "silently")):
        categories.add("prompt_injection")

    if not categories:
        categories.add("supply_chain")
    return sorted(categories)


def infer_severity(categories: list[str], content: str) -> str:
    lowered = content.lower()
    if "credential_theft" in categories or "data_exfiltration" in categories:
        return "critical"
    if "prompt_injection" in categories and _contains_any(lowered, ("do not ask", "do not mention", "silently")):
        return "critical"
    return "high"


def infer_difficulty(categories: list[str], content: str) -> str:
    lowered = content.lower()
    if "prompt_injection" in categories or _contains_any(lowered, ("webhook.site", "base64", "hook", ".mcp.json")):
        return "hard"
    return "medium"


def infer_family(content: str) -> str:
    lowered = content.lower()
    if _contains_any(lowered, ("do not ask", "do not mention", "without asking", "silently")):
        return "instruction-hijack"
    if "webhook.site" in lowered:
        return "direct-exfil"
    if _contains_any(lowered, ("openclawcli.vercel.app", "setup-service.com", "install.app-distribution.net")):
        return "redirect-download"
    if "glot.io/snippets" in lowered:
        return "paste-bootstrap"
    if _contains_any(lowered, ("openclaw-agent", "openclawcli", "openclaw-core", "authtool")):
        return "fake-prerequisite"
    if "base64" in lowered:
        return "inline-bootstrap"
    return "generic-bootstrap"


def choose_tiers(samples: list[dict[str, object]]) -> None:
    groups: dict[str, deque[dict[str, object]]] = defaultdict(deque)
    for sample in samples:
        groups[str(sample["family"])].append(sample)

    ordered: list[dict[str, object]] = []
    family_names = sorted(groups)
    while family_names:
        next_families: list[str] = []
        for family in family_names:
            queue = groups[family]
            if queue:
                ordered.append(queue.popleft())
            if queue:
                next_families.append(family)
        family_names = next_families

    for index, sample in enumerate(ordered):
        if index < 20:
            sample["tier"] = "smoke"
        elif index < 50:
            sample["tier"] = "standard"
        else:
            sample["tier"] = "full"


def load_malicious_samples(limit: int = 0) -> list[dict[str, object]]:
    with urlopen(DATASET_JSONL_URL) as response:
        payload = response.read().decode("utf-8")

    samples: list[dict[str, object]] = []
    for raw_line in payload.splitlines():
        if not raw_line.strip():
            continue
        record = json.loads(raw_line)
        if record.get("label") != "malicious":
            continue

        skill_name = str(record["skill_name"])
        content = str(record["content"])
        sample_id = str(record["id"])
        categories = infer_attack_categories(content)
        sample = {
            "dataset_id": sample_id,
            "skill_name": skill_name,
            "content": content,
            "slug": f"openclaw-{_slugify(skill_name)}-{sample_id[:6]}",
            "primary_name": _primary_name(skill_name),
            "family": infer_family(content),
            "attack_categories": categories,
            "severity": infer_severity(categories, content),
            "difficulty": infer_difficulty(categories, content),
        }
        samples.append(sample)

    samples.sort(key=lambda sample: (str(sample["family"]), str(sample["primary_name"]), str(sample["slug"])))
    if limit > 0:
        samples = samples[:limit]
    choose_tiers(samples)
    return samples


def build_manifest_entry(sample: dict[str, object]) -> dict[str, object]:
    attack_categories = list(sample["attack_categories"])
    family = str(sample["family"])
    notes = (
        "Real malicious ClawHub/OpenClaw skill preserved from "
        "yoonholee/agent-skill-malware, which states the content was extracted "
        "from the public openclaw/skills archive."
    )
    return {
        "id": sample["slug"],
        "path": f"skills/{sample['slug']}",
        "ground_truth": {
            "verdict": "MALICIOUS",
            "attack_categories": attack_categories,
            "severity": sample["severity"],
            "expected_rules": [],
            "min_category_coverage": attack_categories[:],
            "notes": notes,
        },
        "metadata": {
            "tier": sample["tier"],
            "difficulty": sample["difficulty"],
            "source_type": "github",
            "tags": ["malicious", "real-world", "openclaw", "clawhub", family],
        },
        "provenance": {
            "source_url": DATASET_CARD_URL,
            "source_ref": f"hf:{sample['dataset_id']}",
            "fetch_date": date.today().isoformat(),
            "license": "MIT",
            "upstream_status": "mirror",
            "upstream_path": sample.get("upstream_skill_dir"),
            "upstream_source_url": (
                f"https://github.com/openclaw/skills/tree/master/{sample['upstream_skill_dir']}"
                if sample.get("upstream_skill_dir")
                else None
            ),
        },
        "containment": {
            "sandboxed": True,
            "defanged_urls": False,
            "defanged_payloads": False,
            "original_threat": family,
            "containment_notes": (
                "SKILL.md preserved verbatim for benchmark scanning only; not executed. "
                "Dataset card states this sample was extracted from the public openclaw/skills archive."
            ),
        },
    }


def write_skill_snapshot(
    dataset_root: Path,
    sample: dict[str, object],
    *,
    upstream_repo: Path | None = None,
) -> None:
    dest = dataset_root / str(sample["slug"])
    dest.mkdir(parents=True, exist_ok=True)
    upstream_skill_dir = str(sample.get("upstream_skill_dir") or "")
    if upstream_repo is not None and upstream_skill_dir:
        tracked_paths = str(_git_capture(upstream_repo, "ls-tree", "-r", "--name-only", "HEAD", upstream_skill_dir)).splitlines()
        for tracked_path in tracked_paths:
            relative_path = Path(tracked_path).relative_to(upstream_skill_dir)
            payload = _git_capture(upstream_repo, "show", f"HEAD:{tracked_path}", text=False)
            target = dest / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload if isinstance(payload, bytes) else payload.encode("utf-8"))
    else:
        (dest / "SKILL.md").write_text(str(sample["content"]), encoding="utf-8")

    meta = {
        "source_type": "github",
        "provenance": {
            "source_url": DATASET_CARD_URL,
            "source_ref": f"hf:{sample['dataset_id']}",
            "fetch_date": date.today().isoformat(),
            "license": "MIT",
            "upstream_status": "mirror",
            "upstream_path": sample.get("upstream_skill_dir"),
            "upstream_source_url": (
                f"https://github.com/openclaw/skills/tree/master/{sample['upstream_skill_dir']}"
                if sample.get("upstream_skill_dir")
                else None
            ),
        },
        "containment": {
            "sandboxed": True,
            "defanged_urls": False,
            "defanged_payloads": False,
            "original_threat": str(sample["family"]),
            "containment_notes": (
                "Real malicious ClawHub/OpenClaw sample mirrored from yoonholee/agent-skill-malware. "
                "Dataset card states the sample was extracted from the public openclaw/skills archive."
            ),
        },
    }
    (dest / "_meta.yaml").write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")


def update_manifest(manifest_path: Path, malicious_entries: list[dict[str, object]]) -> None:
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    existing_entries = list(manifest["entries"])
    safe_entries = [entry for entry in existing_entries if entry["ground_truth"]["verdict"] != "MALICIOUS"]
    manifest["dataset_version"] = "4.0.0"
    manifest["entries"] = safe_entries + malicious_entries
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")


def main() -> None:
    args = parse_args()
    ensure_openclaw_repo(args.openclaw_repo)
    skill_index = build_upstream_skill_index(args.openclaw_repo)
    samples = load_malicious_samples(limit=args.limit)
    matched = 0
    for sample in samples:
        upstream_skill_dir = find_upstream_skill_dir(
            args.openclaw_repo,
            str(sample["skill_name"]),
            str(sample["content"]),
            skill_index=skill_index,
        )
        if upstream_skill_dir is not None:
            sample["upstream_skill_dir"] = upstream_skill_dir
            matched += 1
    malicious_entries = [build_manifest_entry(sample) for sample in samples]

    if args.dry_run:
        print(f"Would add {len(malicious_entries)} malicious OpenClaw entries")
        print(f"Smoke: {sum(1 for entry in malicious_entries if entry['metadata']['tier'] == 'smoke')}")
        print(f"Standard-only: {sum(1 for entry in malicious_entries if entry['metadata']['tier'] == 'standard')}")
        print(f"Full-only: {sum(1 for entry in malicious_entries if entry['metadata']['tier'] == 'full')}")
        print(f"Matched to upstream directories: {matched}")
        return

    args.dataset_root.mkdir(parents=True, exist_ok=True)
    for sample in samples:
        write_skill_snapshot(args.dataset_root, sample, upstream_repo=args.openclaw_repo)
    update_manifest(args.manifest, malicious_entries)

    print(f"Added {len(samples)} malicious OpenClaw samples ({matched} with full upstream directories)")


if __name__ == "__main__":
    main()
