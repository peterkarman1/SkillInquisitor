#!/usr/bin/env python3
"""Build a real-world benchmark slice from OpenClaw/ClawHub samples.

This script downloads the public `yoonholee/agent-skill-malware` dataset from
Hugging Face, preserves the labeled malicious and benign samples as benchmark
skill snapshots, and appends them to the benchmark manifest alongside the
current safe real-world corpus.

The malicious SKILL.md content is preserved verbatim. Benchmark scans only read
these files; they are never executed by this script.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
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
        shutil.rmtree(repo)

    repo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            OPENCLAW_REPO_URL,
            str(repo),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def build_upstream_skill_index(repo: Path) -> dict[str, list[str]]:
    index: dict[str, list[str]] = defaultdict(list)
    skills_root = repo / "skills"
    if not skills_root.exists():
        return {}

    for path in skills_root.rglob("*"):
        if not path.is_file():
            continue
        if path.name.lower() != "skill.md":
            continue
        index[path.parent.name.lower()].append(str(path.parent.relative_to(repo)))
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
        candidate_content = (repo / candidate / "SKILL.md").read_text(encoding="utf-8").replace("\r\n", "\n").strip()
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


def infer_label_metadata(label: str, content: str) -> tuple[list[str], str | None, str, str]:
    normalized_label = label.lower()
    if normalized_label == "benign":
        return [], None, "medium", "benign"

    categories = infer_attack_categories(content)
    return categories, infer_severity(categories, content), infer_difficulty(categories, content), infer_family(content)


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


def load_dataset_samples(limit: int = 0) -> list[dict[str, object]]:
    with urlopen(DATASET_JSONL_URL) as response:
        payload = response.read().decode("utf-8")

    samples: list[dict[str, object]] = []
    for raw_line in payload.splitlines():
        if not raw_line.strip():
            continue
        record = json.loads(raw_line)

        skill_name = str(record["skill_name"])
        content = str(record["content"])
        sample_id = str(record["id"])
        label = str(record["label"]).lower()
        categories, severity, difficulty, family = infer_label_metadata(label, content)
        sample = {
            "dataset_id": sample_id,
            "skill_name": skill_name,
            "content": content,
            "label": label,
            "slug": f"openclaw-{_slugify(skill_name)}-{sample_id[:6]}",
            "primary_name": _primary_name(skill_name),
            "family": family,
            "attack_categories": categories,
            "severity": severity,
            "difficulty": difficulty,
        }
        samples.append(sample)

    malicious_samples = [sample for sample in samples if sample["label"] == "malicious"]
    benign_samples = [sample for sample in samples if sample["label"] != "malicious"]

    malicious_samples.sort(key=lambda sample: (str(sample["family"]), str(sample["primary_name"]), str(sample["slug"])))
    benign_samples.sort(key=lambda sample: (str(sample["primary_name"]), str(sample["slug"])))
    if limit > 0:
        malicious_samples = malicious_samples[:limit]

    choose_tiers(malicious_samples)
    for sample in benign_samples:
        sample["tier"] = "full"

    return malicious_samples + benign_samples


def build_manifest_entry(sample: dict[str, object]) -> dict[str, object]:
    attack_categories = list(sample["attack_categories"])
    family = str(sample["family"])
    is_malicious = str(sample.get("label", "malicious")).lower() == "malicious"
    notes = (
        "Real malicious ClawHub/OpenClaw skill preserved from "
        "yoonholee/agent-skill-malware, which states the content was extracted "
        "from the public openclaw/skills archive."
        if is_malicious
        else "Real benign ClawHub/OpenClaw skill preserved from yoonholee/agent-skill-malware."
    )
    entry = {
        "id": sample["slug"],
        "path": f"skills/{sample['slug']}",
        "ground_truth": {
            "verdict": "MALICIOUS" if is_malicious else "SAFE",
            "attack_categories": attack_categories,
            "severity": sample["severity"],
            "expected_rules": [],
            "min_category_coverage": attack_categories[:],
            "notes": notes,
        },
        "metadata": {
            "tier": sample["tier"],
            "difficulty": sample["difficulty"],
            "source_type": "huggingface_mirror",
            "tags": [("malicious" if is_malicious else "safe"), "real-world", "openclaw", "clawhub", family],
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
    }
    if is_malicious:
        entry["containment"] = {
            "sandboxed": True,
            "defanged_urls": False,
            "defanged_payloads": False,
            "original_threat": family,
            "containment_notes": (
                "SKILL.md preserved verbatim for benchmark scanning only; not executed. "
                "Dataset card states this sample was extracted from the public openclaw/skills archive."
            ),
        }
    return entry


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
        source_root = upstream_repo / upstream_skill_dir
        for source_path in source_root.rglob("*"):
            if source_path.is_dir():
                continue
            relative_path = source_path.relative_to(source_root)
            target = dest / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target)
    else:
        (dest / "SKILL.md").write_text(str(sample["content"]), encoding="utf-8")

    meta = {
        "source_type": "huggingface_mirror",
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
    }
    if str(sample.get("label", "malicious")).lower() == "malicious":
        meta["containment"] = {
            "sandboxed": True,
            "defanged_urls": False,
            "defanged_payloads": False,
            "original_threat": str(sample["family"]),
            "containment_notes": (
                "Real malicious ClawHub/OpenClaw sample mirrored from yoonholee/agent-skill-malware. "
                "Dataset card states the sample was extracted from the public openclaw/skills archive."
            ),
        }
    (dest / "_meta.yaml").write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")


def update_manifest(manifest_path: Path, mirror_entries: list[dict[str, object]]) -> None:
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    existing_entries = list(manifest["entries"])
    preserved_entries = []
    for entry in existing_entries:
        provenance = entry.get("provenance") or {}
        if provenance.get("source_url") == DATASET_CARD_URL:
            continue
        preserved_entries.append(entry)

    manifest["dataset_version"] = "4.1.0"
    manifest["entries"] = preserved_entries + mirror_entries
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")


def main() -> None:
    args = parse_args()
    ensure_openclaw_repo(args.openclaw_repo)
    skill_index = build_upstream_skill_index(args.openclaw_repo)
    samples = load_dataset_samples(limit=args.limit)
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
    mirror_entries = [build_manifest_entry(sample) for sample in samples]
    malicious_count = sum(1 for sample in samples if sample["label"] == "malicious")
    benign_count = sum(1 for sample in samples if sample["label"] != "malicious")

    if args.dry_run:
        print(f"Would add {len(mirror_entries)} OpenClaw mirror entries")
        print(f"Malicious: {malicious_count}")
        print(f"Benign: {benign_count}")
        print(f"Smoke: {sum(1 for entry in mirror_entries if entry['metadata']['tier'] == 'smoke')}")
        print(f"Standard-only: {sum(1 for entry in mirror_entries if entry['metadata']['tier'] == 'standard')}")
        print(f"Full-only: {sum(1 for entry in mirror_entries if entry['metadata']['tier'] == 'full')}")
        print(f"Matched to upstream directories: {matched}")
        return

    args.dataset_root.mkdir(parents=True, exist_ok=True)
    for sample in samples:
        write_skill_snapshot(args.dataset_root, sample, upstream_repo=args.openclaw_repo)
    update_manifest(args.manifest, mirror_entries)

    print(
        f"Added {len(samples)} OpenClaw mirror samples "
        f"({malicious_count} malicious, {benign_count} benign, {matched} with full upstream directories)"
    )


if __name__ == "__main__":
    main()
