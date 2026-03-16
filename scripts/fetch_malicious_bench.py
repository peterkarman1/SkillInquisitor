#!/usr/bin/env python3
"""Fetch malicious skills from MaliciousAgentSkillsBench for the benchmark dataset.

Downloads the dataset CSV from HuggingFace, then fetches individual malicious
skills via their URLs. Defangs all content before saving.

Usage:
    python scripts/fetch_malicious_bench.py [--dry-run] [--limit N]
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path
from urllib.request import urlopen

DATASET_URL = "https://huggingface.co/datasets/ProtectSkills/MaliciousAgentSkillsBench/resolve/main/data/malicious_skills.csv"

OUTPUT_DIR = Path("benchmark/dataset/real-world/malicious")

# Map MaliciousAgentSkillsBench Pattern values to our Category enum
TAXONOMY_MAP: dict[str, list[str]] = {
    "Remote Code Execution": ["behavioral"],
    "External Transmission": ["data_exfiltration"],
    "Network sniffing / Credential theft": ["credential_theft"],
    "Behavior Manipulation": ["prompt_injection"],
    "Context Leakage": ["data_exfiltration", "prompt_injection"],
    "Hidden Instructions": ["prompt_injection", "steganography"],
    "Instruction Override": ["prompt_injection"],
    "Code Obfuscation": ["obfuscation"],
    "File System Scan": ["credential_theft"],
    "Privilege Escalation": ["persistence"],
    "Hardcoded Tokens": ["credential_theft"],
    "Excessive Permissions": ["structural"],
    "Data Exfiltration": ["data_exfiltration"],
    "Unpinned Dependencies": ["supply_chain"],
}

# Patterns for defanging
DEFANG_URL_PATTERN = re.compile(
    r"https?://(?!(?:localhost|127\.0\.0\.1|example\.com|httpbin\.org|evil\.example\.com))[^\s\"'>)}\]]+",
)
DEFANG_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b",
)


def defang_content(text: str) -> str:
    """Replace live URLs and IPs with defanged versions."""
    result = DEFANG_URL_PATTERN.sub("https://evil.example.com/DEFANGED", text)
    # Don't defang common safe IPs
    safe_ips = {"127.0.0.1", "0.0.0.0", "169.254.169.254", "localhost"}
    for match in DEFANG_IP_PATTERN.finditer(result):
        ip_str = match.group().split(":")[0]
        if ip_str not in safe_ips:
            result = result.replace(match.group(), "192.0.2.1")  # RFC 5737 TEST-NET
    return result


def map_patterns(pattern_str: str) -> list[str]:
    """Map semicolon-separated Pattern string to our category taxonomy."""
    if not pattern_str:
        return []
    categories: set[str] = set()
    for pattern in pattern_str.split(";"):
        pattern = pattern.strip()
        mapped = TAXONOMY_MAP.get(pattern, [])
        categories.update(mapped)
    return sorted(categories)


def severity_from_patterns(pattern_str: str) -> str:
    """Estimate severity from the number and type of patterns."""
    if not pattern_str:
        return "medium"
    patterns = [p.strip() for p in pattern_str.split(";")]
    high_severity = {"Remote Code Execution", "Privilege Escalation", "Data Exfiltration", "Credential theft"}
    if any(p in high_severity or "Credential" in p for p in patterns):
        return "critical" if len(patterns) >= 3 else "high"
    return "high" if len(patterns) >= 2 else "medium"


def slug_from_entry(source: str, repo: str, skill_name: str) -> str:
    """Generate a filesystem-safe slug from dataset fields."""
    raw = f"{repo}-{skill_name}".lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    # Ensure uniqueness with a short hash
    h = hashlib.md5(f"{source}:{repo}:{skill_name}".encode()).hexdigest()[:6]
    return f"masb-{slug[:50]}-{h}"


def fetch_skill_from_url(url: str, dest: Path) -> bool:
    """Attempt to clone a skill from its URL. Returns True on success."""
    try:
        # Most URLs are GitHub repo URLs — try shallow clone
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", url, tmpdir],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False

            # Find SKILL.md in the cloned repo
            tmp = Path(tmpdir)
            skill_files = list(tmp.rglob("SKILL.md"))
            if not skill_files:
                # No SKILL.md — copy all non-git files
                dest.mkdir(parents=True, exist_ok=True)
                for item in tmp.iterdir():
                    if item.name == ".git":
                        continue
                    if item.is_dir():
                        shutil.copytree(item, dest / item.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, dest / item.name)
            else:
                # Copy the skill directory
                skill_dir = skill_files[0].parent
                if skill_dir == tmp:
                    dest.mkdir(parents=True, exist_ok=True)
                    for item in tmp.iterdir():
                        if item.name == ".git":
                            continue
                        if item.is_dir():
                            shutil.copytree(item, dest / item.name, dirs_exist_ok=True)
                        else:
                            shutil.copy2(item, dest / item.name)
                else:
                    shutil.copytree(skill_dir, dest, dirs_exist_ok=True)

            # Defang all text files
            for fpath in dest.rglob("*"):
                if fpath.is_file() and fpath.suffix in (".md", ".py", ".sh", ".js", ".ts", ".yaml", ".yml", ".txt", ".json", ".go", ".rb", ".rs"):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="replace")
                        defanged = defang_content(content)
                        if defanged != content:
                            fpath.write_text(defanged, encoding="utf-8")
                    except Exception:
                        pass

            return True
    except Exception:
        return False


def write_meta(dest: Path, entry: dict, fetched: bool) -> None:
    """Write _meta.yaml for a malicious skill."""
    categories = map_patterns(entry.get("Pattern", ""))
    meta = f"""source_type: malicious_bench
provenance:
  source_url: "{entry.get('url', '')}"
  source_ref: "masb-snapshot"
  fetch_date: "{date.today().isoformat()}"
  license: "MIT"
  upstream_status: {"active" if fetched else "unknown"}
containment:
  sandboxed: true
  defanged_urls: true
  defanged_payloads: true
  original_threat: "{entry.get('Pattern', 'unknown').replace('"', "'")}"
  containment_notes: "Fetched from MaliciousAgentSkillsBench. All URLs defanged. Content may be partial if original was taken down."
"""
    (dest / "_meta.yaml").write_text(meta, encoding="utf-8")


def generate_manifest_entry(slug: str, entry: dict) -> str:
    """Generate a YAML manifest entry for a fetched skill."""
    categories = map_patterns(entry.get("Pattern", ""))
    severity = severity_from_patterns(entry.get("Pattern", ""))
    cats_yaml = "\n".join(f"        - {c}" for c in categories) if categories else ""
    cats_section = f"\n      attack_categories:\n{cats_yaml}" if categories else "\n      attack_categories: []"

    return f"""  - id: "{slug}"
    path: "real-world/malicious/{slug}"
    ground_truth:
      verdict: MALICIOUS{cats_section}
      severity: {severity}
      expected_rules: []
      min_category_coverage: []
      notes: "From MaliciousAgentSkillsBench. Patterns: {entry.get('Pattern', 'unknown')}"
    metadata:
      tier: standard
      difficulty: medium
      source_type: malicious_bench
      tags: [masb, real-world]
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch malicious skills from MaliciousAgentSkillsBench")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be fetched")
    parser.add_argument("--limit", type=int, default=0, help="Only fetch first N skills")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()

    # Download the CSV
    print(f"Downloading dataset from {DATASET_URL}...")
    try:
        response = urlopen(DATASET_URL)
        csv_data = response.read().decode("utf-8")
    except Exception as exc:
        print(f"Failed to download dataset: {exc}", file=sys.stderr)
        sys.exit(1)

    reader = csv.DictReader(io.StringIO(csv_data))
    entries = list(reader)
    print(f"Found {len(entries)} malicious skills in dataset")

    if args.limit > 0:
        entries = entries[: args.limit]
        print(f"Limiting to first {args.limit} skills")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest_entries: list[str] = []
    fetched_count = 0
    failed_count = 0

    for i, entry in enumerate(entries, 1):
        slug = slug_from_entry(entry.get("source", ""), entry.get("repo", ""), entry.get("skill_name", ""))
        url = entry.get("url", "")
        dest = args.output_dir / slug

        if args.dry_run:
            print(f"[{i}/{len(entries)}] Would fetch: {slug} from {url}")
            manifest_entries.append(generate_manifest_entry(slug, entry))
            continue

        if dest.exists():
            print(f"[{i}/{len(entries)}] {slug}... SKIP (exists)")
            manifest_entries.append(generate_manifest_entry(slug, entry))
            fetched_count += 1
            continue

        print(f"[{i}/{len(entries)}] {slug}...", end=" ", flush=True)

        if url and fetch_skill_from_url(url, dest):
            write_meta(dest, entry, fetched=True)
            manifest_entries.append(generate_manifest_entry(slug, entry))
            print("OK")
            fetched_count += 1
        else:
            # Create a stub with just _meta.yaml and a placeholder SKILL.md
            dest.mkdir(parents=True, exist_ok=True)
            placeholder = f"""---
name: {slug}
description: "Placeholder for unavailable malicious skill"
---

# {entry.get('skill_name', 'Unknown')}

This skill was identified as malicious in the MaliciousAgentSkillsBench dataset
but could not be fetched (original may have been taken down).

Original patterns: {entry.get('Pattern', 'unknown')}
Original source: {entry.get('source', 'unknown')}
"""
            (dest / "SKILL.md").write_text(placeholder, encoding="utf-8")
            write_meta(dest, entry, fetched=False)
            manifest_entries.append(generate_manifest_entry(slug, entry))
            print("STUB (fetch failed)")
            failed_count += 1

    print(f"\nDone: {fetched_count} fetched, {failed_count} stubs, {len(entries)} total")
    print(f"Skills saved to: {args.output_dir}")

    # Print manifest entries
    if manifest_entries:
        manifest_path = args.output_dir.parent.parent / "masb_manifest_entries.yaml"
        manifest_path.write_text(
            "  # MaliciousAgentSkillsBench entries\n" + "\n".join(manifest_entries),
            encoding="utf-8",
        )
        print(f"Manifest entries written to: {manifest_path}")
        print("Append these to benchmark/manifest.yaml manually.")


if __name__ == "__main__":
    main()
