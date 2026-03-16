#!/usr/bin/env python3
"""Copy test fixtures to benchmark dataset and generate manifest entries."""

import os
import shutil
import re
from pathlib import Path

try:
    import yaml
except ImportError:
    # Fallback: we'll generate YAML manually
    yaml = None

PROJECT_ROOT = Path("/Users/peterkarman/git/SkillInquisitor")
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"
BENCHMARK_DIR = PROJECT_ROOT / "benchmark" / "dataset" / "from-fixtures"
MANIFEST_PATH = PROJECT_ROOT / "benchmark" / "manifest.yaml"

# Severity ranking for determining highest
SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def parse_yaml_simple(path):
    """Parse YAML file using PyYAML if available, else basic parsing."""
    if yaml:
        with open(path) as f:
            return yaml.safe_load(f)
    # Basic fallback - not needed if yaml is available
    raise ImportError("PyYAML required")


def get_fixture_dirs():
    """Find all fixture directories with SKILL.md, excluding templates/local/config."""
    result = []
    for skill_md in sorted(FIXTURES_DIR.rglob("SKILL.md")):
        rel = skill_md.relative_to(FIXTURES_DIR)
        parts = rel.parts
        # Skip templates, local, config
        if any(p in ("templates", "local", "config") for p in parts):
            continue
        fixture_dir = skill_md.parent
        # Skip nested SKILL.md (inside another fixture that also has SKILL.md)
        parent = fixture_dir.parent
        is_nested = False
        while parent != FIXTURES_DIR and parent != FIXTURES_DIR.parent:
            if (parent / "SKILL.md").exists():
                is_nested = True
                break
            parent = parent.parent
        if is_nested:
            continue
        result.append(fixture_dir)
    return result


def make_slug(fixture_dir):
    """Convert fixture path to a slug ID."""
    name = fixture_dir.name  # e.g., D-1A-unicode-tags
    slug = name.lower()
    slug = re.sub(r'-+', '-', slug).strip('-')
    return slug


def get_category_tag(fixture_dir):
    """Get category tag from fixture path."""
    rel = fixture_dir.relative_to(FIXTURES_DIR)
    parts = rel.parts
    if parts[0] == "deterministic" and len(parts) >= 2:
        return parts[1]
    return parts[0]


def parse_expected_yaml(fixture_dir):
    """Parse expected.yaml to extract ground truth."""
    expected_path = fixture_dir / "expected.yaml"
    if not expected_path.exists():
        return None

    data = parse_yaml_simple(expected_path)
    findings = data.get("findings", []) or []

    if not findings:
        return {
            "verdict": "SAFE",
            "attack_categories": [],
            "severity": None,
            "expected_rules": [],
        }

    categories = set()
    rule_ids = set()
    max_severity = "info"

    for finding in findings:
        cat = finding.get("category", "")
        if cat:
            categories.add(cat)
        rule_id = finding.get("rule_id", "")
        if rule_id:
            rule_ids.add(rule_id)
        sev = finding.get("severity", "info")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity, 0):
            max_severity = sev

    return {
        "verdict": "MALICIOUS",
        "attack_categories": sorted(categories),
        "severity": max_severity,
        "expected_rules": sorted(rule_ids),
    }


def write_meta_yaml(dest_dir, rel_fixture_path):
    """Write _meta.yaml file."""
    content = (
        f'source_type: fixture\n'
        f'source_fixture_path: "tests/fixtures/{rel_fixture_path}"\n'
        f'notes: "Copied from test fixture"\n'
    )
    with open(dest_dir / "_meta.yaml", "w") as f:
        f.write(content)


def main():
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

    fixture_dirs = get_fixture_dirs()
    print(f"Found {len(fixture_dirs)} fixture directories")

    entries = []
    counter = 0

    for fixture_dir in fixture_dirs:
        slug = make_slug(fixture_dir)
        fixture_id = f"fixture-{slug}"
        rel_fixture_path = fixture_dir.relative_to(FIXTURES_DIR)
        category_tag = get_category_tag(fixture_dir)

        ground_truth = parse_expected_yaml(fixture_dir)
        if ground_truth is None:
            print(f"  SKIP (no expected.yaml): {rel_fixture_path}")
            continue

        # Copy fixture directory
        dest_dir = BENCHMARK_DIR / slug
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        shutil.copytree(fixture_dir, dest_dir)

        # Remove expected.yaml from the copy
        copied_expected = dest_dir / "expected.yaml"
        if copied_expected.exists():
            copied_expected.unlink()

        # Create _meta.yaml
        write_meta_yaml(dest_dir, rel_fixture_path)

        counter += 1
        tier = "smoke" if counter <= 10 else "standard"

        # Build tags
        tags = [category_tag]
        if ground_truth["verdict"] == "SAFE":
            tags.append("safe")
        if "injection" in slug:
            tags.append("injection")
        if "unicode" in slug or "rtlo" in slug or "zero-width" in slug:
            tags.append("unicode")
        if "base64" in slug:
            tags.append("encoding")
        if "exfil" in slug or "send" in slug:
            tags.append("exfiltration")
        tags = sorted(set(tags))

        entries.append({
            "id": fixture_id,
            "slug": slug,
            "ground_truth": ground_truth,
            "tier": tier,
            "tags": tags,
        })
        print(f"  OK: {fixture_id} (verdict={ground_truth['verdict']})")

    print(f"\nTotal entries to append: {len(entries)}")

    # Generate YAML text
    lines = []
    lines.append("")
    lines.append("  # ===========================================================================")
    lines.append(f"  # FIXTURE-SOURCED ENTRIES ({len(entries)})")
    lines.append("  # ===========================================================================")

    for entry in entries:
        gt = entry["ground_truth"]
        lines.append("")
        lines.append(f"  - id: {entry['id']}")
        lines.append(f"    path: from-fixtures/{entry['slug']}")
        lines.append("    ground_truth:")
        lines.append(f"      verdict: {gt['verdict']}")

        if gt["attack_categories"]:
            lines.append("      attack_categories:")
            for cat in gt["attack_categories"]:
                lines.append(f"        - {cat}")
        else:
            lines.append("      attack_categories: []")

        if gt["severity"] is None:
            lines.append("      severity: null")
        else:
            lines.append(f"      severity: {gt['severity']}")

        if gt["expected_rules"]:
            lines.append("      expected_rules:")
            for rule in gt["expected_rules"]:
                lines.append(f"        - {rule}")
        else:
            lines.append("      expected_rules: []")

        lines.append("      min_category_coverage: []")
        lines.append('      notes: ""')
        lines.append("    metadata:")
        lines.append(f"      tier: {entry['tier']}")
        lines.append("      difficulty: easy")
        lines.append("      source_type: fixture")
        lines.append("      tags:")
        for tag in entry["tags"]:
            lines.append(f"        - {tag}")

    yaml_text = "\n".join(lines) + "\n"

    with open(MANIFEST_PATH, "a") as f:
        f.write(yaml_text)

    print(f"\nAppended {len(entries)} entries to {MANIFEST_PATH}")
    print(f"Copied {len(entries)} fixture directories to {BENCHMARK_DIR}")


if __name__ == "__main__":
    main()
