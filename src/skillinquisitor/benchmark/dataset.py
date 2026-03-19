from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ValidationError


class FalsePositiveRisk(BaseModel):
    category: str
    reason: str


class GroundTruth(BaseModel):
    verdict: Literal["MALICIOUS", "SAFE", "AMBIGUOUS"]
    attack_categories: list[str] = []
    severity: str | None = None
    expected_rules: list[str] = []
    min_category_coverage: list[str] = []
    false_positive_risk: list[FalsePositiveRisk] = []
    notes: str = ""


class Provenance(BaseModel):
    source_url: str = ""
    source_ref: str = ""
    fetch_date: str = ""
    license: str = ""
    upstream_status: str = "unknown"


class Containment(BaseModel):
    sandboxed: bool = True
    defanged_urls: bool = True
    defanged_payloads: bool = True
    original_threat: str = ""
    containment_notes: str = ""


class EntryMetadata(BaseModel):
    tier: Literal["smoke", "standard", "full"] = "standard"
    difficulty: Literal["easy", "medium", "hard"] = "medium"
    source_type: Literal["github", "malicious_bench", "synthetic", "fixture"] = "synthetic"
    tags: list[str] = []


class ManifestEntry(BaseModel):
    id: str
    path: str
    ground_truth: GroundTruth
    metadata: EntryMetadata = EntryMetadata()
    provenance: Provenance | None = None
    containment: Containment | None = None


class DecisionPolicy(BaseModel):
    default_threshold: float = 60.0


class BenchmarkManifest(BaseModel):
    schema_version: int = 1
    dataset_version: str = "1.0.0"
    decision_policy: DecisionPolicy = DecisionPolicy()
    entries: list[ManifestEntry]


def load_manifest(path: Path) -> BenchmarkManifest:
    """Load and validate a benchmark manifest from a YAML file."""
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        msg = f"Expected a YAML mapping at top level in {path}, got {type(data).__name__}"
        raise ValueError(msg)
    try:
        return BenchmarkManifest(**data)
    except ValidationError as exc:
        msg = f"Invalid benchmark manifest in {path}: {exc}"
        raise ValueError(msg) from exc


def filter_entries(
    manifest: BenchmarkManifest,
    tier: str = "standard",
    tags: list[str] | None = None,
    source_types: set[str] | None = None,
) -> list[ManifestEntry]:
    """Filter manifest entries by tier and optional tags.

    Tier filtering is inclusive: smoke includes only smoke,
    standard includes smoke+standard, full includes all.
    Tag filtering requires ALL specified tags to be present.
    """
    tier_hierarchy: dict[str, set[str]] = {
        "smoke": {"smoke"},
        "standard": {"smoke", "standard"},
        "full": {"smoke", "standard", "full"},
    }
    allowed_tiers = tier_hierarchy.get(tier, {"smoke", "standard", "full"})

    results: list[ManifestEntry] = []
    for entry in manifest.entries:
        if entry.metadata.tier not in allowed_tiers:
            continue
        if source_types is not None and entry.metadata.source_type not in source_types:
            continue
        if tags:
            if not all(tag in entry.metadata.tags for tag in tags):
                continue
        results.append(entry)
    return results


def resolve_skill_path(entry: ManifestEntry, dataset_root: Path) -> Path:
    """Resolve a manifest entry's path relative to the dataset root.

    Raises FileNotFoundError if the resolved path doesn't exist.
    """
    resolved = dataset_root / entry.path
    if not resolved.exists():
        msg = f"Skill path does not exist: {resolved}"
        raise FileNotFoundError(msg)
    return resolved
