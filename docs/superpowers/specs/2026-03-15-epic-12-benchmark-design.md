# Epic 12 Part 1 — Benchmark Framework Design Spec

## Scope

**Part 1 (this spec):** Self-benchmarking — dataset, runner, metrics, reports. Test SkillInquisitor against labeled skills, measure detection quality, track regressions.

**Part 2 (future):** Comparative benchmarking — frontier model baselines (Claude/GPT-4o/Gemini), external tool comparison (Cisco skill-scanner, SkillSentry), cost analysis.

---

## 1. Architecture

### 1.1 Module Location

All benchmark code lives under `src/skillinquisitor/benchmark/`, matching the project's existing package structure:

```
src/skillinquisitor/benchmark/
├── __init__.py           # Exports runner, public types
├── runner.py             # Orchestrates benchmark runs
├── metrics.py            # Confusion matrix, precision/recall/F1, per-category
├── dataset.py            # Loads manifest, resolves skill paths, filters by tier
└── report.py             # Generates Markdown benchmark report
```

### 1.2 Dataset Location

Stored in-repo for reproducibility. ~15-20MB total (500 skills × ~20KB avg).

```
benchmark/
├── manifest.yaml         # Single source of truth: every entry with ground truth + metadata
├── dataset/
│   ├── real-world/
│   │   ├── safe/         # Snapshots from Trail of Bits, Anthropic, Cloudflare, etc.
│   │   │   └── tob-semgrep-rule-creator/
│   │   │       ├── SKILL.md
│   │   │       ├── references/
│   │   │       └── _meta.yaml    # Provenance, license, source URL, fetch date
│   │   └── malicious/    # Snapshots from MaliciousAgentSkillsBench
│   │       └── masb-outlook-hijacker/
│   │           ├── SKILL.md
│   │           ├── scripts/
│   │           └── _meta.yaml    # Provenance, containment notes
│   ├── synthetic/
│   │   ├── malicious/    # Crafted attack skills covering all 23 rule families
│   │   ├── safe/         # Clean counterparts for false-positive testing
│   │   └── ambiguous/    # Deliberately gray-area skills
│   └── from-fixtures/    # Copied snapshots of existing tests/fixtures/ skills
│       └── d19-read-send-chain/
│           ├── SKILL.md
│           ├── scripts/
│           └── _meta.yaml
├── baselines/            # Blessed result sets for regression detection
│   └── v1.json
└── results/              # gitignored — output of benchmark runs
```

**No symlinks.** Fixtures referenced in the benchmark are copied as snapshots into `benchmark/dataset/from-fixtures/`. This avoids Windows compatibility issues and packaging brittleness. A CI check validates that fixture snapshots remain consistent with their source fixtures.

### 1.3 CLI Interface

Wired into the existing `benchmark_app` Typer group:

```
skillinquisitor benchmark run [OPTIONS]
  --tier TIER           smoke | standard | full (default: standard)
  --layer LAYER         deterministic | ml | llm (repeatable, default: all enabled)
  --concurrency N       Max parallel skills (default: auto)
  --output DIR          Results directory (default: benchmark/results/<run-id>)
  --timeout SECONDS     Per-skill timeout (default: 60)
  --baseline PATH       Baseline results for regression comparison
  --threshold FLOAT     Binary decision threshold on risk_score (default: 60.0)
  --dataset PATH        Path to manifest.yaml (default: benchmark/manifest.yaml)

skillinquisitor benchmark compare RUN_A RUN_B [OPTIONS]
  --format FORMAT       table | json | markdown (default: table)
  --show-regressions    Only show skills where RUN_B is worse
```

---

## 2. Manifest Schema

### 2.1 Top-Level Structure

```yaml
schema_version: 1
dataset_version: "1.0.0"    # semver: major=label changes, minor=new entries, patch=metadata fixes

# Configurable policy for binary classification
decision_policy:
  # Risk scores at or above this threshold are classified as "detected" (positive)
  # Multiple thresholds can be evaluated in a single run for ROC analysis
  default_threshold: 60.0
  # Verdict mapping: which scanner verdicts count as "detected"?
  # This is derived from the threshold, but documented for clarity:
  # score >= 60 → SAFE/LOW RISK (negative); score < 60 → MEDIUM/HIGH/CRITICAL (positive)

entries:
  - id: "tob-semgrep-rule-creator"
    # ... entry fields below
```

### 2.2 Entry Schema

```yaml
- id: "tob-semgrep-rule-creator"         # Human-readable slug, unique across manifest
  path: "real-world/safe/tob-semgrep-rule-creator"  # Relative to benchmark/dataset/

  ground_truth:
    verdict: SAFE                          # MALICIOUS | SAFE | AMBIGUOUS
    attack_categories: []                  # List of Category enum values
    severity: null                         # null for SAFE, Severity enum for MALICIOUS
    expected_rules: []                     # Optional: specific rule_ids that MUST fire
    min_category_coverage: []              # Optional: categories that MUST appear in findings
    false_positive_risk:                   # Optional: what a scanner might wrongly flag
      - category: credential_theft
        reason: "References secret scanning patterns in docs"
    notes: "Security-focused skill with attack-adjacent language"

  metadata:
    tier: standard                         # smoke | standard | full
    difficulty: medium                     # easy | medium | hard
    source_type: github                    # github | malicious_bench | synthetic | fixture
    tags: ["security-adjacent", "false-positive-stress", "markdown-only"]

  provenance:                              # Required for real-world skills
    source_url: "https://github.com/trailofbits/skills/tree/main/plugins/semgrep-rule-creator"
    source_ref: "abc123def456"             # Pinned commit SHA
    fetch_date: "2026-03-15"
    license: "Apache-2.0"
    upstream_status: active                # active | archived | deleted | unknown

  containment:                             # Required for malicious skills
    sandboxed: true                        # Content is inert (no live C2, defanged URLs)
    defanged_urls: true                    # URLs replaced with [DEFANGED] or example.com
    defanged_payloads: true                # Actual malware payloads removed/stubbed
    original_threat: "AMOS credential stealer via fake prerequisites"
    containment_notes: "All curl targets replaced with httpbin.org/post"
```

### 2.3 Key Design Decisions

**Three verdicts, not five.** MALICIOUS/SAFE/AMBIGUOUS. The scanner's five-level verdict is compared via a configurable threshold, not exact match.

**Configurable decision threshold.** The `default_threshold` (risk score below which the scanner's output is treated as "detected malicious") is a policy choice. Default 60.0 means MEDIUM RISK and above = positive. Users can compare at multiple operating points (e.g., threshold=40 for aggressive, threshold=80 for conservative).

**`expected_rules` is optional, always minimum coverage.** When present, the benchmark checks that at least these rules fired — not exact equality. Additional findings beyond the expected set are not penalized. This prevents brittleness as rules evolve.

**`min_category_coverage` is distinct from `expected_rules`.** It checks that findings exist in the specified categories, without requiring specific rule IDs. Useful for real-world malicious skills where you know "this is credential theft" but don't want to assert which specific D-7/D-8 variant fires.

**Provenance is required for real-world skills.** License, source URL, pinned ref, fetch date. This matters for redistribution and reproducibility.

**Containment is required for malicious skills.** All malicious samples in the dataset must be defanged — no live C2 URLs, no actual malware binaries, no functional exploit payloads. The containment metadata documents what was neutralized and how.

---

## 3. Runner Design

### 3.1 Pipeline Integration

The runner reuses `run_pipeline()` from `pipeline.py` but must handle the model lifecycle carefully.

**Current pipeline behavior:** Each call to `run_pipeline()` creates detector objects, loads ML models, runs inference, and unloads. This is correct for single scans but wasteful for 500+ sequential scans.

**Benchmark session refactor:** The runner introduces a `BenchmarkSession` that:
1. Creates a `ScanConfig` once based on CLI options
2. Pre-loads ML ensemble models (if ML layer enabled) and holds them for the session
3. Pre-loads LLM model (if LLM layer enabled) and holds it for the session
4. Runs each skill through the pipeline with the pre-loaded models
5. Unloads all models at session teardown

This requires a small refactor: the ML ensemble and LLM judge need a "use existing loaded model" mode in addition to their current "load, run, unload" cycle. The cleanest approach is to make the loaded model state injectable — the benchmark session creates the model objects once and passes them to each pipeline run. The pipeline's existing load/unload paths remain untouched for normal CLI scans.

**Concurrency:** Async semaphore-bounded worker pool. Auto-selected concurrency: deterministic=50, ML=6, LLM=3. The semaphore prevents overwhelming GPU memory or API rate limits.

### 3.2 Per-Skill Execution

For each skill in the filtered manifest:

1. Resolve skill path from manifest entry → absolute filesystem path
2. Call `resolve_input(path)` to build `Skill` objects
3. Call `run_pipeline(skills, config)` (with shared model context)
4. Capture `ScanResult` and wall-clock timing per layer
5. Compare result against ground truth from manifest
6. Write findings-focused result line to JSONL (no raw artifact content)
7. On error: capture exception, record as errored, continue

**Error isolation is critical.** A single skill failure must never abort the run. The error is recorded and the report includes an "Errors" section.

### 3.3 Progress Reporting

Emit to stderr (stdout reserved for structured output):
```
[142/537] tob-semgrep-rule-creator... OK (0.3s)
[143/537] masb-outlook-hijacker... OK (2.1s, 4 findings)
[144/537] broken-skill... ERROR: ValueError (0.0s)
```

Suppress with `--quiet`.

---

## 4. Ground Truth Comparison

### 4.1 Binary Classification

The primary metric level. Every entry with verdict MALICIOUS or SAFE participates. AMBIGUOUS entries are excluded and reported separately.

**Decision function:** Given scanner risk_score and configurable threshold T:
- `risk_score < T` → scanner says "detected" (positive)
- `risk_score >= T` → scanner says "safe" (negative)

Note: lower risk_score = more risk in SkillInquisitor's model (score starts at 100, deductions for findings). So a score of 20 means HIGH RISK.

**Confusion matrix cells:**

| | Ground Truth: MALICIOUS | Ground Truth: SAFE |
|---|---|---|
| Scanner: Detected (score < T) | True Positive | False Positive |
| Scanner: Safe (score >= T) | False Negative | True Negative |

### 4.2 Category-Level Comparison

For MALICIOUS entries with `attack_categories` or `min_category_coverage`:

- **Category hit:** At least one finding in the skill has a matching category. This is minimum coverage, not exact match.
- **Category miss:** Ground truth lists a category but no finding matches it.
- **Extra categories:** Scanner finds categories not listed in ground truth. Not penalized (the scanner may correctly detect additional issues).

Per-category recall = (skills where category was hit) / (skills where category is in ground truth).

### 4.3 Rule-Level Comparison

For entries with `expected_rules`:

- **Rule hit:** The rule_id appears in at least one finding for the skill.
- **Rule miss:** Expected rule_id was not found.
- Same minimum-coverage semantics — additional rules firing is not a failure.

### 4.4 AMBIGUOUS Handling

AMBIGUOUS skills are excluded from precision/recall/F1 computation. They are reported as a distribution: "Of N ambiguous skills, scanner produced: X SAFE, Y LOW RISK, Z MEDIUM RISK, ..." This informs threshold tuning without distorting accuracy metrics.

---

## 5. Metrics Engine

### 5.1 Implementation: Hand-Rolled

No sklearn dependency. The math is straightforward, and minimizing the dependency surface matters for a security tool. A `ConfusionMatrix` dataclass with derived properties for precision, recall, F1, FPR, FNR.

### 5.2 Metric Groups

**Group A — Detection Effectiveness:**
- Binary precision, recall, F1
- Per-category recall (one number per attack category)
- False positive rate on known-safe skills
- False negative count at CRITICAL/HIGH severity (the dangerous misses)

**Group B — Severity Accuracy:**
- Mean absolute severity error (ordinal distance on 0-4 scale)
- Under-severity rate (scanner rates lower than ground truth — the dangerous direction)
- Over-severity rate

**Group C — Finding Coverage:**
- Category coverage rate: for entries with `min_category_coverage`, what % of expected categories had at least one finding?
- Rule coverage rate: for entries with `expected_rules`, what % of expected rules fired?

**Group D — Performance:**
- Latency percentiles per layer: p50, p95, p99
- Total wall-clock time
- Throughput: skills/second
- Error rate (skills that failed to scan)

---

## 6. Results Storage

### 6.1 Findings-Focused JSONL

One line per skill. **No raw artifact content** — the scanner already treats content as sensitive and excludes it from JSON output. Store only findings and metadata.

```json
{
  "skill_id": "masb-outlook-hijacker",
  "ground_truth": {"verdict": "MALICIOUS", "attack_categories": ["prompt_injection", "credential_theft"], "severity": "critical"},
  "scan_result": {
    "risk_score": 15,
    "verdict": "HIGH RISK",
    "finding_count": 7,
    "findings": [
      {"rule_id": "D-11A", "category": "prompt_injection", "severity": "high", "confidence": 0.95, "message": "..."},
      {"rule_id": "D-7A", "category": "credential_theft", "severity": "high", "confidence": 1.0, "message": "..."}
    ]
  },
  "timing": {"deterministic_ms": 12, "ml_ms": 340, "llm_ms": 0, "total_ms": 352},
  "comparison": {"binary": "TP", "category_hits": ["prompt_injection", "credential_theft"], "category_misses": [], "rule_hits": ["D-11A", "D-7A"], "rule_misses": []},
  "error": null
}
```

### 6.2 Summary JSON

```json
{
  "run_id": "20260315-143022-9a51a78",
  "git_sha": "9a51a78",
  "dirty": false,
  "timestamp": "2026-03-15T14:30:22Z",
  "dataset_version": "1.0.0",
  "config": {"layers": ["deterministic", "ml"], "tier": "standard", "threshold": 60.0, "concurrency": 6},
  "metrics": { "precision": 0.94, "recall": 0.87, "f1": 0.90, "fpr": 0.06, "...": "..." },
  "skill_count": 200,
  "error_count": 2,
  "wall_clock_seconds": 342.1
}
```

### 6.3 Run Directory

```
benchmark/results/<run-id>/
├── results.jsonl     # Per-skill findings-focused results
├── summary.json      # Aggregate metrics, config, provenance
└── report.md         # Generated Markdown report
```

Run ID: `YYYYMMDD-HHMMSS-<short-git-sha>` (append `-dirty` if working tree is dirty).

### 6.4 Baselines

`benchmark/baselines/v1.json` — a blessed `summary.json` snapshot. The `benchmark compare` command diffs against this. Updating the baseline is a deliberate act, not automatic.

---

## 7. Report Structure

```markdown
# SkillInquisitor Benchmark Report

## Run Metadata
Date, git SHA, dataset version, layers enabled, tier, threshold, wall-clock time.

## Executive Summary
5-10 lines: precision/recall/F1, skills scanned, regressions since baseline,
weakest detection category.

## Regression Delta (if baseline provided)
New failures (correct→wrong), new fixes (wrong→correct), net metric deltas.
Non-zero regressions produce exit code 1.

## Confusion Matrix
Binary 2×2 with precision/recall/F1/FPR derived.
Ambiguous distribution (separate table).

## Per-Category Detection Rates
Category × severity table: detected/total per cell.
"Worst categories" callout: 3-5 categories with lowest detection rates.

## Performance
Per-layer latency percentiles. Slowest 5 skills.

## Error Analysis
False negatives by category (count + up to 3 representative examples).
False positives by trigger rule (count + up to 3 examples).
Top 10 most concerning failures (ranked by severity × confidence delta).

## Errors
Skills that failed to scan: count, skill IDs, exception summaries.
```

**Length target:** Under 500 lines for a 500-skill run. The report is a lens, not a database.

---

## 8. Dataset Composition

### 8.1 MVP (Phase 1: ~200 skills)

| Category | Source | Count |
|---|---|---|
| Safe | Real-world (ToB, Anthropic, Cloudflare subset) | 50 |
| Safe | Synthetic clean counterparts | 30 |
| Malicious | MaliciousAgentSkillsBench subset | 60 |
| Malicious | Synthetic (all 23 rule families, 1+ each) | 30 |
| Ambiguous | Synthetic gray-area | 15 |
| Ambiguous | Reclassified from real-world scanning | 15 |
| **Total** | | **200** |

### 8.2 Full (Phase 2: ~540 skills)

| Category | Source | Count |
|---|---|---|
| Safe | Real-world repos (all 180) | ~180 |
| Safe | Synthetic counterparts | ~46 |
| Safe | From fixtures (safe subset) | ~32 |
| Malicious | MaliciousAgentSkillsBench (all 157) | 157 |
| Malicious | Synthetic (46 across 7 categories) | 46 |
| Malicious | From fixtures (malicious subset) | ~32 |
| Ambiguous | Synthetic | ~30 |
| Ambiguous | Reclassified real-world | ~20 |
| **Total** | | **~543** |

### 8.3 Tier Assignment

- **smoke (~50):** 1-2 per rule family (malicious + safe counterpart), 5 ambiguous. Deterministic only. Runs on every PR in ~2 minutes.
- **standard (~200):** MVP set. Deterministic + ML. Runs nightly in ~15-30 minutes.
- **full (~540):** Everything. All layers. Release benchmarks. 2-4 hours.

### 8.4 Containment Policy

All malicious skills in the dataset MUST be defanged:
- Replace live C2 URLs with `httpbin.org/post` or `evil.example.com`
- Remove actual malware binaries (keep stubs that trigger detection)
- Replace real credentials with obviously fake ones (`AKIA_FAKE_KEY_DO_NOT_USE`)
- Document all neutralizations in `_meta.yaml` containment fields

The skill content should still trigger SkillInquisitor's detectors (patterns like `curl`, `base64 -d`, `eval()` remain) but be safe to store and process.
