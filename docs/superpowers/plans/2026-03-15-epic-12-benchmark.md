# Epic 12 Part 1 — Benchmark Framework Implementation Plan

**Spec:** `docs/superpowers/specs/2026-03-15-epic-12-benchmark-design.md`
**Research:** `docs/research/epic-12-benchmark-dataset-research.md`

---

## Phase 1: Framework Skeleton

Build the benchmark modules, manifest schema, and CLI wiring. Prove the end-to-end loop works with a handful of test skills before building the full dataset.

### Chunk 1.1: Manifest Schema & Dataset Loader

**Files:**
- `src/skillinquisitor/benchmark/__init__.py` — Package init, exports
- `src/skillinquisitor/benchmark/dataset.py` — Manifest loading, entry filtering, path resolution

**Steps:**

1. Create `src/skillinquisitor/benchmark/__init__.py` with package docstring and public imports.

2. Define Pydantic models in `dataset.py` for the manifest schema:
   - `GroundTruth`: verdict (MALICIOUS/SAFE/AMBIGUOUS), attack_categories, severity, expected_rules, min_category_coverage, false_positive_risk, notes
   - `Provenance`: source_url, source_ref, fetch_date, license, upstream_status
   - `Containment`: sandboxed, defanged_urls, defanged_payloads, original_threat, containment_notes
   - `EntryMetadata`: tier (smoke/standard/full), difficulty, source_type, tags
   - `ManifestEntry`: id, path, ground_truth, metadata, provenance (optional), containment (optional)
   - `DecisionPolicy`: default_threshold
   - `BenchmarkManifest`: schema_version, dataset_version, decision_policy, entries

3. Implement `load_manifest(path: Path) -> BenchmarkManifest` — YAML loading with Pydantic validation.

4. Implement `filter_entries(manifest, tier, tags) -> list[ManifestEntry]` — Filter by tier (smoke includes smoke; standard includes smoke+standard; full includes all).

5. Implement `resolve_skill_path(entry, dataset_root) -> Path` — Resolves entry.path relative to dataset root directory.

6. Create a minimal test manifest with 3 entries (1 safe, 1 malicious, 1 ambiguous) and a test for loading/filtering.

**Validation:** `uv run pytest tests/test_benchmark_dataset.py -v` passes.

### Chunk 1.2: Metrics Engine

**Files:**
- `src/skillinquisitor/benchmark/metrics.py` — All metric computation, no external deps

**Steps:**

1. Define `ConfusionMatrix` dataclass with fields: tp, fp, tn, fn. Add properties: precision, recall, f1, fpr, fnr, accuracy. Handle division-by-zero (return 0.0).

2. Define `BenchmarkResult` for a single skill:
   - `skill_id: str`
   - `ground_truth: GroundTruth`
   - `risk_score: int`
   - `verdict: str`
   - `findings: list[FindingSummary]` (rule_id, category, severity, confidence, message — no raw content)
   - `timing: dict[str, float]` (per-layer ms)
   - `error: str | None`
   - `binary_outcome: str` (TP/FP/TN/FN/EXCLUDED)

3. Define `FindingSummary` — lightweight finding representation stripped of artifact content.

4. Implement `classify_binary(ground_truth_verdict, risk_score, threshold) -> str`:
   - AMBIGUOUS → EXCLUDED
   - MALICIOUS + score < threshold → TP
   - MALICIOUS + score >= threshold → FN
   - SAFE + score >= threshold → TN
   - SAFE + score < threshold → FP

5. Implement `compute_confusion_matrix(results: list[BenchmarkResult]) -> ConfusionMatrix`.

6. Implement `compute_per_category_recall(results) -> dict[str, CategoryRecall]`:
   - For each attack category in ground truth, count how many skills had at least one finding in that category.
   - Return {category: {detected: N, total: M, recall: N/M}}.

7. Implement `compute_category_coverage(result: BenchmarkResult) -> CoverageResult`:
   - Compare findings categories against min_category_coverage.
   - Return hits, misses.

8. Implement `compute_rule_coverage(result: BenchmarkResult) -> CoverageResult`:
   - Compare finding rule_ids against expected_rules.
   - Return hits, misses.

9. Implement `compute_severity_accuracy(results) -> SeverityMetrics`:
   - For TP results only: ordinal distance between ground truth severity and max finding severity.
   - Return mean_absolute_error, under_severity_rate, over_severity_rate.

10. Implement `compute_latency_stats(results) -> LatencyStats`:
    - p50, p95, p99 for total and per-layer.
    - Throughput (skills/second).

11. Implement `compute_all_metrics(results, threshold) -> BenchmarkMetrics` — aggregates all of the above.

12. Write tests covering: perfect classification, all-wrong classification, mixed results, empty input, threshold sensitivity.

**Validation:** `uv run pytest tests/test_benchmark_metrics.py -v` passes.

### Chunk 1.3: Benchmark Runner

**Files:**
- `src/skillinquisitor/benchmark/runner.py` — Orchestration

**Steps:**

1. Define `BenchmarkRunConfig`:
   - `tier: str`
   - `layers: list[str]`
   - `concurrency: int`
   - `timeout: float`
   - `threshold: float`
   - `manifest_path: Path`
   - `dataset_root: Path`
   - `output_dir: Path`
   - `baseline_path: Path | None`

2. Define `BenchmarkRun`:
   - `run_id: str` (YYYYMMDD-HHMMSS-<short-sha>)
   - `config: BenchmarkRunConfig`
   - `results: list[BenchmarkResult]`
   - `metrics: BenchmarkMetrics`
   - `git_sha: str`
   - `dirty: bool`
   - `timestamp: str`
   - `dataset_version: str`
   - `wall_clock_seconds: float`

3. Implement `generate_run_id() -> str` — timestamp + git SHA.

4. Implement `async run_benchmark(config: BenchmarkRunConfig) -> BenchmarkRun`:
   a. Load manifest, filter by tier.
   b. Build `ScanConfig` from benchmark config (enable/disable layers per --layer flags).
   c. For each entry: resolve skill path, call `resolve_input()`, call `run_pipeline()`, capture timing.
   d. Use `asyncio.Semaphore(concurrency)` to bound concurrent scans.
   e. Wrap each skill scan in try/except — capture errors, never abort.
   f. Build `BenchmarkResult` for each skill from `ScanResult` + ground truth + timing.
   g. Compute all metrics via `compute_all_metrics()`.
   h. Return `BenchmarkRun`.

5. **Pipeline model lifecycle — careful handling:**
   - For the initial implementation, use the existing per-scan load/unload cycle. This is slower but correct and requires no pipeline refactoring.
   - Track total time. If benchmarks prove that model load/unload is the bottleneck (likely for ML layer), add a `BenchmarkSession` context manager in a follow-up that pre-loads models and injects them into the pipeline. This is noted as a performance optimization, not a blocker for Phase 1.
   - The runner's `ScanConfig` manipulation (disabling layers) already works because `run_pipeline` respects `config.layers.*.enabled`.

6. Implement `save_results(run: BenchmarkRun, output_dir: Path)`:
   - Write `results.jsonl` — one JSON line per BenchmarkResult, findings-focused (no raw content).
   - Write `summary.json` — run metadata + aggregate metrics.

7. Implement `load_baseline(path: Path) -> BenchmarkRun` — load a previous summary.json for comparison.

8. Write test using the 3-entry test manifest from Chunk 1.1. Mock `run_pipeline` to return predictable results.

**Validation:** `uv run pytest tests/test_benchmark_runner.py -v` passes.

### Chunk 1.4: Report Generator

**Files:**
- `src/skillinquisitor/benchmark/report.py` — Markdown report generation

**Steps:**

1. Implement `generate_report(run: BenchmarkRun, baseline: BenchmarkRun | None) -> str`:
   - Returns complete Markdown string.

2. Section: **Run Metadata** — date, git SHA, dataset version, layers, tier, threshold, wall-clock time.

3. Section: **Executive Summary** — 5-10 lines: precision/recall/F1, skills scanned, error count. If baseline exists, note regression count. Highlight weakest detection category.

4. Section: **Regression Delta** (only if baseline provided):
   - New failures: skills correct in baseline but wrong now.
   - New fixes: skills wrong in baseline but correct now.
   - Metric deltas table: each metric with baseline value, current value, delta.

5. Section: **Confusion Matrix** — ASCII 2×2 table with TP/FP/TN/FN counts and derived metrics.
   - Separate table for AMBIGUOUS verdict distribution.

6. Section: **Per-Category Detection Rates** — table with category, detected, total, recall percentage, inline bar.
   - "Worst categories" callout: bottom 3-5 by recall.

7. Section: **Performance** — latency percentile table per layer. Top 5 slowest skills.

8. Section: **Error Analysis**:
   - False negatives grouped by attack category (count + up to 3 example skill IDs with ground truth notes).
   - False positives grouped by trigger rule_id (count + up to 3 examples).
   - Top 10 most concerning failures ranked by `severity_ordinal × (1 - risk_score/100)`.

9. Section: **Errors** — skills that failed to scan: count, IDs, exception messages.

10. Write test: generate report from known BenchmarkRun, assert expected sections present, assert metrics values appear.

**Validation:** `uv run pytest tests/test_benchmark_report.py -v` passes.

### Chunk 1.5: CLI Wiring

**Files:**
- `src/skillinquisitor/cli.py` — Replace benchmark stubs with real commands

**Steps:**

1. Replace `benchmark_run` stub with full implementation:
   - Parse all CLI options into `BenchmarkRunConfig`.
   - Call `async run_benchmark(config)`.
   - Call `save_results(run, output_dir)`.
   - Generate report, write to output_dir/report.md.
   - Print executive summary to stdout.
   - Exit code: 0 if no regressions (or no baseline), 1 if regressions found.

2. Replace `benchmark_compare` stub with implementation:
   - Load two BenchmarkRun objects from result directories.
   - Compute deltas for all metrics.
   - Print comparison table (or markdown/json per --format).
   - List regressions and fixes.
   - Exit code: 0 if no regressions in run B vs run A, 1 otherwise.

3. Add `benchmark bless` command:
   - Copies a run's summary.json to `benchmark/baselines/<name>.json`.
   - Used to create new baselines after intentional changes.

4. Write integration test: run `benchmark run` CLI against test manifest, verify output files exist and contain expected structure.

**Validation:** CLI `skillinquisitor benchmark run --tier smoke --dataset <test-manifest>` produces results directory with results.jsonl, summary.json, report.md.

---

## Phase 2: Synthetic Dataset

Create the synthetic malicious, safe, and ambiguous skills that exercise every detection vector.

### Chunk 2.1: Synthetic Malicious Skills — Categories A-C

Create skills covering steganography, encoding, and secrets/exfiltration.

**Skills to create (18 total):**

Category A — Steganography & Unicode (5):
- S-A1: hidden-unicode-exfil (D-1A + D-9A + D-19A)
- S-A2: zero-width-injection (D-1B + D-11A)
- S-A3: bidi-filename-spoof (D-1D)
- S-A4: homoglyph-typosquat (D-2A + D-20D)
- S-A5: keyword-split-eval (D-6A + D-10A)

Category B — Encoding & Obfuscation (6):
- S-B1: base64-credential-theft (D-3A + D-7A + D-9A + D-19A)
- S-B2: rot13-shell-dropper (D-4A + D-4B + D-10A)
- S-B3: hex-xor-payload (D-5A + D-5B)
- S-B4: nested-encoding-chain (D-3A + D-5A + D-5C)
- S-B5: html-comment-injection (D-21A + D-11A)
- S-B6: code-fence-disguise (D-22A + D-10A)

Category C — Secrets & Exfiltration (7):
- S-C1: aws-cred-harvester (D-7A + D-9A + D-19A) — Python script
- S-C2: ssh-key-exfil (D-7A + D-9A + D-19A) — Shell script
- S-C3: cloud-metadata-ssrf (D-7B + D-9A + D-19C) — Python script
- S-C4: env-var-dump (D-8A + D-8B + D-9A) — Shell script
- S-C5: dynamic-exec-backdoor (D-10A) — Python script
- S-C6: multi-file-chain (D-7A + D-9A + D-19A) — read in script A, send in script B
- S-C7: eval-with-fetch (D-10A + D-9A) — Go script (language diversity)

**For each skill:**
1. Create directory under `benchmark/dataset/synthetic/malicious/<skill-name>/`
2. Write SKILL.md with realistic frontmatter and description
3. Write scripts/references as needed with defanged payloads
4. Write `_meta.yaml` with containment metadata
5. Add manifest entry with ground truth, expected_rules, tier assignment

**Containment:** All URLs defanged to `evil.example.com` or `httpbin.org/post`. All credential values are obviously fake. All eval/exec targets are inert strings.

### Chunk 2.2: Synthetic Malicious Skills — Categories D-G

Category D — Injection & Suppression (10):
- S-D1: instruction-override (D-11A)
- S-D2: role-rebinding (D-11B)
- S-D3: system-mimicry (D-11E)
- S-D4: delimiter-injection (D-11D)
- S-D5: jailbreak-signatures (D-11F)
- S-D6: suppress-output (D-12A + D-12B)
- S-D7: suppress-confirmation (D-12C + D-12D)
- S-D8: frontmatter-injection (D-13A + D-13B + D-13C)
- S-D9: description-injection (D-13E + D-11A)
- S-D10: coercive-language (D-11A) — SKILL.md only, realistic

Category E — Structural & Supply Chain (6):
- S-E1: missing-skill-md (D-14A) — scripts only, no SKILL.md
- S-E2: binary-smuggling (D-14) — fake .md that's actually ELF header
- S-E3: shortener-redirect (D-15) — bit.ly URLs in SKILL.md
- S-E4: typosquat-anthropic (D-20D) — "antrhopic-skills" requirement
- S-E5: registry-override (D-20B) — pip --index-url attacker registry
- S-E6: density-anomaly (D-23) — 50KB SKILL.md, 90% encoded

Category F — Persistence & Cross-Agent (8):
- S-F1: time-bomb (D-16A) — datetime conditional
- S-F2: env-gated-payload (D-16B) — CI-only activation
- S-F3: cron-persistence (D-17A) — crontab write
- S-F4: bashrc-backdoor (D-17A) — .bashrc append
- S-F5: git-hook-hijack (D-17A) — post-commit hook exfil
- S-F6: cross-agent-write (D-18A) — write to .cursor/skills/
- S-F7: broad-auto-invoke (D-18C) — "Use for all tasks"
- S-F8: sleeper-activation (D-16) — codeword trigger

Category G — Multi-Vector Compound (8):
- S-G1: full-kill-chain — recon → cred access → exfil → persistence
- S-G2: skillject-style-stealth — benign SKILL.md + malicious aux script
- S-G3: amos-replica — fake prerequisite + curl payload (defanged)
- S-G4: agent-hijacker — override + suppression + behavior manipulation
- S-G5: supply-chain-trojan — 98% legit with 3 injected lines
- S-G6: mcp-tool-poisoner — hidden `<IMPORTANT>` credential extraction
- S-G7: cognitive-rootkit — SOUL.md/AGENTS.md persistence write
- S-G8: all-evasion — every obfuscation technique combined

Same process as Chunk 2.1 for each skill.

### Chunk 2.3: Synthetic Safe Counterparts

For each category A-G, create safe skills that use similar language/patterns but are legitimately benign:

- safe-aws-sdk-usage (counterpart to S-C1) — references AWS in docs
- safe-cloud-deployment (counterpart to S-C3) — mentions 169.254.169.254 in cloud setup
- safe-prompt-engineering-guide (counterpart to S-D1) — discusses injection educationally
- safe-cron-scheduler (counterpart to S-F3) — legitimate cron management
- safe-git-hooks-setup (counterpart to S-F5) — legitimate pre-commit hooks
- safe-base64-encoding-tutorial (counterpart to S-B1) — educational base64
- safe-security-scanner-docs (counterpart to S-G1) — discusses kill chains in documentation
- ... (30 total safe counterparts)

Each gets manifest entry with verdict: SAFE and `false_positive_risk` documenting why it's tricky.

### Chunk 2.4: Synthetic Ambiguous Skills

Create 30 deliberately gray-area skills:

- ambig-env-config-sender — reads env vars and sends to "analytics" endpoint
- ambig-file-indexer — broad filesystem access for legitimate indexing
- ambig-code-sandbox — executes user-provided code in a restricted context
- ambig-auto-updater — self-modifying skill that fetches updates
- ambig-telemetry-collector — collects usage stats, sends to endpoint
- ... (30 total)

Each gets manifest entry with verdict: AMBIGUOUS and detailed notes explaining the ambiguity.

---

## Phase 3: Real-World Dataset Acquisition

### Chunk 3.1: Safe Skills from GitHub

**Steps:**

1. Write `scripts/fetch_benchmark_skills.py` — a one-time acquisition script that:
   a. Clones repos at pinned SHAs (from research doc's catalog).
   b. Extracts individual skill directories.
   c. Writes each to `benchmark/dataset/real-world/safe/<slug>/`.
   d. Generates `_meta.yaml` with provenance (source_url, source_ref, fetch_date, license).

2. Acquire skills in priority order:
   - Trail of Bits (35 skills, Apache-2.0) — highest priority, rich structure
   - Anthropic Official (17 skills) — canonical reference
   - Cloudflare (7), Netlify (12), Vercel (8) — platform diversity
   - HuggingFace (8), HashiCorp (3), Stripe (2) — domain diversity
   - Selected community skills (10-15) — structural diversity

3. Total target: ~100 real-world safe skills for MVP, expanding to 180 for full.

4. Add manifest entries for each acquired skill. Assign tiers: 30 as smoke, rest as standard.

### Chunk 3.2: Malicious Skills from MaliciousAgentSkillsBench

**Steps:**

1. Download `malicious_skills.csv` from HuggingFace.

2. Fetch actual skill content via the URLs in the dataset. For each:
   a. Download skill files.
   b. Defang all content (replace live URLs, remove actual payloads, fake credentials).
   c. Write to `benchmark/dataset/real-world/malicious/<slug>/`.
   d. Write `_meta.yaml` with containment metadata.
   e. Document all defanging in containment_notes.

3. Create `benchmark/taxonomy_map.yaml` mapping MaliciousAgentSkillsBench Pattern values to our Category enum:
   ```yaml
   "Remote Code Execution": [code_execution, obfuscation]
   "External Transmission": [data_exfiltration]
   "Network sniffing / Credential theft": [credential_theft]
   "Behavior Manipulation": [prompt_injection]
   "Context Leakage": [data_exfiltration, prompt_injection]
   "Hidden Instructions": [prompt_injection, steganography]
   "Instruction Override": [prompt_injection]
   "Code Obfuscation": [obfuscation]
   ```

4. Add manifest entries with mapped ground truth. Target: 60 for MVP, all 157 for full.

### Chunk 3.3: Fixture Integration

**Steps:**

1. For each existing fixture in `tests/fixtures/` that has benchmark value:
   a. Copy the fixture directory to `benchmark/dataset/from-fixtures/<fixture-id>/`.
   b. Write `_meta.yaml` with source_type: fixture, source fixture path.
   c. Add manifest entry.
   d. Ground truth derived from fixture's `expected.yaml` (verdict from presence/absence of findings, categories from finding categories).

2. Add CI check: `scripts/validate_fixture_sync.py` that verifies benchmark fixture copies match their source fixtures. Run in test suite.

3. Target: ~50 fixtures (skip templates and redundant variants).

---

## Phase 4: Integration & Polish

### Chunk 4.1: End-to-End Smoke Test

**Steps:**

1. Create `tests/test_benchmark_integration.py`:
   a. Run `benchmark run --tier smoke` against the real dataset.
   b. Verify results.jsonl, summary.json, report.md are generated.
   c. Verify metrics are within expected ranges (not exact values — ranges account for ML non-determinism).
   d. Verify all smoke-tier skills produce results (no crashes).

2. Add to `scripts/run-test-suite.sh`.

### Chunk 4.2: Baseline & Regression Testing

**Steps:**

1. Run full benchmark: `skillinquisitor benchmark run --tier standard`.
2. Review report. Identify any surprising results.
3. Bless the baseline: `skillinquisitor benchmark bless --name v1`.
4. Add CI job: run smoke benchmark on every PR, compare against blessed baseline, fail on regressions.

### Chunk 4.3: Documentation Sync

**Steps:**

1. Update `docs/requirements/architecture.md` Epic 12 section with final module structure and decisions.
2. Update `docs/requirements/business-requirements.md` with any BRD deviations.
3. Update `README.md` with benchmark usage instructions.
4. Update `CHANGELOG.md` with Epic 12 Part 1 entry.
5. Update `TODO.md` with Epic 12 progress.

---

## Phase Summary

| Phase | Chunks | Skills Added | Key Deliverable |
|---|---|---|---|
| 1: Framework | 1.1-1.5 | 3 (test only) | Working `benchmark run` + `compare` + report |
| 2: Synthetic | 2.1-2.4 | ~120 | All 23 rule families covered with malicious + safe + ambiguous |
| 3: Real-World | 3.1-3.3 | ~260 | MaliciousAgentSkillsBench + GitHub safe skills + fixtures |
| 4: Polish | 4.1-4.3 | 0 | CI integration, baseline, docs sync |
| **Total** | | **~383 (MVP) to ~543 (full)** | |

## Dependencies & Risks

**Risk: ML/LLM model load/unload overhead.** Phase 1 uses per-scan lifecycle (correct but slow). If smoke benchmark exceeds 5 minutes, add `BenchmarkSession` pre-loading as a follow-up optimization.

**Risk: MaliciousAgentSkillsBench URLs may be dead.** Fetch early in Phase 3. Any unavailable skills are noted and excluded from the dataset.

**Risk: Defanging malicious skills may remove detection signals.** Balance containment with detection fidelity. Test each defanged skill against the scanner to verify it still triggers expected rules.

**Dependency: No new external dependencies.** Metrics are hand-rolled. YAML/JSON loading uses existing deps. No matplotlib required (charts are optional enhancement for Part 2).
