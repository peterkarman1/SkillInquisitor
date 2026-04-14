# Codebase Simplification Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove the ML ensemble, legacy numeric scoring, and VRAM auto-detection to aggressively simplify the codebase.

**Architecture:** Two-phase removal. Phase 1 removes the ML ensemble and legacy 0-100 scoring together (they're coupled through cross-layer dedup and soft finding gates). Phase 2 removes VRAM auto-detection independently. Finding-filtering logic (chain absorption, soft gate, dedup, LLM adjustments) is preserved and moved out of the scoring framing. Output model becomes: risk_label + binary_label + annotated findings.

**Tech Stack:** Python, Pydantic models, pytest fixtures, YAML config

**Design doc:** `docs/plans/2026-04-10-codebase-simplification-design.md`

---

## Phase 1: Remove ML Ensemble + Remove Legacy Numeric Scoring

### Task 1: Document ML Ensemble for Posterity

**Files:**
- Create: `docs/archive/ml-ensemble.md`

**Step 1: Write the archive document**

Create `docs/archive/ml-ensemble.md` with a complete description of how the ML ensemble worked before removal. Cover:
- Three-model architecture (deberta 184M/0.40, wolf-defender 308M/0.35, jailbreak-detector 66M/0.25)
- Sequential load-one-run-unload memory management cycle
- Weighted soft voting: `ensemble_score = sum(score_i * weight_i) / sum(weight_i)`
- Long-text chunking (1800 chars, 3-line overlap)
- Configurable threshold (default 0.5)
- Borderline findings (score < 0.85) auto-marked soft for LLM consensus
- Doc-like segment soft marking
- HuggingFace model download and caching
- Runtime pooling with `_PooledInjectionModel` and `_MLPoolEntry`
- Pipeline integration: segment collection, artifact filtering, decisive combo bypass
- Config schema: `MLConfig`, `WeightedModelConfig`
- Finding representation: rule_id `ML-PI`, layer `ML_ENSEMBLE`, category `PROMPT_INJECTION`

Source files to reference while writing (read these first):
- `src/skillinquisitor/detectors/ml/ensemble.py`
- `src/skillinquisitor/detectors/ml/models.py`
- `src/skillinquisitor/detectors/ml/download.py`

**Step 2: Commit**

```bash
git add docs/archive/ml-ensemble.md
git commit -m "docs: archive ML ensemble documentation before removal"
```

---

### Task 2: Delete ML Source Code and Fixtures

**Files:**
- Delete: `src/skillinquisitor/detectors/ml/ensemble.py`
- Delete: `src/skillinquisitor/detectors/ml/models.py`
- Delete: `src/skillinquisitor/detectors/ml/download.py`
- Delete: `src/skillinquisitor/detectors/ml/__init__.py`
- Delete: `tests/test_ml.py`
- Delete: `tests/fixtures/ml/` (entire directory — 6 fixtures)
- Modify: `tests/fixtures/manifest.yaml` — remove all entries with `suite: ml`

**Step 1: Delete the ML detector package**

```bash
rm -rf src/skillinquisitor/detectors/ml/
```

**Step 2: Delete ML tests and fixtures**

```bash
rm tests/test_ml.py
rm -rf tests/fixtures/ml/
```

**Step 3: Remove ML fixture entries from manifest.yaml**

Read `tests/fixtures/manifest.yaml` and remove every entry where `suite: ml`. There are 6 entries to remove:
- `ml-injection-obvious-body`
- `ml-injection-subtle-frontmatter`
- `ml-injection-hidden-comment`
- `ml-injection-decoded-base64`
- `ml-safe-quoted-injection-docs`
- `ml-safe-complex-instructions`

**Step 4: Commit**

```bash
git add -A
git commit -m "remove: delete ML ensemble source code, tests, and fixtures"
```

---

### Task 3: Remove ML from Pipeline

**Files:**
- Modify: `src/skillinquisitor/pipeline.py`

**Step 1: Read the file**

Read `src/skillinquisitor/pipeline.py` in full.

**Step 2: Remove ML imports and functions**

Remove:
- Line 14: `from skillinquisitor.detectors.ml import MLPromptInjectionEnsemble`
- Lines 254-266: `run_ml_ensemble()` function
- Lines 269-280: `collect_ml_segments()` function
- Lines 392-417: `_artifact_is_ml_candidate()` function
- Lines 646-688: `_expand_ml_segment()` function

**Step 3: Remove ML calls from run_pipeline()**

In `run_pipeline()`:
- Lines 107-112: Remove the ML skip logic (`has_decisive_non_llm_combo` check that skips ML)
- Lines 123-126: Remove the `run_ml_ensemble()` call and segment collection

The pipeline should go directly from deterministic rules to LLM analysis. The decisive combo check for skipping LLM should remain.

**Step 4: Verify no dangling references**

Search pipeline.py for any remaining references to `ml`, `ML`, `ensemble`, `_artifact_is_ml_candidate`, `collect_ml_segments`, `_expand_ml_segment`. Remove any stragglers.

**Step 5: Commit**

```bash
git add src/skillinquisitor/pipeline.py
git commit -m "remove: strip ML ensemble from pipeline orchestration"
```

---

### Task 4: Remove ML from Runtime

**Files:**
- Modify: `src/skillinquisitor/runtime.py`

**Step 1: Read the file**

Read `src/skillinquisitor/runtime.py` in full.

**Step 2: Remove ML imports, pool classes, and methods**

Remove:
- Line 19: `from skillinquisitor.detectors.ml.models import InjectionModel, build_injection_model`
- Lines 82-86: `_MLPoolEntry` dataclass
- Lines 88-102: `_PooledInjectionModel` class
- Lines 247-270: `get_ml_models()` method on `ScanRuntime`
- Lines 150-153: `ml_section()` context manager method
- Lines 31-32: `ml_cold_loads`, `ml_warm_reuses` from `RuntimeTelemetry`
- Line 127: `_ml_pool` initialization
- Lines 145-148: ML pool cleanup in `_close_sync()`
- Line 121: `ml_global_slots` semaphore initialization

**Step 3: Commit**

```bash
git add src/skillinquisitor/runtime.py
git commit -m "remove: strip ML pool, lifecycle, and telemetry from runtime"
```

---

### Task 5: Remove ML from Config Models

**Files:**
- Modify: `src/skillinquisitor/models.py`

**Step 1: Read the file**

Read `src/skillinquisitor/models.py` in full.

**Step 2: Remove ML config types and enum value**

Remove:
- Lines 201-204: `WeightedModelConfig` class
- Lines 238-247: `MLConfig` class
- Line 373: `ml: MLConfig = Field(default_factory=MLConfig)` from `LayersConfig`
- Line 52: `ML_ENSEMBLE` from `DetectionLayer` enum
- Lines 527-529: `ml_lifecycle`, `ml_resident_model_limit` from `RuntimeConfig`

Search for any remaining references to `MLConfig`, `WeightedModelConfig`, `ml_lifecycle`, `ml_resident_model_limit`, `ml_global_slots`, `ML_ENSEMBLE` and remove them.

**Step 3: Commit**

```bash
git add src/skillinquisitor/models.py
git commit -m "remove: strip ML config types and enum values from data model"
```

---

### Task 6: Remove ML from CLI and Benchmark Runner

**Files:**
- Modify: `src/skillinquisitor/cli.py`
- Modify: `src/skillinquisitor/benchmark/runner.py`

**Step 1: Read both files**

Read `src/skillinquisitor/cli.py` and `src/skillinquisitor/benchmark/runner.py` in full.

**Step 2: Update CLI**

In `cli.py`:
- Lines 10-11: Remove ML download/list imports (`download_configured_models`, `list_model_statuses` from `detectors.ml`)
- Remove ML model download logic from the `models_download` command
- Remove ML model list logic from the `models_list` command
- Lines 130, 200, 418: Remove `"ml"` from all default layer lists (layers should now default to `["deterministic", "llm"]`)
- Update `--layer` option help text to remove ML references

**Step 3: Update Benchmark Runner**

In `benchmark/runner.py`:
- Lines 191-192: Remove ML from layer config setup
- Lines 214-217: Remove ML lifecycle config (`ml_lifecycle`, `ml_global_slots`, `ml_resident_model_limit`)
- Line 278: Remove "ml" from layer timing metadata extraction
- Update `BenchmarkRunConfig` layer defaults to `["deterministic", "llm"]`

**Step 4: Commit**

```bash
git add src/skillinquisitor/cli.py src/skillinquisitor/benchmark/runner.py
git commit -m "remove: strip ML references from CLI and benchmark runner"
```

---

### Task 7: Remove ML References from Adjudication and Scoring

**Files:**
- Modify: `src/skillinquisitor/adjudication.py`
- Modify: `src/skillinquisitor/scoring.py`

**Step 1: Read both files**

Read `src/skillinquisitor/adjudication.py` and `src/skillinquisitor/scoring.py` in full.

**Step 2: Update Adjudication**

In `adjudication.py`:
- Lines 128, 162-163, 184: Remove `ml_signals` from `build_evidence_packet()`. Remove the `ml_signals` field from `EvidencePacket` (in models.py if defined there, or inline).
- Line 384: Remove ML signal checks in `heuristic_adjudicate()` (e.g., `has_substantive_ml_signal` logic)
- Remove any remaining references to `ML_ENSEMBLE` layer

**Step 3: Update Scoring (ML dedup references only — full scoring removal is next task)**

In `scoring.py`:
- In the cross-layer dedup logic (lines 84-108): simplify since only deterministic + LLM layers remain. Remove any ML-specific handling.

**Step 4: Commit**

```bash
git add src/skillinquisitor/adjudication.py src/skillinquisitor/scoring.py
git commit -m "remove: strip ML signal references from adjudication and scoring"
```

---

### Task 8: Remove ML Dependencies from pyproject.toml

**Files:**
- Modify: `pyproject.toml`

**Step 1: Read pyproject.toml**

Read `pyproject.toml` in full.

**Step 2: Remove the `ml` extras group**

Remove the `[project.optional-dependencies] ml = [...]` section containing `torch`, `transformers`, `huggingface_hub`, `safetensors`.

If `--all-extras` references this group indirectly, verify the install still works.

**Step 3: Update uv.lock**

```bash
uv sync --group dev
```

**Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "remove: drop ML dependencies (torch, transformers, huggingface_hub)"
```

---

### Task 9: Remove ML from Tests

**Files:**
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_benchmark_runner.py`
- Modify: `tests/conftest.py`

**Step 1: Read the test files**

Read all three files.

**Step 2: Update test_pipeline.py**

Remove or update tests that mock `run_ml_ensemble` or reference ML:
- Tests like `test_pipeline_runs_ml_ensemble_on_text_segments()` (around line 2622)
- Tests like `test_pipeline_skips_ml_and_llm_for_decisive_deterministic_combo()` (around line 2674) — keep the LLM skip part, remove ML part
- Tests referencing `ML-PI` findings or `ML_ENSEMBLE` layer
- Line 24 area: remove ML mock imports

**Step 3: Update test_benchmark_runner.py**

Remove ML layer selection tests. Update any tests that reference ML in their layer lists.

**Step 4: Update conftest.py**

- Line 440: Remove the `ml_ensemble` / `ml` scope handling that disables ML when not in scope. Since ML no longer exists, this branch is dead code.
- Remove any ML fixture loading logic.

**Step 5: Run the test suite to verify ML removal is clean**

```bash
uv run pytest tests/ -x -q --ignore=tests/test_ml.py 2>&1 | head -50
```

Expected: Tests should fail on scoring/verdict-related assertions (that's the next task) but NOT on ML import errors.

**Step 6: Commit**

```bash
git add tests/test_pipeline.py tests/test_benchmark_runner.py tests/conftest.py
git commit -m "remove: strip ML references from test suite"
```

---

### Task 10: Extract Finding-Filtering Logic from Scoring

This is the bridge task between ML removal and legacy score removal. The finding-filtering logic currently inside `compute_score()` needs to be extracted into a standalone function before we delete the numeric math.

**Files:**
- Modify: `src/skillinquisitor/scoring.py`

**Step 1: Read scoring.py in full**

Read `src/skillinquisitor/scoring.py`.

**Step 2: Create `prepare_findings()` function**

Extract the following logic blocks from `compute_score()` into a new `prepare_findings(findings, config)` function that returns the annotated findings list:

1. **LLM adjustment identification** (lines 66-73): Map LLM-DISPUTE/LLM-CONFIRM findings to their referenced targets
2. **Chain absorption** (lines 75-82): Mark component findings with `absorbed_by` annotation in their details
3. **Cross-layer dedup** (lines 84-108): Mark lower-confidence duplicate findings with `deduped=True` in their details
4. **Soft finding gate** (lines 110-138): Set `soft_status` to `"confirmed"` or `"rejected"` based on LLM consensus. Respect `soft_fallback_confidence` for rules with overrides.
5. **LLM adjustment annotations** (lines 150-165): Annotate findings with dispute/confirm disposition and adjusted confidence

The function should:
- Accept `findings: list[Finding]` and `config: ScanConfig`
- Return `list[Finding]` with details dicts enriched with annotations
- NOT compute any numeric deductions, severity weights, geometric decay, or suppression multipliers
- NOT return a score or verdict

```python
def prepare_findings(findings: list[Finding], config: ScanConfig) -> list[Finding]:
    """Annotate findings with chain absorption, soft status, dedup, and LLM adjustments."""
    ...
    return annotated_findings
```

**Step 3: Add tests for prepare_findings()**

In `tests/test_scoring.py`, add tests (or repurpose existing ones) that verify:
- Chain absorption marks component findings
- Soft findings without LLM confirmation are marked rejected
- Soft findings with LLM confirmation are marked confirmed
- Cross-layer dedup marks lower-confidence duplicates
- LLM dispute/confirm annotations are applied

**Step 4: Run tests**

```bash
uv run pytest tests/test_scoring.py -v
```

**Step 5: Commit**

```bash
git add src/skillinquisitor/scoring.py tests/test_scoring.py
git commit -m "refactor: extract prepare_findings() from compute_score()"
```

---

### Task 11: Remove Legacy Numeric Scoring

**Files:**
- Modify: `src/skillinquisitor/scoring.py`
- Modify: `src/skillinquisitor/models.py`

**Step 1: Read both files**

Read `src/skillinquisitor/scoring.py` and `src/skillinquisitor/models.py`.

**Step 2: Delete from scoring.py**

Remove everything except `prepare_findings()` (from Task 10):
- `ScoredResult` dataclass (lines 29-33)
- `compute_score()` function (lines 36-228)
- `_score_to_verdict()` helper (lines 242-252)
- Any remaining imports only used by the deleted code

**Step 3: Delete from models.py**

Remove:
- `ScoringWeightsConfig` class (lines 377-381)
- From `ScoringConfig` (lines 384-395): remove `weights`, `decay_factor`, `severity_floors`, `suppression_multiplier` fields
- Rename `ScoringConfig` to `FindingPolicyConfig` (keep `chain_absorption`, `soft_confirmed_boost`, `soft_confirmation_threshold`, `llm_dispute_factor`, `llm_confirm_factor`)
- From `DecisionPolicyConfig` (lines 427-431): remove `keep_legacy_score` field
- From `ScanResult` (lines 560-561): remove `risk_score: int` and `verdict: str` fields
- `risk_label_to_legacy_verdict()` from `adjudication.py` (lines 112-119)

Update all references to `ScoringConfig` → `FindingPolicyConfig` across the codebase (likely in `models.py` `ScanConfig` class and in `scoring.py`).

**Step 4: Commit**

```bash
git add src/skillinquisitor/scoring.py src/skillinquisitor/models.py src/skillinquisitor/adjudication.py
git commit -m "remove: delete legacy numeric scoring, ScoredResult, verdict strings"
```

---

### Task 12: Update Pipeline to Use prepare_findings()

**Files:**
- Modify: `src/skillinquisitor/pipeline.py`

**Step 1: Read pipeline.py**

Read `src/skillinquisitor/pipeline.py`.

**Step 2: Replace compute_score() calls with prepare_findings()**

At lines 149-151 and 191-193, replace:
```python
scored = compute_score(findings, config)
```
with:
```python
findings = prepare_findings(findings, config)
```

Remove:
- Import of `compute_score` and `ScoredResult`
- Population of `risk_score` and `verdict` in `ScanResult` construction
- The `"scoring"` key in `layer_metadata`

The pipeline should now return `ScanResult` with `risk_label` and `binary_label` from adjudication and `findings` from `prepare_findings()`, but no `risk_score` or `verdict`.

**Step 3: Commit**

```bash
git add src/skillinquisitor/pipeline.py
git commit -m "refactor: pipeline uses prepare_findings() instead of compute_score()"
```

---

### Task 13: Update Formatters

**Files:**
- Modify: `src/skillinquisitor/formatters/console.py`
- Modify: `src/skillinquisitor/formatters/json.py`
- Modify: `src/skillinquisitor/formatters/sarif.py`

**Step 1: Read all three formatter files**

**Step 2: Update console formatter**

At lines 25-28: Replace the four-label block with just `risk_label` and `binary_label`:
```python
f"Risk label: {result.risk_label.value}"
f"Binary label: {result.binary_label}"
```
Remove `result.verdict` and `result.risk_score` references.
At lines 145-150: Remove verbose scoring details output (the `layer_metadata["scoring"]` section).

**Step 3: Update JSON formatter**

At lines 33-36: Remove `"verdict"` and `"risk_score"` from the output dict. Keep `"risk_label"` and `"binary_label"`.

**Step 4: Update SARIF formatter**

At line 149: Remove `verdict` and `risk_score` from the properties object. Keep `risk_label` and `binary_label`.

**Step 5: Commit**

```bash
git add src/skillinquisitor/formatters/
git commit -m "remove: strip legacy verdict and risk_score from all output formatters"
```

---

### Task 14: Migrate Fixture expected.yaml Files

This is the largest single task by file count (~65 fixtures).

**Files:**
- Modify: `tests/conftest.py`
- Modify: Every `expected.yaml` under `tests/fixtures/`

**Step 1: Read conftest.py**

Read `tests/conftest.py`, focusing on:
- Line 390: where `verdict` is read from YAML
- Lines 567-583: where verdict is validated
- The `FixtureExpectation` dataclass (line 82)

**Step 2: Update FixtureExpectation to use risk_label**

Replace the `verdict: str` field with `risk_label: str` in the `FixtureExpectation` dataclass.

Update `_build_expectation()` (line 390) to read `risk_label` from YAML instead of `verdict`.

Update `_assert_matches()` (lines 567-583) to compare `result.risk_label.value` against `expectation.risk_label`. Preserve the hierarchical upgrade behavior:
- `LOW` accepts actual `MEDIUM`, `HIGH`, `CRITICAL`
- `MEDIUM` accepts actual `HIGH`, `CRITICAL`
- `HIGH` accepts actual `CRITICAL`

**Step 3: Migrate all expected.yaml files**

Use this mapping to convert verdict strings to risk_label values:
- `SAFE` → `LOW`
- `LOW RISK` → `LOW`
- `MEDIUM RISK` → `MEDIUM`
- `HIGH RISK` → `HIGH`
- `CRITICAL` → `CRITICAL`

For each `expected.yaml`, replace `verdict: <old>` with `risk_label: <new>`.

Write a script or use sed to automate this across all ~65 fixtures:
```bash
# In tests/fixtures/, recursively update expected.yaml files
find tests/fixtures/ -name "expected.yaml" -exec sed -i '' \
  -e 's/^verdict: SAFE$/risk_label: LOW/' \
  -e 's/^verdict: LOW RISK$/risk_label: LOW/' \
  -e 's/^verdict: MEDIUM RISK$/risk_label: MEDIUM/' \
  -e 's/^verdict: HIGH RISK$/risk_label: HIGH/' \
  -e 's/^verdict: CRITICAL$/risk_label: CRITICAL/' {} \;
```

Verify no `verdict:` lines remain:
```bash
grep -r "^verdict:" tests/fixtures/
```

**Step 4: Commit**

```bash
git add tests/conftest.py tests/fixtures/
git commit -m "migrate: fixture expected.yaml from verdict to risk_label"
```

---

### Task 15: Update Scoring Tests

**Files:**
- Modify: `tests/test_scoring.py`

**Step 1: Read test_scoring.py**

Read `tests/test_scoring.py` in full.

**Step 2: Rewrite tests**

Delete all tests that assert on `risk_score` or `verdict` from `compute_score()`. Replace with tests for `prepare_findings()`:

- Test chain absorption: D-19A finding absorbs D-7A + D-9A components → components have `absorbed_by` in details
- Test soft gate: soft finding without LLM confirmation → `soft_status: "rejected"`
- Test soft gate: soft finding with LLM confirmation → `soft_status: "confirmed"`
- Test cross-layer dedup: same segment+category from two layers → lower confidence marked `deduped`
- Test LLM dispute annotation: disputed finding has adjusted confidence
- Test LLM confirm annotation: confirmed finding has boost annotation

**Step 3: Run tests**

```bash
uv run pytest tests/test_scoring.py -v
```

Expected: All new tests pass.

**Step 4: Commit**

```bash
git add tests/test_scoring.py
git commit -m "test: rewrite scoring tests for prepare_findings() annotation logic"
```

---

### Task 16: Update Pipeline and Remaining Tests

**Files:**
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_adjudication.py` (if it references verdict)

**Step 1: Read and update test_pipeline.py**

Search for all references to `result.verdict`, `result.risk_score`, `ScoredResult`, `compute_score` in `tests/test_pipeline.py`.

Replace `result.verdict` assertions with `result.risk_label` assertions using the same mapping:
- `"SAFE"` / `"LOW RISK"` → `RiskLabel.LOW`
- `"MEDIUM RISK"` → `RiskLabel.MEDIUM`
- `"HIGH RISK"` → `RiskLabel.HIGH`
- `"CRITICAL"` → `RiskLabel.CRITICAL`

Remove any assertions on `result.risk_score`.

**Step 2: Update test_adjudication.py if needed**

Check for references to `risk_label_to_legacy_verdict()` — if tests call it, remove those tests.

**Step 3: Run full test suite**

```bash
uv run pytest tests/ -x -q 2>&1 | tail -20
```

Expected: All tests pass.

**Step 4: Commit**

```bash
git add tests/
git commit -m "test: update pipeline and adjudication tests for risk_label output"
```

---

### Task 17: Update Benchmark Metrics and Report

**Files:**
- Modify: `src/skillinquisitor/benchmark/metrics.py`
- Modify: `src/skillinquisitor/benchmark/report.py`

**Step 1: Read both files**

Read `src/skillinquisitor/benchmark/metrics.py` and `src/skillinquisitor/benchmark/report.py`.

**Step 2: Update metrics.py**

- Remove `risk_score: int` and `verdict: str` from `BenchmarkResult` (keep `risk_label`, `binary_label`)
- Remove score-based ranking logic (line 376 area: `1 - r.risk_score / 100.0`)
- Update any logic that references `verdict`

**Step 3: Update report.py**

- Remove legacy verdict count tables (line 239-240 area)
- Remove `risk_score` from FN/FP analysis tables (line 236, 386 area)
- Use `risk_label` throughout for all report sections

**Step 4: Commit**

```bash
git add src/skillinquisitor/benchmark/
git commit -m "remove: strip legacy score and verdict from benchmark metrics and reports"
```

---

### Task 18: Update Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `CHANGELOG.md`
- Modify: `TODO.md` (if applicable)
- Modify: `CLAUDE.md`

**Step 1: Read all doc files**

Read each file.

**Step 2: Update README.md**

- Remove all ML ensemble references (Layer 2 description, model table, ML features list)
- Update the three-layer pipeline to a two-layer pipeline (deterministic + LLM)
- Remove legacy scoring section (0-100 score, verdict mapping table, severity weights table)
- Update Risk Scoring section to describe risk_label + binary_label as primary outputs
- Remove `--extra ml` from install instructions
- Update `uv sync` commands
- Remove ML model download from setup instructions
- Update Docker image descriptions (no longer bundle ML models)
- Update configuration example (remove `ml:` section, remove scoring weights/floors)

**Step 3: Update architecture.md**

- Remove ML ensemble from pipeline description
- Update data flow diagrams
- Remove ML-specific config documentation

**Step 4: Update business-requirements.md**

- Reflect simplified two-layer architecture
- Update output model description

**Step 5: Update CHANGELOG.md**

Add entry:
```markdown
## [Unreleased]

### Removed
- ML prompt-injection ensemble (Layer 2) — three HuggingFace classifiers, torch/transformers dependencies, ML fixtures and tests. Documented in docs/archive/ml-ensemble.md.
- Legacy 0-100 numeric scoring — subtractive score, verdict strings, ScoredResult type, severity weights, geometric decay, severity floors.
- `--extra ml` install group and all ML dependencies.

### Changed
- Output model simplified to risk_label (LOW/MEDIUM/HIGH/CRITICAL) + binary_label (malicious/not_malicious) + annotated findings.
- Pipeline is now two-layer: deterministic rules + LLM code analysis.
- Finding-filtering logic (chain absorption, soft gate, dedup, LLM adjustments) preserved as prepare_findings().
- Fixture expected.yaml files migrated from verdict to risk_label.
```

**Step 6: Update CLAUDE.md**

- Update Architecture section to reflect two-layer pipeline
- Remove ML references from Build & Test section
- Update `uv sync` commands

**Step 7: Commit**

```bash
git add README.md docs/ CHANGELOG.md CLAUDE.md TODO.md
git commit -m "docs: update all documentation for ML removal and scoring simplification"
```

---

### Task 19: Phase 1 Verification

**Step 1: Run full test suite**

```bash
./scripts/run-test-suite.sh
```

Expected: All tests pass. No references to ML_ENSEMBLE, compute_score, ScoredResult, verdict (in production code), risk_score remain.

**Step 2: Verify no dead imports**

```bash
cd /Users/peterkarman/git/DryRunSec/SkillInquisitor
grep -r "from skillinquisitor.detectors.ml" src/
grep -r "MLConfig\|WeightedModelConfig\|ML_ENSEMBLE" src/
grep -r "compute_score\|ScoredResult\|_score_to_verdict\|ScoringWeightsConfig" src/
grep -r "risk_score\|\.verdict" src/skillinquisitor/ --include="*.py"
```

Expected: No matches.

**Step 3: Verify the scanner runs end-to-end**

```bash
uv run skillinquisitor scan tests/fixtures/deterministic/encoding/D-3-base64/ --format json 2>/dev/null | python -m json.tool | head -20
```

Expected: JSON output with `risk_label`, `binary_label`, findings — no `risk_score` or `verdict`.

**Step 4: Commit any fixups**

If any stragglers found, fix and commit.

---

## Phase 2: Remove VRAM Auto-Detection

### Task 20: Simplify Model Group Selection

**Files:**
- Modify: `src/skillinquisitor/detectors/llm/models.py`

**Step 1: Read the file**

Read `src/skillinquisitor/detectors/llm/models.py` in full.

**Step 2: Delete hardware detection functions**

Remove:
- Lines 24-27: `HardwareProfile` dataclass
- Lines 54-65: `detect_hardware_profile()` function
- Lines 68-105: `_detect_gpu_profile()` function
- Lines 108-124: `_detect_mps_memory_gb()` function
- Any imports only used by these functions (subprocess, shutil for `which`, torch conditional imports)

**Step 3: Simplify select_llm_model_group()**

Replace the current function (lines 127-147) with:

```python
def select_llm_model_group(
    requested_group: str | None = None,
    default_group: str = "tiny",
) -> str:
    """Return the requested group or fall back to default (tiny)."""
    return requested_group or default_group
```

**Step 4: Simplify resolve_group_models()**

Update `resolve_group_models()` (lines 150-169):
- Remove `hardware` parameter
- Remove GPU-conditional logic
- Keep: explicit models list override, group lookup from `model_groups`, fallback to tiny

```python
def resolve_group_models(
    config: ScanConfig,
    requested_group: str | None = None,
) -> tuple[str, list[LLMModelConfig]]:
    llm = config.layers.llm
    if llm.models:
        return ("custom", list(llm.models))
    group = select_llm_model_group(requested_group, llm.default_group)
    models = list(llm.model_groups.get(group) or [])
    if not models and group != "tiny":
        models = list(llm.model_groups.get("tiny") or [])
        group = "tiny"
    return (group, models)
```

**Step 5: Remove hardware parameter from build_code_analysis_model()**

Line 440: Remove `hardware: HardwareProfile` parameter. The accelerator for llama-server can default to "cpu" or be derived from a simpler config field if needed.

**Step 6: Commit**

```bash
git add src/skillinquisitor/detectors/llm/models.py
git commit -m "remove: delete VRAM auto-detection, simplify model group selection"
```

---

### Task 21: Remove Config Fields

**Files:**
- Modify: `src/skillinquisitor/models.py`

**Step 1: Read models.py**

Read `src/skillinquisitor/models.py`, focusing on `LLMConfig`.

**Step 2: Remove VRAM config fields**

From `LLMConfig` (around lines 351-369), remove:
- `auto_select_group: bool = True`
- `gpu_min_vram_gb_for_balanced: float = 8.0`
- `device_policy: str = "auto"`

Keep:
- `default_group: str = "tiny"`
- `model_groups: dict`
- All other LLM fields

**Step 3: Commit**

```bash
git add src/skillinquisitor/models.py
git commit -m "remove: strip VRAM config fields from LLMConfig"
```

---

### Task 22: Update All Callers

**Files:**
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `src/skillinquisitor/adjudication.py`
- Modify: `src/skillinquisitor/detectors/llm/judge.py`
- Modify: `src/skillinquisitor/benchmark/runner.py`
- Modify: `src/skillinquisitor/cli.py`

**Step 1: Read all five files**

**Step 2: Update runtime.py**

- Remove import of `detect_hardware_profile` (line 16 area)
- At line 169-170: Remove `hardware = detect_hardware_profile(...)` call. Change `resolve_group_models()` call to not pass `hardware`:
```python
group_name, model_configs = resolve_group_models(config, requested_group=requested_group)
```

**Step 3: Update adjudication.py**

- Lines 14-15: Remove `detect_hardware_profile` import
- Line 858: Remove `hardware = detect_hardware_profile(...)` call
- Lines 859-862: Simplify `resolve_group_models()` call to not pass `hardware`

**Step 4: Update judge.py**

- Line 15: Remove `detect_hardware_profile` import
- Line 148: Remove `hardware = detect_hardware_profile(...)` call
- Line 149: Simplify `resolve_group_models()` call to not pass `hardware`

**Step 5: Update benchmark/runner.py**

- Line 29: Remove `detect_hardware_profile` import
- Lines 171-175: Remove hardware detection for concurrency. Replace with fixed conservative default:
  - `max_workers = 2` for full-stack (deterministic + LLM) runs
  - Higher (e.g., `min(4, os.cpu_count() or 2)`) for deterministic-only runs
  - `--concurrency` flag still overrides
- Remove `resolve_group_models()` hardware parameter usage

**Step 6: Update cli.py**

- Lines 439-440: Simplify `--llm-group` override. Instead of setting both `default_group` and `auto_select_group = False`, just set `default_group`:
```python
if llm_group:
    overrides["layers"]["llm"]["default_group"] = llm_group
```
Remove the `auto_select_group` line.

**Step 7: Commit**

```bash
git add src/skillinquisitor/runtime.py src/skillinquisitor/adjudication.py \
  src/skillinquisitor/detectors/llm/judge.py src/skillinquisitor/benchmark/runner.py \
  src/skillinquisitor/cli.py
git commit -m "remove: strip hardware detection from all callers of model group selection"
```

---

### Task 23: Update Docker Config and Tests

**Files:**
- Modify: `docker/skillinquisitor-container-config.yaml`
- Modify: `tests/test_llm.py`
- Modify: `tests/test_benchmark_runner.py`
- Modify: `tests/test_cli.py`

**Step 1: Update Docker config**

Read `docker/skillinquisitor-container-config.yaml`. Remove the `auto_select_group: false` line (field no longer exists in schema).

**Step 2: Update test_llm.py**

- Remove `test_select_llm_model_group_prefers_tiny_for_cpu_and_balanced_for_8gb_gpu()` (lines 114-135)
- Remove any tests that construct `HardwareProfile` or mock `detect_hardware_profile`
- Add a simple test:
```python
def test_select_llm_model_group_defaults_to_tiny():
    assert select_llm_model_group() == "tiny"

def test_select_llm_model_group_respects_requested():
    assert select_llm_model_group(requested_group="balanced") == "balanced"
```

**Step 3: Update test_benchmark_runner.py**

Remove hardware-mocking test scenarios that construct HardwareProfile for MPS/CUDA scenarios. Simplify to test that concurrency uses fixed defaults.

**Step 4: Update test_cli.py**

Remove assertions about `auto_select_group` being set to False. The `--llm-group` test should just verify `default_group` is set.

**Step 5: Run tests**

```bash
uv run pytest tests/test_llm.py tests/test_benchmark_runner.py tests/test_cli.py -v
```

Expected: All pass.

**Step 6: Commit**

```bash
git add docker/ tests/
git commit -m "remove: strip VRAM auto-detection from Docker config and tests"
```

---

### Task 24: Phase 2 Documentation and Final Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `CHANGELOG.md`
- Modify: `CLAUDE.md`

**Step 1: Update docs**

In README.md:
- Remove VRAM auto-detection description from LLM section
- Simplify model group description: "tiny is the default; use `--llm-group balanced` to override"
- Remove references to `auto_select_group`, `device_policy`, `gpu_min_vram_gb_for_balanced`

In architecture.md:
- Remove hardware detection description

In CHANGELOG.md, add to Unreleased:
```markdown
- VRAM auto-detection removed. Model group defaults to `tiny`; use `--llm-group` to override.
- Removed config fields: `auto_select_group`, `gpu_min_vram_gb_for_balanced`, `device_policy`.
- Benchmark concurrency uses fixed conservative defaults instead of GPU probing.
```

**Step 2: Run full test suite**

```bash
./scripts/run-test-suite.sh
```

Expected: All tests pass.

**Step 3: Final dead code check**

```bash
grep -r "detect_hardware_profile\|HardwareProfile\|_detect_gpu_profile\|_detect_mps_memory" src/
grep -r "auto_select_group\|gpu_min_vram_gb_for_balanced\|device_policy" src/
```

Expected: No matches.

**Step 4: End-to-end verification**

```bash
uv run skillinquisitor scan tests/fixtures/deterministic/encoding/D-3-base64/ --format json 2>/dev/null | python -m json.tool | head -20
uv run skillinquisitor scan tests/fixtures/safe/simple-formatter/ --format json 2>/dev/null | python -m json.tool | head -20
```

Expected: Clean JSON with risk_label, binary_label, findings. No legacy fields. No errors.

**Step 5: Commit**

```bash
git add README.md docs/ CHANGELOG.md CLAUDE.md
git commit -m "docs: update documentation for VRAM auto-detection removal"
```
