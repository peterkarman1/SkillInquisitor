# Hybrid Final Adjudication Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace score-first verdicting with a hybrid final-adjudication pipeline that emits `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`, keeps binary benchmark evaluation flexible, and preserves layered evidence plus hard guardrails.

**Architecture:** Keep deterministic, ML, and targeted/repo LLM evidence collection intact, then add a new evidence-packet and final-adjudication stage after the existing findings pipeline. During migration, retain `risk_score` as compatibility metadata while switching runtime and benchmark truth to the adjudicated risk label plus configurable binary mapping.

**Tech Stack:** Python 3.13, Pydantic models, Typer CLI, pytest, existing deterministic/ML/LLM pipeline, benchmark runner and metrics framework.

---

## File Structure

- Create: `src/skillinquisitor/adjudication.py`
  Responsibility: evidence packet building, guardrail evaluation, final LLM/heuristic adjudication, binary-label mapping helpers.
- Modify: `src/skillinquisitor/models.py`
  Responsibility: add decision-policy config, final adjudicator config, adjudication result models, scan result contract updates.
- Modify: `src/skillinquisitor/pipeline.py`
  Responsibility: call the new adjudication stage after findings collection and propagate adjudication metadata into `ScanResult`.
- Modify: `src/skillinquisitor/scoring.py`
  Responsibility: slim to legacy compatibility scoring and helper usage during migration; keep old path available while no longer driving the primary verdict.
- Modify: `src/skillinquisitor/detectors/llm/judge.py`
  Responsibility: expose reusable model execution path or prompt helpers for final adjudication without entangling targeted verification.
- Modify: `src/skillinquisitor/benchmark/metrics.py`
  Responsibility: classify results from risk labels via configurable binary cutoff and record predicted risk-label metrics.
- Modify: `src/skillinquisitor/benchmark/runner.py`
  Responsibility: store adjudicated labels in benchmark results and pass policy config into metrics.
- Modify: `src/skillinquisitor/config.py`
  Responsibility: ensure new decision-policy and final-adjudicator config fields are parsed, merged, and validated correctly.
- Modify: `src/skillinquisitor/cli.py`
  Responsibility: present adjudicated labels in CLI output and benchmark summaries.
- Modify: `src/skillinquisitor/formatters/console.py`
  Responsibility: render risk labels and adjudication summary instead of score-first messaging.
- Modify: `src/skillinquisitor/formatters/json.py`
  Responsibility: serialize adjudication payload and keep `risk_score` as compatibility metadata if configured.
- Modify: `src/skillinquisitor/formatters/sarif.py`
  Responsibility: map new labels into SARIF severity/level output.
- Modify: `benchmark/manifest.yaml`
  Responsibility: add optional real-dataset review metadata fields and leave room for expected risk labels.
- Test: `tests/test_pipeline.py`
  Responsibility: verify adjudication stage behavior, binary mapping, and merged result behavior.
- Test: `tests/test_config.py`
  Responsibility: verify defaults, env/CLI merge behavior, validation, and cutoff/final-adjudicator toggles for the new config contract.
- Test: `tests/test_scoring.py`
  Responsibility: narrow to compatibility scoring behavior and any helper contracts still intentionally retained.
- Test: `tests/test_llm.py`
  Responsibility: cover final adjudicator prompt/result parsing and fallback logic.
- Test: `tests/test_benchmark_runner.py`
  Responsibility: verify benchmark classification uses adjudicated risk labels rather than thresholds.
- Test: `tests/test_benchmark_metrics.py`
  Responsibility: verify label-based confusion-matrix behavior and risk-label metrics directly.
- Test: `tests/test_benchmark_manifest.py`
  Responsibility: verify old and new manifest schemas load correctly, including review metadata.
- Test: `tests/test_cli.py`
  Responsibility: verify displayed verdicts and benchmark summaries use the new labels.
- Test: `tests/test_formatters.py` or existing formatter test files
  Responsibility: update serialized output expectations for adjudication payloads.
- Modify: `README.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `TODO.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/benchmark-optimization-log-2026-03-16.md`

## Chunk 1: Config and Result Contract

### Task 1: Add decision-policy and adjudication models

**Files:**
- Create: `src/skillinquisitor/adjudication.py`
- Modify: `src/skillinquisitor/models.py`
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing contract tests for adjudication result fields**

Add tests that expect `ScanResult` to carry:
- `risk_label`
- `binary_label`
- `adjudication`

Include one test for an empty scan and one for a scan with findings where the final verdict no longer defaults to `SAFE`.

- [ ] **Step 2: Run the targeted contract tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py -q -k 'empty_pipeline_returns_zero_findings or adjudication'`
Expected: FAIL because `ScanResult` and pipeline output do not yet expose the new fields.

- [ ] **Step 3: Add configuration and result models**

Implement in `src/skillinquisitor/models.py`:
- `RiskLabel` enum or equivalent stable string contract
- `FinalAdjudicatorConfig`
- `GuardrailRuleConfig`
- `DecisionPolicyConfig`
- `EvidenceDriver`
- `AdjudicationResult`

Update `ScanConfig` to include `decision_policy`.
Update `ScanResult` to include:
- `risk_label`
- `binary_label`
- `adjudication`

Keep `risk_score` and legacy `verdict` for migration compatibility in this phase.

- [ ] **Step 4: Add config parsing and validation coverage**

Update `src/skillinquisitor/config.py` and tests so:
- `decision_policy.mode`
- `decision_policy.binary_cutoff`
- `decision_policy.keep_legacy_score`
- `decision_policy.hard_guardrails`
- `layers.llm.final_adjudicator.*`

all have explicit defaults, validation, env/config/CLI override behavior, and merge coverage.

- [ ] **Step 5: Add evidence-packet helpers skeleton**

Create `src/skillinquisitor/adjudication.py` with:
- `build_evidence_packet(...)`
- `determine_guardrail_floor(...)`
- `map_risk_label_to_binary(...)`
- placeholder `final_adjudicate(...)`

Keep the first pass minimal and deterministic so the pipeline can compile before final LLM logic is added.

- [ ] **Step 6: Run the targeted contract and config tests to verify they pass**

Run:
- `uv run pytest tests/test_pipeline.py -q -k 'empty_pipeline_returns_zero_findings or adjudication'`
- `uv run pytest tests/test_config.py -q -k 'decision_policy or final_adjudicator or binary_cutoff or keep_legacy_score or hard_guardrails'`
Expected: PASS

## Chunk 2: Final Adjudication in the Pipeline

### Task 2: Replace score-first verdicting with adjudication-first verdicting

**Files:**
- Modify: `src/skillinquisitor/adjudication.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `src/skillinquisitor/scoring.py`
- Test: `tests/test_pipeline.py`
- Test: `tests/test_llm.py`

- [ ] **Step 1: Write failing tests for adjudication-driven pipeline output**

Add tests that verify:
- the pipeline derives `risk_label` and `binary_label` from adjudication
- guardrails can force a minimum label
- binary output comes from policy mapping rather than directly from a model response
- merged scan results recompute adjudication from merged findings

- [ ] **Step 2: Run the targeted adjudication tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py -q -k 'risk_label or binary_label or guardrail or merge_scan_results'`
Expected: FAIL because the pipeline still uses `compute_score` as the primary decision policy.

- [ ] **Step 3: Implement heuristic-first adjudication**

In `src/skillinquisitor/adjudication.py`:
- build a compact evidence packet from findings
- compute confirmed/disputed categories
- identify high-signal findings and chain findings
- implement guardrail floor evaluation
- implement a conservative heuristic adjudicator for fallback and migration

The heuristic version should produce stable labels even before the final LLM prompt path is added.

- [ ] **Step 4: Make the evidence packet a tested contract**

Define explicit Pydantic or dataclass models for:
- `EvidencePacket`
- `ArtifactEvidenceSummary`
- `EvidenceDriver`

Add tests that verify required contents such as:
- confirmed categories
- disputed categories
- chain findings
- ML signals
- LLM confirmation/dispute signals
- artifact summaries

- [ ] **Step 5: Thread adjudication into the pipeline**

In `src/skillinquisitor/pipeline.py`:
- call `final_adjudicate(...)` after deterministic/ML/LLM findings are collected
- store its results in `ScanResult`
- derive migration-era legacy `verdict` from the adjudicated risk label
- keep `risk_score` only as compatibility metadata, not the source of truth

In `merge_scan_results(...)`:
- recompute adjudication from merged findings
- recompute legacy compatibility fields from the merged adjudication

- [ ] **Step 6: Add final LLM adjudicator support**

Implement prompt and result parsing for final adjudication using existing LLM runtime plumbing, but constrain model output to:
- one risk label
- rationale
- cited drivers

Do not let the model choose `binary_label`; derive that after parsing.

Use the heuristic adjudicator when:
- LLM layer is disabled
- final adjudicator is disabled
- the final prompt returns malformed output

- [ ] **Step 7: Run targeted adjudication and LLM tests**

Run:
- `uv run pytest tests/test_pipeline.py -q -k 'risk_label or binary_label or guardrail or merge_scan_results'`
- `uv run pytest tests/test_llm.py -q -k 'adjudicat'`
Expected: PASS

## Chunk 3: Benchmark Contract Migration

### Task 3: Move benchmark truth from score threshold to risk-label mapping

**Files:**
- Modify: `src/skillinquisitor/benchmark/metrics.py`
- Modify: `src/skillinquisitor/benchmark/runner.py`
- Test: `tests/test_benchmark_runner.py`

- [ ] **Step 1: Write failing benchmark tests for label-based classification**

Add tests asserting:
- `HIGH` and `CRITICAL` classify as flagged under default cutoff
- `LOW` and `MEDIUM` classify as not flagged under default cutoff
- changing the cutoff changes binary classification without changing stored risk labels
- benchmark results retain predicted risk labels

- [ ] **Step 2: Run targeted benchmark tests to verify they fail**

Run: `uv run pytest tests/test_benchmark_runner.py -q -k 'label_based or binary_cutoff or risk_label'`
Expected: FAIL because classification still depends on `risk_score < threshold`.

- [ ] **Step 3: Implement label-based benchmark metrics**

In `src/skillinquisitor/benchmark/metrics.py`:
- add label-based classification helpers
- keep threshold-based classification available only for migration compatibility if required by older tests
- update benchmark metrics to record predicted risk-label distribution

In `src/skillinquisitor/benchmark/runner.py`:
- store `risk_label`, `binary_label`, and adjudication summary in `BenchmarkResult`
- stop treating `threshold` as the primary classification mechanism

- [ ] **Step 4: Make the real dataset primary benchmark authority**

Implement an explicit benchmark-data selection/reporting policy so primary benchmark runs and reports are driven by the real dataset. Synthetic skills may remain loadable for secondary regression coverage, but they must not silently remain part of the primary benchmark scorecard.

Add tests proving the primary benchmark selection path excludes synthetic-only data when that mode is enabled.

- [ ] **Step 5: Add manifest review metadata support**

Extend benchmark data models to accept optional fields like:
- `review_status`
- `reviewer`
- `review_notes`
- `expected_risk_label`

Do not require full corpus relabeling yet; make the schema forward-compatible.

- [ ] **Step 6: Run targeted benchmark and schema tests**

Run:
- `uv run pytest tests/test_benchmark_runner.py -q -k 'label_based or binary_cutoff or risk_label'`
- `uv run pytest tests/test_benchmark_metrics.py -q -k 'label_based or binary_cutoff or risk_label'`
- `uv run pytest tests/test_benchmark_manifest.py -q`
Expected: PASS

## Chunk 4: User-Facing Output and Docs

### Task 4: Switch formatters and docs to the new decision contract

**Files:**
- Modify: `src/skillinquisitor/cli.py`
- Modify: `src/skillinquisitor/formatters/console.py`
- Modify: `src/skillinquisitor/formatters/json.py`
- Modify: `src/skillinquisitor/formatters/sarif.py`
- Modify: `README.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `TODO.md`
- Modify: `CHANGELOG.md`
- Test: `tests/test_cli.py`
- Test: formatter tests

- [ ] **Step 1: Write failing CLI/formatter tests**

Add tests asserting:
- CLI no longer prints `SAFE`
- console output emphasizes `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- JSON output includes the adjudication payload
- SARIF mapping still works with the new labels

- [ ] **Step 2: Run the targeted CLI/formatter tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -q -k 'risk label or adjudication or safe'`
Expected: FAIL because output is still score-era and `SAFE`-oriented.

- [ ] **Step 3: Implement formatter and CLI updates**

Update all user-facing outputs to prefer:
- `risk_label`
- `binary_label`
- adjudication summary and drivers

Retain `risk_score` only in machine-readable compatibility output when configured.

- [ ] **Step 4: Update docs**

Sync:
- `README.md`
- `docs/requirements/architecture.md`
- `docs/requirements/business-requirements.md`
- `TODO.md`
- `CHANGELOG.md`

Document:
- score no longer drives the primary verdict
- no `SAFE` verdict
- benchmark binary mapping is configurable
- real dataset is the benchmark authority

- [ ] **Step 5: Run targeted CLI/formatter tests**

Run:
- `uv run pytest tests/test_cli.py -q`
- `uv run pytest tests -q -k 'formatter or sarif or json'`
Expected: PASS

## Chunk 5: Full Verification and Benchmark Loop

### Task 5: Verify the redesign and rerun the optimization loop

**Files:**
- Modify: `docs/benchmark-optimization-log-2026-03-16.md`

- [ ] **Step 1: Run the full unit/framework suite**

Run: `uv run pytest tests -q`
Expected: PASS

- [ ] **Step 2: Run smoke benchmark with the new decision policy**

Run:
`env SKILLINQUISITOR_LAYERS__LLM__REPOMIX__COMMAND=npx SKILLINQUISITOR_LAYERS__LLM__REPOMIX__ARGS='["-y","repomix"]' uv run skillinquisitor benchmark run --tier smoke --llm-group balanced --concurrency 4 --timeout 300 --output benchmark/results/smoke-hybrid-final-20260317`

Expected:
- successful end-to-end run
- benchmark results now classified from risk labels rather than thresholds
- artifacts written under `benchmark/results/smoke-hybrid-final-20260317`

- [ ] **Step 3: Inspect the smoke result**

Capture:
- precision
- recall
- F1
- category weak spots
- top FP/FN clusters

Run:
- `cat benchmark/results/smoke-hybrid-final-20260317/summary.json`
- `sed -n '1,240p' benchmark/results/smoke-hybrid-final-20260317/report.md`

Update `docs/benchmark-optimization-log-2026-03-16.md` with:
- what changed
- what the new policy improved
- what still regressed or stayed flat

- [ ] **Step 4: Run standard benchmark**

Run:
`env SKILLINQUISITOR_LAYERS__LLM__REPOMIX__COMMAND=npx SKILLINQUISITOR_LAYERS__LLM__REPOMIX__ARGS='["-y","repomix"]' uv run skillinquisitor benchmark run --tier standard --llm-group balanced --concurrency 4 --timeout 300 --output benchmark/results/standard-hybrid-final-20260317`

Expected:
- either measurable improvement in benchmark quality or a clear signal that the architecture change did not solve the core failure modes
- artifacts written under `benchmark/results/standard-hybrid-final-20260317`

- [ ] **Step 5: Decide whether to continue on this path or pivot**

Run:
- `cat benchmark/results/standard-hybrid-final-20260317/summary.json`
- `sed -n '1,260p' benchmark/results/standard-hybrid-final-20260317/report.md`

If the architecture helps:
- continue iterative optimization on evidence quality and final adjudication prompts

If it does not:
- log the failure mode explicitly
- identify whether the next path should focus on dataset relabeling, evidence extraction, or an alternate adjudication policy

Record that decision in `docs/benchmark-optimization-log-2026-03-16.md`.
