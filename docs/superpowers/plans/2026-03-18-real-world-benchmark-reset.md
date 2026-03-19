# Real-World Benchmark Reset Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the benchmark corpus to real-world-only data, removing synthetic and fixture entries from benchmark evaluation while preserving them in the regression suite.

**Architecture:** The benchmark manifest and dataset become an externally sourced corpus containing only `github` safe skills and `malicious_bench` malicious skills. Benchmark profile names, smoke-tier composition, reporting defaults, and tests are updated so the benchmark contract enforces real-world-only behavior by default.

**Tech Stack:** Python, Typer, Pytest, YAML manifest under `benchmark/`

---

## Chunk 1: Contract And Tests

### Task 1: Update benchmark contract tests

**Files:**
- Modify: `tests/test_benchmark_dataset.py`
- Modify: `tests/test_benchmark_runner.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_benchmark_report.py`

- [ ] Add failing tests asserting the benchmark manifest contains only `github` and `malicious_bench`.
- [ ] Add failing tests asserting the smoke tier contains both safe and malicious real-world entries.
- [ ] Update runner/CLI tests to expect `real_world` defaults and `malicious_only` filtering.
- [ ] Run: `uv run pytest tests/test_benchmark_dataset.py tests/test_benchmark_runner.py tests/test_cli.py tests/test_benchmark_report.py -q`
- [ ] Confirm failures reflect the old mixed benchmark contract.

## Chunk 2: Benchmark Code Contract

### Task 2: Rename benchmark profiles around real-world usage

**Files:**
- Modify: `src/skillinquisitor/benchmark/runner.py`
- Modify: `src/skillinquisitor/cli.py`
- Modify: `src/skillinquisitor/benchmark/report.py`

- [ ] Change the default benchmark profile to `real_world`.
- [ ] Support `safe_only` and `malicious_only` dataset profiles.
- [ ] Keep compatibility aliases only where harmless.
- [ ] Ensure report generation has a sane default `dataset_profile`.
- [ ] Run the targeted benchmark tests again and confirm code-contract failures are reduced to dataset-content mismatches.

## Chunk 3: Manifest And Dataset Purge

### Task 3: Remove synthetic and fixture benchmark entries

**Files:**
- Modify: `benchmark/manifest.yaml`
- Delete: `benchmark/dataset/skills/skill-0000` through `benchmark/dataset/skills/skill-0173`

- [ ] Filter the manifest down to `github` and `malicious_bench` entries only.
- [ ] Bump `dataset_version` to reflect the benchmark-breaking corpus change.
- [ ] Retier a balanced subset of real malicious entries into `smoke` so the smoke suite remains meaningful.
- [ ] Delete the removed benchmark skill directories.
- [ ] Run: `uv run pytest tests/test_benchmark_dataset.py tests/test_benchmark_runner.py tests/test_cli.py tests/test_benchmark_report.py -q`
- [ ] Confirm the new real-world-only benchmark contract passes.

## Chunk 4: Docs And Project Sync

### Task 4: Sync benchmark docs to the new corpus

**Files:**
- Modify: `README.md`
- Modify: `TODO.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `docs/research/epic-12-benchmark-dataset-research.md`

- [ ] Update docs to describe the benchmark as real-world-only.
- [ ] Move synthetic/fixture discussion to regression coverage, not benchmark scoring.
- [ ] Record the destructive corpus reset and the new source-family counts.

## Chunk 5: Verification And Baseline

### Task 5: Run the benchmark and capture the new baseline

**Files:**
- Output: `benchmark/results/<run-id>/summary.json`
- Output: `benchmark/results/<run-id>/report.md`

- [ ] Run: `uv run pytest tests -q`
- [ ] Run the updated real-world smoke benchmark.
- [ ] Run the updated real-world standard benchmark.
- [ ] Summarize:
  - all real-world benchmark entries
  - `safe_only`
  - `malicious_only`
- [ ] Note any immediate blind spots for the next optimization pass.
