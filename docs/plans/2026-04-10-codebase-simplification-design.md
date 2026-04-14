# Codebase Simplification Design

**Date:** 2026-04-10
**Goal:** Aggressively simplify the codebase by removing the ML ensemble, legacy numeric scoring, and VRAM auto-detection.

## Motivation

The scanner works but is harder to understand than it needs to be. Three subsystems add complexity without proportional value today:

1. **ML prompt-injection ensemble** -- three HuggingFace classifiers with sequential load/unload, weighted voting, chunking, and borderline-to-soft marking. Heavy dependency tree (torch, transformers, huggingface_hub). Can be brought back later if needed.
2. **Legacy 0-100 numeric scoring** -- subtractive score with geometric decay, severity floors, suppression multipliers, and verdict strings. The actual decisions (CLI exit code, benchmark metrics, binary malicious/not_malicious) already use `risk_label` and `binary_label` from adjudication. The numeric score is vestigial.
3. **VRAM auto-detection** -- GPU probing via PyTorch, nvidia-smi, and macOS sysctl to auto-select "balanced" model group at >= 8GB VRAM. Over-engineered for the current state where tiny and balanced produce identical benchmark accuracy.

## Output Model After Simplification

Every scan produces:

- `risk_label`: LOW | MEDIUM | HIGH | CRITICAL
- `binary_label`: malicious | not_malicious
- `findings`: full list of all findings from all active layers, annotated with their processing status (absorbed, soft-confirmed, soft-rejected, disputed, confirmed, deduped)

The 0-100 `risk_score`, legacy `verdict` strings ("SAFE", "LOW RISK", etc.), and `ScoredResult` type are removed.

## Approach: Two Phases

### Phase 1: Remove ML Ensemble + Remove Legacy Numeric Scoring

ML and scoring are intertwined (cross-layer dedup between ML and deterministic, ML borderline findings feed the soft gate, scoring config covers both). Removing them together avoids intermediate awkward states.

#### 1A: ML Removal

**Deleted entirely:**

- `src/skillinquisitor/detectors/ml/` (ensemble.py, models.py, download.py, __init__.py)
- `tests/test_ml.py`
- `tests/fixtures/ml/` and their entries in `tests/fixtures/manifest.yaml`
- `--extra ml` install group from pyproject.toml (torch, transformers, huggingface_hub, safetensors)

**Removed from other files:**

- `pipeline.py`: `MLPromptInjectionEnsemble` import, `run_ml_ensemble()`, `collect_ml_segments()`, `_expand_ml_segment()`, `_artifact_is_ml_candidate()`, all ML segment collection logic
- `runtime.py`: `InjectionModel`/`build_injection_model` imports, `_ml_pool`, `_MLPoolEntry`, `_PooledInjectionModel`, `get_ml_models()`, `ml_section()`, ML telemetry fields, `ml_lifecycle`/`ml_resident_model_limit`/`ml_global_slots` from RuntimeConfig
- `cli.py`: ML download/list imports and logic, `"ml"` from default layer lists
- `benchmark/runner.py`: ML from default layers, ML lifecycle config, ML-specific concurrency tuning
- `models.py`: `MLConfig`, `WeightedModelConfig`, `ml` field from `LayersConfig`, `DetectionLayer.ML_ENSEMBLE` enum value, ML runtime config fields
- `adjudication.py`: `ml_signals` references in evidence packet building
- `scoring.py`: cross-layer dedup logic referencing ML layer

**Tests updated:**

- `test_pipeline.py`: remove/update tests that mock ML ensemble
- `test_benchmark_runner.py`: remove ML layer selection tests
- `conftest.py`: remove ML scope handling from fixture harness

**Documentation:**

- Write `docs/archive/ml-ensemble.md` documenting how the ML ensemble worked before deletion
- Update README, architecture.md, business-requirements.md

#### 1B: Legacy Numeric Scoring Removal

**Deleted from `scoring.py`:**

- `compute_score()` function (the entire 0-100 deduction math)
- `ScoredResult` dataclass
- `_score_to_verdict()` helper
- `ScoringWeightsConfig` (CRITICAL=30, HIGH=20, MEDIUM=10, LOW=5, INFO=0)
- Severity weights, `decay_factor`, `severity_floors` config fields
- Geometric diminishing returns logic
- Suppression multiplier math

**Finding-filtering logic moves (not deleted):**

The following pre-processing steps currently in `compute_score()` move into a new `prepare_findings()` function (or into adjudication.py directly):

- Chain absorption: D-19 chains absorb component findings, mark `absorbed=True`
- Soft finding gate: unconfirmed soft findings marked rejected, confirmed get annotation
- Cross-layer dedup: same segment+category from multiple layers, keep higher confidence
- LLM dispute/confirm adjustments: findings annotated with LLM disposition

These steps annotate findings instead of computing numeric deductions. All findings stay in the list with metadata like `absorbed_by`, `soft_status`, `deduped`.

**`ScanResult` model:**

- Remove `risk_score: int` field
- Remove `verdict: str` field
- Keep `risk_label`, `binary_label`, `adjudication`, `findings`, `layer_metadata`

**`ScoringConfig` simplification:**

- Remove `weights`, `decay_factor`, `severity_floors`, `suppression_multiplier`
- Keep `chain_absorption`, `soft_confirmed_boost`, `soft_confirmation_threshold`, `llm_dispute_factor`, `llm_confirm_factor`
- Rename to `FindingPolicyConfig` or fold into `DecisionPolicyConfig`
- Remove `keep_legacy_score` no-op flag from `DecisionPolicyConfig`

**Formatter changes:**

- Console: remove legacy score/verdict lines, show risk_label + binary_label as primary output
- JSON: remove `risk_score` and `verdict` fields
- SARIF: remove `verdict` and `risk_score` from properties

**Fixture updates (~100+ files):**

- Migrate every `expected.yaml` from `verdict: "SAFE"` to `risk_label: LOW` (etc.)
- Update regression harness (`conftest.py`) to check `risk_label` instead of `verdict`

**Test changes:**

- `test_scoring.py`: rewrite to test finding-annotation logic (chain absorption, soft gate, dedup, LLM adjustments) instead of numeric scores
- `test_pipeline.py`: update assertions from `result.verdict` to `result.risk_label`

**Benchmark changes:**

- `metrics.py`: remove `risk_score` from `BenchmarkResult`, remove score-based ranking
- `report.py`: remove legacy verdict counts and score-based tables, use risk_label throughout

#### What Stays Unchanged in Phase 1

- All 62 deterministic rules (including soft rule designations)
- LLM layer (judge.py, prompts.py, llm/models.py, llm/download.py)
- Adjudication heuristic logic (escalation ladder, hard guardrails, decisive combos, evidence packets)
- Soft finding LLM consensus (deterministic soft rules still require 75% LLM consensus)
- Normalization pipeline (segment extraction, provenance chains)
- Input resolution (local/git remote/stdin)
- VRAM auto-detection (Phase 2)
- `--llm-group` flag
- Docker images (just no longer bundle ML models)

### Phase 2: Remove VRAM Auto-Detection

**Deleted from `detectors/llm/models.py`:**

- `_detect_gpu_profile()`: PyTorch CUDA/MPS detection
- `_detect_mps_memory_gb()`: macOS sysctl memory query
- `detect_hardware_profile()`: multi-fallback detection orchestrator
- `HardwareProfile` dataclass
- `auto_select_group` branch in `select_llm_model_group()` that compares VRAM to threshold

**`select_llm_model_group()` becomes:**

```python
def select_llm_model_group(requested_group: str | None, default_group: str = "tiny") -> str:
    return requested_group or default_group
```

**`resolve_group_models()` simplification:**

- Remove `hardware` parameter
- Remove GPU-conditional logic
- Look up group name in `model_groups` dict with fallback to tiny

**Config model cleanup (`models.py`):**

- Remove `auto_select_group`, `gpu_min_vram_gb_for_balanced`, `device_policy` from `LLMConfig`
- Keep `default_group: str = "tiny"`
- Keep `model_groups` dict (tiny, balanced, large definitions stay)

**Callers updated:**

- `runtime.py`: remove `hardware` parameter from `resolve_group_models()` call, remove import
- `adjudication.py`: remove hardware detection call and import
- `judge.py`: remove hardware detection call and import
- `benchmark/runner.py`: remove hardware detection from model group selection; simplify concurrency to fixed conservative default (2 workers for full-stack, higher for deterministic-only)

**CLI:**

- `--llm-group` flag stays as-is
- Override just sets `default_group` directly (no `auto_select_group = False` needed)

**Tests:**

- `test_llm.py`: remove auto-detection tests, add simple default-is-tiny test
- `test_benchmark_runner.py`: remove/simplify hardware-mocking scenarios
- `test_cli.py`: largely unchanged

**Docker:**

- Remove `auto_select_group` line from container config (field no longer exists)
