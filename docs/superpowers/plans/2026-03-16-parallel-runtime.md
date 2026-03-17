# Parallel Runtime Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a shared runtime foundation that enables honest benchmark concurrency, internal multi-skill scan concurrency, and scan-scoped LLM reuse without breaking low-memory defaults or current scan output behavior.

**Architecture:** Introduce a shared runtime object that can be passed through `run_pipeline(...)`, with explicit concurrency ownership: benchmark worker count stays on `BenchmarkRunConfig`, scan worker count lives in shared scan/runtime config, and ML/LLM heavy sections remain globally single-flight by default. Phase 1 establishes the runtime seams and safe concurrency model; phase 2 uses those seams to remove repeated LLM startup inside one scan; later phases extend that to command-scoped pools and richer telemetry.

**Tech Stack:** Python, asyncio, Pydantic, Typer, pytest, unittest.mock, llama.cpp `llama-server`, Hugging Face/transformers wrappers, repo-local docs

---

## Chunk 1: Contracts And Runtime Scaffolding

### Task 1: Define runtime config ownership, lifecycle shape, and fallback runtime contracts

**Files:**
- Modify: `src/skillinquisitor/models.py`
- Create: `src/skillinquisitor/runtime.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_benchmark_runner.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for worker-config ownership and runtime-aware pipeline signatures**

```python
def test_benchmark_run_config_exposes_concurrency():
    config = BenchmarkRunConfig(concurrency=3)
    assert config.concurrency == 3


def test_scan_config_runtime_defaults():
    config = ScanConfig()
    assert config.runtime.scan_workers == 1
    assert config.runtime.ml_global_slots == 1
    assert config.runtime.llm_global_slots == 1
    assert config.runtime.ml_lifecycle == "scan"
    assert config.runtime.llm_lifecycle == "scan"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_benchmark_runner.py tests/test_cli.py tests/test_pipeline.py -q -k 'concurrency or runtime'`
Expected: FAIL because `BenchmarkRunConfig` has no `concurrency`, `ScanConfig` has no `runtime`, and pipeline/runtime hooks do not exist yet

- [ ] **Step 3: Implement minimal runtime contracts and config fields**

```python
class RuntimeConfig(BaseModel):
    scan_workers: int = 1
    ml_global_slots: int = 1
    llm_global_slots: int = 1
    ml_lifecycle: str = "scan"
    llm_lifecycle: str = "scan"


class ScanRuntime:
    def __init__(self, config: ScanConfig) -> None:
        ...

    @classmethod
    def from_config(cls, config: ScanConfig) -> "ScanRuntime":
        return cls(config)
```

- [ ] **Step 4: Re-run targeted tests to verify they pass**

Run: `uv run pytest tests/test_benchmark_runner.py tests/test_cli.py tests/test_pipeline.py -q -k 'concurrency or runtime'`
Expected: PASS

### Task 2: Thread optional runtime through the pipeline with owned fallback creation

**Files:**
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `src/skillinquisitor/benchmark/runner.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_benchmark_runner.py`

- [ ] **Step 1: Write failing tests proving injected runtime objects are passed through and reused**

```python
@pytest.mark.asyncio()
async def test_run_pipeline_accepts_runtime(monkeypatch):
    runtime = object()
    seen = {}

    async def fake_run_ml_ensemble(skills, config, runtime=None):
        seen["ml_runtime"] = runtime
        return [], {"enabled": True, "findings": 0, "models": []}

    async def fake_run_llm_analysis(skills, config, *, prior_findings, runtime=None):
        seen["llm_runtime"] = runtime
        return [], {"enabled": True, "findings": 0, "models": []}

    ...
    assert seen["ml_runtime"] is runtime
    assert seen["llm_runtime"] is runtime


@pytest.mark.asyncio()
async def test_run_pipeline_creates_fallback_runtime_when_missing(monkeypatch):
    seen = {}
    ...
    assert seen["runtime_created"] is True
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_pipeline.py tests/test_benchmark_runner.py -q -k 'runtime'`
Expected: FAIL because `run_pipeline`, `run_ml_ensemble`, `run_llm_analysis`, and `_scan_single_skill` do not accept runtime yet

- [ ] **Step 3: Implement the minimal parameter threading**

```python
async def run_pipeline(..., runtime: ScanRuntime | None = None) -> ScanResult:
    ...
    ml_findings, ml_metadata = await run_ml_ensemble(normalized_skills, config, runtime=runtime)
    llm_findings, llm_metadata = await run_llm_analysis(..., runtime=runtime)
```

- [ ] **Step 4: Re-run targeted tests to verify pass**

Run: `uv run pytest tests/test_pipeline.py tests/test_benchmark_runner.py -q -k 'runtime'`
Expected: PASS

## Chunk 2: Async-Safe Runtime Guards And Cleanup

### Task 3: Add cleanup-safe runtime guards for ML and LLM heavy sections

**Files:**
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_benchmark_runner.py`

- [ ] **Step 1: Write failing tests proving ML and LLM heavy sections serialize by default and release on exit**

```python
@pytest.mark.asyncio()
async def test_runtime_serializes_llm_sections_by_default(...):
    ...
    assert max_inflight == 1


@pytest.mark.asyncio()
async def test_runtime_releases_slots_when_section_exits(...):
    ...
    assert acquire_count == release_count
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_pipeline.py tests/test_benchmark_runner.py -q -k 'serializes_llm or releases_slots or serializes_ml'`
Expected: FAIL because runtime guards do not exist yet

- [ ] **Step 3: Implement async context-manager guards with structured cleanup**

```python
class ScanRuntime:
    @asynccontextmanager
    async def ml_section(self):
        async with self._ml_slots:
            yield

    @asynccontextmanager
    async def llm_section(self):
        async with self._llm_slots:
            yield
```

- [ ] **Step 4: Re-run targeted tests to verify pass**

Run: `uv run pytest tests/test_pipeline.py tests/test_benchmark_runner.py -q -k 'serializes_llm or releases_slots or serializes_ml'`
Expected: PASS

### Task 4: Move blocking LLM work off the event loop and cover timeout/cancel cleanup

**Files:**
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `src/skillinquisitor/detectors/llm/judge.py`
- Modify: `tests/test_llm.py`
- Modify: `tests/test_benchmark_runner.py`

- [ ] **Step 1: Write failing tests proving blocking LLM execution is offloaded and timed-out work releases runtime state**

```python
@pytest.mark.asyncio()
async def test_llm_runtime_offloads_blocking_generation(monkeypatch):
    ...
    assert to_thread_calls >= 1


@pytest.mark.asyncio()
async def test_timeout_releases_runtime_llm_slot(...):
    ...
    assert runtime slot is available after timeout
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_llm.py tests/test_benchmark_runner.py -q -k 'offloads_blocking_generation or releases_runtime_llm_slot'`
Expected: FAIL because the LLM judge still calls synchronous model methods directly and timeout cleanup is not asserted

- [ ] **Step 3: Implement `asyncio.to_thread(...)` offload and timeout-safe cleanup hooks**

```python
async def _run_blocking_llm(self, fn, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)
```

- [ ] **Step 4: Re-run targeted tests to verify pass**

Run: `uv run pytest tests/test_llm.py tests/test_benchmark_runner.py -q -k 'offloads_blocking_generation or releases_runtime_llm_slot'`
Expected: PASS

## Chunk 3: Honest Worker Concurrency

### Task 5: Add real benchmark worker concurrency with stable ordering and safe defaults

**Files:**
- Modify: `src/skillinquisitor/benchmark/runner.py`
- Modify: `src/skillinquisitor/cli.py`
- Modify: `tests/test_benchmark_runner.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests for `BenchmarkRunConfig.concurrency`, CLI `--concurrency`, stable ordering, and safe layered defaults**

```python
def test_benchmark_cli_accepts_concurrency_option():
    ...


@pytest.mark.asyncio()
async def test_run_benchmark_preserves_manifest_order_with_concurrency(...):
    ...
    assert [r.skill_id for r in run.results] == ["safe-001", "mal-001", "ambig-001"]
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_benchmark_runner.py tests/test_cli.py -q -k 'concurrency or manifest_order'`
Expected: FAIL because runner and CLI do not implement benchmark concurrency

- [ ] **Step 3: Implement benchmark worker concurrency using the shared runtime**

```python
async def run_benchmark(config: BenchmarkRunConfig) -> BenchmarkRun:
    semaphore = asyncio.Semaphore(max(1, config.concurrency))
    runtime = ScanRuntime(scan_config)
    ...
```

- [ ] **Step 4: Re-run targeted tests to verify pass**

Run: `uv run pytest tests/test_benchmark_runner.py tests/test_cli.py -q -k 'concurrency or manifest_order'`
Expected: PASS

### Task 6: Add `scan --workers` with deterministic aggregate merge and unchanged formatter contract

**Files:**
- Modify: `src/skillinquisitor/cli.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for multi-skill aggregate merge ordering, score recomputation, and failure propagation**

```python
def test_scan_command_accepts_workers_option():
    ...


@pytest.mark.asyncio()
async def test_parallel_skill_results_merge_into_one_scan_result(...):
    ...
    assert merged.skills order is deterministic
    assert merged scoring is recomputed


@pytest.mark.asyncio()
async def test_parallel_scan_propagates_per_skill_failure(...):
    ...
    with pytest.raises(RuntimeError):
        ...
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_cli.py tests/test_pipeline.py -q -k 'workers or aggregate or propagates_per_skill_failure'`
Expected: FAIL because `scan` has no `--workers` and aggregate merge behavior is not implemented

- [ ] **Step 3: Implement scan worker plumbing with deterministic merged output**

```python
@app.command()
def scan(..., workers: int = typer.Option(1, "--workers")) -> None:
    ...
```

- [ ] **Step 4: Re-run targeted tests to verify pass**

Run: `uv run pytest tests/test_cli.py tests/test_pipeline.py -q -k 'workers or aggregate or propagates_per_skill_failure'`
Expected: PASS

## Chunk 4: Scan-Scoped LLM Persistence

### Task 7: Reuse loaded LLM model handles across general, targeted, and repo analysis inside one scan

**Files:**
- Modify: `src/skillinquisitor/detectors/llm/judge.py`
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `tests/test_llm.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests proving one load/unload cycle per model per scan**

```python
@pytest.mark.asyncio()
async def test_llm_scan_lifecycle_loads_once_for_general_and_repo():
    model = FakeCodeAnalysisModel()
    judge = LLMCodeJudge(models=[model])
    ...
    assert model.load_calls == 1
    assert model.unload_calls == 1
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_llm.py tests/test_pipeline.py -q -k 'loads_once_for_general_and_repo or scan_lifecycle'`
Expected: FAIL because the judge currently loads/unloads once for prompt jobs and again for repo jobs

- [ ] **Step 3: Implement scan-scoped LLM lifecycle reuse**

```python
for model in models:
    await runtime.load_model(model)
    try:
        ...
        ...
    finally:
        await runtime.unload_model(model)
```

- [ ] **Step 4: Re-run targeted tests to verify pass**

Run: `uv run pytest tests/test_llm.py tests/test_pipeline.py -q -k 'loads_once_for_general_and_repo or scan_lifecycle'`
Expected: PASS

## Chunk 5: Telemetry, Docs, And Phase 2+ Plan Sync

### Task 8: Add benchmark runtime telemetry fields and sync docs

**Files:**
- Modify: `src/skillinquisitor/benchmark/runner.py`
- Modify: `src/skillinquisitor/benchmark/report.py`
- Modify: `tests/test_benchmark_runner.py`
- Modify: `tests/test_benchmark_report.py`
- Modify: `README.md`
- Modify: `TODO.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `docs/superpowers/specs/2026-03-16-parallel-runtime-design.md`

- [ ] **Step 1: Write failing tests for telemetry persistence and report rendering**

```python
def test_summary_includes_runtime_telemetry(tmp_path):
    run = BenchmarkRun(...)
    save_results(run, tmp_path)
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert "runtime" in summary
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_benchmark_runner.py tests/test_benchmark_report.py -q -k 'runtime telemetry'`
Expected: FAIL because runtime telemetry is not persisted yet

- [ ] **Step 3: Implement minimal telemetry schema and sync documentation to shipped behavior**

```python
summary["runtime"] = {
    "benchmark_concurrency": ...,
    "scan_workers": ...,
    "ml_global_slots": ...,
    "llm_global_slots": ...,
}
```

- [ ] **Step 4: Run full targeted verification for the shipped slice**

Run: `uv run pytest tests/test_benchmark_runner.py tests/test_benchmark_report.py tests/test_cli.py tests/test_pipeline.py tests/test_llm.py -q`
Expected: PASS for the changed areas

## Chunk 6: Later Phases

### Task 9: Command-scoped LLM pooling

**Files:**
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `src/skillinquisitor/detectors/llm/judge.py`
- Modify: `src/skillinquisitor/detectors/llm/models.py`
- Test: `tests/test_llm.py`
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Add command-scoped model registry**
- [ ] **Step 2: Add bounded request-slot management per model**
- [ ] **Step 3: Add lifecycle and cleanup verification**
- [ ] **Step 4: Re-run targeted LLM and pipeline tests**

### Task 10: LLM eviction, TTL, and repomix cache

**Files:**
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `src/skillinquisitor/detectors/llm/judge.py`
- Test: `tests/test_llm.py`
- Test: `tests/test_benchmark_runner.py`

- [ ] **Step 1: Add eviction and TTL policies**
- [ ] **Step 2: Add repo-pack caching**
- [ ] **Step 3: Add telemetry for warm/cold reuse**
- [ ] **Step 4: Re-run targeted tests**

### Task 11: ML command-scoped coordinator

**Files:**
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `src/skillinquisitor/detectors/ml/ensemble.py`
- Modify: `src/skillinquisitor/detectors/ml/models.py`
- Test: `tests/test_ml.py`
- Test: `tests/test_pipeline.py`
- Test: `tests/test_benchmark_runner.py`

- [ ] **Step 1: Add single-flight loaded-instance coordination**
- [ ] **Step 2: Add optional multi-instance high-memory mode**
- [ ] **Step 3: Verify low-memory default equivalence**
- [ ] **Step 4: Re-run targeted ML, pipeline, and benchmark tests**

### Task 12: High-memory tuning and hardware detection

**Files:**
- Modify: `src/skillinquisitor/runtime.py`
- Modify: `src/skillinquisitor/detectors/llm/models.py`
- Modify: `README.md`
- Modify: `docs/requirements/architecture.md`
- Test: `tests/test_llm.py`
- Test: `tests/test_benchmark_runner.py`

- [ ] **Step 1: Improve device and memory detection**
- [ ] **Step 2: Add aggressive tuning controls**
- [ ] **Step 3: Document high-memory recommendations**
- [ ] **Step 4: Re-run targeted verification**
