# Parallel Scan and Benchmark Runtime — Design Spec

## Problem

Full-stack scans are much slower than they need to be because heavyweight ML and LLM resources are recreated inside each scan.

Today:

- Benchmark runs are hard-serialized in [`src/skillinquisitor/benchmark/runner.py`](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/benchmark/runner.py).
- The ML layer already supports bounded concurrency inside one scan, but still loads and unloads model state per scan.
- The LLM layer starts and kills fresh `llama-server` processes per model per scan, then repeats that cycle again for repo-wide analysis.
- `repomix` is also executed per skill with no benchmark- or command-scoped caching.

This keeps memory usage conservative, but it leaves a lot of throughput on the table for both:

- `skillinquisitor scan` on machines that want parallel skill processing
- `skillinquisitor benchmark run` on machines that can hold multiple models in memory

The goal is to add safe parallelism without regressing low-memory users.

---

## 1. Design Summary

The implementation will introduce a shared command-scoped runtime that sits underneath both the normal scan path and the benchmark runner.

That runtime will:

- own shared ML execution state
- own shared LLM server pools
- own global concurrency controls and memory-conscious admission gates
- cache repo packing where appropriate
- expose telemetry for warm-vs-cold behavior and queueing

Both `scan` and `benchmark run` will use the same pipeline/runtime architecture. The benchmark runner will no longer need a one-off performance path.

The default behavior stays conservative:

- one benchmark worker or scan worker by default
- one global heavyweight ML slot by default
- one in-flight request per LLM model by default
- no requirement to keep multiple models resident unless the user opts in
- no command-scoped residency by default in the initial rollout

High-memory users can then opt into:

- resident LLM servers for the full command lifetime
- more benchmark or scan workers
- higher per-model request parallelism
- more global ML slots

---

## 2. Approaches Considered

### 2.1 Recommended: Shared Command-Scoped Runtime

Create a `ScanRuntime` / `PipelineRuntime` object that is instantiated once per command and passed into `run_pipeline(...)`.

Pros:

- one architecture for both `scan` and `benchmark`
- lets us solve model lifecycle once
- supports conservative defaults and high-memory tuning
- easiest path to future telemetry and resource policy

Cons:

- requires touching the shared scan path
- requires careful detector injection boundaries

### 2.2 Benchmark-Only Parallel Runtime

Build a separate benchmark execution path with pooled resources, while leaving `scan` untouched.

Pros:

- smaller short-term diff
- faster path to benchmark-only speedups

Cons:

- duplicates lifecycle logic
- does not help normal `scan`
- would likely need to be refactored away later

### 2.3 Global Cross-Command Daemon

Run a long-lived background process that owns model servers and accepts work from multiple commands.

Pros:

- best possible warm-start behavior
- can amortize model startup across many commands

Cons:

- much higher complexity
- port ownership, stale config, cleanup, and debugging become harder
- surprising behavior for local users

This is explicitly out of scope for the first implementation.

---

## 3. Chosen Architecture

### 3.1 New Runtime Layer

Add a new command-scoped runtime object:

```python
class ScanRuntime:
    ml: MLRuntimeCoordinator
    llm: LLMRuntimeCoordinator
    telemetry: RuntimeTelemetry

    async def close(self) -> None: ...
```

`ScanRuntime` is created:

- once per `skillinquisitor scan` invocation
- once per `skillinquisitor benchmark run` invocation

It is then passed through the pipeline:

```python
await run_pipeline(skills=skills, config=config, runtime=runtime)
```

If no runtime is provided, the pipeline creates a conservative ephemeral runtime so existing call sites still work.

### 3.2 Execution Model

Adding worker concurrency at the command layer is necessary but not sufficient. Several heavyweight sections still block today, so the implementation must make those runtime boundaries async-safe before promising meaningful overlap.

The initial execution model is:

- async worker tasks at the command layer
- blocking heavyweight boundaries moved behind `asyncio.to_thread(...)` or async subprocess APIs where needed
- runtime-owned semaphores and queues for ML and LLM work

Important caveats:

- deterministic rule execution remains synchronous Python in the initial rollout
- phase 1 does not promise immediate speedups for every deterministic-only workload shape
- the first gains come from honest concurrency controls, scan-scoped reuse, and non-event-loop-blocking ML/LLM orchestration

### 3.3 ML Runtime Coordinator

The ML coordinator is responsible for memory ownership across scans.

Responsibilities:

- build model wrappers once per command when reuse is enabled
- enforce a global async semaphore for heavy ML inference slots
- optionally keep model state resident between scans
- expose telemetry for load time, inference time, and queue wait

Low-memory default:

- `global_slots = 1`
- resident reuse disabled or limited to scan-scoped reuse

High-memory mode:

- `global_slots > 1`
- optional resident models across the full command lifetime

This means multiple benchmark or scan workers can overlap deterministic checks, input loading, normalization, and waiting, while the ML coordinator still guarantees safe bounded memory behavior.

### 3.4 LLM Runtime Coordinator

The LLM coordinator is responsible for managing shared `llama-server` instances keyed by model identity.

Responsibilities:

- start resident model servers on demand
- reuse them across all scans in the command
- enforce bounded in-flight request counts per model
- evict or close servers according to lifecycle policy
- expose cold-start time, queue wait, request duration, and reuse counts

Keyed by:

- model id
- resolved model path
- context window
- accelerator / device settings
- runtime-relevant server args

The existing `CodeAnalysisModel` abstraction remains, but `load()` and `unload()` will no longer always mean “spawn process” and “kill process”. In persistent modes they become acquire/release operations against a shared registry.

Pooled LLM execution requires an async-safe adapter boundary. The implementation may keep the current synchronous model wrappers internally, but pooled modes must not call blocking `load()` or `generate_structured()` directly on the event loop. The runtime layer must expose async methods and handle blocking model operations via thread offload or an async client boundary.

### 3.5 Repo Packing Cache

Repo packing should move behind runtime-managed caching for command-scoped reuse.

Cache key:

- skill path
- repomix command
- repomix args
- token-budget-relevant config

In the current codebase, benchmark runs scan each skill once, so repo-pack caching is not a primary throughput lever in phase 1. It is still useful later for repeated same-skill scans, reruns inside a long-lived command, and centralizing repo-pack telemetry.

---

## 4. Lifecycle Policies

The core design requirement is that high-memory and low-memory users must both be supported without code forks.

### 4.1 LLM Lifecycle Policies

Add a lifecycle mode for LLM runtime:

- `ephemeral`
  - current behavior
  - load and unload immediately around use
- `scan`
  - keep servers resident for the full scan, including repo review
  - unload after the scan completes
- `command`
  - keep servers resident for the full CLI command
  - shared across all scans in that command

Defaults in the initial rollout:

- normal `scan`: `scan`
- `benchmark run`: `scan`

### 4.2 ML Lifecycle Policies

Add a similar lifecycle mode for ML runtime:

- `ephemeral`
  - current behavior
- `scan`
  - build or load once per scan
- `command`
  - share across the full command lifetime

Defaults in the initial rollout:

- normal `scan`: `scan`
- `benchmark run`: `scan`

Even in `command` mode, the default global slot count remains `1` unless the user opts in to more.

---

## 5. Parallelism Model

### 5.1 Worker Parallelism

Add real command-level worker parallelism:

- `scan` can parallelize across multiple resolved skills
- `benchmark run` can parallelize across manifest entries

This is distinct from detector-internal concurrency.

New concepts:

- command worker count
- ML global slot count
- per-LLM-model request concurrency

These must be configured separately.

### 5.2 Deterministic Layer

Deterministic checks are CPU-bound and safe to parallelize per skill with no shared heavyweight state.

However, the initial runtime refactor does not assume that an async worker pool alone will deliver major deterministic-only speedups. The first implementation goal is correct bounded concurrency and shared-runtime plumbing, not a dedicated CPU-parallel deterministic executor.

### 5.3 ML Layer

The ML layer remains globally bounded by runtime-owned semaphores.

That means:

- multiple scans can run in parallel
- but only a bounded number of ML-heavy sections execute simultaneously
- low-memory systems can keep this at `1`

Resident ML reuse in later phases uses single-flight semantics per loaded model instance. If a user wants more than one concurrent ML-heavy section, the runtime must allocate more than one model instance; it must not send concurrent work through the same mutable loaded classifier object without explicit proof that the wrapper is thread-safe.

### 5.4 LLM Layer

The LLM layer uses persistent servers plus bounded request concurrency.

That means:

- multiple scans can share the same resident model servers
- each model server handles a bounded number of requests
- request queueing is explicit and measurable

The current hardcoded `--parallel 1` behavior will become configurable.

Until pooled async-safe LLM request handling exists, phase 1 must treat LLM-heavy sections as globally single-flight even if worker concurrency is greater than `1`.

---

## 6. Configuration Changes

### 6.1 Benchmark and Scan Worker Controls

Add command-level concurrency controls:

```yaml
runtime:
  scan_workers: 1
```

CLI equivalents:

- `skillinquisitor scan --workers N`
- `skillinquisitor benchmark run --concurrency N`

### 6.2 ML Runtime Controls

```yaml
layers:
  ml:
    lifecycle: scan          # ephemeral | scan | command
    global_slots: 1
    max_concurrency: 1       # existing per-scan/per-model setting remains
    resident_model_limit: 1
```

`global_slots` controls cross-scan heavy inference parallelism.

### 6.3 LLM Runtime Controls

```yaml
layers:
  llm:
    lifecycle: scan          # ephemeral | scan | command
    resident_model_limit: 1
    idle_ttl_seconds: 300
    server_parallel_requests: 1
    server_threads: 4
    gpu_layers: auto
```

The new knobs separate model-group selection from runtime residency and concurrency.

`resident_model_limit` caps how many models may remain resident at one time. It does not need to equal the size of the active model group.

Example:

- balanced group has 3 models
- `resident_model_limit: 1` means the runtime may keep only one of them warm at once
- that one model can still stay resident across targeted and repo passes within a scan
- loading another model may evict the least recently used resident model

### 6.4 Memory Policy Profiles

Add optional runtime profiles for ergonomics:

- `safe`
  - workers `1`
  - ML global slots `1`
  - LLM request concurrency `1`
  - resident model limit `1`
- `balanced`
  - conservative parallelism with reuse
- `aggressive`
  - intended for large-memory machines

Users can override the underlying numeric settings directly.

### 6.5 Config Precedence

The implementation will preserve and extend the project's existing precedence rules:

1. built-in defaults
2. global config file
3. project config file
4. environment overrides
5. command-specific CLI overrides

Runner-only fields such as benchmark tier, dataset path, output path, baseline path, timeout, threshold, and worker concurrency remain on `BenchmarkRunConfig`.

Shared runtime behavior such as lifecycle, resident limits, ML global slots, and LLM request concurrency belongs in `ScanConfig`.

If a benchmark CLI flag needs to override shared runtime behavior for that one run, it is translated into `cli_overrides` before `ScanConfig` is built, and that explicit benchmark CLI value wins for that run.

---

## 7. Pipeline Changes

### 7.1 `run_pipeline(...)`

`run_pipeline(...)` gains an optional runtime parameter:

```python
async def run_pipeline(
    skills: list[Skill],
    config: ScanConfig,
    runtime: ScanRuntime | None = None,
) -> ScanResult:
    ...
```

`run_ml_ensemble(...)` and `run_llm_analysis(...)` also accept the runtime so they can use shared coordinators instead of instantiating ad hoc detectors every time.

### 7.2 Detector Injection

The pipeline must stop constructing brand-new ML and LLM heavy runtimes by default in parallel-heavy paths.

Instead:

- `MLPromptInjectionEnsemble` becomes a thin executor over models supplied by the runtime
- `LLMCodeJudge` becomes a consumer of runtime-managed model handles or server clients

The existing test seam for injected model objects should remain available.

The runtime contract must also continue to support lightweight or non-server-backed models such as the heuristic LLM runtime. The pooled-runtime design cannot assume every model implementation owns a subprocess.

---

## 8. Benchmark Runner Changes

### 8.1 Honest Concurrency

`BenchmarkRunConfig` gains a real `concurrency` field and the CLI exposes it again.

The runner will:

- build one command-scoped runtime
- use a semaphore-bounded worker pool
- preserve per-skill error isolation
- preserve stable result ordering in saved outputs

### 8.2 Output and Telemetry

Benchmark summaries should record:

- worker concurrency
- ML global slots
- LLM request concurrency
- cold-start counts
- warm reuse counts
- queue wait totals

This is important because warm-server results should not be confused with cold-start results.

### 8.3 Cancellation and Timeout Requirements

Shared runtime means timeout and cancellation behavior must be explicit requirements, not incidental behavior.

Requirements:

- runtime acquire/release operations use structured cleanup
- cancelled scans release ML semaphores and LLM request slots
- timed-out scans do not leave queued LLM work attached to dead callers
- benchmark per-skill timeout still uses `asyncio.wait_for(...)`, but cleanup extends to pooled runtime state
- command shutdown terminates or releases all owned subprocesses deterministically

---

## 9. `scan` Command Changes

The `scan` CLI should support worker parallelism when multiple skills are resolved from one input.

Examples:

- scanning a directory of multiple skills
- scanning a manifest-like local batch in the future

Parallel multi-skill scan must preserve the current CLI output contract:

- `scan` still returns one aggregated `ScanResult`
- formatter behavior remains unchanged
- merged finding ordering must be deterministic
- scoring is recomputed once over the merged findings set after parallel work completes
- normalized skills are merged in input order
- a per-skill pipeline failure still fails the overall `scan` command to preserve current behavior
- total timing remains command-scoped; per-skill timing may be added only as internal telemetry unless formatters are explicitly changed

This is an internal execution optimization, not a user-visible shift to per-skill output.

For a single skill, the main benefit still comes from persistent ML/LLM lifecycle within the scan, especially by avoiding repeated LLM reloads between targeted and repo analysis.

---

## 10. Failure Handling

### 10.1 LLM Server Failures

Persistent mode requires explicit server hygiene:

- failed starts must be removed from the registry
- unhealthy servers must be evicted and recreated
- port ownership must be tracked
- shutdown must terminate all child processes at command end

### 10.2 Backpressure

If workers outpace available ML or LLM slots:

- requests wait on semaphores or per-model queues
- queue wait time is measured
- timeouts surface clearly in per-skill results

### 10.3 Graceful Low-Memory Behavior

Low-memory users must still get correct results:

- defaults stay conservative
- parallelism is opt-in above safe settings
- lifecycle policies can be set back to `ephemeral`

---

## 11. Phased Implementation Plan

### Phase 1: Runtime Scaffolding and Honest Concurrency Controls

Goal:

- add real runtime/session plumbing
- add real benchmark `concurrency`
- keep low-memory-safe defaults

Work:

- add runtime config models
- add `ScanRuntime`
- thread runtime through `run_pipeline(...)`
- update benchmark runner to use a worker semaphore
- add `scan --workers` with unchanged aggregate-output semantics
- move blocking runtime boundaries off the event loop where needed for correctness
- add explicit global single-flight guards for ML and LLM heavy sections
- document that `concurrency > 1` in phase 1 overlaps setup and deterministic work, while ML and LLM still serialize safely by default

Outcome:

- shared runtime boundaries exist for later phases
- concurrency controls become real and testable
- low-memory behavior stays conservative by default

### Phase 2: LLM Scan-Scoped Persistence

Goal:

- eliminate double and repeated `llama-server` reloads inside a scan

Work:

- make `scan` lifecycle mean load once for all prompt jobs and repo review
- update LLM judge to reuse loaded model handles across both passes
- add telemetry for cold starts and reuse

Outcome:

- immediate speedup even with `workers=1`

### Phase 3A: Command-Scoped LLM Server Pool

Goal:

- share resident LLM servers across scans in one command

Work:

- add server registry keyed by model identity
- add bounded per-model request concurrency

Outcome:

- parallel benchmark and scan workers can share the same LLM model servers

### Phase 3B: LLM Eviction, TTL, and Repo Cache

Goal:

- make pooled LLM reuse operationally safe for longer-running commands

Work:

- add idle TTL support
- add eviction behavior for `resident_model_limit`
- add repomix cache
- expand pooled-runtime telemetry

Outcome:

- pooled LLM reuse is robust and observable

### Phase 4: ML Command-Scoped Coordinator

Goal:

- share ML ownership across scans safely

Work:

- add global ML slot semaphore
- allow command-scoped model reuse
- keep default `global_slots=1`
- add opt-in high-memory tuning

Outcome:

- worker parallelism helps even when ML is enabled, without uncontrolled memory duplication

### Phase 5: High-Memory Tuning and Telemetry

Goal:

- make large-memory systems like `128 GB` VRAM setups worth it

Work:

- tune LLM per-model request concurrency
- optionally allow more resident models or duplicate pools in aggressive mode
- improve hardware detection and unified-memory reporting
- publish cold-vs-warm benchmark telemetry

Outcome:

- high-end systems can scale aggressively without making that the default path

---

## 12. Testing Strategy

### 12.1 Unit Tests

- runtime lifecycle policy selection
- ML semaphore behavior
- LLM server registry acquisition and release
- repomix cache hits and misses
- worker ordering and error isolation

### 12.2 Integration Tests

- benchmark runner honors `concurrency`
- deterministic-only benchmarks actually overlap work
- ML-enabled benchmarks preserve safe default memory ownership
- scan command can process multiple skills in parallel
- LLM persistence removes duplicate load/unload cycles

### 12.3 Regression Tests

- no behavior change in findings, verdicts, or scoring from warm runtime reuse alone
- low-memory defaults remain equivalent to current output

---

## 13. Documentation Updates Required

This work will require synchronizing:

- [`README.md`](/Users/peterkarman/git/SkillInquisitor/README.md)
- [`CHANGELOG.md`](/Users/peterkarman/git/SkillInquisitor/CHANGELOG.md)
- [`TODO.md`](/Users/peterkarman/git/SkillInquisitor/TODO.md)
- [`docs/requirements/architecture.md`](/Users/peterkarman/git/SkillInquisitor/docs/requirements/architecture.md)
- benchmark design docs that currently describe concurrency more optimistically than the implementation

---

## 14. Recommendation

Implement the shared command-scoped runtime in phases, starting with honest concurrency controls and scan-scoped LLM persistence.

That sequencing gives the biggest performance win per unit of risk:

- Phase 1 fixes benchmark truthfulness and establishes safe shared-runtime boundaries
- Phase 2 speeds up normal scans immediately
- Phase 3 and 4 unlock shared heavy-resource parallelism safely
- Phase 5 lets very large-memory machines scale further without forcing that complexity onto everyone
