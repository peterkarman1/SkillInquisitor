# Benchmark Optimization Log

## Goal

Raise benchmark quality and runtime performance without overfitting to individual benchmark skills. Changes must generalize to future unseen datasets.

## Rules

- No fixture-specific cheats or benchmark-specific hardcoding.
- Keep the full unit and framework test suite green.
- Record every meaningful experiment, whether it helps or not.

## Environment Notes

- Date: 2026-03-16
- Branch: `codex/parallel-runtime-phase1`
- Starting commit for this pass: `1966e7d`

## Experiment Log

### 2026-03-16 1. Baseline collection

- Status: completed
- Notes:
  - Verified balanced models are configured and cached.
  - Confirmed Apple Silicon hardware detection now reports available unified memory for runtime policy decisions.
  - Refreshed the full unit/framework suite after runtime/test alignment work.
- Evidence:
  - `uv run pytest tests -q` -> `481 passed` before the later scoring/runtime tuning pass.
  - `uv run skillinquisitor models list` showed the balanced group cached locally.

### 2026-03-16 2. Benchmark control-path fix

- Status: completed
- Hypothesis:
  - The benchmark runner was not honoring environment-based config overrides, which made it impossible to force the intended `balanced` group or repomix command from the CLI environment.
- Change:
  - Benchmark config construction now passes process environment through `load_config(...)`.
  - Added benchmark CLI support for `--llm-group`.
- Outcome:
  - Confirmed balanced-model benchmark launches now use the intended balanced GGUF set instead of silently falling back to `tiny`.
- Evidence:
  - Targeted tests:
    - `uv run pytest tests/test_benchmark_runner.py tests/test_cli.py -q -k 'llm_group or process_environment or concurrency_option'` -> `4 passed`
  - Live verification:
    - observed `llama-server` processes for `NVIDIA-Nemotron-3-Nano-4B`, `OmniCoder-9B`, and `Qwen3.5-9B` during benchmark launch.

### 2026-03-16 3. LLM structured-output tightening

- Status: completed
- Hypothesis:
  - The local llama runtime was spending too much time producing long reasoning-heavy responses even though the judge only needs a short JSON object.
- Change:
  - Reduced default LLM `max_output_tokens` from `512` to `256`.
  - Stopped forcing Qwen-specific thinking mode in the llama-server command.
  - Added `Connection: close` on local chat-completion requests to make the HTTP behavior more deterministic.
- Outcome:
  - Focused LLM/runtime tests stayed green.
  - Manual balanced-model probes returned valid structured responses quickly.
  - This reduced per-request token budget and removed one obvious source of runaway response length.
- Evidence:
  - `uv run pytest tests/test_llm.py -q -k 'config_defaults_to_tiny_balanced_large_groups or qwen_llama_server_command_does_not_force_thinking_mode or llama_cpp_generate_structured_requests_connection_close or llm_judge_runs_models_sequentially_and_emits_targeted_finding or llm_judge_degrades_gracefully_when_one_model_returns_malformed_output or llm_judge_loads_models_once_for_successful_repo_bundle_analysis or llm_command_runtime_reuses_loaded_models_across_analyze_calls'` -> `7 passed`
  - Manual probe against balanced local llama-server:
    - single Nemotron chat-completion returned in about `5.7s`
    - four concurrent Qwen chat-completion requests completed in about `16.7s`

### 2026-03-16 4. Benchmark heavy-layer slot widening

- Status: completed
- Hypothesis:
  - Command-scoped pooling was present, but benchmark runs still left `ml_global_slots` and `llm_global_slots` at `1`, effectively serializing the heavy layers.
- Change:
  - In benchmark mode with `concurrency > 1`, the runner now raises:
    - `runtime.ml_global_slots`
    - `runtime.llm_global_slots`
    - while preserving low-memory defaults outside that path.
- Outcome:
  - Verified that benchmark launches now issue multiple simultaneous requests against pooled balanced servers.
  - This is the first benchmark run shape that actually exercised shared-server concurrency rather than just shared residency.
- Evidence:
  - `uv run pytest tests/test_benchmark_runner.py -q -k 'BuildScanConfig or llm_group or runtime_telemetry'` -> `3 passed`
  - Live inspection during benchmark launch showed four simultaneous client connections into the shared Qwen server.

### 2026-03-16 5. LLM semantic scoring promotion

- Status: completed
- Hypothesis:
  - Semantic LLM findings like `LLM-TGT-EXFIL` and `LLM-REPO` were being treated as minor confirm/dispute adjustments instead of direct evidence, limiting recall on cross-file and semantics-heavy detections.
- Change:
  - Scoring now treats only adjustment-style LLM findings as adjustments:
    - `LLM-DISPUTE`
    - `LLM-CONFIRM`
    - `LLM-TGT-VERIFY`
  - More specific semantic LLM findings can now score as direct findings while still using references for traceability/absorption.
- Outcome:
  - Focused scoring regressions passed.
  - This should improve recall where the deterministic layer provides a clue and the LLM provides the real semantic conclusion.
- Evidence:
  - `uv run pytest tests/test_scoring.py -q -k 'LLMDispute or LLMConfirm or LLMSemanticFindings'` -> `5 passed`

### 2026-03-16 6. Full-suite safety gate after tuning

- Status: completed
- Notes:
  - Re-ran the full unit/framework suite after the scoring and runtime changes.
- Evidence:
  - `uv run pytest tests -q` -> `487 passed, 9 warnings in 490.12s`

### 2026-03-16 7. Smoke benchmark investigation

- Status: completed
- What we learned:
  - Full-stack balanced smoke runs were initially mismeasured in an LLM-only mode; the real full-stack run restored plausible detection behavior.
  - The local llama-server `--parallel 4` path is viable once the benchmark actually exercises pooled heavy-layer concurrency.
  - The current bottleneck is now total benchmark workload and orchestration efficiency more than model startup churn alone.
- Evidence:
  - `SKILLINQUISITOR_LAYERS__LLM__REPOMIX__COMMAND=npx SKILLINQUISITOR_LAYERS__LLM__REPOMIX__ARGS='["-y","repomix"]' uv run skillinquisitor benchmark run --tier smoke --llm-group balanced --concurrency 4 --timeout 300 --output benchmark/results/smoke-balanced-fullstack-20260317a`
  - Result: `TP=18 FP=6 TN=14 FN=5`, precision `75.0%`, recall `78.3%`, F1 `76.6%`, `0` errors, wall clock `11m 5s`

### 2026-03-17 8. Deterministic fixture hardening for soft Unicode/encoding signals

- Status: completed
- Hypothesis:
  - The `D-1C`, `D-2A`, and `D-5` regression fixtures had drifted into `SAFE` expectations because their original content no longer gave the LLM a truly malicious artifact to confirm.
- Change:
  - Kept the original Unicode/obfuscation trigger text in each `SKILL.md`.
  - Moved the malicious behavior into a dedicated `scripts/exfil.py` artifact for each fixture.
  - Updated the expectations to require both the original deterministic finding and a confirmed `LLM-TGT-EXFIL` finding on the script with `D-19A` traceability and confidence floor.
- Outcome:
  - The fixtures now prove the product catches the weird deterministic surface and the real malicious code path together instead of normalizing the whole case back to `SAFE`.
- Evidence:
  - `uv run pytest tests/test_deterministic.py -q -k 'D-1C-variation-selector or D-2A-homoglyph-command or D-5-hex-xor'` -> `3 passed`
  - `uv run pytest tests -q` -> `487 passed, 9 warnings in 596.62s`

## Results Summary

- Full unit/framework suite currently green: `487 passed`
- Balanced benchmark control path is now honest and externally steerable.
- Balanced server pooling is live and benchmark heavy-layer concurrency now actually engages pooled servers.
- Semantic LLM findings now have a path to influence score directly instead of acting only as weak adjustments.
- Full-stack balanced smoke result is now recorded at `75.0%` precision / `78.3%` recall / `76.6%` F1 with `0` benchmark errors.
