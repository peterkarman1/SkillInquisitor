# Benchmark Optimization Log

## Goal

Raise benchmark quality and runtime performance without overfitting to individual benchmark skills. Changes must generalize to future unseen datasets.

## Rules

- No fixture-specific cheats or benchmark-specific hardcoding.
- Keep the full unit and framework test suite green.
- Record every meaningful experiment, whether it helps or not.

## Environment Notes

- Date: 2026-03-16
- Branch: `codex/benchmark-optimization-loop`
- Starting commit for this pass: `0dd521e`

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

### 2026-03-17 9. Cross-agent recall expansion

- Status: completed
- Hypothesis:
  - `D-18A` was too narrow because it mainly looked for direct write verbs, which missed realistic cross-agent propagation language like copy/sync/mirror.
- Change:
  - Broadened cross-agent targeting patterns to include copy/sync/mirror/replicate/clone phrasing for other agent config directories and `SKILL.md` paths.
- Outcome:
  - Direct benchmark spot-check on `skill-0039` moved from `SAFE` behavior to a real `D-18A` hit and `MEDIUM RISK`.
- Evidence:
  - Added targeted regression:
    - `tests/test_pipeline.py::test_pipeline_flags_cross_agent_sync_copy_instructions`
  - Manual scan:
    - `uv run skillinquisitor scan benchmark/dataset/skills/skill-0039 --format json`
    - observed `D-18A` with `risk_score=59`, verdict `MEDIUM RISK`

### 2026-03-17 10. Suppression scoring repair

- Status: completed
- Hypothesis:
  - Suppression benchmark samples were being detected but then scored back to `SAFE` because:
    - `D-12A` was only medium severity
    - same-layer deterministic findings were incorrectly cross-layer deduped
    - semantic LLM findings were absorbing the deterministic evidence they referenced
- Change:
  - Raised `D-12A` to `HIGH`.
  - Allowed suppression findings to become targeted LLM candidates.
  - Fixed scoring so only true `D-19*` chain findings absorb referenced evidence.
  - Fixed cross-layer dedup so same-layer findings do not dedup each other.
- Outcome:
  - Benchmark `skill-0023` moved from `SAFE` to `MEDIUM RISK` with no benchmark-specific hardcoding.
- Evidence:
  - Added targeted regressions in:
    - `tests/test_llm.py`
    - `tests/test_pipeline.py`
    - `tests/test_scoring.py`
  - Manual scan:
    - `uv run skillinquisitor scan benchmark/dataset/skills/skill-0023 --format json`
    - observed `risk_score=59`, verdict `MEDIUM RISK`

### 2026-03-17 11. LLM targeted signal stabilization

- Status: completed
- Hypothesis:
  - Targeted LLM reviews were losing useful semantics because model-generated categories drifted away from the targeted question, and confirmed `LLM-TGT-VERIFY` findings were not being promoted into stronger semantic rule IDs.
- Change:
  - Preserved the targeted job category when aggregating targeted LLM responses.
  - Promoted confirmed targeted verify findings into stronger semantic rule IDs like `LLM-TGT-EXFIL`, `LLM-TGT-OBF`, `LLM-TGT-CROSS`, `LLM-TGT-PERSIST`, and `LLM-TGT-EXEC`.
  - Skipped the redundant general LLM prompt when a target already has targeted findings.
- Outcome:
  - Obfuscation and exfiltration spot checks now retain the intended category instead of drifting to unrelated ones.
  - This also reduces LLM prompt load per artifact.
- Evidence:
  - Added targeted regressions in `tests/test_llm.py` for:
    - targeted category preservation
    - semantic rule-id promotion
    - general-prompt suppression when targeted prompts exist
  - Manual scans:
    - `skill-0113`, `skill-0117`, `skill-0118` now score `MEDIUM RISK`

### 2026-03-17 12. Precision pass on docs-heavy safe skills

- Status: completed
- Hypothesis:
  - The biggest remaining safe-skill false positives are driven by:
    - ML prompt-injection on documentation/reference text
    - URL findings on plain documentation links
    - targeted LLM category drift on obfuscation-style reviews
- Change:
  - Excluded `/references/` artifacts from ML candidate admission.
  - Made doc-like ML prompt-injection findings soft by default unless the text contains explicit prompt-control cues.
  - Downgraded plain documentation `D-15E` and `D-15G` URL findings to `INFO`.
  - Preserved job categories across all targeted LLM jobs, not only `LLM-TGT-VERIFY`.
- Outcome:
  - Focused ML/LLM/pipeline regressions are green.
  - This should reduce the common safe-skill pattern of tutorial/reference text being promoted into real `ML-PI` or URL risk deductions.
- Evidence:
  - `uv run pytest tests/test_ml.py -q -k 'marks_doc_like_non_cue_segments_as_soft or keeps_explicit_prompt_injection_cues_hard_when_high_confidence or ml_command_runtime_reuses_loaded_models'` -> `3 passed`
  - `uv run pytest tests/test_llm.py -q -k 'targeted_verify_preserves_job_category_when_model_drifts or targeted_obfuscation_preserves_job_category_when_model_drifts'` -> `2 passed`
  - `uv run pytest tests/test_pipeline.py -q -k 'treats_documentation_unknown_external_url_as_info or treats_documentation_non_https_url_as_info or collect_ml_segments_excludes_reference_docs or flags_unknown_external_url_in_actionable_markdown'` -> `4 passed`
  - `uv run pytest tests/test_ml.py tests/test_llm.py tests/test_pipeline.py -q -k 'marks_doc_like_non_cue_segments_as_soft or keeps_explicit_prompt_injection_cues_hard_when_high_confidence or targeted_obfuscation_preserves_job_category_when_model_drifts or targeted_verify_preserves_job_category_when_model_drifts or treats_documentation_unknown_external_url_as_info or treats_documentation_non_https_url_as_info or collect_ml_segments_excludes_reference_docs or flags_unknown_external_url_in_actionable_markdown'` -> `8 passed`

### 2026-03-17 13. Standard benchmark orchestration investigation

- Status: in_progress
- Hypothesis:
  - Standard-tier optimization needs a trustworthy baseline, but the benchmark runner emits almost no progress until the end, making it hard to distinguish “slow” from “wedged.”
- Change:
  - Launched a fresh full-stack balanced standard benchmark with repomix enabled:
    - `benchmark/results/standard-balanced-fullstack-20260317b`
  - Confirmed the runner holds a live Python parent plus three shared balanced `llama-server` processes, with active localhost connections into the pooled servers.
  - Killed one earlier stale attempt before starting the fresh run.
- Outcome:
  - The run appeared opaque rather than crashed, but it became stale as the code changed underneath it.
  - This reinforced the need for better benchmark observability/checkpointing in a later runtime pass.
- Evidence:
  - Launch command:
    - `SKILLINQUISITOR_LAYERS__LLM__REPOMIX__COMMAND=npx SKILLINQUISITOR_LAYERS__LLM__REPOMIX__ARGS='["-y","repomix"]' uv run skillinquisitor benchmark run --tier standard --llm-group balanced --concurrency 4 --timeout 300 --output benchmark/results/standard-balanced-fullstack-20260317b`
  - Live inspection showed:
    - one benchmark Python process
    - three pooled balanced `llama-server` processes
    - active localhost client connections into the shared servers

### 2026-03-17 14. Exfiltration transport expansion

- Status: completed
- Hypothesis:
  - Several benchmark exfiltration samples use transport APIs that `D-9A` did not recognize, especially `urllib.request.Request(..., data=...)` and split-file cache-and-sync flows.
- Change:
  - Expanded `NETWORK_SEND_PATTERNS` to include:
    - `urllib.request.Request(..., data=...)`
    - `axios.post/put/patch(...)`
    - `navigator.sendBeacon(...)`
    - Go `http.Post`, `http.PostForm`, and `http.NewRequest("POST" | "PUT" | "PATCH", ...)`
  - Added a shell secret-harvest pattern for `env | grep` style bulk secret collection.
  - Added deterministic regressions for:
    - direct `urllib` POST detection
    - split-file cache-and-sync exfil chain formation
- Outcome:
  - The chain logic now has the transport evidence it needs for more real-world Python/Go/JS exfiltration patterns instead of depending on `requests.post` alone.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'flags_urllib_request_network_send or emits_chain_for_split_file_cached_exfiltration or emits_critical_chain_when_code_and_markdown_combine'` -> `3 passed`

### 2026-03-17 15. Smoke rerun on latest branch state

- Status: in_progress
- Notes:
  - A first smoke rerun was started, then intentionally canceled because a new exfiltration transport patch landed before it completed.
  - A second smoke rerun was also canceled after the semantic prompt-routing patch landed.
  - The current active run is:
    - `benchmark/results/smoke-balanced-fullstack-20260317d`
- Evidence:
  - Launch command:
    - `SKILLINQUISITOR_LAYERS__LLM__REPOMIX__COMMAND=npx SKILLINQUISITOR_LAYERS__LLM__REPOMIX__ARGS='["-y","repomix"]' uv run skillinquisitor benchmark run --tier smoke --llm-group balanced --concurrency 4 --timeout 300 --output benchmark/results/smoke-balanced-fullstack-20260317d`

### 2026-03-17 16. Text prompt-attack semantic routing

- Status: completed
- Hypothesis:
  - Hard prompt attacks living in `SKILL.md` were often detected deterministically but never got semantic LLM review, and confirmed prompt/credential semantic findings still collapsed into the generic `LLM-TGT-VERIFY` adjustment path.
- Change:
  - `collect_llm_targets(...)` now routes text artifacts into LLM review when prior findings indicate prompt injection, suppression, cross-agent behavior, credential theft, or obfuscation.
  - Hard `PROMPT_INJECTION`, `SUPPRESSION`, and `CREDENTIAL_THEFT` findings are now eligible for targeted LLM review.
  - Confirmed targeted semantic findings can now upgrade into:
    - `LLM-TGT-INJECT`
    - `LLM-TGT-SUPPRESS`
    - `LLM-TGT-CRED`
- Outcome:
  - Text-only prompt attacks can now get semantic confirmation instead of relying solely on deterministic scoring or ML.
  - Prompt-injection semantics now have a direct-scoring path analogous to exfiltration and obfuscation.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'routes_text_prompt_injection_targets_to_llm or runs_llm_analysis_on_code_targets'` -> `2 passed`
  - `uv run pytest tests/test_llm.py -q -k 'suppression_findings_are_targeted_llm_candidates or prompt_injection_findings_are_targeted_llm_candidates or targeted_verify_confirmed_exfiltration_upgrades_rule_id or targeted_verify_confirmed_prompt_injection_upgrades_rule_id'` -> `4 passed`

### 2026-03-17 17. Duplicate exfil semantic job collapse

- Status: completed
- Hypothesis:
  - The LLM prompt builder was issuing duplicate semantic reviews for the same exfiltration target when one prior finding was a `D-19A` chain and another was a direct `DATA_EXFILTRATION` finding like `D-9A`.
- Change:
  - Routed direct `Category.DATA_EXFILTRATION` findings to `LLM-TGT-EXFIL` in `_targeted_rule_id(...)` instead of leaving them on the generic `LLM-TGT-VERIFY` path.
  - Reworked the regression to model the real duplicate case (`D-19A` + `D-9A`) rather than a mixed exfiltration/credential-theft pair.
- Outcome:
  - Duplicate exfil semantic jobs now merge before prompt generation instead of producing both `LLM-TGT-EXFIL` and a late-upgraded `LLM-TGT-VERIFY`.
- Evidence:
  - `uv run pytest tests/test_llm.py -q -k 'prompt_builder_merges_duplicate_non_soft_targeted_reviews or prompt_builder_skips_general_job_when_target_has_targeted_findings or targeted_verify_confirmed_exfiltration_upgrades_rule_id'` -> `3 passed`

### 2026-03-17 18. Hidden prompt-override fixture hardening sync

- Status: completed
- Hypothesis:
  - Several deterministic encoding fixtures were still asserting `SAFE` even though their hidden Base64 payload decodes to `ignore previous instructions`, which the current deterministic pipeline now correctly treats as real prompt injection after extraction.
- Change:
  - Updated the deterministic expectations for:
    - `D-21-html-comments`
    - `D-22-code-fences`
    - `nested-encoding`
  - Added `D-11A` to those fixture contracts and updated verdicts to `MEDIUM RISK`.
  - Synced the three malicious LLM-backed obfuscation fixtures (`D-1C`, `D-2A`, `D-5`) to the corrected semantic category routing (`LLM-TGT-EXFIL` on `data_exfiltration` rather than the older `behavioral` category on the markdown artifact).
- Outcome:
  - The regression harness now matches the real scanner contract for hidden prompt overrides instead of preserving stale “obfuscation only” expectations.
- Evidence:
  - `uv run pytest tests/test_deterministic.py -q -k 'D-21-html-comments or D-22-code-fences or nested-encoding or D-5-hex-xor or D-1C-variation-selector or D-2A-homoglyph-command'` -> `6 passed`

### 2026-03-17 19. Scoring contract sync for direct semantic findings

- Status: completed
- Hypothesis:
  - One scoring regression test still assumed confirmed `LLM-TGT-*` findings absorb their referenced deterministic evidence, but the current optimized scorer intentionally counts these semantic findings as direct evidence instead of weak adjustments.
- Change:
  - Updated the scoring regression to assert:
    - `effective_finding_count == 2`
    - `absorbed_count == 0`
  - Kept the key behavioral assertion that the combined raw score is worse than the deterministic evidence alone.
- Outcome:
  - The scoring test suite now reflects the current benchmark-oriented semantic scoring design.
- Evidence:
  - `uv run pytest tests/test_scoring.py -q -k 'semantic_confirm_scores_as_direct_finding or semantic_llm_findings_do_not_absorb_referenced_deterministic_evidence or confirm_increases_deduction'` -> `3 passed`

### 2026-03-17 20. Smoke result and standard-tier hypotheses refresh

- Status: completed
- Hypothesis:
  - After the latest semantic and routing fixes, smoke should improve substantially and the next bottlenecks should shift from recall to doc/example precision on larger tiers.
- Change:
  - Completed a fresh smoke full-stack run:
    - `benchmark/results/smoke-balanced-fullstack-20260317d`
  - Ran parallel read-only analysis on the remaining smoke false positives and on standard/full-tier opportunities.
- Outcome:
  - Smoke reached:
    - `precision = 85.2%`
    - `recall = 100.0%`
    - `f1 = 92.0%`
    - `TP=23 FP=4 TN=16 FN=0`
  - The next likely generalizable wins are:
    - example/reference-aware suppression of repeated `D-10A` / `D-22A` style findings
    - artifact-level caps or dedup for repeated doc signals
    - more realistic frontmatter structural handling
    - broader multi-file/staged behavioral chain formation
    - section-aware URL handling for actionable setup/install prose vs passive references
- Evidence:
  - Smoke summary:
    - `benchmark/results/smoke-balanced-fullstack-20260317d/summary.json`
  - Sidecar analyses highlighted these files and rule families:
    - `benchmark/results/smoke-balanced-fullstack-20260317d/results.jsonl`
    - `src/skillinquisitor/detectors/rules/behavioral.py`
    - `src/skillinquisitor/detectors/rules/encoding.py`
    - `src/skillinquisitor/detectors/rules/injection.py`
    - `src/skillinquisitor/detectors/rules/structural.py`
    - `src/skillinquisitor/policies.py`

### 2026-03-17 21. Full regression baseline restored before standard loop

- Status: completed
- Hypothesis:
  - Benchmark iteration is only trustworthy if the full unit/framework suite is green after the latest routing, scoring, and fixture updates.
- Change:
  - Re-ran the full suite after the duplicate-job fix, fixture sync, and scoring contract update.
- Outcome:
  - The codebase is back to a clean regression baseline.
- Evidence:
  - `uv run pytest tests -q` -> `507 passed, 9 warnings`

### 2026-03-17 22. Standard benchmark baseline on tuned branch

- Status: completed
- Hypothesis:
  - The smoke-tuned branch should preserve strong precision on the larger `standard` tier, but the earlier full-tier analysis suggested recall would now be the main bottleneck.
- Change:
  - Ran a fresh full-stack `standard` benchmark with balanced LLMs, pooled model servers, and repomix enabled:
    - `benchmark/results/standard-balanced-fullstack-20260317c`
- Outcome:
  - Precision remained strong at `81.2%`, but recall fell to `56.1%`, producing `66.4%` F1.
  - The main remaining weakness is recall on:
    - `data_exfiltration`
    - `credential_theft`
    - `prompt_injection`
    - `behavioral`
  - The main FP buckets are still repeated documentation/example signals:
    - `D-15E`
    - `D-15G`
    - `D-10A`
    - `ML-PI`
    - `D-22A`
- Evidence:
  - `benchmark/results/standard-balanced-fullstack-20260317c/summary.json`
  - `benchmark/results/standard-balanced-fullstack-20260317c/report.md`

### 2026-03-17 23. Frontmatter realism and actionable markdown routing

- Status: completed
- Hypothesis:
  - `D-13A` is overfiring on common real-world skill metadata, and markdown files with actionable installer/setup URLs are still under-routed to LLM review.
- Change:
  - Expanded the default allowed frontmatter field set and field types to include common benign metadata observed across the benchmark corpus:
    - `version`
    - `author`
    - `license`
    - `tags`
    - `allowed-tools`
    - `argument-hint`
    - `preconditions`
    - `metadata`
    - `category`
    - `tools`
    - `requires`
    - `capabilities`
    - `model`
    - `thinking`
    - `max_turns`
    - `max_budget`
    - `dependencies`
    - `hooks`
  - Routed markdown artifacts into LLM review when they contain actionable structural URL findings (`D-15E`, `D-15F`, `D-15G`) in `actionable_instruction` context.
  - Made URL context detection section-aware for headings such as:
    - `Prerequisites`
    - `Installation`
    - `Setup`
    - `Usage`
- Outcome:
  - Realistic skill metadata no longer triggers `D-13A` by default.
  - Installer/setup markdown is now eligible for semantic LLM review even when the initial deterministic signal is structural.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'allows_common_benign_frontmatter_fields or routes_actionable_markdown_url_targets_to_llm'` -> covered in the broader targeted pipeline slice below

### 2026-03-17 24. Harder env-harvest and multiline persistence detection

- Status: completed
- Hypothesis:
  - Some exfiltration and persistence misses come from patterns that are more specific than generic env enumeration and from multi-line shell writes that the current line-local regexes miss.
- Change:
  - Added a new deterministic rule:
    - `D-8C` for targeted secret-environment harvesting pipelines such as `env | grep ... key|secret|token ...`
  - Left generic env enumeration on `D-8B`, but moved the secret-focused shell pipeline into the new high-severity rule.
  - Broadened persistence and cross-agent target regexes to match bounded multi-line shell writes, which catches patterns like multi-line `echo` payloads redirected into `.git/hooks/*`.
- Outcome:
  - Obvious secret-harvest shell pipelines now get a hard deterministic signal instead of relying on the softer `D-8B` path.
  - Multi-line hook writes now trigger persistence detection.
- Evidence:
  - New regression fixture:
    - `tests/fixtures/deterministic/secrets/D-8-targeted-env-harvest`
  - `uv run pytest tests/test_deterministic.py -q -k 'D-8-targeted-env-harvest or D-8-generic-env-enum or D-19-read-send-chain'` -> `3 passed`
  - `uv run pytest tests/test_pipeline.py -q -k 'emits_chain_for_secret_env_pipeline_exfiltration or detects_multiline_hook_write_as_persistence'` -> covered in the broader targeted pipeline slice below

### 2026-03-17 25. Narrowed D-18C to truly broad auto-invocation language

- Status: completed
- Hypothesis:
  - `D-18C` should fire on descriptions that claim nearly unlimited workspace scope, but not on long domain-specific descriptions for focused skills.
- Change:
  - Added explicit broad-scope phrase checks for language like:
    - `almost any request`
    - `all tasks`
    - `across the workspace`
  - Required either those phrases or a much higher generic-description density before emitting `D-18C`.
- Outcome:
  - Focused domain descriptions are less likely to be mislabeled as broad auto-invocation abuse.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'flags_broad_auto_invocation_description or does_not_flag_scoped_domain_description_as_broad_auto_invocation'` -> covered in the broader targeted pipeline slice below

### 2026-03-17 26. Verification baseline after standard-driven fixes

- Status: completed
- Hypothesis:
  - The standard-driven precision/recall fixes need a fresh all-tests verification before the next benchmark run.
- Change:
  - Re-ran targeted deterministic/pipeline slices and then the full suite.
- Outcome:
  - The branch is green again after the new frontmatter, routing, env-harvest, multiline persistence, and `D-18C` changes.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'flags_broad_auto_invocation_description or does_not_flag_scoped_domain_description_as_broad_auto_invocation or allows_common_benign_frontmatter_fields or emits_chain_for_secret_env_pipeline_exfiltration or detects_multiline_hook_write_as_persistence or routes_actionable_markdown_url_targets_to_llm'` -> `6 passed`
  - `uv run pytest tests/test_deterministic.py -q -k 'D-8-targeted-env-harvest or D-8-generic-env-enum or D-19-read-send-chain'` -> `3 passed`
  - `uv run pytest tests -q` -> `513 passed, 9 warnings`

### 2026-03-17 27. Correlated chain synthesis and markdown exfil LLM routing

- Status: completed
- Hypothesis:
  - Some safe documentation is being stitched into hard `D-19` chains even when the component findings are unrelated examples, while some markdown-only exfiltration cases never reach the LLM because `data_exfiltration` findings are not treated as text-review targets.
- Change:
  - Reworked behavioral chain selection to choose the best-correlated evidence combination instead of the first matching action flags.
  - Added linkage scoring based on:
    - same file / line proximity
    - code vs markdown sources
    - actionable context
    - penalties for markdown-only and code-fence/comment-only combinations
  - Routed markdown artifacts into LLM review when prior findings indicate:
    - `data_exfiltration`
    - `persistence`
    - markdown source or actionable instruction context
- Outcome:
  - Unlinked markdown examples no longer automatically escalate into hard `D-19` findings.
  - Markdown-only exfiltration instructions now have a path to semantic LLM confirmation.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'emits_chain_for_secret_env_pipeline_exfiltration or does_not_emit_chain_for_unlinked_markdown_examples or routes_markdown_exfiltration_targets_to_llm or emits_high_chain_for_markdown_only_exfiltration or emits_critical_chain_when_code_and_markdown_combine or emits_chain_for_split_file_cached_exfiltration'` -> `6 passed`

### 2026-03-17 28. Recall pass for variable-mediated secret reads and frontmatter hierarchy override

- Status: completed
- Hypothesis:
  - Standard-set misses include exfiltration that hides the sensitive path behind a variable alias and prompt-control language expressed as hierarchy override rather than classic “ignore previous instructions”.
- Change:
  - Added variable-mediated sensitive path detection for patterns like:
    - `env_file = os.path.expanduser("~/.env")`
    - followed later by `open(env_file, ...)` or `Path(env_file).read_*()`
  - Added direct `urllib.request.urlopen(..., data=...)` outbound-send detection.
  - Expanded prompt-injection hierarchy override signatures with phrases like:
    - `priority override`
    - `veto power`
    - `overrides all other skills/frameworks`
    - `stop all other skills/frameworks`
- Outcome:
  - More credential/exfil source-sink chains can now form deterministically.
  - Frontmatter descriptions that claim override authority now surface as prompt-injection findings.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'variable_mediated_secret_read_and_urlopen_send or flags_priority_override_in_frontmatter_description or avoids_duplicate_instruction_override_on_frontmatter_description or emits_chain_for_split_file_cached_exfiltration or routes_markdown_exfiltration_targets_to_llm'` -> `5 passed`

### 2026-03-17 29. Precision pass for code-fence provenance and reference URIs

- Status: completed
- Hypothesis:
  - Documentation examples are being over-amplified by `D-22A`, and obviously benign license/schema reference URIs are still contributing `D-15E` / `D-15G` noise.
- Change:
  - Restricted `D-21A` / `D-22A` provenance amplification to higher-signal child findings:
    - prompt injection
    - obfuscation
    - suppression
    - `D-10A`
    - `D-17A`
    - `D-19A/B/C`
  - Added URL fast-path suppression for:
    - license files
    - schema/XML namespace hosts like `w3.org`, `purl.org`, `schemas.openxmlformats.org`
    - schema files under `/schemas/`
- Outcome:
  - Safe install snippets inside code fences no longer pick up `D-22A` just because they touch agent directories.
  - License boilerplate and XML namespace URIs stop contributing structural URL noise.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'does_not_emit_code_fence_provenance_for_safe_install_example or flags_priority_override_in_frontmatter_description or variable_mediated_secret_read_and_urlopen_send'` -> `3 passed`
  - `uv run pytest tests/test_deterministic.py -q -k 'D-22-code-fences or D-19-read-send-chain or D-13E-description-injection'` -> `3 passed`
  - `uv run pytest tests/test_pipeline.py -q -k 'ignores_license_reference_urls or ignores_schema_namespace_urls or routes_actionable_markdown_url_targets_to_llm'` -> `3 passed`
  - `uv run pytest tests/test_deterministic.py -q -k 'D-15'` -> `2 passed`

### 2026-03-17 30. Structural allowlist realism for agent companion files

- Status: completed
- Hypothesis:
  - Safe skills increasingly ship top-level companion files like `AGENTS.md` and `metadata.json`; treating them as unexpected structure adds benchmark noise without providing real security signal.
- Change:
  - Added the following top-level files to the structural allowlist:
    - `AGENTS.md`
    - `CLAUDE.md`
    - `GEMINI.md`
    - `metadata.json`
- Outcome:
  - Common agent companion files no longer generate `D-14C` by default.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q -k 'allows_common_top_level_agent_companion_files or ignores_license_reference_urls or ignores_schema_namespace_urls'` -> `3 passed`

### 2026-03-17 31. Broader regression sweep after the latest optimization stack

- Status: completed
- Hypothesis:
  - After stacking chain-correlation, markdown LLM routing, variable-mediated secret reads, frontmatter hierarchy override, code-fence provenance narrowing, URL reference suppression, and structural allowlist realism, the two most directly impacted regression files should still be fully green.
- Change:
  - Re-ran the full `pipeline` and `deterministic` test files under the current branch state.
- Outcome:
  - Both direct regression files are green.
- Evidence:
  - `uv run pytest tests/test_pipeline.py -q` -> `81 passed, 9 warnings`
  - `uv run pytest tests/test_deterministic.py -q` -> `59 passed, 9 warnings`

### 2026-03-17 32. Standard benchmark rerun on the earlier dirty optimization state

- Status: completed
- Hypothesis:
  - The earlier dirty branch state, before the most recent chain/LLM/precision passes landed, should still be benchmarked so we can separate “already improved” from “still pending measurement”.
- Change:
  - Completed a real `standard` full-stack balanced run with repomix enabled:
    - output: `benchmark/results/standard-balanced-fullstack-20260317d`
- Outcome:
  - Metrics improved over `standard-balanced-fullstack-20260317c`, but mostly through higher recall with worse precision.
  - Result:
    - precision `78.3%`
    - recall `59.7%`
    - f1 `67.8%`
    - `TP=83 FP=23 TN=72 FN=56`
  - Biggest remaining problem areas in that run:
    - `behavioral` recall collapsed to `32.4%`
    - `data_exfiltration` recall stayed at `44.4%`
    - `credential_theft` recall stayed at `48.6%`
- Evidence:
  - `benchmark/results/standard-balanced-fullstack-20260317d/summary.json`
  - `benchmark/results/standard-balanced-fullstack-20260317d/report.md`

### 2026-03-17 33. Full-suite recovery after latest fixture and LLM emission fixes

- Status: completed
- Hypothesis:
  - After suppressing informational targeted LLM emissions and reconciling the affected regression fixtures/tests, the full unit/framework suite should be green again.
- Change:
  - Removed informational targeted LLM noise from emitted findings.
  - Updated the affected regression expectations:
    - `tests/fixtures/llm/exfil-script/expected.yaml`
    - `tests/fixtures/deterministic/unicode/D-1C-variation-selector/expected.yaml`
    - `tests/fixtures/deterministic/unicode/D-2A-homoglyph-command/expected.yaml`
    - `tests/fixtures/deterministic/encoding/D-5-hex-xor/expected.yaml`
  - Updated the synthetic LLM judge tests to align with the tighter targeted-emission contract.
- Outcome:
  - Full suite is green again.
- Evidence:
  - `uv run pytest tests/test_llm.py -q -k 'test_llm_judge_runs_models_sequentially_and_emits_targeted_finding or test_llm_judge_degrades_gracefully_when_one_model_returns_malformed_output or test_llm_fixtures'` -> `3 passed`
  - `uv run pytest tests -q` -> `521 passed, 9 warnings`

## Results Summary

- Full unit/framework suite currently green: `521 passed`
- Directly affected regression files now green after the newest passes:
  - `tests/test_pipeline.py` -> `81 passed`
  - `tests/test_deterministic.py` -> `59 passed`
- Most recent completed `standard` benchmark result:
  - `standard-balanced-fullstack-20260317d`
  - precision `78.3%`
  - recall `59.7%`
  - f1 `67.8%`
- Balanced benchmark control path is now honest and externally steerable.
- Balanced server pooling is live and benchmark heavy-layer concurrency now actually engages pooled servers.
- Semantic LLM findings now have a path to influence score directly instead of acting only as weak adjustments.
- Full-stack balanced smoke result is now recorded at `85.2%` precision / `100.0%` recall / `92.0%` F1 with `0` benchmark errors.
- Latest standard full-stack balanced result is recorded at `81.2%` precision / `56.1%` recall / `66.4%` F1 with `0` benchmark errors.
- Current optimization emphasis:
  - measure `standard-balanced-fullstack-20260317e`, which is the first run that includes the newest chain, LLM-emission, secret-read, URL, and structural precision changes
  - keep raising recall on staged exfiltration, credential harvesting, and coercive prompt-control language
  - keep cutting documentation/example false positives without giving back smoke precision

### 2026-03-17 34. First hybrid-final smoke benchmark on the new label pipeline

- Status: completed
- Hypothesis:
  - The new hybrid final-adjudication path, with label-based binary classification and balanced local judges, might outperform the old score-threshold path by using the LLM as a final arbiter over structured evidence.
- Change:
  - Ran a full-stack smoke benchmark with repomix enabled on the new hybrid-final pipeline:
    - output: `benchmark/results/smoke-hybrid-final-20260317b`
- Outcome:
  - The unrestricted hybrid-final path was not a net win.
  - It achieved:
    - precision `63.9%`
    - recall `100.0%`
    - f1 `78.0%`
    - `TP=23 FP=13 TN=7 FN=0`
    - wall clock `24m 53s`
  - Compared with the earlier best smoke run, recall stayed perfect but false positives jumped sharply and runtime nearly tripled.
  - Main diagnosis:
    - the final adjudicator was escalating structurally suspicious but ultimately benign skills
    - repeated identical findings were acting like corroboration
    - prompt-injection categories were being promoted too aggressively
- Evidence:
  - `benchmark/results/smoke-hybrid-final-20260317b/summary.json`
  - `benchmark/results/smoke-hybrid-final-20260317b/report.md`

### 2026-03-17 35. Bounded hybrid-final retry with dedupe and final-judge gating

- Status: completed
- Hypothesis:
  - If the final adjudicator only runs once heuristic evidence is already high enough to justify it, and repeated findings no longer count as independent corroboration, the label path should recover much of its lost precision and runtime.
- Change:
  - Updated adjudication policy to:
    - dedupe repeated findings before promotion logic
    - stop auto-promoting prompt injection alone to `HIGH`
    - skip final LLM adjudication when the heuristic baseline is below `HIGH`
  - Re-ran smoke:
    - output: `benchmark/results/smoke-hybrid-final-20260317c`
- Outcome:
  - This repaired the worst regression but was still not good enough:
    - precision `76.0%`
    - recall `82.6%`
    - f1 `79.2%`
    - `TP=19 FP=6 TN=14 FN=4`
    - wall clock `18m 39s`
  - The path was now much cleaner, but it became too conservative on a handful of credential-theft, persistence, and obfuscation cases that the old scorer still caught.
- Evidence:
  - `benchmark/results/smoke-hybrid-final-20260317c/summary.json`
  - `benchmark/results/smoke-hybrid-final-20260317c/report.md`

### 2026-03-17 36. Repaired label policy reaches parity with the best smoke benchmark

- Status: completed
- Hypothesis:
  - If rejected soft findings stop contributing to high-risk promotion, certain high-signal malicious categories regain explicit policy weight, and soft rejected suppression no longer forces `HIGH`, the label-based pipeline can recover the missing true positives without reintroducing the hybrid false-positive spike.
- Change:
  - Updated adjudication policy to:
    - ignore rejected soft findings for promotion
    - treat high credential-theft and persistence signals as high-risk evidence
    - treat paired high obfuscation signals as high-risk evidence
    - keep suppression/cross-agent auto-promotion scoped to corroborating findings instead of all findings
  - Verified with direct scans on the key benchmark skills:
    - `skill-0026`, `skill-0047`, and `skill-0117` moved back into the malicious bucket
    - `skill-0178` moved down to `LOW / not_malicious`
  - Re-ran smoke:
    - output: `benchmark/results/smoke-hybrid-final-20260317e`
  - Re-ran the full suite.
- Outcome:
  - The repaired label path now ties the earlier best smoke result on headline metrics:
    - precision `85.2%`
    - recall `100.0%`
    - f1 `92.0%`
    - `TP=23 FP=4 TN=16 FN=0`
  - Runtime is still slower than the old best smoke run:
    - `19m 20s` vs `9m 18s`
  - The full unit/framework suite is green again.
- Evidence:
  - `benchmark/results/smoke-hybrid-final-20260317e/summary.json`
  - `uv run pytest tests -q` -> `544 passed, 9 warnings`

## Results Summary

- Full unit/framework suite currently green: `544 passed`
- Best current smoke result on the repaired label path:
  - `smoke-hybrid-final-20260317e`
  - precision `85.2%`
  - recall `100.0%`
  - f1 `92.0%`
- The label-based hybrid path is now benchmark-competitive on smoke, but still slower than the old best score-threshold path.
- Current optimization emphasis:
  - carry the repaired label policy into `standard`
  - watch for the same two failure modes at larger scale:
    - safe documentation/example suppression paths getting over-promoted
    - borderline malicious credential/persistence/obfuscation cases getting under-promoted

### 2026-03-18 37. Real-world benchmark reset exposed a much weaker baseline

- Status: completed
- Change:
  - Removed synthetic and fixture entries from the benchmark corpus so the primary benchmark is now real-world only.
  - Kept fixtures and synthetic skills in the regression suite rather than the benchmark scorecard.
- Outcome:
  - The benchmark now reflects real-world performance more honestly, but the numbers dropped sharply:
    - smoke `35.3%` F1 in `benchmark/results/real-world-smoke-20260318a`
    - standard `44.4%` F1 in `benchmark/results/real-world-standard-20260318a`
  - Main weakness shifted to real malicious recall rather than synthetic parity.

### 2026-03-18 38. Dangerous-medium promotion improved real-world standard recall

- Status: completed
- Hypothesis:
  - The scanner is already surfacing useful evidence on the real-world corpus, but it under-promotes medium-strength dangerous categories into the malicious bucket.
- Change:
  - Updated heuristic adjudication to promote corroborating medium+ findings in dangerous categories and explicit high-signal rules.
  - Re-ran real-world smoke and standard.
- Outcome:
  - Smoke stayed weak but usable for regression:
    - `benchmark/results/real-world-smoke-20260318c`
    - precision `37.5%`
    - recall `30.0%`
    - f1 `33.3%`
  - Standard improved materially over the new real-world baseline:
    - `benchmark/results/real-world-standard-20260318b`
    - precision `57.1%`
    - recall `49.0%`
    - f1 `52.7%`
  - Remaining false positives were concentrated in doc/example-heavy safe skills.

### 2026-03-18 39. Context-aware promotion and narrower exec matching

- Status: in progress
- Hypothesis:
  - Some of the new safe false positives are caused by treating documentation examples as executable behavior and by an overly broad `exec(` pattern that matches method calls like `sql.exec(`.
- Change:
  - Added shared segment-context classification for behavioral and temporal findings.
  - Added context-aware dangerous promotion so documentation-only markdown findings no longer auto-promote to malicious.
  - Narrowed dynamic execution matching so method calls like `db.sql.exec(...)` do not trip `D-10A`.
  - Added targeted tests covering:
    - documentation vs executable snippet context
    - non-matching `sql.exec(...)`
    - documentation-only adjudication behavior
- Verification:
  - Focused suites passed:
    - `uv run pytest tests/test_adjudication.py tests/test_pipeline.py tests/test_deterministic.py -q -k 'adjudicate or semgrep_yaml_exec_example or sql_exec_method_call or documented_ci_conditional or D-9-network-send or D-18-auto-invocation'`
    - result: `17 passed`
  - Real-world smoke rerun:
    - `benchmark/results/real-world-smoke-20260318d`
    - unchanged from `20260318c` at `33.3%` F1
    - per-skill diff was empty
- Read:
  - This pass appears neutral on smoke and is being evaluated on standard separately.

### 2026-03-18 40. Fixed benchmark metadata contamination and started credential-surface expansion

- Status: in progress
- Change:
  - Confirmed that benchmark-side `_meta.yaml` files were being scanned as skill artifacts.
  - Fixed input resolution to ignore internal metadata files:
    - `_meta.yaml`
    - `expected.yaml`
  - Added test coverage in `tests/test_input.py`.
  - Verified `skill-0207` no longer emits a fake `D-14C` finding from `_meta.yaml`.
  - Added a new bounded credential-surface rule `D-8D` for:
    - hardcoded credential literals like `api_key=...`, `database_url=...`, `anthropic_key=...`
    - paired CLI credentials like `--username=...` plus `--password=...`
    - placeholder filtering for values like `your_password`, `your_api_key`, `user@example.com`, and ellipsis examples
- Verification:
  - `uv run pytest tests/test_input.py tests/test_pipeline.py -q -k 'internal_metadata_files or hardcoded_cli_credentials or hardcoded_api_key_in_executable_snippet or ignores_placeholder_credential_examples'`
    - targeted cases passed in narrower runs
  - Direct deterministic scans now show:
    - `skill-0224` emits `D-8D`
    - `skill-0248` emits `D-8D`
    - `skill-0207` emits no findings after metadata exclusion
- Next:
  - Re-run the real-world benchmark on top of:
    - metadata exclusion
    - context-aware promotion
    - `D-8D`
