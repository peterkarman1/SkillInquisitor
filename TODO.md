# SkillInquisitor — Implementation TODO

Track implementation progress across all epics. When completing a task, check the box and fill in the implementation notes (files changed, key decisions, deviations from architecture doc).

**Format:**
```
- [x] Task description
  > **Done:** Brief notes on what was implemented, files created/changed, any deviations from the architecture doc.
```

---

## Epic 1 — CLI Scaffold, Pipeline & Configuration

- [x] Create `pyproject.toml` with package definition and extras (`[ml]`, `[llm]`, `[all]`)
  > **Done:** Added `pyproject.toml`, `uv.lock`, and `asdf` runtime pinning with `.tool-versions`. Chose `uv` + Hatchling for the initial package workflow and left ML/LLM extras empty until those epics land.
- [x] Implement shared data model in `src/skillinquisitor/models.py` (Skill, Artifact, Segment, ProvenanceStep, Location, Finding, ScanResult, ScanConfig, all enums)
  > **Done:** Added the shared Pydantic model layer in `src/skillinquisitor/models.py`, including enums, scan/result objects, and the future-facing config shape used by the CLI, config loader, and pipeline.
- [x] Implement `src/skillinquisitor/__init__.py` and `__main__.py` entry point
  > **Done:** Added package version export in `src/skillinquisitor/__init__.py` and module entrypoint wiring in `src/skillinquisitor/__main__.py`.
- [x] Implement `src/skillinquisitor/input.py` — resolve local files, directories, GitHub URLs, stdin; group into Skill objects; handle `.skillinquisitorignore`
  > **Done:** Added async input resolution for local files, directories, stdin, and GitHub URLs in `src/skillinquisitor/input.py`. Skills are grouped by directories containing `SKILL.md`; `.git` metadata and non-UTF8 artifacts are skipped to keep GitHub scans robust.
- [x] Implement `src/skillinquisitor/normalize.py` — passthrough initially, interface for Segment extraction from Artifacts
  > **Done:** Added passthrough normalization in `src/skillinquisitor/normalize.py` that produces a single `ORIGINAL` segment per artifact while preserving provenance structure.
- [x] Implement `src/skillinquisitor/config.py` — full config system: YAML schema, loading, merging (defaults → global → project → CLI → env vars), validation
  > **Done:** Added config defaults, YAML loading, deep merge, env override extraction, CLI override application, warnings for unknown keys, and `ScanConfig` validation in `src/skillinquisitor/config.py`.
- [x] Implement `src/skillinquisitor/pipeline.py` — orchestrator: normalization, layer routing (deterministic per-segment, ML/LLM batch), graceful degradation on missing dependencies
  > **Done:** Added the async pipeline in `src/skillinquisitor/pipeline.py` and later extended it with optional shared-runtime plumbing, runtime-aware ML/LLM routing, and merged multi-skill result aggregation so scan and benchmark commands can parallelize safely without changing the public result contract.
- [x] Implement `src/skillinquisitor/detectors/base.py` — detector protocols (per-segment and batch interfaces)
  > **Done:** Added protocol interfaces for per-segment and batch detectors in `src/skillinquisitor/detectors/base.py`.
- [x] Implement `src/skillinquisitor/cli.py` — `scan` command with `--format`, `--checks`, `--skip`, `--severity`, `--config`, `--quiet`, `--verbose`, `--baseline` flags; stub `models`, `rules`, `benchmark` subcommands
  > **Done:** Added a Typer-based CLI in `src/skillinquisitor/cli.py`. `scan` now runs the actual Epic 1 stack end-to-end and `models`, `rules`, and `benchmark` subcommands are present with explicit not-implemented exits.
- [x] Implement minimal `src/skillinquisitor/formatters/console.py` — basic finding output for development
  > **Done:** Added a minimal console formatter in `src/skillinquisitor/formatters/console.py` for safe-result summaries.
- [x] Implement minimal `src/skillinquisitor/formatters/json.py` — JSON serialization of ScanResult
  > **Done:** Added JSON serialization in `src/skillinquisitor/formatters/json.py` using the shared Pydantic model output.
- [x] Verify: `pip install -e .` works, `skillinquisitor scan` runs empty pipeline, exit codes correct, config merging works, GitHub URL cloning works
  > **Done:** Verified with `uv sync --group dev`, `uv run pytest tests -v`, `uv run python -m skillinquisitor scan tests/fixtures/local/basic-skill`, `uv run python -m skillinquisitor scan tests/fixtures/local/basic-skill --format json`, and a live GitHub scan against `https://github.com/pallets/click`.

---

## Epic 2 — Regression Test Harness

- [x] Set up `tests/conftest.py` with pytest fixtures for loading test skills and running scanner pipeline
  > **Done:** Replaced the empty `tests/conftest.py` with the Epic 2 harness core: manifest loading, `expected.yaml` schema validation, real pipeline scan helpers, normalized finding projection, scoped exactness handling, and comparison assertions.
- [x] Create `tests/fixtures/manifest.yaml` schema and loader in `tests/`
  > **Done:** Added `tests/fixtures/manifest.yaml` as the fixture index and wired loaders around it in `tests/conftest.py`. The manifest carries suite/status/tags metadata but does not duplicate expected findings.
- [x] Create `expected.yaml` format: verdict, expected findings (check, category, severity, line_range, message_contains), false_positives
  > **Done:** Implemented the approved Epic 2 contract instead of the earlier draft format. `expected.yaml` now uses `schema_version`, `verdict`, `match_mode`, optional `scope`, exact normalized `findings`, and `forbid_findings`. Updated `docs/requirements/architecture.md` to match this decision.
- [x] Create `tests/test_pipeline.py` — integration tests for full pipeline
  > **Done:** Extended `tests/test_pipeline.py` with a harness integration test that monkeypatches production `resolve_input` and `run_pipeline` functions and proves the fixture scan helper routes through the real pipeline boundary.
- [x] Create `tests/test_deterministic.py`, `tests/test_ml.py`, `tests/test_llm.py`, `tests/test_scoring.py` — initially empty, grow with later epics
  > **Done:** Added `tests/test_deterministic.py` for fixture index, schema, and exact/scoped matching coverage, plus future-facing `tests/test_ml.py`, `tests/test_llm.py`, and `tests/test_scoring.py` entrypoints that skip cleanly until those fixtures land.
- [x] Create 5+ safe skill baselines in `tests/fixtures/safe/` that pass with zero findings
  > **Done:** Added five self-contained safe fixture directories covering minimal markdown, SSH deployment, multi-file build flow, network health checks, and docs linting.
- [x] Create fixture template directory with example `SKILL.md` and `expected.yaml` for copying
  > **Done:** Added `tests/fixtures/templates/deterministic-minimal/` as the canonical copy starting point for new deterministic fixtures.
- [x] Verify: `pytest tests/` runs and passes, fixture loading works, manifest aggregation reports coverage by check ID
  > **Done:** Verified with targeted pytest runs during each red/green cycle and a final full-suite run. The harness currently indexes fixtures through the manifest and supports suite/tag/check metadata for future reporting. After merge, synced `docs/requirements/business-requirements.md` and `docs/requirements/architecture.md` to the final Epic 2 harness contract and config precedence.

---

## Epic 3 — Deterministic: Unicode & Steganography

- [x] Implement `src/skillinquisitor/detectors/rules/engine.py` — rule registry, discovery, filtering by config, execution
  > **Done:** Added `src/skillinquisitor/detectors/rules/engine.py` with a metadata-driven registry, built-in/custom rule construction, config-aware filtering, single-rule execution support, and deterministic finding ordering. `src/skillinquisitor/detectors/rules/__init__.py` now exports the engine entrypoints used by the pipeline and CLI.
- [x] Implement custom rules loading from YAML config (D-24)
  > **Done:** Wired `ScanConfig.custom_rules` into the deterministic registry so regex-based custom rules register as first-class segment rules and execute through the same engine path as built-ins.
- [x] Implement `src/skillinquisitor/detectors/rules/unicode.py` — D-1: Unicode tag chars (U+E0000-E007F), zero-width chars, variation selectors, RTLO
  > **Done:** Added `src/skillinquisitor/detectors/rules/unicode.py` with built-in rules `D-1A` through `D-1D` for Unicode tag characters, zero-width characters, variation selectors, and bidi override characters.
- [x] Implement D-2: homoglyph detection (mixed-script content)
  > **Done:** Added aggressive mixed-script token detection (`D-2A`) that targets suspicious identifier-like tokens while avoiding plain single-script multilingual prose.
- [x] Implement D-6: keyword splitting detection (`e.v.a.l` patterns)
  > **Done:** Added dangerous-keyword-family normalization plus `D-6A` artifact-level findings for security-relevant separator obfuscation such as `e.v.a.l`.
- [x] Implement real normalization in `normalize.py` — strip zero-width chars, replace homoglyphs, remove splitters; flag differences as findings (NC-3)
  > **Done:** Replaced passthrough normalization with typed transformation recording in `src/skillinquisitor/normalize.py`. The pipeline now preserves the original source-mapped segment, computes normalized artifact content, and exposes `NC-3A` as a dedicated artifact-level finding when security-relevant normalization changed the file.
- [x] Implement `skillinquisitor rules list` and `skillinquisitor rules test` CLI subcommands
  > **Done:** `src/skillinquisitor/cli.py` now implements `rules list` against the real registry and `rules test <rule-id> <file>` against the full normalization + deterministic execution path.
- [x] Add test fixtures in `tests/fixtures/deterministic/unicode/` for each check variant
  > **Done:** Added positive and negative Unicode fixtures plus manifest entries under `tests/fixtures/deterministic/unicode/` for `D-1A` through `D-1D`, `D-2A`, `D-6A`, `NC-3A`, and safe baselines.
- [x] Verify: all acceptance criteria from architecture doc pass, `pytest tests/test_deterministic.py` green
  > **Done:** Verified with `uv run pytest tests/test_normalize.py tests/test_config.py tests/test_pipeline.py tests/test_cli.py tests/test_deterministic.py -q`, the full-suite helper `./scripts/run-test-suite.sh`, and targeted `rules list` / `rules test` CLI execution.

---

## Epic 4 — Deterministic: Encoding & Obfuscation

- [x] Implement D-3: Base64 payload detection — find, decode, re-scan decoded content recursively (with depth limit)
  > **Done:** Extended `src/skillinquisitor/normalize.py` to derive bounded Base64 child segments with deterministic IDs, parent linkage, source offsets, and per-segment normalized views. Added `D-3A` in `src/skillinquisitor/detectors/rules/encoding.py` and regression coverage in `tests/test_normalize.py`, `tests/test_pipeline.py`, and `tests/fixtures/deterministic/encoding/D-3-base64/`.
- [x] Implement D-4: ROT13 detection — codec references + ROT13-encode-and-scan
  > **Done:** Added `ROT13_TRANSFORM` support in `src/skillinquisitor/models.py`, signal-gated ROT13-derived segments in `src/skillinquisitor/normalize.py`, and `D-4A`/`D-4B` findings in `src/skillinquisitor/detectors/rules/encoding.py`. Added CLI and fixture coverage for the rule surface.
- [x] Implement D-5: hex/XOR obfuscation — `chr(ord(c) ^ N)`, `bytes.fromhex()`, long hex strings
  > **Done:** Added `HEX_DECODE` model support and deterministic `D-5A`/`D-5B` detection paths in `src/skillinquisitor/detectors/rules/encoding.py` for suspicious hex payloads and XOR-style decode constructs. Covered current behavior with `tests/fixtures/deterministic/encoding/D-5-hex-xor/`.
- [x] Implement D-21: HTML comment extraction — extract inner content as child Segments with provenance
  > **Done:** Added HTML comment child-segment extraction in `src/skillinquisitor/normalize.py` with parent linkage, provenance, raw source anchoring, and overlap exclusion. Added contextual `D-21A` post-processing plus regression fixtures for malicious and safe comment cases.
- [x] Implement D-22: code fence extraction — strip fences, extract inner content as child Segments
  > **Done:** Added code-fence child-segment extraction in `src/skillinquisitor/normalize.py`, fence-language metadata, precedence over HTML comments, and contextual `D-22A` post-processing. Covered positive and safe fence cases in the Epic 4 fixture suite.
- [x] Extend `normalize.py` to produce child Segments for decoded/extracted content with ProvenanceStep chains
  > **Done:** Refactored normalization into reusable segment-level helpers, added deterministic segment IDs, per-segment normalized views, bounded traversal state, and recursive expansion across original, comment, fence, Base64, and ROT13-derived segments.
- [x] Add test fixtures in `tests/fixtures/deterministic/encoding/` including multi-layer encoding and nested provenance cases
  > **Done:** Added an Epic 4 deterministic fixture corpus plus manifest entries for Base64, ROT13, hex/XOR, HTML comments, code fences, nested encoding, and safe false-positive baselines. Added a fixture-local `.skillinquisitorignore` for the ROT13 case to keep harness metadata out of the scan target.
- [x] Verify: provenance chains trace correctly through nested extractions, `pytest` green
  > **Done:** Verified with targeted red/green pytest cycles in `tests/test_normalize.py`, `tests/test_pipeline.py`, `tests/test_cli.py`, and `tests/test_deterministic.py`. Final verification still requires the fresh focused suite and `./scripts/run-test-suite.sh` run before closing the branch.

---

## Epic 5 — Deterministic: Secrets & Exfiltration

- [x] Implement `src/skillinquisitor/detectors/rules/secrets.py` — D-7: sensitive file references (.env, .ssh/, .aws/, cloud metadata endpoints)
  > **Done:** Added `src/skillinquisitor/detectors/rules/secrets.py` with D-7A/D-7B detection for operational sensitive-path references and cloud metadata endpoint references. The implementation differentiates markdown instructions from code-like access and tags findings with `READ_SENSITIVE` or `SSRF_METADATA`.
- [x] Implement D-8: environment variable references (ANTHROPIC_API_KEY, os.environ, process.env, etc.)
  > **Done:** Added D-8A/D-8B in `src/skillinquisitor/detectors/rules/secrets.py` for known secret-bearing environment variable names and suspicious environment enumeration. Kept benign config reads such as `PORT` out of scope to preserve the balanced false-positive posture.
- [x] Implement `src/skillinquisitor/detectors/rules/behavioral.py` — D-9: network exfiltration patterns (curl, wget, requests, urllib, etc.)
  > **Done:** Added `src/skillinquisitor/detectors/rules/behavioral.py` with send-oriented D-9A detection for POST/PUT/PATCH-style requests, shell upload commands, socket sends, and imperative markdown send instructions. Legitimate health-check GETs remain safe.
- [x] Implement D-10: dangerous code patterns (eval, exec, subprocess, os.system, compile, __import__)
  > **Done:** Added D-10A dynamic-execution detection in `src/skillinquisitor/detectors/rules/behavioral.py` for `eval`, `exec`, `compile`, `__import__`, subprocess/system execution primitives, and shell `bash -c` / `sh -c` forms.
- [x] Implement action flag tagging on Findings (READ_SENSITIVE, NETWORK_SEND, EXEC_DYNAMIC, WRITE_SYSTEM, etc.)
  > **Done:** Epic 5 component findings now populate `Finding.action_flags` with `READ_SENSITIVE`, `NETWORK_SEND`, `EXEC_DYNAMIC`, and `SSRF_METADATA`, plus `details.source_kind` for markdown-vs-code chain severity decisions.
- [x] Implement D-19: behavior chain analysis — two-pass (tag then chain), accumulate at Skill level across Artifacts, configurable chain definitions
  > **Done:** Added skill-level D-19 postprocessing in `src/skillinquisitor/detectors/rules/behavioral.py` and wired it through `src/skillinquisitor/detectors/rules/engine.py`. Built-in default chains now cover Data Exfiltration, Credential Theft, and Cloud Metadata SSRF; markdown-only chains downgrade to `HIGH`, while chains involving code/scripts escalate to `CRITICAL`.
- [x] Add test fixtures in `tests/fixtures/deterministic/secrets/` including individual benign actions and combined chains
  > **Done:** Added a full Epic 5 fixture corpus under `tests/fixtures/deterministic/secrets/` with component positives, safe false-positive baselines, and cross-file D-19 chains. Updated `tests/fixtures/manifest.yaml`, `tests/test_deterministic.py`, `tests/test_pipeline.py`, and `tests/test_cli.py` to exercise both component and postprocessed rule surfaces.
- [x] Verify: `curl` alone is not CRITICAL, `curl` + `.env` read is CRITICAL; chains work across files in same skill directory
  > **Done:** Verified through focused pytest runs covering secrets fixtures, behavioral fixtures, markdown-only vs code-backed D-19 severity, postprocessed `rules test D-19A`, and cross-file chain synthesis. Full-suite verification is required before branch completion and is tracked in the final verification step.

---

## Epic 6 — Deterministic: Injection & Suppression

- [x] Implement `src/skillinquisitor/detectors/rules/injection.py` — D-11: known injection patterns (jailbreak phrases, role delimiters, system prompt mimicry)
  > **Done:** Added `src/skillinquisitor/detectors/rules/injection.py` with D-11A through D-11F for exact instruction overrides, role rebinding, system-prompt disclosure, delimiter injection, system mimicry, and canonical jailbreak signatures. Kept the deterministic layer intentionally narrow and frontmatter-aware to avoid broad semantic matching.
- [x] Implement D-12: suppression directive detection with amplifier metadata flag
  > **Done:** Added D-12A through D-12D with `SUPPRESSION_PRESENT` plus specific suppression flags and structured amplifier metadata in `Finding.details`. The implementation differentiates concealment, silent execution, output suppression, and confirmation bypass.
- [x] Implement D-13: YAML frontmatter validation — spec allowlist, description length, YAML injection constructs, action directives in description
  > **Done:** Extended `src/skillinquisitor/normalize.py`, `src/skillinquisitor/pipeline.py`, `src/skillinquisitor/models.py`, and `src/skillinquisitor/config.py` so `SKILL.md` frontmatter is parsed before rule execution, duplicate keys and parser/token observations are preserved, and `FRONTMATTER_DESCRIPTION` is scanned as a first-class segment. Added D-13A through D-13E in `src/skillinquisitor/detectors/rules/injection.py`.
- [x] Add test fixtures in `tests/fixtures/deterministic/injection/` including known phrases, rephrasings, and suppression + attack combos
  > **Done:** Added deterministic injection fixtures plus manifest coverage in `tests/fixtures/deterministic/injection/`, `tests/fixtures/manifest.yaml`, and `tests/test_deterministic.py`. Added harness support for `config_override`, `action_flags_contains`, and `details_contains` in `tests/conftest.py`.
- [x] Verify: suppression findings carry amplifier flag, frontmatter validation catches injection-in-description
  > **Done:** Verified with focused Epic 6 pipeline tests, deterministic fixture runs, and CLI registry coverage in `tests/test_pipeline.py`, `tests/test_deterministic.py`, and `tests/test_cli.py`.

---

## Epic 7 — Deterministic: Structural & Metadata

- [x] Implement `src/skillinquisitor/detectors/rules/structural.py` — D-14: skill directory structure validation (unexpected files, executables, binaries)
  > **Done:** Added skill-scoped D-14 structure validation in `src/skillinquisitor/detectors/rules/structural.py` using the new artifact metadata from `src/skillinquisitor/input.py`. The implementation distinguishes declared-skill layout checks from synthetic scans and covers nested manifests, risky top-level directories, unexpected files, executables, binaries, archives, and suspicious hidden entries.
- [x] Implement D-15: URL classification — allowlist, shorteners, IP-based, hex-encoded, unknown domains
  > **Done:** Added segment-scoped D-15 URL classification with canonicalization (`hxxp`, `[.]`, host normalization, punycode handling), context-sensitive severities, config-driven allowlists, and safe health-check suppression. URLs are classified across markdown, code, and derived segments.
- [x] Implement D-20: package poisoning — custom indices, typosquatted package names (Levenshtein distance against known AI/ML packages)
  > **Done:** Added D-20A through D-20E for Python/JavaScript/Cargo registry overrides, curated protected-package typosquatting, and dependency-confusion patterns. The implementation uses the new default policy datasets in `src/skillinquisitor/policies.py` and the expanded config schema in `src/skillinquisitor/models.py`.
- [x] Implement skill name typosquatting — compare frontmatter `name` against known popular skill names
  > **Done:** Added D-20F skill-name typosquatting with normalized skill names, length-aware Damerau-Levenshtein thresholds, and allowlists. Frontmatter-derived skill names are resolved in `src/skillinquisitor/pipeline.py` before skill-scoped rules execute.
- [x] Implement D-23: file size anomaly — byte-to-visible-character ratio
  > **Done:** Implemented D-23 as display-density and hidden-content analysis rather than a naive byte/character ratio. `src/skillinquisitor/detectors/rules/structural.py` now flags non-rendered-content inflation, invisible-unicode mass, and opaque text blobs only when size and corroboration thresholds are met.
- [x] Add test fixtures in `tests/fixtures/deterministic/structural/`
  > **Done:** Added structural regression fixtures for skill layout, actionable and allowlisted URLs, typosquatted packages, and safe allowlisted documentation links. Updated `tests/test_deterministic.py` and `tests/test_pipeline.py` with focused structural assertions.
- [x] Verify: URL allowlist configurable, typosquatting catches near-misses, structure validation is per-skill-directory
  > **Done:** Verified through focused unit tests, config-sensitive regression fixtures, and end-to-end CLI/pipeline coverage. The harness now automatically scopes legacy malicious fixtures by manifest check IDs so new structural detections do not destabilize older suites.

---

## Epic 8 — Deterministic: Persistence & Cross-Agent

- [x] Implement `src/skillinquisitor/detectors/rules/temporal.py` — D-16: time-bomb detection (datetime, counters, environment-conditional behavior)
  > **Done:** Added `src/skillinquisitor/detectors/rules/temporal.py` with D-16A through D-16C for time-based, environment-gated, and state/counter-gated behavior. The implementation requires these signals to participate in a conditional or delayed-behavior pattern rather than flagging benign timestamp/logging usage.
- [x] Implement D-17: persistence target detection (agent configs, shell configs, cron, git hooks) — both markdown and code
  > **Done:** Added D-17A persistence-write detection across markdown and code with `WRITE_SYSTEM` action flags. The rule requires a write/create/install primitive plus a persistence target such as shell rc files, agent config files, cron, launchd/systemd, or git hooks.
- [x] Implement D-18: cross-agent targeting (writes to other agents' directories, shadow skill installation)
  > **Done:** Added D-18A for cross-agent writes and shadow skill installation with `CROSS_AGENT` action flags. The implementation is conservative for `.github`-style paths and focuses on write/install semantics plus known agent directories from config.
- [x] Implement auto-invocation abuse heuristic (broad descriptions, excessive generic keywords)
  > **Done:** Added D-18C as an artifact-scoped heuristic over `SKILL.md` frontmatter descriptions. It flags only broad descriptions with high generic-action density when `disable-model-invocation` is not explicitly set to `true`.
- [x] Add test fixtures in `tests/fixtures/deterministic/temporal/`
  > **Done:** Added deterministic temporal fixtures for time bombs, persistence writes, cross-agent skill installation, broad auto-invocation descriptions, and safe datetime logging. Updated fixture indexing and deterministic regression coverage accordingly.
- [x] Verify: configurable agent directory list, persistence detected in both markdown instructions and code
  > **Done:** Verified through focused pipeline tests, deterministic fixtures, and registry/CLI checks. `TemporalPolicyConfig.agent_directories` is now part of the config model and available for future policy tuning.

---

## Epic 9 — ML Prompt Injection Ensemble

- [x] Implement `src/skillinquisitor/detectors/ml/download.py` — model download and caching at `~/.skillinquisitor/models/`
  > **Done:** Added cache-aware ML model status/download helpers in `src/skillinquisitor/detectors/ml/download.py`. The current implementation targets configured HuggingFace sequence classifiers, reports cache state from the shared model cache dir, and degrades gracefully when the ML extra is not installed.
- [x] Implement `src/skillinquisitor/detectors/ml/models.py` — InjectionModel protocol, InjectionResult dataclass, HuggingFace classifier wrapper, label-to-malicious-score mapping
  > **Done:** Added `InjectionResult`, a model catalog with Prompt Guard 2 86M plus open fallback prompt-injection profiles, an optional-dependency guard, and a HuggingFace classifier wrapper that normalizes native labels into a malicious score in `src/skillinquisitor/detectors/ml/models.py`.
- [x] Implement `src/skillinquisitor/detectors/ml/ensemble.py` — sequential load-one-run-all-unload cycle, weighted voting aggregation, confidence/uncertainty/max-risk calculation
  > **Done:** Added `MLPromptInjectionEnsemble` in `src/skillinquisitor/detectors/ml/ensemble.py` with weighted soft voting, mean confidence, disagreement-based uncertainty, max-risk tracking, segment-level ML findings, bounded concurrency controlled by `layers.ml.max_concurrency` (default `1`), and graceful skip-on-failure behavior for gated or unavailable models.
- [x] Implement `skillinquisitor models list` and `skillinquisitor models download` CLI subcommands
  > **Done:** Replaced the Epic 1 stubs in `src/skillinquisitor/cli.py` with working ML model management commands backed by the shared config loader and the new cache/download helpers.
- [x] Implement graceful absence — import guard for torch/transformers, empty results + warning when missing
  > **Done:** The ensemble now returns an empty ML result set with explanatory metadata when the `ml` extra is unavailable, allowing the base deterministic install to keep working without crashes.
- [x] Add test fixtures in `tests/fixtures/ml/` for obvious injection, subtle injection, and benign complex skills
  > **Done:** Added active ML fixtures under `tests/fixtures/ml/` covering obvious body-text injection, frontmatter description injection, hidden HTML-comment payloads, Base64-derived injection text, quoted defensive examples, and complex-but-benign instructions. Indexed them in `tests/fixtures/manifest.yaml`.
- [x] Verify: models load one at a time with memory freed between, segment-level findings with per-model scores, auto-download on first use
  > **Done:** Added focused coverage in `tests/test_ml.py`, `tests/test_pipeline.py`, `tests/test_cli.py`, and `tests/test_config.py` for aggregation math, load/predict/unload lifecycle, per-model failure handling, long-markdown chunking, pipeline wiring, CLI model management, and config defaults. ML findings now carry per-model scores in `details`.

---

## Epic 10 — LLM Code Analysis

- [x] Implement `src/skillinquisitor/detectors/llm/models.py` — CodeAnalysisModel protocol, local llama.cpp wrapper, hardware-aware model-group selection
  > **Done:** Added `src/skillinquisitor/detectors/llm/models.py` with a `CodeAnalysisModel` protocol, hardware detection, `tiny` / `balanced` / `large` group selection, a llama.cpp local runtime, and a lightweight heuristic runtime used for fixture-backed end-to-end tests. The shipped defaults now include a populated `balanced` group with Nemotron 4B Q8_0, OmniCoder 9B Q4_K_M, and Qwen3.5 9B Q4_K_M GGUF models at the existing `>= 8 GB` auto-select threshold.
- [x] Implement `src/skillinquisitor/detectors/llm/prompts.py` — general security analysis prompt, targeted prompt templates keyed to deterministic finding categories
  > **Done:** Added JSON-constrained prompt builders in `src/skillinquisitor/detectors/llm/prompts.py` for general per-file review, deterministic-targeted verification, and `repomix` whole-skill review.
- [x] Implement `src/skillinquisitor/detectors/llm/judge.py` — sequential load-one-run-all-unload, general + targeted passes, semantic agreement aggregation
  > **Done:** Added `src/skillinquisitor/detectors/llm/judge.py` with `LLMTarget` collection, sequential model load/run/unload orchestration, targeted prompt routing from deterministic findings, consensus aggregation, confirm/dispute dispositions, and optional whole-skill planning for `repomix`.
- [x] Implement `src/skillinquisitor/detectors/llm/download.py` — model download and caching
  > **Done:** Added cache-aware LLM model listing, Hugging Face GGUF download helpers, local-path resolution, and shared cache handling in `src/skillinquisitor/detectors/llm/download.py`.
- [x] Implement structured output parsing with graceful degradation on unparseable responses
  > **Done:** The LLM layer now expects structured JSON responses, records per-model failures in layer metadata, and degrades to deterministic+ML behavior when no usable LLM models are available.
- [ ] Implement API inference wrapper
  > **Done:** Deferred. Epic 10 currently ships local llama.cpp inference plus the internal heuristic test runtime; cloud/API adapters remain future work.
- [ ] Implement deep analysis mode (richer prompts, more context)
  > **Done:** Deferred. The config flag remains available, but the shipped prompt set does not yet differentiate deep-analysis behavior.
- [x] Add test fixtures in `tests/fixtures/llm/` for exfil scripts, obfuscated payloads, legitimate network usage
  > **Done:** Added active fixtures in `tests/fixtures/llm/` covering exfil confirmation, obfuscated payload confirmation, benign network usage, and a deterministic-chain dispute case. Activated the real fixture runner in `tests/test_llm.py`.
- [ ] Verify: targeted findings reference deterministic findings, LLM can upgrade and downgrade confidence, API-based inference works
  > **Done:** Partially complete. Targeted findings now reference deterministic findings and fixture coverage verifies both confirm and dispute flows; API-based inference remains future work.

---

## Epic 11 — Risk Scoring & Output Formatters

- [x] Implement `src/skillinquisitor/scoring.py` — subtractive scoring (100 base), severity weights, suppression amplifier, cross-layer reinforcement, chain absorption, LLM downgrade
  > **Done:** Added `src/skillinquisitor/scoring.py` with subtractive scoring from 100, diminishing returns within severity tiers (geometric decay factor 0.7), confidence weighting for ML/LLM findings, chain absorption (chain findings absorb component deductions), cross-layer dedup (same segment+category across layers = single deduction), LLM adjustment (dispute reduces deduction + lifts severity floor; confirm boosts deduction), suppression amplifier (D-12 presence multiplies other deductions by 1.5x), severity floors (undisputed CRITICAL caps at 39, HIGH caps at 59), and verdict mapping (SAFE/LOW RISK/MEDIUM RISK/HIGH RISK/CRITICAL).
- [ ] Implement `src/skillinquisitor/alerts.py` — Discord/Telegram/Slack webhook alerting with severity threshold trigger
  > **Deferred to Epic 15.** Webhook alerts were descoped from Epic 11 to keep the scoring and formatter scope manageable.
- [x] Implement `src/skillinquisitor/formatters/console.py` — full implementation: grouped by file, color-coded severity, summary section, --quiet/--verbose support
  > **Done:** Rewrote `src/skillinquisitor/formatters/console.py` with grouped-by-file output, severity sorting (CRITICAL first), chain cross-references, absorbed finding annotations, suppression indicators, summary footer, and verbose mode for per-model scores.
- [x] Implement `src/skillinquisitor/formatters/json.py` — stable documented schema
  > **Done:** Updated `src/skillinquisitor/formatters/json.py` with findings-focused output (no raw file content for security), summary stats, version field, and a stable schema suitable for the Epic 13 agent skill interface.
- [x] Implement `src/skillinquisitor/formatters/sarif.py` — SARIF 2.1.0 compliant output
  > **Done:** Added `src/skillinquisitor/formatters/sarif.py` with SARIF 2.1.0 compliance for GitHub Code Scanning and VS Code, relatedLocations for chain findings, severity-to-level mapping, and a custom properties namespace.
- [ ] Implement delta mode (`--baseline`) in formatters
  > **Deferred to Epic 15.** Delta/baseline mode was descoped from Epic 11 along with webhook alerts.
- [x] Add test fixtures in `tests/fixtures/compound/` for scoring edge cases
  > **Done:** Added compound scoring regression fixtures covering suppression amplification, chain absorption, cross-layer dedup, LLM dispute/confirm adjustments, diminishing returns, severity floors, and verdict boundary cases.
- [x] Verify: SARIF validates, suppression amplifies, chains don't double-count, cross-layer dedup works
  > **Done:** Verified SARIF 2.1.0 schema compliance, suppression amplification behavior, chain absorption without double-counting, cross-layer dedup, LLM confirm/dispute adjustments, severity floors, and verdict-based exit codes through compound fixture and regression test coverage.

---

## Epic 12 — Comparative Benchmark & Evaluation

- [x] Implement `src/skillinquisitor/benchmark/dataset.py` — manifest schema, dataset loading, filtering, path resolution
  > **Done:** 8 Pydantic models (GroundTruth, Provenance, Containment, EntryMetadata, ManifestEntry, DecisionPolicy, BenchmarkManifest, FalsePositiveRisk) plus load_manifest, filter_entries, resolve_skill_path. Configurable decision threshold, minimum-coverage semantics for expected_rules and min_category_coverage.
- [x] Implement `src/skillinquisitor/benchmark/metrics.py` — hand-rolled confusion matrix, precision/recall/F1, per-category recall, severity accuracy, latency stats
  > **Done:** ConfusionMatrix with @property derived metrics, BenchmarkResult, FindingSummary, classify_binary with configurable threshold, compute_all_metrics aggregator. No sklearn dependency. 68 tests.
- [x] Implement `src/skillinquisitor/benchmark/runner.py` — async benchmark orchestration with semaphore concurrency
  > **Done:** BenchmarkRunConfig, BenchmarkRun, generate_run_id (timestamp+git SHA), run_benchmark with asyncio.Semaphore, save_results as findings-focused JSONL + summary JSON, error isolation per skill, and a real `concurrency` field that shares one runtime across benchmark workers. 37 tests plus phase-1 concurrency coverage.
- [x] Implement `src/skillinquisitor/benchmark/report.py` — Markdown report with executive summary, confusion matrix, per-category detection rates, error analysis
  > **Done:** generate_report with 9 sections: metadata, executive summary, regression delta (conditional), confusion matrix, per-category table with bar visualization, performance, error analysis (FN/FP grouping + top 10 failures), scan errors. 58 tests.
- [x] Implement `skillinquisitor benchmark run`, `benchmark compare`, `benchmark bless` CLI commands
  > **Done:** Replaced stubs in cli.py. benchmark run supports --tier/--layer/--threshold/--baseline/--concurrency/--timeout with real worker concurrency, benchmark compare loads two summary.json files and diffs metrics, benchmark bless copies run results to baselines directory, and `scan` now also supports `--workers` for multi-skill parallelism. Exit code 1 on regressions.
- [x] Implement shared scan runtime phase 1 for parallel scan and benchmark execution
  > **Done:** Added `src/skillinquisitor/runtime.py`, `ScanConfig.runtime`, `scan --workers`, benchmark worker reuse of one shared runtime, default single-flight ML/LLM guards, and thread-offloaded LLM execution. This phase deliberately keeps low-memory defaults safe while enabling overlap for input resolution, normalization, deterministic checks, and other non-heavy work.
- [x] Build labeled benchmark dataset from real-world skills
  > **Done:** Reset `benchmark/manifest.yaml` and `benchmark/dataset/skills/` to a real-world-only benchmark corpus sourced from `obra/superpowers`, then widened the Hugging Face importer in `scripts/fetch_openclaw_malicious_skills.py` to preserve the full `yoonholee/agent-skill-malware` mirror: `124` malicious rows plus `223` benign rows. The importer now uses a shallow local clone of `openclaw/skills`, matches mirrored rows back to exact upstream skill directories by `SKILL.md` content, and preserves the full upstream skill directory when available. The shipped benchmark now contains `422` real-world skills total: `298` safe plus `124` malicious, with 40-skill smoke (20 safe + 20 malicious), 100-skill standard (50 safe + 50 malicious), and 422-skill full tiers. Synthetic and fixture skills remain only in `tests/fixtures/`. The current shipped default full-corpus checkpoint is `benchmark/results/20260322-022028-ac3f17c-dirty` at `TP=123, FP=13, TN=285, FN=1` with a `2918.5s` wall clock, and the later `--llm-group tiny` comparison run matched the same confusion matrix in `2892.4s`.
- [ ] Implement `src/skillinquisitor/benchmark/frontier.py` — frontier model baselines (Claude, GPT-4o, Gemini)
  > **Deferred to Part 2.**
- [ ] Implement `src/skillinquisitor/benchmark/tools.py` — existing tool comparison (SkillSentry, ClawCare, Cisco skill-scanner)
  > **Deferred to Part 2.**
- [ ] Expand dataset to 500+ skills with MaliciousAgentSkillsBench integration
  > **Deferred to Part 2.** Fetch script written at scripts/fetch_malicious_bench.py. Research docs at `docs/research/epic-12-benchmark-dataset-research.md` and `docs/research/2026-03-19-real-malicious-skills-sources.md` now catalog real-world malicious source families, including OpenClaw/ClawHub archive samples, the `yoonholee/agent-skill-malware` mirror, and the broader `skills.rest` / `skillsmp.com` ecosystem from arXiv `2602.06547`.
- [ ] Verify: frontier comparison, value proposition thresholds evaluated, report is honest about results
  > **Deferred to Part 2.**

---

## Epic 13 — Agent Skill Interface

- [ ] Create `src/skillinquisitor/skill/SKILL.md` — agent skill definition with YAML frontmatter and instructions
  > **Done:**
- [ ] Create `src/skillinquisitor/skill/scripts/scan.sh` (or `scan.py`) — thin CLI wrapper
  > **Done:**
- [ ] Verify: SKILL.md conforms to Agent Skills spec, skill passes its own scan (S-6), works across agents
  > **Done:**

---

## Epic 14 — Integrations (GitHub Actions & Pre-commit Hook)

- [ ] Create GitHub Action definition — detect changed skill files, run scan, output SARIF, upload to Code Scanning, severity threshold gate
  > **Done:**
- [ ] Create pre-commit hook (`hooks/pre-commit`) — filter staged files to skill directories, run scan, block on threshold
  > **Done:**
- [ ] Create `.pre-commit-hooks.yaml` for pre-commit framework integration
  > **Done:**
- [ ] Verify: both use standard CLI, both scan only changed/staged files, both work deterministic-only by default
  > **Done:**

---

## Epic 15+ — Future / Stretch

These are not scheduled. Check the box and add notes when work begins.

- [ ] Webhook alerts — Discord/Telegram/Slack (deferred from Epic 11)
  > **Done:**
- [ ] Delta/baseline mode — `--baseline <previous-result.json>` (deferred from Epic 11)
  > **Done:**
- [ ] Remediation guidance per finding type — R-9 (deferred from Epic 11)
  > **Done:**
- [ ] Known-Good Skill Registry (BRD 8.1)
  > **Done:**
- [ ] Skill Provenance Verification (BRD 8.2)
  > **Done:**
- [ ] Skill Diffing (BRD 8.3)
  > **Done:**
- [ ] Skill Capability Declaration & Enforcement (BRD 8.4)
  > **Done:**
- [ ] Batch & Marketplace Scanning (BRD 8.5)
  > **Done:**
- [ ] Watch Mode & Continuous Monitoring (CLI-16, BRD 8.6)
  > **Done:**
- [ ] Cross-Skill Correlation (BRD 8.8)
  > **Done:**
- [ ] Incremental Scanning (P-4)
  > **Done:**
- [ ] Report History & Trending (BRD 8.9)
  > **Done:**
