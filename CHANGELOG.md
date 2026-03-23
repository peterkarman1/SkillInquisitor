# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Research note for rebuilding the malicious benchmark corpus from real-world sources, covering the `openclaw/skills` archive, `yoonholee/agent-skill-malware`, and the broader `skills.rest` / `skillsmp.com` ecosystem documented in arXiv `2602.06547`
- Real-world malicious benchmark importer that matches mirrored `yoonholee/agent-skill-malware` samples back to `openclaw/skills` and preserves the full upstream skill directory when available
- Business requirements document (`docs/requirements/business-requirements.md`)
- Architecture and epic roadmap (`docs/requirements/architecture.md`)
- Agent skill attack vectors risk registry (`docs/research/agent-skill-attack-vectors.md`)
- Agent skills cross-platform comparison (`docs/research/agent-skills-comparison.md`)
- PromptForest architecture analysis (`docs/research/promptforest-architecture.md`)
- SkillSentry architecture analysis (`docs/research/skillsentry-architecture.md`)
- CLAUDE.md project instructions
- Epic 1 Python package scaffold with `uv` workflow, Typer CLI, shared models, config loading, input resolution, normalization, empty pipeline, and text/JSON formatters
- Epic 1 regression tests for packaging, config precedence, input resolution, normalization, pipeline behavior, and CLI command handling
- Epic 2 schema-first regression harness with fixture manifest indexing, exact normalized finding comparison, scoped exactness, and production-pipeline execution helpers
- Five safe baseline fixtures plus future-facing ML, LLM, and scoring regression suite entrypoints
- Regression harness contributor guide at `docs/testing/regression-harness.md`
- Epic 3 deterministic rule engine with registry-driven built-in/custom rule loading, Unicode/steganography detections, typed normalization transformations, and `rules list` / `rules test` CLI support
- Epic 3 deterministic Unicode fixture corpus covering Unicode tags, zero-width characters, variation selectors, bidi overrides, homoglyphs, keyword splitting, normalization deltas, and safe false-positive baselines
- Repo-local `scripts/run-test-suite.sh` helper for running the full regression suite through the documented `uv` workflow
- Epic 4 recursive segment expansion with deterministic segment IDs, parent linkage, per-segment normalized views, markdown HTML comment and code-fence extraction, bounded Base64 decoding, ROT13-derived segments, and deterministic traversal limits
- Epic 4 encoding rule family covering Base64 payloads, ROT13 references and transformed content, hex payload patterns, XOR constructs, contextual HTML comment/code-fence findings, and multi-layer post-processing hooks
- Epic 4 deterministic encoding fixture corpus covering positive, safe, contextual, and nested cases
- Epic 5 secrets rule family covering sensitive credential paths, cloud metadata endpoints, known secret environment variables, and suspicious environment enumeration
- Epic 5 behavioral rule family covering outbound send behavior, dynamic execution, and skill-level D-19 behavior-chain synthesis with component references
- Epic 5 deterministic secrets fixture corpus covering positive, safe, component, and cross-file chain scenarios
- Epic 6 injection rule family covering instruction overrides, role rebinding, system-prompt disclosure, delimiter injection, system-prompt mimicry, canonical jailbreak signatures, suppression directives, and structured frontmatter validation
- Epic 7 structural rule family covering skill-scope layout validation, context-sensitive URL classification, package poisoning and skill-name typosquatting, and display-density anomaly detection
- Epic 8 temporal rule family covering time-bomb conditionals, persistence-target writes, cross-agent writes and shadow skill installation, and broad auto-invocation descriptions
- Epic 9 ML prompt-injection layer with a configurable ensemble runner, Prompt Guard 2 86M plus open fallback model profiles, cache/download helpers, `models list` / `models download` CLI commands, long-segment chunking, and fake-backed ML regression fixtures
- Epic 10 LLM code-analysis layer with llama.cpp-backed local inference, configurable `tiny` / `balanced` / `large` model groups, hardware-aware auto-selection, deterministic-targeted verification prompts, optional `repomix` whole-skill review planning, and GGUF cache/download helpers
- Frontmatter-aware artifact metadata including parsed field spans, parser observations, binary signatures, executability, byte size, and synthetic-vs-declared scan provenance
- Regression harness support for fixture-local config overrides plus selector-based `action_flags`, `details`, referenced-rule, and confidence assertions
- Deterministic fixture corpora for injection, structural, and temporal rule families
- Active Epic 10 regression fixtures covering exfiltration confirmation, obfuscated payload confirmation, benign network usage, and deterministic-chain dispute behavior
- Epic 11 scoring engine (`src/skillinquisitor/scoring.py`) with subtractive scoring from 100, diminishing returns within severity tiers (geometric decay factor 0.7), confidence weighting for ML/LLM findings, chain absorption, cross-layer dedup, LLM confirm/dispute adjustments, suppression amplifier (D-12 presence multiplies other deductions by 1.5x), and severity floors (undisputed CRITICAL caps at 39, undisputed HIGH caps at 59)
- Epic 11 verdict mapping: SAFE (80-100), LOW RISK (60-79), MEDIUM RISK (40-59), HIGH RISK (20-39), CRITICAL (0-19) with verdict-based exit codes
- Epic 11 console formatter with grouped-by-file output, severity sorting, chain cross-references, absorbed finding annotations, suppression indicators, summary footer, and verbose mode
- Epic 11 JSON formatter with findings-focused output (no raw file content for security), summary stats, version field, and stable schema for the Epic 13 agent skill interface
- Epic 11 SARIF 2.1.0 formatter for GitHub Code Scanning and VS Code with relatedLocations for chain findings, severity-to-level mapping, and custom properties namespace
- Epic 11 CLI wiring for `--format sarif`, verbose flag passthrough to console, and verdict-based exit codes
- Epic 11 compound scoring regression fixtures in `tests/fixtures/compound/`
- Epic 12 Part 1 benchmark framework (`src/skillinquisitor/benchmark/`) with dataset loader, metrics engine, runner, and Markdown report generator
- Epic 12 benchmark CLI commands: `benchmark run` (with --tier, --layer, --threshold, --baseline), `benchmark compare`, and `benchmark bless`
- Epic 12 benchmark dataset with 207 labeled skills: 91 malicious (50 synthetic + 41 from fixtures), 85 safe (30 synthetic + 22 from fixtures + 33 real-world from GitHub), 31 ambiguous (synthetic)
- Epic 12 synthetic malicious skills covering all 23 rule families across 7 categories: steganography, encoding, secrets/exfiltration, injection/suppression, structural/supply chain, persistence/cross-agent, and multi-vector compound attacks
- Epic 12 synthetic safe counterparts (30 false-positive stress tests) and ambiguous skills (30 gray-area scenarios)
- Epic 12 real-world safe skills from Trail of Bits (15), Anthropic (8), Cloudflare (3), HashiCorp (2), Vercel (2), Stripe (1), Supabase (1), HuggingFace (1)
- Epic 12 fetch scripts for GitHub skills (`scripts/fetch_benchmark_skills.py`) and MaliciousAgentSkillsBench (`scripts/fetch_malicious_bench.py`)
- Epic 12 benchmark research document (`docs/research/epic-12-benchmark-dataset-research.md`) with competitive landscape, attack taxonomy, and dataset sources
- Configurable binary decision threshold for benchmark classification (default 60.0, not hardcoded)
- Findings-focused JSONL results storage (no raw artifact content, matching app's security policy)
- Provenance metadata for real-world skills and containment metadata for malicious skills
- Shipped `balanced` llama.cpp model defaults for the LLM layer: NVIDIA Nemotron 3 Nano 4B Q8_0, OmniCoder 9B Q4_K_M, and Qwen3.5 9B Q4_K_M
- Phase 1 shared scan runtime scaffolding in `src/skillinquisitor/runtime.py` with runtime-aware pipeline hooks, safe ML/LLM section guards, and multi-skill result merging
- Benchmark dataset profile controls with `real_world`, `safe_only`, and `malicious_only` source filters

### Changed
- Local development baseline is now Python `3.13.12` managed through `asdf`
- Project setup and execution docs now use `uv` instead of `pip install -e`
- Repository instructions now require relevant tests for meaningful code changes and direct scanner behavior changes toward the regression harness
- BRD and architecture docs now reflect the final Epic 2 harness contract, fixture indexing model, scoped exactness behavior, and actual config precedence
- Console output now includes deterministic findings instead of always printing an empty report
- Path normalization in the regression harness now compares fixture findings using repo-relative paths instead of absolute worktree paths
- Architecture and Epic 4 design docs now align on recursive segment expansion, raw-vs-normalized segment contracts, contextual post-processing, and bounded deterministic traversal
- README, TODO, and architecture docs now describe the implemented Epic 5 mixed-severity chain policy and default built-in chain set
- Benchmark defaults now target a real-world-only corpus, removing synthetic and fixture skills from the benchmark scorecard while keeping them in the regression suite
- Benchmark manifest and dataset snapshots now contain 75 GitHub safe skills sourced from `obra/superpowers` and `trailofbits/skills`
- Benchmark manifest and dataset snapshots now also include the full `yoonholee/agent-skill-malware` mirror: 124 malicious OpenClaw/ClawHub samples plus 223 benign OpenClaw/ClawHub samples, bringing the shipped real-world benchmark corpus to 422 total skills with a 20/20 smoke split, 50/50 standard split, and 422-skill full tier
- `rules test` now supports postprocessed D-19 behavior-chain rules by scanning component evidence and returning only the requested chain finding
- Deterministic fixture scans now ignore harness-local `expected.yaml` artifacts and automatically scope legacy malicious fixtures by manifest check IDs when no explicit scope is provided
- `rules test` now normalizes with the merged config contract and resolves frontmatter-derived skill names before single-rule execution
- URL classification now uses canonical host normalization, context-sensitive severities, and a safe exception for plain GET health checks
- Frontmatter parsing now records duplicate keys, merge keys, embedded document markers, parser/token observations, and extracted `FRONTMATTER_DESCRIPTION` segments for downstream rules
- ML config now exposes auto-download, bounded concurrency, batch sizing, and minimum segment length controls, and environment overrides can parse structured YAML/JSON values
- The main pipeline now runs deterministic checks, ML prompt-injection analysis, and LLM code analysis in order, with LLM findings carrying confirm/dispute dispositions and references back to deterministic evidence
- `models list` and `models download` now cover both ML and LLM model configuration, and `scan` now supports `--llm-group` to force a model group per run
- Epic 11 deferred webhook alerts (Discord/Telegram/Slack), delta/baseline mode (`--baseline`), and remediation guidance per finding type (R-9) to Epic 15
- The default `balanced` LLM model group is now populated and selected automatically on systems with `>= 8 GB` VRAM instead of falling back to `tiny`
- `skillinquisitor scan` now supports `--workers` for parallel multi-skill scans while preserving a single merged report
- `skillinquisitor benchmark run --concurrency` is now a real worker control instead of documentation-only behavior
- The LLM judge now offloads blocking model execution from the event loop and reuses each loaded model across prompt and repo-bundle passes within a scan
- Benchmark runs now honor environment-driven config overrides and the CLI `--llm-group` selection consistently, so balanced-model and repomix smoke/standard runs exercise the intended stack instead of silently falling back
- Local llama.cpp requests now use a tighter structured-output budget and avoid Qwen-specific forced thinking so benchmark LLM passes return faster, smaller JSON responses
- Semantic LLM findings such as targeted exfiltration and repo-review conclusions can now contribute as direct scoring evidence instead of being limited to weak confirm/dispute nudges

### Fixed
- GitHub repository scans now skip `.git` metadata and non-UTF8/binary artifacts instead of crashing during input collection
- Recursive markdown scanning now avoids duplicate Base64 findings by respecting comment and code-fence extraction precedence
- Markdown mentions of `.env` and simple health-check GET requests no longer overfire as Epic 5 component findings
- Safe temporal examples no longer trip on plain datetime logging, and overlapping temporal regexes now dedupe to one finding per source span
- Benchmark worker concurrency now widens ML/LLM heavy-layer slots in benchmark mode so pooled balanced servers can actually serve multiple workers during smoke/standard/full runs
- The `D-1C`, `D-2A`, and `D-5` deterministic regression fixtures now pair their original Unicode/obfuscation trigger with a real malicious exfiltration script, preventing those cases from drifting back to `SAFE`
- Real-world safe benchmark precision work originally eliminated false malicious classifications across the 75-skill GitHub-safe corpus by tightening workflow-takeover, ML-promotion, bootstrap/setup, reference-example, and approval-bypass handling
- Benchmark dataset profiles now filter `safe_only` and `malicious_only` by curated ground-truth verdicts rather than assuming all malicious real-world samples come from a separate source type
- Benchmark auto-concurrency now treats `0` as an adaptive worker count, using a conservative 2-worker ceiling for full-stack runs on capable hardware and wider fan-out for deterministic-only runs
- Final adjudication now recognizes decisive deterministic malicious combos directly, preventing later weaker LLM votes from downgrading obvious malicious chains
- Reference-example structural findings no longer promote handbook/reference documents into broad LLM text review by themselves, reducing both false positives and latency
- The pipeline now skips redundant ML and LLM passes for decisive fake-prerequisite, obfuscation, and corroborated prompt-takeover combinations
- Benchmark scans now ignore internal `_meta.json` metadata files in addition to `_meta.yaml`
- The Hugging Face importer now preserves both benign and malicious rows from `yoonholee/agent-skill-malware`, not just the malicious slice
- The OpenClaw benchmark importer now uses a local shallow clone plus filesystem matching/copying instead of slow per-file git plumbing when rebuilding mirrored skill snapshots
- The benchmark schema and real-world dataset profile now recognize `huggingface_mirror` as a first-class source family
- The current shipped full-corpus real-world benchmark run is `benchmark/results/20260322-022028-ac3f17c-dirty` with `TP=123`, `FP=13`, `TN=285`, `FN=1`, `90.4%` precision, `99.2%` recall, and a `2918.5s` wall clock
- README, architecture, and BRD scoring/benchmark documentation are now synchronized with the current 62-rule pipeline, `risk_label` / `binary_label` adjudication flow, the 422-skill real-world corpus, and the matching `--llm-group tiny` full benchmark comparison
- `scan` and `benchmark run` now emit live progress to `stderr` by default, including input discovery, per-skill progress, and benchmark progress, while `--quiet` suppresses those progress lines and machine-readable `stdout` remains clean for JSON and SARIF
- Removed the shipped `HeuristicCodeAnalysisModel` pseudo-LLM runtime. Product code now supports only real `llama_cpp` LLM runtimes, while fixture-backed tests inject explicit fake LLM models from the test harness instead of relying on a production semantic shortcut.
- README now warns that benchmark/dataset workflows pull real malicious skill content onto disk and recommends running those flows inside an isolated container or VM. It also adds a candid orientation note explaining that the system is benchmark-validated but still takes deliberate study to fully understand end-to-end.
