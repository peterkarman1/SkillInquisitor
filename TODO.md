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
  > **Done:** Added the empty async pipeline scaffold in `src/skillinquisitor/pipeline.py`. It normalizes artifacts, returns an empty finding set, and produces a stable safe result shape with layer metadata.
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

- [ ] Set up `tests/conftest.py` with pytest fixtures for loading test skills and running scanner pipeline
  > **Done:**
- [ ] Create `tests/fixtures/manifest.yaml` schema and loader in `tests/`
  > **Done:**
- [ ] Create `expected.yaml` format: verdict, expected findings (check, category, severity, line_range, message_contains), false_positives
  > **Done:**
- [ ] Create `tests/test_pipeline.py` — integration tests for full pipeline
  > **Done:**
- [ ] Create `tests/test_deterministic.py`, `tests/test_ml.py`, `tests/test_llm.py`, `tests/test_scoring.py` — initially empty, grow with later epics
  > **Done:**
- [ ] Create 5+ safe skill baselines in `tests/fixtures/safe/` that pass with zero findings
  > **Done:**
- [ ] Create fixture template directory with example `SKILL.md` and `expected.yaml` for copying
  > **Done:**
- [ ] Verify: `pytest tests/` runs and passes, fixture loading works, manifest aggregation reports coverage by check ID
  > **Done:**

---

## Epic 3 — Deterministic: Unicode & Steganography

- [ ] Implement `src/skillinquisitor/detectors/rules/engine.py` — rule registry, discovery, filtering by config, execution
  > **Done:**
- [ ] Implement custom rules loading from YAML config (D-24)
  > **Done:**
- [ ] Implement `src/skillinquisitor/detectors/rules/unicode.py` — D-1: Unicode tag chars (U+E0000-E007F), zero-width chars, variation selectors, RTLO
  > **Done:**
- [ ] Implement D-2: homoglyph detection (mixed-script content)
  > **Done:**
- [ ] Implement D-6: keyword splitting detection (`e.v.a.l` patterns)
  > **Done:**
- [ ] Implement real normalization in `normalize.py` — strip zero-width chars, replace homoglyphs, remove splitters; flag differences as findings (NC-3)
  > **Done:**
- [ ] Implement `skillinquisitor rules list` and `skillinquisitor rules test` CLI subcommands
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/deterministic/unicode/` for each check variant
  > **Done:**
- [ ] Verify: all acceptance criteria from architecture doc pass, `pytest tests/test_deterministic.py` green
  > **Done:**

---

## Epic 4 — Deterministic: Encoding & Obfuscation

- [ ] Implement D-3: Base64 payload detection — find, decode, re-scan decoded content recursively (with depth limit)
  > **Done:**
- [ ] Implement D-4: ROT13 detection — codec references + ROT13-encode-and-scan
  > **Done:**
- [ ] Implement D-5: hex/XOR obfuscation — `chr(ord(c) ^ N)`, `bytes.fromhex()`, long hex strings
  > **Done:**
- [ ] Implement D-21: HTML comment extraction — extract inner content as child Segments with provenance
  > **Done:**
- [ ] Implement D-22: code fence extraction — strip fences, extract inner content as child Segments
  > **Done:**
- [ ] Extend `normalize.py` to produce child Segments for decoded/extracted content with ProvenanceStep chains
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/deterministic/encoding/` including multi-layer encoding and nested provenance cases
  > **Done:**
- [ ] Verify: provenance chains trace correctly through nested extractions, `pytest` green
  > **Done:**

---

## Epic 5 — Deterministic: Secrets & Exfiltration

- [ ] Implement `src/skillinquisitor/detectors/rules/secrets.py` — D-7: sensitive file references (.env, .ssh/, .aws/, cloud metadata endpoints)
  > **Done:**
- [ ] Implement D-8: environment variable references (ANTHROPIC_API_KEY, os.environ, process.env, etc.)
  > **Done:**
- [ ] Implement `src/skillinquisitor/detectors/rules/behavioral.py` — D-9: network exfiltration patterns (curl, wget, requests, urllib, etc.)
  > **Done:**
- [ ] Implement D-10: dangerous code patterns (eval, exec, subprocess, os.system, compile, __import__)
  > **Done:**
- [ ] Implement action flag tagging on Findings (READ_SENSITIVE, NETWORK_SEND, EXEC_DYNAMIC, WRITE_SYSTEM, etc.)
  > **Done:**
- [ ] Implement D-19: behavior chain analysis — two-pass (tag then chain), accumulate at Skill level across Artifacts, configurable chain definitions
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/deterministic/secrets/` including individual benign actions and combined chains
  > **Done:**
- [ ] Verify: `curl` alone is not CRITICAL, `curl` + `.env` read is CRITICAL; chains work across files in same skill directory
  > **Done:**

---

## Epic 6 — Deterministic: Injection & Suppression

- [ ] Implement `src/skillinquisitor/detectors/rules/injection.py` — D-11: known injection patterns (jailbreak phrases, role delimiters, system prompt mimicry)
  > **Done:**
- [ ] Implement D-12: suppression directive detection with amplifier metadata flag
  > **Done:**
- [ ] Implement D-13: YAML frontmatter validation — spec allowlist, description length, YAML injection constructs, action directives in description
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/deterministic/injection/` including known phrases, rephrasings, and suppression + attack combos
  > **Done:**
- [ ] Verify: suppression findings carry amplifier flag, frontmatter validation catches injection-in-description
  > **Done:**

---

## Epic 7 — Deterministic: Structural & Metadata

- [ ] Implement `src/skillinquisitor/detectors/rules/structural.py` — D-14: skill directory structure validation (unexpected files, executables, binaries)
  > **Done:**
- [ ] Implement D-15: URL classification — allowlist, shorteners, IP-based, hex-encoded, unknown domains
  > **Done:**
- [ ] Implement D-20: package poisoning — custom indices, typosquatted package names (Levenshtein distance against known AI/ML packages)
  > **Done:**
- [ ] Implement skill name typosquatting — compare frontmatter `name` against known popular skill names
  > **Done:**
- [ ] Implement D-23: file size anomaly — byte-to-visible-character ratio
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/deterministic/structural/`
  > **Done:**
- [ ] Verify: URL allowlist configurable, typosquatting catches near-misses, structure validation is per-skill-directory
  > **Done:**

---

## Epic 8 — Deterministic: Persistence & Cross-Agent

- [ ] Implement `src/skillinquisitor/detectors/rules/temporal.py` — D-16: time-bomb detection (datetime, counters, environment-conditional behavior)
  > **Done:**
- [ ] Implement D-17: persistence target detection (agent configs, shell configs, cron, git hooks) — both markdown and code
  > **Done:**
- [ ] Implement D-18: cross-agent targeting (writes to other agents' directories, shadow skill installation)
  > **Done:**
- [ ] Implement auto-invocation abuse heuristic (broad descriptions, excessive generic keywords)
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/deterministic/temporal/`
  > **Done:**
- [ ] Verify: configurable agent directory list, persistence detected in both markdown instructions and code
  > **Done:**

---

## Epic 9 — ML Prompt Injection Ensemble

- [ ] Implement `src/skillinquisitor/detectors/ml/download.py` — model download and caching at `~/.skillinquisitor/models/`
  > **Done:**
- [ ] Implement `src/skillinquisitor/detectors/ml/models.py` — InjectionModel protocol, InjectionResult dataclass, HuggingFace classifier wrapper, label-to-malicious-score mapping
  > **Done:**
- [ ] Implement `src/skillinquisitor/detectors/ml/ensemble.py` — sequential load-one-run-all-unload cycle, weighted voting aggregation, confidence/uncertainty/max-risk calculation
  > **Done:**
- [ ] Implement `skillinquisitor models list` and `skillinquisitor models download` CLI subcommands
  > **Done:**
- [ ] Implement graceful absence — import guard for torch/transformers, empty results + warning when missing
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/ml/` for obvious injection, subtle injection, and benign complex skills
  > **Done:**
- [ ] Verify: models load one at a time with memory freed between, segment-level findings with per-model scores, auto-download on first use
  > **Done:**

---

## Epic 10 — LLM Code Analysis

- [ ] Implement `src/skillinquisitor/detectors/llm/models.py` — CodeAnalysisModel protocol, local inference wrapper, API inference wrapper
  > **Done:**
- [ ] Implement `src/skillinquisitor/detectors/llm/prompts.py` — general security analysis prompt, targeted prompt templates keyed to deterministic finding categories
  > **Done:**
- [ ] Implement `src/skillinquisitor/detectors/llm/judge.py` — sequential load-one-run-all-unload, general + targeted passes, semantic agreement aggregation
  > **Done:**
- [ ] Implement `src/skillinquisitor/detectors/llm/download.py` — model download and caching
  > **Done:**
- [ ] Implement structured output parsing with graceful degradation on unparseable responses
  > **Done:**
- [ ] Implement deep analysis mode (richer prompts, more context)
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/llm/` for exfil scripts, obfuscated payloads, legitimate network usage
  > **Done:**
- [ ] Verify: targeted findings reference deterministic findings, LLM can upgrade and downgrade confidence, API-based inference works
  > **Done:**

---

## Epic 11 — Risk Scoring & Output Formatters

- [ ] Implement `src/skillinquisitor/scoring.py` — subtractive scoring (100 base), severity weights, suppression amplifier, cross-layer reinforcement, chain absorption, LLM downgrade
  > **Done:**
- [ ] Implement `src/skillinquisitor/alerts.py` — Discord/Telegram/Slack webhook alerting with severity threshold trigger
  > **Done:**
- [ ] Implement `src/skillinquisitor/formatters/console.py` — full implementation: grouped by file, color-coded severity, summary section, --quiet/--verbose support
  > **Done:**
- [ ] Implement `src/skillinquisitor/formatters/json.py` — stable documented schema
  > **Done:**
- [ ] Implement `src/skillinquisitor/formatters/sarif.py` — SARIF 2.1.0 compliant output
  > **Done:**
- [ ] Implement delta mode (`--baseline`) in formatters
  > **Done:**
- [ ] Add test fixtures in `tests/fixtures/compound/` for scoring edge cases
  > **Done:**
- [ ] Verify: SARIF validates, suppression amplifies, chains don't double-count, cross-layer dedup works
  > **Done:**

---

## Epic 12 — Comparative Benchmark & Evaluation

- [ ] Implement `src/skillinquisitor/benchmark/runner.py` — benchmark orchestration using real pipeline
  > **Done:**
- [ ] Implement `src/skillinquisitor/benchmark/metrics.py` — accuracy, precision, recall, F1, per-category recall, false positive rate, ECE, latency, cost
  > **Done:**
- [ ] Implement `src/skillinquisitor/benchmark/dataset.py` — dataset loading from manifest
  > **Done:**
- [ ] Implement `src/skillinquisitor/benchmark/frontier.py` — frontier model baselines (Claude, GPT-4o, Gemini)
  > **Done:**
- [ ] Implement `src/skillinquisitor/benchmark/tools.py` — existing tool comparison (SkillSentry, ClawCare)
  > **Done:**
- [ ] Implement `src/skillinquisitor/benchmark/report.py` — comparison tables, heatmaps, confusion matrices, value proposition evaluation
  > **Done:**
- [ ] Build labeled dataset with 500+ skills (real-world + synthetic, 40% malicious / 40% safe / 20% ambiguous)
  > **Done:**
- [ ] Implement `skillinquisitor benchmark run`, `benchmark compare` CLI subcommands
  > **Done:**
- [ ] Verify: per-layer metrics, frontier comparison, value proposition thresholds evaluated, report is honest about results
  > **Done:**

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
