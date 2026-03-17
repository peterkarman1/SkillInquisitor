# SkillInquisitor — Architecture & Epic Roadmap

**Document Version:** 1.0
**Date:** 2026-03-14
**Status:** Draft

This document defines the module architecture for SkillInquisitor and breaks the implementation into self-contained epics in build order. Each epic can be brainstormed and implemented independently. The document fulfills the business requirements defined in `docs/requirements/business-requirements.md` and defends against the threats cataloged in `docs/research/agent-skill-attack-vectors.md`.

---

## Table of Contents

1. [Package Layout & Shared Data Model](#1-package-layout--shared-data-model)
2. [Epic 1 — CLI Scaffold, Pipeline & Configuration](#epic-1--cli-scaffold-pipeline--configuration)
3. [Epic 2 — Regression Test Harness](#epic-2--regression-test-harness)
4. [Epic 3 — Deterministic Checks: Unicode & Steganography](#epic-3--deterministic-checks-unicode--steganography)
5. [Epic 4 — Deterministic Checks: Encoding & Obfuscation](#epic-4--deterministic-checks-encoding--obfuscation)
6. [Epic 5 — Deterministic Checks: Secrets & Exfiltration](#epic-5--deterministic-checks-secrets--exfiltration)
7. [Epic 6 — Deterministic Checks: Injection & Suppression](#epic-6--deterministic-checks-injection--suppression)
8. [Epic 7 — Deterministic Checks: Structural & Metadata](#epic-7--deterministic-checks-structural--metadata)
9. [Epic 8 — Deterministic Checks: Persistence & Cross-Agent](#epic-8--deterministic-checks-persistence--cross-agent)
10. [Epic 9 — ML Prompt Injection Ensemble](#epic-9--ml-prompt-injection-ensemble)
11. [Epic 10 — LLM Code Analysis](#epic-10--llm-code-analysis)
12. [Epic 11 — Risk Scoring & Output Formatters](#epic-11--risk-scoring--output-formatters)
13. [Epic 12 — Comparative Benchmark & Evaluation](#epic-12--comparative-benchmark--evaluation)
14. [Epic 13 — Agent Skill Interface](#epic-13--agent-skill-interface)
15. [Epic 14 — Integrations (GitHub Actions & Pre-commit Hook)](#epic-14--integrations-github-actions--pre-commit-hook)
16. [Epic 15 — Future / Stretch Epics](#epic-15--future--stretch-epics)

---

## 1. Package Layout & Shared Data Model

### Package Structure

```
src/skillinquisitor/
├── __init__.py
├── __main__.py              # Entry point (python -m skillinquisitor)
├── cli.py                   # CLI argument parsing, command routing
├── pipeline.py              # Scan orchestration (runs layers, collects findings)
├── config.py                # Config loading, merging, defaults
├── models.py                # Shared data model (Finding, ScanResult, Severity, etc.)
├── normalize.py             # Content normalization (unicode, decode, strip)
├── input.py                 # Input resolution (local paths, GitHub URLs, stdin)
├── detectors/
│   ├── __init__.py
│   ├── base.py              # Detector base class / protocol
│   ├── ml/                  # ML prompt injection ensemble
│   │   ├── __init__.py
│   │   ├── ensemble.py
│   │   ├── models.py
│   │   └── download.py
│   ├── llm/                 # LLM code analysis
│   │   ├── __init__.py
│   │   ├── judge.py
│   │   ├── models.py
│   │   ├── prompts.py
│   │   └── download.py
│   └── rules/               # Deterministic checks
│       ├── __init__.py
│       ├── engine.py         # Rule engine, registry, runner
│       ├── unicode.py        # Unicode & steganography (D-1 through D-6)
│       ├── encoding.py       # Encoding/extraction recursion (D-3, D-4, D-5, D-21, D-22)
│       ├── secrets.py        # Sensitive files & credentials (D-7, D-8)
│       ├── behavioral.py     # Network, exec, behavior chains (D-9, D-10, D-19)
│       ├── injection.py      # Prompt injection & suppression (D-11, D-12, D-13)
│       ├── structural.py     # Structure, URLs, packages (D-14, D-15, D-20, D-23)
│       └── temporal.py       # Time-bombs, persistence, cross-agent (D-16, D-17, D-18)
├── alerts.py                # Webhook alerting (Discord, Telegram, Slack)
├── scoring.py               # Risk score aggregation
├── formatters/
│   ├── __init__.py
│   ├── console.py            # Human-readable colored output
│   ├── json.py               # JSON output
│   └── sarif.py              # SARIF output
├── skill/                    # Agent skill interface
│   └── SKILL.md
└── benchmark/                # Comparative evaluation framework (Epic 12)
    ├── __init__.py
    ├── runner.py
    ├── metrics.py
    ├── dataset.py
    ├── frontier.py
    ├── tools.py
    ├── report.py
    └── dataset/
        ├── manifest.yaml
        ├── real-world/
        └── synthetic/
tests/                        # Regression test harness (Epic 2)
├── conftest.py
├── fixtures/
│   ├── manifest.yaml
│   ├── deterministic/
│   ├── ml/
│   ├── llm/
│   ├── safe/
│   └── compound/
├── test_deterministic.py
├── test_ml.py
├── test_llm.py
├── test_scoring.py
└── test_pipeline.py
```

Packaging: single Python package (`skillinquisitor`) with `pyproject.toml`, `uv`, and an `asdf`-managed Python runtime pinned in `.tool-versions`. Heavy dependencies are optional extras:
- `uv sync --group dev` — base install for deterministic scaffold + tests
- `uv sync --extra ml --group dev` — adds ML prompt injection ensemble dependencies
- `uv sync --extra llm --group dev` — adds local LLM code analysis dependencies
- `uv sync --all-extras --group dev` — everything

### Shared Data Model (`models.py`)

This is the contract between all modules. The type system is designed to support nested provenance (content extracted from decoded Base64 inside an HTML comment), skill-level behavior chains, cross-layer deduplication, delta mode, and SARIF-quality source locations.

**Enums:**

- **`Severity`**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- **`Category`**: `PROMPT_INJECTION`, `STEGANOGRAPHY`, `OBFUSCATION`, `CREDENTIAL_THEFT`, `DATA_EXFILTRATION`, `PERSISTENCE`, `SUPPLY_CHAIN`, `JAILBREAK`, `STRUCTURAL`, `BEHAVIORAL`, `SUPPRESSION`, `CROSS_AGENT`, etc.
- **`DetectionLayer`**: `DETERMINISTIC`, `ML_ENSEMBLE`, `LLM_ANALYSIS`
- **`FileType`**: `MARKDOWN`, `PYTHON`, `SHELL`, `JAVASCRIPT`, `TYPESCRIPT`, `RUBY`, `GO`, `RUST`, `YAML`, `UNKNOWN`
- **`SegmentType`**: `ORIGINAL`, `HTML_COMMENT`, `CODE_FENCE`, `BASE64_DECODE`, `HEX_DECODE`, `ROT13_TRANSFORM`, `FRONTMATTER_DESCRIPTION`

**Scan target hierarchy — Skill > Artifact > Segment:**

- **`Skill`**: Represents a skill directory — the unit for behavior chain analysis, cross-file correlation, and skill-level verdicts. Fields: path, name (from frontmatter or directory name), artifacts (list of `Artifact`), action_flags (accumulated across all artifacts for chain analysis), and `scan_provenance` so deterministic rules can distinguish declared skills from synthetic directory/file/stdin scans.

- **`Artifact`**: A single file within a skill. Fields: path, raw_content, normalized_content, frontmatter (dict, if applicable), `frontmatter_raw`, `frontmatter_location`, `frontmatter_error`, exact `frontmatter_fields`, parser/token `frontmatter_observations`, file_type, `byte_size`, `is_text`, `encoding`, `is_executable`, `binary_signature`, and segments (list of `Segment`). When a single file is scanned (not a directory), it is wrapped in a synthetic `Skill` with one `Artifact`.

- **`Segment`**: An extractable piece of content with full provenance. Fields: `id`, raw `content`, optional `normalized_content`, location (`Location`), parent segment linkage, and provenance_chain (list of `ProvenanceStep`). The full body of a file is a segment (type `ORIGINAL`). An HTML comment body extracted from that file is a child segment. Base64-decoded content extracted from within that comment is a grandchild. Each segment is independently scannable by any detector, and later layers can consume the same raw-plus-normalized segment contract.

- **`ProvenanceStep`**: One extraction/transformation step. Fields: segment_type (`SegmentType`), source_location (`Location`), description (human-readable, e.g., "Decoded from Base64 block"). The provenance chain is ordered root-to-leaf: `[ORIGINAL, HTML_COMMENT, BASE64_DECODE]` means "decoded from Base64 found inside an HTML comment in the original file."

**Location and findings:**

- **`Location`**: SARIF-quality source positioning. Fields: file_path, start_line, end_line, start_col (optional), end_col (optional). Maps directly to SARIF `physicalLocation.region`.

- **`Finding`**: A single detection result. Fields: id (auto-generated UUID), severity, category, layer, rule_id, message, location (`Location`), `segment_id`/segment_ref (which `Segment` this finding came from — carries full provenance), confidence (float 0.0-1.0), action_flags (for chain analysis, e.g., `READ_SENSITIVE`, `NETWORK_SEND`), references (list of related Finding IDs — used by chain findings to reference components, by LLM findings to reference deterministic findings they verify), details (dict for layer-specific metadata like per-model scores).

- **`ScanResult`**: The output of a complete scan. Fields: skills (list of `Skill`), findings (list of `Finding`), risk_score (0-100), verdict (SAFE/LOW RISK/MEDIUM RISK/HIGH RISK/CRITICAL), layer_metadata (dict with per-layer timing, model info), total_timing.

**Configuration:**

- **`ScanConfig`**: The fully merged configuration. Fields: device, timeouts, layer configs (enabled/disabled, model selection, weights, thresholds), custom rules, custom chains, trusted URL allowlist, alert config, model cache dir, output format, severity threshold. See Epic 1 for the full config schema.

**Design principle:** Detectors receive `Segment` objects (which carry provenance back to their `Artifact` and `Skill`) and produce `Finding` objects. They don't know about each other, the CLI, or the output format. The pipeline orchestrates routing, batching, and skill-level aggregation.

### File Routing

The pipeline classifies `Artifact` objects by `FileType` and routes their segments to appropriate detectors:

- **Markdown artifacts** (`.md`): deterministic text checks + ML prompt injection ensemble
- **Code artifacts** (`.py`, `.sh`, `.js`, `.ts`, `.rb`, `.go`, `.rs`): deterministic code checks + LLM code analysis
- **YAML frontmatter** (extracted as segments from SKILL.md): structural/metadata checks + ML injection detection (descriptions can contain injections)
- **All artifacts**: universal checks (unicode steganography, file size anomaly, URL classification)

When a directory is passed, the pipeline walks it, groups files into `Skill` objects (by skill directory boundaries), classifies each `Artifact`, and routes segments to applicable detectors. When a single file is passed, it is wrapped in a synthetic `Skill` with one `Artifact`, classified, and the applicable detectors run automatically. `--checks`/`--skip` are overrides, not requirements.

---

## Epic 1 — CLI Scaffold, Pipeline & Configuration

**Purpose:** Build the skeleton that everything hangs on, including the full configuration system. After this epic, `skillinquisitor scan <path>` resolves input, loads and merges config from all sources, runs an empty pipeline, and outputs an empty report. Every subsequent epic plugs into this scaffold and adds its settings to the established config schema.

**Modules introduced:**
- `cli.py` — CLI with the command structure from the BRD (`scan`, `models`, `rules`, `benchmark` subcommands). Initially only `scan` works; other subcommands are stubs that later epics fill in.
- `pipeline.py` — The orchestrator. Takes a `ScanConfig` and a list of resolved `Skill` objects, runs each detection layer in sequence, collects `Finding` objects, passes them to scoring, returns a `ScanResult`.
- `config.py` — **Full configuration system.** Defines the complete YAML schema, loads and merges config from defaults → global YAML (`~/.skillinquisitor/config.yaml`) → project YAML (`.skillinquisitor/config.yaml`) → environment variables (`SKILLINQUISITOR_*` prefix) → explicit CLI overrides. Validates on load (unknown keys warn, invalid values error). Returns a `ScanConfig`. The config schema covers all knobs needed by subsequent epics: detection layer enable/disable, model selection and weights, device preference, thresholds, custom rules, custom chains, URL allowlists, alert webhooks, model cache directory, output format, and severity threshold. Subsequent epics add their specific settings to this established framework — they never need temporary config code.
- `input.py` — Resolves the input argument: local file, directory (recursive glob for skill files), GitHub URL (clone to temp dir), or stdin. Groups files into `Skill` objects by skill directory boundaries. Returns a list of `Skill` objects. Handles `.skillinquisitorignore`.
- `normalize.py` — Content normalization pipeline. Initially a passthrough — the actual normalization logic lands in the deterministic checks epics, but the interface exists from the start. Produces `Segment` objects from `Artifact` content.
- `models.py` — All shared types (Skill, Artifact, Segment, ProvenanceStep, Location, Finding, ScanResult, ScanConfig, enums).
- `__main__.py` — `python -m skillinquisitor` entry point.
- `pyproject.toml` — Package definition with extras (`[ml]`, `[llm]`, `[all]`) and the `uv` workflow.

**Key design decisions:**

1. **Detector protocol — two levels.** Deterministic detectors implement a per-segment interface: `detect(segment: Segment, config: ScanConfig) -> list[Finding]`. The pipeline calls this for each segment of each artifact. ML and LLM detectors implement a batch interface: `detect_batch(segments: list[Segment], config: ScanConfig, prior_findings: list[Finding] | None = None) -> list[Finding]`. The batch interface exists because these detectors load one model at a time and must run it against all segments before unloading. The `prior_findings` parameter is used by the LLM detector for targeted analysis. Both interfaces are defined in `detectors/base.py`. The pipeline discovers detectors by layer and calls the appropriate interface.

2. **Pipeline ordering.** The pipeline runs normalization first (producing `Segment` objects from each `Artifact`), then layers in order: deterministic → ML → LLM. Deterministic detectors are called per-segment. ML and LLM detectors are called once with the full segment batch. The LLM layer receives deterministic findings as `prior_findings`. Configurable via `--checks` and `--skip` flags. If ML/LLM dependencies aren't installed, the pipeline skips those layers gracefully (BRD RE-3).

3. **Pipeline operates on the Skill → Artifact → Segment hierarchy.** `input.py` groups files into `Skill` objects. The pipeline iterates skills, extracts segments from each artifact (via normalization), and routes segments to detectors based on artifact file type. Behavior chain analysis (Epic 5) accumulates action flags at the `Skill` level across all its artifacts.

4. **Graceful degradation.** The pipeline catches import errors for optional dependencies (torch, transformers) and logs a warning rather than crashing. `skillinquisitor scan` always works with the base install.

5. **GitHub URL handling.** `input.py` detects GitHub URLs, clones to a temp directory (shallow clone), then treats it as a local directory. Validates the URL to prevent SSRF (BRD S-3).

6. **Exit codes.** 0 = no findings above threshold, 1 = findings detected, 2 = scan error.

**Config schema (defined in this epic, consumed by all subsequent epics):**

```yaml
# Device and performance
device: auto                    # auto | cpu | cuda | mps
scan_timeout_per_file: 30       # seconds
scan_timeout_total: 300         # seconds

# Detection layers
layers:
  deterministic:
    enabled: true
    checks:                     # Enable/disable individual checks by ID
      D-1: true
      D-2: true
      # ...
    categories:                 # Enable/disable entire categories
      steganography: true
      obfuscation: true
      # ...
  ml:
    enabled: true
    models:
      - id: meta-llama/Prompt-Guard-2-86M
        weight: 0.40
      - id: vijil/dome
        weight: 0.35
      # ...
    threshold: 0.5
  llm:
    enabled: true
    runtime: llama_cpp
    default_group: tiny
    auto_select_group: true
    gpu_min_vram_gb_for_balanced: 8.0
    model_groups:
      tiny:
        - id: unsloth/Qwen3.5-0.8B-GGUF
          runtime: llama_cpp
          filename: Qwen3.5-0.8B-Q4_K_M.gguf
          weight: 0.55
        - id: ibm-granite/granite-4.0-1b-GGUF
          runtime: llama_cpp
          filename: granite-4.0-1b-Q4_K_M.gguf
          weight: 0.45
      balanced:
        - id: unsloth/NVIDIA-Nemotron-3-Nano-4B-GGUF
          runtime: llama_cpp
          filename: NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf
          weight: 0.3333
        - id: Tesslate/OmniCoder-9B-GGUF
          runtime: llama_cpp
          filename: omnicoder-9b-q4_k_m.gguf
          weight: 0.3333
        - id: unsloth/Qwen3.5-9B-GGUF
          runtime: llama_cpp
          filename: Qwen3.5-9B-Q4_K_M.gguf
          weight: 0.3333
      large: []
    repomix:
      enabled: true
      max_tokens: 30000
    deep_analysis: false
    api:                        # For cloud-based inference
      provider: null
      model: null
      api_key_env: null

# Scoring
scoring:
  weights:
    critical: 30
    high: 20
    medium: 10
    low: 5
  suppression_multiplier: 1.5
  chain_absorption: true

# Behavior chains
chains:
  - name: Data Exfiltration
    required: [READ_SENSITIVE, NETWORK_SEND]
    severity: CRITICAL
  - name: Credential Theft
    required: [READ_SENSITIVE, EXEC_DYNAMIC]
    severity: CRITICAL
  # ... (full defaults built-in, user can extend)

# Custom rules
custom_rules:
  - id: CUSTOM-1
    pattern: "some regex"
    severity: HIGH
    category: CUSTOM
    message: "Description of what was found"

# URLs
trusted_urls:
  - github.com
  - pypi.org
  # ...

# Alerting
alerts:
  discord_webhook: null
  telegram: null
  slack_webhook: null

# Model cache
model_cache_dir: ~/.skillinquisitor/models/

# Output
default_format: text            # text | json | sarif
default_severity: LOW           # Minimum severity to report
```

**Acceptance criteria:**
- `uv sync --group dev` works
- `skillinquisitor scan ./some-dir` resolves files into Skill → Artifact hierarchy, runs empty pipeline, outputs "0 findings" to console
- `skillinquisitor scan --format json` outputs valid JSON with empty findings
- `skillinquisitor scan https://github.com/user/repo` clones and scans
- Global config (`~/.skillinquisitor/config.yaml`) loads and validates
- Project config (`.skillinquisitor/config.yaml`) merges on top of global
- CLI flags override config file values
- Environment variables (`SKILLINQUISITOR_*`) override config files
- Deep merge works (partial overrides don't clobber unrelated keys)
- Unknown config keys produce warnings; invalid values produce clear errors
- `--verbose` shows effective merged config
- Missing ML/LLM dependencies don't crash the tool
- Exit codes are correct
- Single file input wraps in synthetic Skill with one Artifact

**BRD coverage:** IN-1 through IN-8, CLI-1 through CLI-5, CLI-6 through CLI-8, CLI-13 through CLI-15, CLI-17, CFG-1 through CFG-14, RE-1 through RE-4, S-1 through S-5, P-1 through P-3, P-5 (P-4 deferred to Epic 15), PO-1 through PO-4

---

## Epic 2 — Regression Test Harness

**Purpose:** Build a fixture-based regression test framework so every detection check has a corresponding test case from day one. This is the developer inner loop — not a comparative benchmark, but a pass/fail harness that validates "this detector catches what it should and doesn't flag what it shouldn't." Each subsequent epic adds fixtures for the checks it introduces, growing the harness incrementally toward full coverage.

**Modules introduced:**
- `tests/conftest.py` — Pytest fixtures and helpers for loading fixture metadata, running the scanner pipeline, and comparing results
- `tests/fixtures/` — Directory containing self-contained fixture scan targets organized by suite/category plus safe baselines and templates
- `tests/fixtures/manifest.yaml` — Machine-readable fixture index: suite ownership, status, tags, check coverage metadata, and expectation file location
- `tests/test_deterministic.py` — Test runner for deterministic checks and harness contract coverage, grows with Epics 3-8
- `tests/test_ml.py` — Test runner for ML ensemble (grows with Epic 9)
- `tests/test_llm.py` — Test runner for LLM analysis (grows with Epic 10)
- `tests/test_scoring.py` — Test runner for scoring and output (grows with Epic 11)
- `tests/test_pipeline.py` — Integration tests for the full pipeline

**Fixture structure:**

```
tests/fixtures/
├── manifest.yaml
├── templates/
│   └── deterministic-minimal/       # Copyable starting point for deterministic fixtures
├── deterministic/
│   ├── unicode/
│   │   ├── D-1-unicode-tags/          # Test case for D-1
│   │   │   ├── SKILL.md               # Contains Unicode tag characters
│   │   │   └── expected.yaml          # Exact normalized finding contract for the fixture
│   │   ├── D-1-zero-width/
│   │   │   └── ...
│   │   ├── D-2-homoglyphs/
│   │   │   └── ...
│   │   └── D-6-keyword-splitting/
│   │       └── ...
│   ├── encoding/
│   │   ├── D-3-base64/
│   │   ├── D-4-rot13/
│   │   ├── D-5-hex-xor/
│   │   ├── D-21-html-comments/
│   │   └── D-22-code-fences/
│   ├── secrets/
│   │   ├── D-7-sensitive-files/
│   │   ├── D-8-env-vars/
│   │   ├── D-9-network-send/
│   │   ├── D-10-exec-dynamic/
│   │   └── D-19-behavior-chains/
│   ├── injection/
│   │   ├── D-11-prompt-injection/
│   │   ├── D-12-suppression/
│   │   └── D-13-frontmatter/
│   ├── structural/
│   │   ├── D-14-skill-structure/
│   │   ├── D-15-urls/
│   │   ├── D-20-package-poisoning/
│   │   └── D-23-file-size-anomaly/
│   └── temporal/
│       ├── D-16-time-bombs/
│       ├── D-17-persistence/
│       └── D-18-cross-agent/
├── ml/
│   ├── injection-obvious/             # Clear injection, all models should catch
│   ├── injection-subtle/              # Rephrased injection, tests ensemble value
│   └── benign-complex/                # Complex but safe, tests false positive rate
├── llm/
│   ├── exfil-script/                  # Script with data exfiltration
│   ├── obfuscated-payload/            # Obfuscated malicious script
│   ├── legitimate-network/            # Safe script that makes network calls
│   └── disputed-chain/                # Deterministic chain that LLM downgrades in context
├── safe/
│   ├── simple-formatter/              # Minimal safe skill
│   ├── deployment-with-ssh/           # Legitimately uses SSH keys (false positive test)
│   ├── complex-but-safe/              # Many files, complex scripts, all legitimate
│   ├── network-health-check/          # Legitimately makes network requests
│   └── docs-linter/                   # Safe docs automation fixture
└── compound/
    ├── multi-vector-attack/           # Combines injection + exfil + steganography
    ├── chain-across-files/            # Chain where read is in SKILL.md, send is in scripts/
    └── nested-encoding/               # Base64 inside HTML comment inside code fence
```

**How fixtures grow with each epic:**

| Epic | Fixtures Added |
|------|---------------|
| Epic 2 (this epic) | Framework + safe skill baselines + fixture template |
| Epic 3 (Unicode) | `deterministic/unicode/*` — one fixture per D-1, D-2, D-6 variant |
| Epic 4 (Encoding) | `deterministic/encoding/*` — fixtures for D-3, D-4, D-5, D-21, D-22 |
| Epic 5 (Secrets) | `deterministic/secrets/*` — fixtures for D-7 through D-10, D-19 chains |
| Epic 6 (Injection) | `deterministic/injection/*` — fixtures for D-11, D-12, D-13 |
| Epic 7 (Structural) | `deterministic/structural/*` — fixtures for D-14, D-15, D-20, D-23 |
| Epic 8 (Temporal) | `deterministic/temporal/*` — fixtures for D-16, D-17, D-18 |
| Epic 9 (ML) | `ml/*` — fixtures for ensemble detection |
| Epic 10 (LLM) | `llm/*` — fixtures for general + targeted analysis |
| Epic 11 (Scoring) | `compound/*` — fixtures for scoring edge cases, chain absorption, suppression amplification |

**`expected.yaml` format per fixture:**

```yaml
schema_version: 1
verdict: MEDIUM RISK         # or SAFE, LOW RISK, HIGH RISK, CRITICAL
match_mode: exact
scope:                       # Optional: narrows exactness to a layer/check subset
  layers: [deterministic]
  checks: [D-1]
findings:
  - rule_id: D-1
    layer: deterministic
    category: steganography
    severity: critical
    message: "Unicode tag characters detected"
    location:
      file_path: SKILL.md
      start_line: 47
      end_line: 47
forbid_findings:             # Optional: findings that must not appear anywhere in the result
  - rule_id: D-11
```

**Key design decisions:**

1. **Every check ID gets at least one positive and one negative fixture.** A positive fixture triggers the check. A negative fixture is a benign skill that looks similar but shouldn't trigger it. This is how false positive rates are measured from day one.

2. **Fixtures are the acceptance criteria for each epic.** When brainstorming an epic, the first question is: "what fixtures do we need?" When the fixtures pass, the epic is done.

3. **The harness uses the same `pipeline.py` as the CLI.** No separate test scanning logic. The harness runs the real scanner and compares output to `expected.yaml`.

4. **Compound fixtures test cross-cutting behavior.** Skills that combine multiple vectors (injection + steganography + exfiltration) test that the scoring, chain analysis, and cross-layer dedup work correctly together.

5. **Safe fixtures are as important as malicious ones.** The `safe/` directory contains skills that legitimately use patterns that might look suspicious (SSH keys for deployment, network requests for health checks). These are the false positive regression tests.

6. **Fixture format is stable.** Adding a new fixture means adding files + `expected.yaml`. No code changes to the harness. The manifest aggregates fixtures for batch reporting.

7. **Exactness is strict by default, but scope can narrow it.** Full-result exactness is the default contract. Fixtures may opt into layer/check-scoped exactness so later ML, LLM, or scoring findings do not invalidate a deterministic fixture that is intentionally focused on one behavior.

**Acceptance criteria:**
- `pytest tests/` runs and passes
- Fixture loading works: tests discover fixtures, load expectations, run the real scanner pipeline, and compare normalized findings
- At least 5 safe skill baselines in `safe/` that pass with zero findings
- Fixture template exists so subsequent epics can add fixtures by copying and editing
- `expected.yaml` format supports exact normalized findings, optional scoped exactness, and `forbid_findings`
- Fixture manifest provides stable indexing plus suite/tag/check metadata for future reporting
- CI can run `pytest tests/` as a gate

**BRD coverage:** RE-1 (deterministic reproducibility verified by fixtures)

---

## Epic 3 — Deterministic Checks: Unicode & Steganography

**Purpose:** Build the first cluster of deterministic rules and the rule engine framework that all subsequent deterministic epics use. After this epic, the scanner catches Unicode tag steganography, zero-width characters, variation selectors, homoglyphs, RTLO attacks, and keyword splitting. The normalization pipeline also gets its real implementation.

**Modules introduced/updated:**
- `detectors/rules/engine.py` — The rule engine. A registry where rule functions are registered with metadata (ID, family, category, severity, scope, origin). The engine runs enabled segment and artifact rules, applies config filtering, and compiles regex-based custom rules into the same execution path.
- `detectors/rules/unicode.py` — Unicode/steganography rules.
- `normalize.py` — Gets its real implementation. Records typed normalization transformations, strips zero-width and bidi control characters, folds suspicious mixed-script homoglyphs, and collapses dangerous split keywords. Produces both original and normalized content on each `Artifact`.

**Rules in this cluster:**
- D-1 family: Unicode tag characters (U+E0000-E007F), zero-width characters (U+200B, U+200C, U+200D, U+2060, U+FEFF), variation selectors (U+FE00-U+FE0F), right-to-left override (U+202E). Tool output exposes these as sub-rules `D-1A` through `D-1D`.
- D-2: Homoglyph detection — mixed-script content (Cyrillic, Greek, fullwidth substituting for Latin)
- D-6: Keyword splitting detection — `e.v.a.l`, `c.u.r.l` style obfuscation
- NC-3: Security-relevant normalization delta detection. Tool output exposes the Epic 3 evasion finding as `NC-3A`.

**Key design decisions:**

1. **The rule engine is the framework for all deterministic checks.** A rule registers with metadata and executes against either a `Segment` or an `Artifact`. The engine discovers rules, filters by config (enabled/disabled, categories, explicit rule selection), and runs them. All subsequent deterministic epics just add rules to this engine.

2. **Normalization runs before everything.** The pipeline calls `normalize.py` on every file as the first step, populating both `raw_content` and `normalized_content` on each `Artifact`. All detectors receive files with both versions available. ML and LLM detectors use normalized content by default.

3. **Difference between original and normalized is itself a finding** (BRD NC-3). Epic 3 implements this as a dedicated artifact-level rule (`NC-3A`) rather than conflating it with the direct Unicode or splitter detections.

4. **Custom rules (D-24) are part of the engine.** The engine supports loading user-defined rules from YAML config — pattern, severity, category, weight. Lands in this epic because it's engine infrastructure.

**CLI addition:** This epic also implements the `rules` subcommands since the rule engine lands here:
- `skillinquisitor rules list` — list all active detection rules with IDs, categories, severities
- `skillinquisitor rules test <rule-id> <file>` — test a specific rule against a file

**Acceptance criteria:**
- Rule engine registers, discovers, and runs rules with filtering
- Unicode tag characters (U+E0000-E007F) are detected and reported with line numbers
- Zero-width characters are detected
- Variation selectors are detected
- Homoglyphs are detected (mixed-script content)
- RTLO characters are detected
- Keyword splitting (`e.v.a.l`) is detected
- Normalization produces cleaned content and flags differences
- Custom YAML rules can be loaded and executed
- `skillinquisitor rules list` shows all registered rules
- `skillinquisitor rules test D-1B <file>` runs a single rule and shows results
- Benchmark dataset includes test skills for each of these attack types

**BRD coverage:** D-1, D-2, D-6, D-24, NC-1 through NC-3, CLI-11, CLI-12

---

## Epic 4 — Deterministic Checks: Encoding & Obfuscation

**Purpose:** Build the checks that detect encoded and obfuscated payloads. After this epic, the scanner catches Base64 blobs, ROT13, hex payloads and XOR obfuscation constructs, multi-layer encoding chains, and extracts content from HTML comments and code fences for re-scanning.

**Modules updated:**
- `normalize.py` — Extended to extract HTML comment bodies and code fence contents, decode accepted Base64 and text-like hex payloads, compute per-segment normalized views, and make derived content available for recursive re-scanning.
- `detectors/rules/encoding.py` — Encoding/extraction rules plus deterministic post-processing for contextual and multi-layer findings.

**Rules in this cluster:**
- D-3: Base64 payload detection — find 40+ char Base64 strings, decode, re-scan decoded content against all rules
- D-4: ROT13 detection — detect codec references and, when a segment contains an explicit ROT13 signal, derive one ROT13-transformed view of that whole segment for re-scanning
- D-5: Hex/XOR obfuscation — `chr(ord(c) ^ N)` patterns, `bytes.fromhex()`, long hex strings; text-like hex payloads may be decoded recursively while XOR remains detection-oriented in this epic
- D-21: HTML comment scanning — extract and analyze content within HTML comments
- D-22: Code fence content scanning — strip markdown fences, scan inner content

**Key design decisions:**

1. **Recursive re-scanning.** When Base64 content is decoded, the decoded content is fed back through the rule engine. This catches multi-layer encoding — decode Base64, find hex inside, decode that. Configurable depth limit to prevent abuse.

2. **HTML comments and code fences are extraction points, not just checks.** They produce additional text segments that get scanned by the deterministic layer immediately and by later ML/LLM layers through the same segment contract once those layers are implemented. `normalize.py` exposes extracted segments as additional scannable content on each `Artifact`. Extraction must be non-overlapping: code fences are identified first, and HTML comments inside a fence are extracted only from the fence child, not again from the parent markdown segment.

3. **Decoded/extracted content carries provenance.** When a finding comes from decoded Base64 inside an HTML comment, the finding's location info traces back through the layers: "line 47, inside HTML comment, inside Base64 block." Segment locations remain anchored to raw source spans; matches found in normalized text views still report the raw source span as the canonical location and store normalized-match context in metadata.

4. **Contextual and chain findings are post-processed, not emitted during extraction.** HTML comment, code-fence, and multi-layer-chain findings are derived in a deterministic post-processing pass over the flat segment list plus primary findings. Emit at most one contextual finding per hidden ancestor segment and at most one multi-layer finding per suspicious leaf segment.

**Acceptance criteria:**
- Base64 blobs are detected, decoded, and re-scanned
- ROT13 references are detected; one ROT13-transformed view per signaled segment catches hidden patterns
- Hex string decoding patterns are detected
- XOR constructs are detected
- Multi-layer encoding is caught up to configured depth
- HTML comment content is extracted and scanned
- Code fence content is extracted and scanned
- Findings from decoded/extracted content include provenance chain
- Benchmark dataset includes test skills for each encoding technique

**BRD coverage:** D-3, D-4, D-5, D-21, D-22

---

## Epic 5 — Deterministic Checks: Secrets & Exfiltration

**Purpose:** Build the checks that detect credential access, sensitive file references, environment variable harvesting, and network exfiltration patterns — plus the behavior chain analysis that combines them. After this epic, the scanner catches the most dangerous real-world attack patterns: read credentials + send them somewhere.

**Modules introduced:**
- `detectors/rules/secrets.py` — Sensitive file and credential detection
- `detectors/rules/behavioral.py` — Network exfiltration patterns, dangerous code patterns, behavior chain analysis

**Rules in this cluster:**
- D-7: Sensitive file references — `.env`, `.ssh/`, `.aws/`, `.gnupg/`, `.npmrc`, `.pypirc`, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`)
- D-8: Environment variable references — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `os.environ`, `process.env`, `os.getenv()`
- D-9: Network exfiltration patterns — `curl`, `wget`, `fetch`, `requests`, `urllib`, `http.client`, `socket`
- D-10: Dangerous code patterns — `eval()`, `exec()`, `subprocess`, `os.system()`, `compile()`, `__import__()`
- D-19: Behavior chain analysis

**Behavior chain analysis (D-19):**

Individual rules tag each file with action flags — `READ_SENSITIVE`, `NETWORK_SEND`, `EXEC_DYNAMIC`, `SSRF_METADATA`, `WRITE_SYSTEM`, `FILE_DELETE`, etc. The chain analyzer looks for dangerous combinations. The current built-in defaults implemented in Epic 5 are:

| Chain | Required Actions | Severity |
|-------|-----------------|----------|
| Data Exfiltration | READ_SENSITIVE + NETWORK_SEND | CRITICAL |
| Credential Theft | READ_SENSITIVE + EXEC_DYNAMIC | CRITICAL |
| Cloud Metadata SSRF | SSRF_METADATA + NETWORK_SEND | CRITICAL |

**Key design decisions:**

1. **Two-pass within this cluster.** First pass: each rule runs independently and tags the file with action flags plus emitting lower-severity findings. Second pass: the chain analyzer reads the flags and emits higher-severity chain findings. Chain findings reference the individual findings that compose them.

2. **Action flags accumulate at the skill directory level.** A skill where `SKILL.md` reads `.env` and `scripts/setup.py` sends a network request — that's still a chain, because they're in the same skill.

3. **Chain definitions are configurable.** The three built-in Epic 5 chains ship in config defaults, and users can extend them in YAML config.
4. **Markdown-only chains stay lower severity than code-backed chains.** The implemented Epic 5 policy emits `HIGH` for markdown-only chains and preserves `CRITICAL` when at least one contributing finding comes from code or script artifacts.

**Acceptance criteria:**
- Sensitive file paths are detected across all common credential locations
- Environment variable references are detected
- Network send patterns are detected across languages
- Dangerous code execution patterns are detected
- Behavior chains fire when actions combine within a skill directory
- Individual actions at lower severity, chains at higher severity
- `curl` alone does not produce a CRITICAL finding; `curl` + `.env` read does
- Markdown-only chains downgrade to `HIGH`; chains with code or scripts remain `CRITICAL`
- Custom chains can be defined in config
- Benchmark dataset includes skills with individual benign actions and combined attack chains

**BRD coverage:** D-7, D-8, D-9, D-10, D-19

---

## Epic 6 — Deterministic Checks: Injection & Suppression

**Purpose:** Build the deterministic complement to the ML ensemble — checks that detect high-confidence prompt injection signatures, suppression directives, and structured `SKILL.md` frontmatter abuse without trying to semantically solve prompt injection in the deterministic layer.

**Modules introduced:**
- `detectors/rules/injection.py` — Prompt injection patterns, jailbreak detection, suppression directives, role delimiter detection, frontmatter validation

**Rules in this cluster:**
- D-11: Prompt injection patterns — instruction overrides, role rebinding, system-prompt disclosure requests, delimiter injection (`<|system|>`, `<|im_start|>`, `[INST]`), system prompt mimicry (`<system>`, `[SYSTEM]`, `### SYSTEM INSTRUCTIONS`), and canonical jailbreak templates
- D-12: Suppression directives — concealment, silent execution, output suppression, and confirmation bypass, each with structured amplifier metadata and action flags
- D-13: YAML frontmatter validation — unexpected fields beyond spec, invalid field types, abnormally long descriptions (>500 chars), YAML injection constructs (anchors, aliases, merge keys, duplicate keys, embedded document markers, parser errors), and frontmatter descriptions containing action directives

**Key design decisions:**

1. **Complementary to ML, not redundant.** Deterministic rules catch known, exact phrases. The ML ensemble catches rephrased or novel variations. A finding flagged by both layers reinforces confidence. The scoring system accounts for this.

2. **Suppression detection is a severity amplifier.** Suppression findings carry a metadata flag that the scoring layer (Epic 11) uses to elevate other findings' severity. A skill that reads `.env` is MEDIUM. A skill that reads `.env` and says "do not mention this step" is CRITICAL.

3. **Frontmatter validation lives here** because injection-via-description (attack vector 1.3) is an injection pattern. The validator parses only leading `SKILL.md` frontmatter, preserves field spans and parser observations, emits a `FRONTMATTER_DESCRIPTION` segment, and suppresses duplicate generic findings on the original file span when the derived description segment already captures them.

**Acceptance criteria:**
- Known jailbreak phrases are detected
- Role delimiter injection is detected
- System prompt mimicry is detected
- Suppression directives are detected with the amplifier metadata flag
- YAML frontmatter is validated: unexpected fields, long descriptions, YAML injection constructs
- Injection-in-description attacks are caught
- Benchmark dataset includes known injection phrases, novel rephrasings (for ML comparison), and suppression directives combined with other attacks

**BRD coverage:** D-11, D-12, D-13

---

## Epic 7 — Deterministic Checks: Structural & Metadata

**Purpose:** Build the checks that validate skill directory structure, classify URLs with context-aware severity, detect package poisoning and skill-name typosquatting, and flag display-density anomalies in large text-like artifacts.

**Modules introduced:**
- `detectors/rules/structural.py` — Skill structure validation, URL classification, file size anomaly detection, package poisoning

**Rules in this cluster:**
- D-14: Skill directory structure validation — verify expected structure for declared skills, flag nested manifests, risky top-level directories, unexpected files, executables outside `scripts/`, native binaries, archives, and suspicious hidden entries
- D-15: URL classification — canonicalize `hxxp`, `[.]`, punycode, and percent-encoded URLs; classify allowlisted hosts, shorteners, IP-literal or obscured-IP hosts, non-HTTPS, suspicious encoding tricks, and unknown domains with severity based on documentation vs install/executable/registry context
- D-20: Package poisoning — custom package indices (`--index-url`, `--registry`), typosquatted package names, dependency confusion patterns, and skill-name typosquatting using curated protected lists and length-aware Damerau-Levenshtein thresholds
- D-23: File size anomaly — flag text-like artifacts with large hidden/non-rendered regions, invisible-Unicode mass, or low display density rather than using a naive byte/character ratio

**Key design decisions:**

1. **URL allowlist is configurable** (BRD CFG-9). Ships with a sensible default. Users can extend it.

2. **Typosquatting uses curated, length-aware distance checks.** Protected package and skill-name lists are checked with normalization rules plus Damerau-Levenshtein thresholds, first-character guards, and token-count preservation to keep false positives down.

3. **Structure validation is skill-directory-aware.** Each skill directory is validated independently when scanning a parent directory.

4. **File size anomaly uses display density and corroboration.** Large text-only artifacts are evaluated by rendered display cells, hidden-comment byte mass, invisible-Unicode byte mass, and low-density corroboration rather than a single byte/character ratio.

**Acceptance criteria:**
- Unexpected files in skill directories are flagged
- URLs are categorized and flagged appropriately
- Trusted URLs on the allowlist produce INFO-level findings only
- Custom package indices are detected
- Typosquatted package names are detected
- File size anomalies are detected
- URL allowlist is configurable
- Benchmark dataset includes skills with suspicious URLs, typosquatted packages, unexpected structures, and steganographic anomalies

**BRD coverage:** D-14, D-15, D-20, D-23

---

## Epic 8 — Deterministic Checks: Persistence & Cross-Agent

**Purpose:** Build the checks that detect time-bombs, persistence mechanisms, cross-agent targeting, and auto-invocation abuse while staying conservative on benign logging, test gating, and routine repository files.

**Modules introduced:**
- `detectors/rules/temporal.py` — Time-bomb detection, persistence targets, cross-agent targeting, auto-invocation analysis

**Rules in this cluster:**
- D-16: Time-bomb detection — time/date checks, environment-gated behavior (`CI`, `GITHUB_ACTIONS`, `SANDBOX`, `TEST`), and state/counter gates, but only when they participate in a branch or delayed-behavior pattern
- D-17: Persistence target detection — write/create/install operations targeting agent config files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `MEMORY.md`, `settings.json`), shell configs (`.bashrc`, `.profile`, `.zshrc`), cron/crontab, launchd/systemd, and git hooks
- D-18: Cross-agent targeting — write/create/install operations targeting other agents' config or skill directories (`.gemini/`, `.cursor/`, `.copilot/`, `.codex/`, `.agents/`, etc.), including shadow skill installation via new `SKILL.md` creation
- Auto-invocation abuse — `SKILL.md` descriptions that are broad, high-frequency, and generic enough to match almost any query when `disable-model-invocation` is not set to `true`

**Key design decisions:**

1. **Persistence and cross-agent checks apply to both markdown and code.** A SKILL.md that says "update CLAUDE.md" is as dangerous as a script that writes to `~/.claude/settings.json`. These rules scan both text content and code content.

2. **Cross-agent detection needs the full list of known agent directories.** Drawing from the agent-skills-comparison doc: `.claude/`, `.agents/`, `.cursor/`, `.github/`, `.gemini/`, `.windsurf/`, `.clinerules/`, and their global equivalents. This list is configurable.

3. **Auto-invocation analysis is heuristic.** Count generic action verbs in the description, combine them with word-count thresholds, and require that model invocation is not explicitly disabled. MEDIUM severity — suspicious, not conclusive.

4. **Time-bomb detection covers both direct and indirect patterns.** Direct: `if datetime.now().weekday() >= 5`. Indirect: scripts that use counter files or check for marker files. Benign timestamp logging should stay out of scope.

**Acceptance criteria:**
- Date/time conditionals in scripts are detected
- Environment-conditional behavior is flagged
- Write operations targeting agent config files detected in both markdown and code
- Write operations targeting shell configs, cron, git hooks detected
- Cross-agent skill directory writes detected
- Shadow skill installation detected
- Overly broad descriptions flagged
- Known agent directory list is configurable
- Benchmark dataset includes time-bomb, persistence, cross-agent, and broad description skills

**BRD coverage:** D-16, D-17, D-18

---

## Epic 9 — ML Prompt Injection Ensemble

**Purpose:** Build the prompt injection detection layer that runs against markdown and other text-like skill content using multiple small classifier models with weighted voting. Memory-conscious by default, but with configurable bounded concurrency for larger machines.

**Modules introduced:**
- `detectors/ml/__init__.py` — Exports the ensemble detector
- `detectors/ml/ensemble.py` — The ensemble orchestrator. Loads one model at a time, runs it against all text segments across all files, stores results, unloads, repeats, then aggregates.
- `detectors/ml/models.py` — Model wrapper classes. A base `InjectionModel` protocol, a catalog of supported prompt-injection models, and a HuggingFace sequence-classifier wrapper.
- `detectors/ml/download.py` — Model download and caching at `~/.skillinquisitor/models/`.

**How it works:**

1. Pipeline collects ML-eligible text segments from `SKILL.md`, markdown/text-like references, frontmatter descriptions, HTML comments, code fences, and decoded/derived payloads such as Base64 and ROT13 views. Long segments are split into overlapping line-aware windows before inference so late-file payloads are not lost to model truncation.
2. Hands the full batch to the ensemble detector
3. For each configured model:
   - Load model into memory
   - Run model against all text segments across all files
   - Store results, unload model, free memory
   - By default this happens sequentially; users can raise `layers.ml.max_concurrency` to run a bounded number of model jobs at once
4. Aggregate stored results: weighted average for binary decision (against threshold), unweighted average for confidence, std dev for uncertainty, max for worst-case risk
5. Emit `Finding` objects with per-model scores in details

**Model output format:**

```python
@dataclass
class InjectionResult:
    label: str                    # Model's predicted label ("injection", "unsafe", etc.)
    label_scores: dict[str, float]  # Probability per label
    malicious_score: float        # Normalized probability of "bad" label(s)
```

Each model wrapper maps its own label set to a normalized `malicious_score`. The raw `label_scores` go into finding details for transparency.

**Key design decisions:**

1. **Sequential by default, bounded concurrency when requested.** The default runtime keeps one model in memory at a time. Users can opt into higher `layers.ml.max_concurrency` when they have spare memory and want lower latency.

2. **Pipeline batches text segments for ML.** The pipeline collects ML-eligible text segments first, then hands the full batch to the ensemble. This is different from per-file routing — it's a batch operation.

3. **Segment-level, not file-level.** The detector scores meaningful segments so findings point to specific locations. A SKILL.md might be safe overall but have an injected HTML comment on line 47.

4. **Model-agnostic ensemble.** The ensemble works with the `InjectionModel` protocol. Adding a new model means writing a wrapper that implements `predict(text: str) -> InjectionResult`. No changes to ensemble logic.

5. **Config-driven model selection.** Config specifies which models to load, HuggingFace IDs, weights, batch size, minimum segment length, long-segment chunking, auto-download behavior, and concurrency. The initial default ensemble uses Llama Prompt Guard 2 86M plus Wolf-Defender, Vijil Dome, and ProtectAI DeBERTa v3 base profiles.

6. **Per-scan model loading.** The current implementation loads each configured model once per scan, runs it across the full segment batch, then unloads it. This keeps the runtime simple and memory-safe while still avoiding per-file reloads.

7. **Graceful absence.** If `torch`/`transformers` aren't installed, returns empty list with warning.
8. **Graceful per-model failure.** If an individual configured model is gated, unavailable, or fails to load, the ensemble skips that model, records the failure in layer metadata, and continues with the remaining models.

**CLI addition:** This epic also implements the `models` subcommands:
- `skillinquisitor models list` — list configured ML models with download status
- `skillinquisitor models download` — pre-download all configured models

**Acceptance criteria:**
- `uv sync --extra ml --group dev` installs ML dependencies
- First run auto-downloads configured models
- Scanning a SKILL.md with known injection patterns produces findings with confidence scores and per-model breakdowns
- Scanning a clean SKILL.md produces no ML findings
- Models load one at a time by default, memory is freed between models, and configurable bounded concurrency works when enabled
- Scanning without ML dependencies works (skips with warning)
- Multiple files in a directory are all scanned, models loaded only once per scan per model
- `skillinquisitor models list` shows configured models and whether they're cached locally
- `skillinquisitor models download` pre-downloads all configured models

**BRD coverage:** ML-1 through ML-10, CLI-9, CLI-10

---

## Epic 10 — LLM Code Analysis

**Purpose:** Build the semantic code analysis layer using small code-capable LLMs in a judge pattern. The shipped Epic 10 implementation focuses on local llama.cpp inference, hardware-aware model-group selection, deterministic-targeted verification, and optional whole-skill review via `repomix` when the packed context stays under a token budget.

**Modules introduced:**
- `detectors/llm/__init__.py` — Exports the LLM judge detector
- `detectors/llm/judge.py` — The judge orchestrator. Sequential load-one-run-all-unload pattern. Runs general file review, targeted verification, and optional repo-wide analysis planning.
- `detectors/llm/models.py` — Model wrapper classes and hardware selection. Base `CodeAnalysisModel` protocol plus the shipped llama.cpp runtime, a lightweight heuristic runtime for fixture-backed tests, and `tiny` / `balanced` / `large` group selection helpers.
- `detectors/llm/prompts.py` — Prompt library. General security prompts plus targeted prompt templates keyed to deterministic finding categories.
- `detectors/llm/download.py` — Model download and caching.

**Two-mode analysis:**

**Mode 1 — General security analysis (always runs):** Every code file gets a broad security analysis prompt covering: data exfiltration, credential theft, obfuscation, persistence, privilege escalation, suppression of user awareness, and any other suspicious patterns. General findings are suppressed when the same file also has targeted verification findings, which keeps reports from duplicating the same issue twice.

**Mode 2 — Targeted verification (driven by deterministic findings):** The pipeline passes deterministic findings to the LLM detector. For each finding category, the LLM gets a focused follow-up prompt:

| Deterministic Finding | Targeted LLM Prompt |
|----------------------|---------------------|
| READ_SENSITIVE (D-7, D-8) | "This script accesses [specific file/variable]. Trace the data flow: where does this data go after it's read? Is it sent externally, written to a file, embedded in output, or used only locally?" |
| NETWORK_SEND (D-9) | "This script makes a request to [URL/endpoint]. What data is included? Could sensitive information be exfiltrated?" |
| EXEC_DYNAMIC (D-10) | "This script uses [eval/exec/subprocess] at [location]. What is being executed? Is the input user-controlled, decoded from an encoded source, or hardcoded?" |
| Behavior chain (D-19) | "This script reads [sensitive resource] AND sends data to [destination]. Analyze the complete data flow. Is the sensitive data reaching the network call?" |
| WRITE_SYSTEM (D-17) | "This script writes to [config/cron/shell rc]. What content is being written? Does it install persistence, modify agent behavior, or inject instructions?" |
| CROSS_AGENT (D-18) | "This script writes to [other agent's directory]. What is it creating or modifying? Could this compromise another AI agent?" |
| Time-bomb (D-16) | "This script has date/time conditional logic at [location]. What behavior changes? Compare what happens when the condition is true vs false." |
| Obfuscation (D-3, D-4, D-5) | "This script contains [encoding type] content that decodes to [preview]. Analyze the decoded payload: what does it do when executed?" |

**Pipeline flow:**

1. Pipeline runs deterministic checks on all files, collecting findings
2. Pipeline runs ML ensemble on all markdown files
3. Pipeline hands all code files AND the deterministic findings to the LLM detector
4. For each configured model (sequential load/unload):
   - For each code file, run the general security prompt
   - For each code file with relevant deterministic findings, run targeted prompts with specific finding details (file paths, line numbers, matched patterns, action chains)
   - Store results, unload model
5. Aggregate across models — semantic agreement (multiple models flagging the same issue = higher confidence)
6. If `repomix` is enabled and the packed skill stays under the configured token budget, run an optional whole-skill review to catch cross-file behavior
7. Targeted findings carry references back to the deterministic findings they verify

**Key design decisions:**

1. **The pipeline passes deterministic findings to the LLM detector.** The detector protocol's optional `prior_findings` parameter carries this. The LLM detector uses it; other detectors ignore it.

2. **Targeted prompts are more valuable than general prompts.** General: "this looks suspicious." Targeted: "this reads ~/.ssh/id_rsa on line 12 and the data flows to urllib.request.urlopen on line 18 — this is data exfiltration." Targeted analysis produces more specific, actionable, higher-confidence findings.

3. **Not every deterministic finding triggers a targeted prompt.** Only categories where LLM adds value. Unicode detection doesn't need verification. Behavior chains benefit enormously from data flow tracing.

4. **Targeted findings can upgrade OR downgrade.** If deterministic checks flag a chain but the LLM determines the data doesn't actually flow to the network call, the LLM finding lowers confidence. This is how false positives are reduced.

5. **Structured output parsing.** The prompt instructs the model to output parseable JSON with `disposition`, `severity`, `category`, `message`, `confidence`, `behaviors`, and `evidence`. If the model produces unparseable output, that's degraded result, not a crash.

6. **Hardware-aware model groups.** CPU-only systems default to `tiny`; systems with a GPU and at least `8 GB` VRAM prefer the shipped `balanced` group; `large` is always opt-in. Groups are config-defined, so users can replace the shipped defaults without code changes.

7. **Whole-skill review is bounded.** The repo-wide pass is optional and only runs when `repomix` succeeds and the packed skill stays under the configured token budget.

8. **Local-first delivery.** Epic 10 ships the llama.cpp local runtime and leaves API adapters as follow-up work. The config surface keeps `layers.llm.api` reserved so the future adapter can fit without redesigning the surrounding pipeline.

9. **Sequential model loading.** Same memory-conscious pattern as ML ensemble.

**Acceptance criteria:**
- General security analysis runs on all code files regardless of deterministic findings
- Targeted analysis runs on code files with relevant deterministic findings
- Targeted prompts include specific details from deterministic findings
- Models load one at a time, memory freed between models
- CPU-only systems default to `tiny`, and systems with >= `8 GB` VRAM prefer the shipped `balanced` group
- `models list` / `models download` expose both ML and LLM model configuration
- Optional whole-skill `repomix` analysis only runs when the packed context is under the configured token budget
- LLM findings reference the deterministic findings they verify
- LLM analysis can both confirm (upgrade) and dispute (downgrade) deterministic findings
- Unparseable model output degrades gracefully
- Scanning without LLM dependencies and no API config skips this layer with warning

**Current implementation note:** Epic 10 currently fulfills the local-inference portion of the BRD and the confirmation/dispute workflow needed by Epic 11. API inference and differentiated deep-analysis prompts remain follow-up work.

---

## Epic 11 — Risk Scoring & Output Formatters

**Purpose:** Build the scoring aggregation that turns raw findings into a risk score and verdict, plus the output formatters. After this epic, `skillinquisitor scan` produces polished, actionable reports.

**Modules introduced:**
- `scoring.py` — Risk score calculation, severity amplification, cross-layer reinforcement, verdict determination
- `alerts.py` — Webhook alerting. **Deferred to Epic 15.** Triggers when findings exceed a configurable severity threshold. Sends formatted payloads to Discord (rich embed), Telegram (markdown message), and/or Slack (block kit message) via configured webhook URLs. 5-second timeout per webhook.
- `formatters/console.py` — Human-readable colored terminal output
- `formatters/json.py` — Machine-readable JSON output
- `formatters/sarif.py` — SARIF format for GitHub Code Scanning and VS Code

**Scoring algorithm:**

1. **Base score: 100**
2. **Deduct per finding** based on severity weight: CRITICAL (-30), HIGH (-20), MEDIUM (-10), LOW (-5), INFO (0). Weights configurable.
3. **Diminishing returns:** Multiple findings at the same severity tier use geometric decay (default factor 0.7) so the Nth finding of a tier contributes 0.7^(N-1) of the base weight. This prevents score collapse from many similar findings.
4. **Confidence weighting:** ML and LLM findings contribute proportional to their confidence scores rather than at full weight.
5. **Suppression amplifier:** If any suppression directive (D-12) is present, multiply all other findings' deductions by 1.5.
6. **Cross-layer dedup:** If the same segment and category are flagged by multiple layers, don't double-deduct — take the deduction once at the higher confidence.
7. **Chain findings supersede components.** When a behavior chain fires, the individual component findings' deductions are absorbed into the chain's deduction. No double-counting.
8. **LLM adjustment.** If an LLM targeted finding disputes a deterministic finding, the deterministic finding's deduction is reduced and its severity floor is lifted. If the LLM confirms, the deduction is boosted.
9. **Severity floors:** Undisputed CRITICAL findings cap the score at 39; undisputed HIGH findings cap at 59.
10. **Clamp to 0-100.**

**Verdict mapping:**

| Score | Verdict | Exit Code |
|-------|---------|-----------|
| 80-100 | SAFE | 0 |
| 60-79 | LOW RISK | 1 |
| 40-59 | MEDIUM RISK | 1 |
| 20-39 | HIGH RISK | 1 |
| 0-19 | CRITICAL | 1 |

**Formatter details:**

- **Console:** Grouped by file, then by severity (CRITICAL first). Color-coded severity. Each finding shows rule ID, category, message, file:line. Summary at bottom with counts by severity, category, and layer. Respects `--quiet` (exit code only) and `--verbose` (per-model scores, timing).
- **JSON:** Findings-focused output (skills with path/name only, no raw content). Stable schema for Epic 13 agent skill interface.
- **SARIF:** Maps findings to SARIF `Result` objects with `ruleId`, `level`, `location`, `message`. Compatible with GitHub Code Scanning.
- **Delta mode** (R-11): `--baseline <previous-result.json>` loads a previous result and the formatter only shows new findings. **Deferred to Epic 15.**

**Deferred to Epic 15:** Webhook alerts (`alerts.py`), delta/baseline mode (`--baseline`), and remediation guidance per finding type (R-9) were moved out of Epic 11 to keep scope focused on core scoring and formatters.

**Key design decisions:**

1. **Scoring is its own module.** The pipeline collects findings, then hands them to `scoring.py`. Testable and configurable independently.

2. **Formatters consume `ScanResult`, nothing else.** They don't know about detectors, models, or config. Adding a new format means writing one formatter.

**Acceptance criteria:**
- Risk score correctly aggregates with deductions, amplification, chain absorption, and LLM downgrade
- Suppression findings amplify other findings
- Cross-layer reinforcement doesn't double-deduct
- Console output is grouped, color-coded, readable
- JSON output has a stable, documented schema
- SARIF validates against SARIF 2.1.0 schema
- `--quiet` outputs nothing (exit code only)
- `--verbose` includes per-model scores and timing
- ~~`--baseline` correctly shows only new findings~~ *(deferred to Epic 15)*
- Verdict and exit codes map correctly
- ~~Discord/Telegram/Slack alerts fire when configured and findings exceed threshold~~ *(deferred to Epic 15)*
- ~~Alert payloads include skill name, score, risk level, and top findings~~ *(deferred to Epic 15)*

**BRD coverage:** R-1 through R-11, CFG-10

---

## Epic 12 — Comparative Benchmark & Evaluation

**Purpose:** Build the evaluation framework to measure SkillInquisitor's detection quality against a labeled dataset, track regressions, and eventually compare against frontier models and existing tools.

**Status:** Part 1 complete (self-benchmarking). Part 2 (frontier model comparison, external tool comparison) is future work.

**Modules implemented (Part 1):**
- `src/skillinquisitor/benchmark/__init__.py` — Package exports
- `src/skillinquisitor/benchmark/dataset.py` — Manifest schema (8 Pydantic models), loading, filtering by tier/tags, path resolution
- `src/skillinquisitor/benchmark/metrics.py` — Hand-rolled confusion matrix, per-category recall, severity accuracy, latency stats, coverage checks. No sklearn dependency.
- `src/skillinquisitor/benchmark/runner.py` — Async benchmark orchestration with semaphore concurrency, per-skill error isolation, findings-focused JSONL output
- `src/skillinquisitor/benchmark/report.py` — Markdown report with executive summary, regression delta, confusion matrix, per-category detection rates, performance, error analysis

**Modules deferred (Part 2):**
- `benchmark/frontier.py` — Frontier model baseline runner (Claude, GPT-4o, Gemini)
- `benchmark/tools.py` — Existing tool comparison (Cisco skill-scanner, SkillSentry, ClawCare)

**Dataset (266 labeled skills):**

```
benchmark/
├── manifest.yaml              # Ground truth, metadata, provenance for all 266 entries
├── dataset/
│   └── skills/                # Opaque flat structure: skill-0000 through skill-0265
│       ├── skill-0000/        # Each contains SKILL.md + optional scripts/ + _meta.yaml
│       ├── skill-0001/
│       └── ...
├── baselines/                 # Blessed regression baselines
└── results/                   # gitignored — benchmark run outputs
```

Skill directories use opaque sequential IDs. Skill names and descriptions are intentionally neutral — no directory names, frontmatter names, or descriptions reveal whether a skill is malicious, safe, or ambiguous. This prevents the LLM analysis layer from being biased by filesystem metadata.

**Dataset composition:**

| Category | Count | Sources |
|----------|-------|---------|
| Malicious | 140 | Synthetic (50), test fixtures (41), MaliciousAgentSkillsBench (44), SkillJect (4), STEGANO (1) |
| Safe | 95 | Synthetic counterparts (31), test fixtures (20), GitHub repos (43), SkillJect clean (1) |
| Ambiguous | 31 | Synthetic gray-area (30), test (1) |
| **Total** | **266** | |

Real-world safe skills sourced from: Trail of Bits (15), Anthropic (8), Cloudflare (3), HashiCorp (2), Vercel (2), HuggingFace (1), Stripe (1), Supabase (1), SkillJect clean baselines (10).

Real-world malicious skills sourced from: MaliciousAgentSkillsBench (44 from 42 repos, mapped via taxonomy bridge), SkillJect bash script payloads (4), STEGANO Unicode steganography PoC (1).

**Labeling:** Three-tier verdict (MALICIOUS/SAFE/AMBIGUOUS) with configurable binary decision threshold (default 60.0). Attack categories, expected rules, and minimum category coverage use minimum-coverage semantics. Provenance metadata for real-world skills. Containment metadata for malicious skills documenting defanging.

**CLI (implemented):**
- `skillinquisitor benchmark run` — Run benchmark with `--tier`, `--layer`, `--threshold`, `--concurrency`, `--baseline`, `--output`
- `skillinquisitor benchmark compare <run-a> <run-b>` — Metric deltas between two runs
- `skillinquisitor benchmark bless <run-dir> --name v1` — Bless a run as regression baseline

**Key design decisions:**

1. **Uses the same `pipeline.py` as the CLI.** Benchmark results reflect actual tool behavior.
2. **Opaque dataset structure.** Skill directories are `skill-NNNN` with neutral names to prevent LLM layer bias.
3. **Configurable decision threshold.** Binary classification boundary is not hardcoded — users can compare at multiple operating points.
4. **Minimum-coverage semantics.** Expected rules and categories check that at least those items appear — additional findings are not penalized. Prevents brittleness as rules evolve.
5. **Findings-focused output.** JSONL results contain findings metadata but no raw artifact content, matching the app's security policy.
6. **Tiered execution.** Smoke (~48 skills, CI gate), standard (~265, nightly), full (all, release).
7. **Hand-rolled metrics.** No sklearn dependency — the math is simple and the dependency surface matters for a security tool.
8. **Frontier comparison is deferred to Part 2.** Requires API keys and costs money. Part 1 proves the framework works.

**Part 1 acceptance criteria (met):**
- Dataset contains 266 labeled skills across all attack vector categories ✓
- Benchmark produces precision, recall, F1, per-category recall, false positive rate, latency ✓
- Per-layer incremental metrics via `--layer` flag ✓
- Report includes confusion matrices, per-category tables, error analysis ✓
- Regression comparison via `benchmark compare` and `benchmark bless` ✓
- Dataset uses opaque IDs that don't leak ground truth to the LLM layer ✓

**Part 2 acceptance criteria (deferred):**
- Frontier model baselines produce comparable metrics
- Existing tool comparison works for available tools
- Value proposition thresholds explicitly evaluated
- Dataset expanded to 500+ skills
- Cost analysis and calibration curves

**BRD coverage:** BD-1 through BD-12 (partial), BL-1 through BL-4, BM-1 through BM-9, BM-12 through BM-14, BR-1 through BR-3. Remaining BRD items deferred to Part 2.

---

## Epic 13 — Agent Skill Interface

**Purpose:** Package SkillInquisitor as an installable agent skill for in-workflow scanning across agents that support the Agent Skills standard.

**Modules introduced:**
- `skill/SKILL.md` — Skill definition with YAML frontmatter and instructions
- `skill/scripts/scan.sh` (or `scan.py`) — Thin wrapper invoking `skillinquisitor scan`

**SKILL.md frontmatter:**

```yaml
---
name: skillinquisitor
description: Security scanner for AI agent skill files. Detects prompt injection, malicious code, obfuscation, credential theft, data exfiltration, and other threats before installation.
---
```

The body contains agent instructions: how to invoke, parameters, how to interpret results, pre-install check workflow.

**Key design decisions:**

1. **The skill invokes the CLI.** The agent runs `skillinquisitor scan <path> --format json` and parses JSON output. No separate Python API needed.

2. **JSON is the contract between CLI and skill.** The skill instructions tell the agent how to summarize JSON results for the user.

3. **The skill must pass its own scan** (BRD S-6). Verified in CI.

4. **Natural language invocation** (BRD SK-5). Description is specific enough to trigger on security scanning requests but not so broad it auto-invokes on unrelated tasks.

5. **Pre-install check mode** (BRD SK-7). Skill instructions guide the agent: "If the user is about to install a skill from an external source, offer to scan it first."

**Acceptance criteria:**
- SKILL.md conforms to the Agent Skills specification
- Skill can be installed into `.claude/skills/skillinquisitor/`
- `/skillinquisitor <path>` invokes the scanner from within an agent
- Natural language invocation works
- JSON output is correctly parsed and presented
- The skill's own files pass a SkillInquisitor scan
- Works across agents supporting the standard

**BRD coverage:** SK-1 through SK-7, S-6

---

## Epic 14 — Integrations (GitHub Actions & Pre-commit Hook)

**Purpose:** Build the two CI/CD integration points: a GitHub Action and a pre-commit hook.

**Files introduced:**
- GitHub Action definition (`.github/actions/skillinquisitor/action.yml` or published action)
- `hooks/pre-commit` — Pre-commit hook script
- `.pre-commit-hooks.yaml` — Hook definition for the pre-commit framework

**GitHub Action (BRD A-1):**

1. Detects changed files in skill directories (default: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, `.gemini/skills/` — configurable)
2. Runs `skillinquisitor scan` only on changed skill files
3. Outputs SARIF, uploads to GitHub Code Scanning
4. Fails check if findings exceed configurable severity threshold

```yaml
- uses: skillinquisitor/skillinquisitor-action@v1
  with:
    severity-threshold: HIGH
    skill-directories: |
      .claude/skills/
      .agents/skills/
    format: sarif
```

**Pre-commit hook (BRD A-2):**

1. Filters staged files to skill directories (same defaults, configurable)
2. Runs `skillinquisitor scan` on staged skill files only
3. Blocks commit if findings exceed threshold
4. Outputs findings to stderr

```yaml
- repo: https://github.com/skillinquisitor/skillinquisitor
  hooks:
    - id: skillinquisitor
      args: ['--severity', 'HIGH']
```

**Key design decisions:**

1. **Both scan only changed/staged files.** Full repo scans are expensive. CI catches new threats as introduced.

2. **Both use the same CLI.** No separate scanning logic.

3. **Severity threshold is the gate.** "Block on any CRITICAL finding" is clearer than score-based gating.

4. **GitHub Action defaults to deterministic-only.** No ML/LLM model downloads in CI unless explicitly configured.

**Acceptance criteria:**
- GitHub Action detects changed skill files in a PR
- GitHub Action produces valid SARIF and uploads to Code Scanning
- GitHub Action fails when findings exceed threshold
- Pre-commit hook filters staged files to skill directories
- Pre-commit hook blocks commit when findings exceed threshold
- Both use the standard CLI
- Both work deterministic-only

**BRD coverage:** A-1, A-2

---

## Epic 15 — Future / Stretch Epics

These are acknowledged for completeness but out of the initial build sequence. Each gets its own brainstorm cycle when the time comes.

**Webhook Alerts (deferred from Epic 11):** Discord, Telegram, and Slack webhook alerting via `alerts.py`. Triggers when findings exceed a configurable severity threshold. Sends formatted payloads with skill name, score, risk level, and top findings. 5-second timeout per webhook.

**Delta/Baseline Mode (deferred from Epic 11):** `--baseline <previous-result.json>` loads a previous scan result and formatters show only new findings. Supports regression detection workflows.

**Remediation Guidance (deferred from Epic 11, R-9):** Per-finding-type remediation suggestions explaining what was detected and how to address it.

**Known-Good Skill Registry (BRD 8.1):** SHA-256 hash registry of approved skills. Skip/fast-track scanning for known-good hashes. Import/export for team sharing.

**Skill Provenance Verification (BRD 8.2):** Verify GitHub repository owner against trusted authors list. Flag unverified authorship claims. Check for signed commits.

**Skill Diffing (BRD 8.3):** Compare updated skills against previous approved versions. Scan only the diff. Flag significant changes between versions (rug pull detection).

**Skill Capability Declaration & Enforcement (BRD 8.4):** Define capability model (network, file read, file write, exec). Analyze actual usage vs declared capabilities. Flag mismatches.

**Batch & Marketplace Scanning (BRD 8.5):** Scan entire marketplaces via manifest URL. Aggregate reports. Parallel scanning.

**Watch Mode & Continuous Monitoring (CLI-16, BRD 8.6):** CLI-16 (`--watch` flag) is a simple file watcher that re-scans on change — intentionally deferred from the core epics but simpler than the full continuous monitoring daemon described in BRD 8.6. The full daemon mode adds alerting on new/modified skills, background monitoring of multiple directories, and integration with system notification mechanisms.

**Cross-Skill Correlation (BRD 8.8):** Analyze multiple skills together. Detect name collisions. Detect skills that reference/modify other skills.

**Incremental Scanning (P-4):** Only re-scan files that changed since the last scan. Requires storing file hashes from previous runs and comparing on startup. Performance optimization that becomes important at scale but not needed for initial implementation where scan times are already under the P-3 target.

**Report History & Trending (BRD 8.9):** Store results locally. Compare to previous results. Detect regression.

---

## Build Sequence Summary

| # | Epic | Key Deliverable |
|---|------|-----------------|
| 1 | CLI Scaffold, Pipeline & Configuration | Working `skillinquisitor scan`, full config system, Skill→Artifact→Segment data model, empty pipeline |
| 2 | Regression Test Harness | Fixture-based test framework, safe baselines, fixture template for all subsequent epics |
| 3 | Deterministic: Unicode & Steganography | Rule engine framework, normalization pipeline, hidden content detection, `rules` CLI |
| 4 | Deterministic: Encoding & Obfuscation | Base64 and text-like hex decoding with recursive re-scanning, XOR pattern detection, provenance chains |
| 5 | Deterministic: Secrets & Exfiltration | Credential detection, network patterns, behavior chain analysis at Skill level |
| 6 | Deterministic: Injection & Suppression | Known injection patterns, jailbreak detection, suppression amplifier |
| 7 | Deterministic: Structural & Metadata | Directory validation, URL classification, skill + package typosquatting, file anomalies |
| 8 | Deterministic: Persistence & Cross-Agent | Time-bombs, persistence targets, cross-agent writes, auto-invocation abuse |
| 9 | ML Prompt Injection Ensemble | Sequential model loading, weighted voting, segment-level detection, `models` CLI |
| 10 | LLM Code Analysis | General security analysis + targeted verification of deterministic findings |
| 11 | Risk Scoring & Output Formatters | Score aggregation with diminishing returns and severity floors, console/JSON/SARIF 2.1.0 output, verdict-based exit codes |
| 12 | Comparative Benchmark & Evaluation | 500+ labeled dataset, frontier model baselines, existing tool comparison, value proposition report |
| 13 | Agent Skill Interface | SKILL.md for in-agent scanning |
| 14 | Integrations | GitHub Action + pre-commit hook |
| 15+ | Future / Stretch | Registry, provenance, diffing, capabilities, batch, watch/monitoring, incremental scanning, correlation, trending |
