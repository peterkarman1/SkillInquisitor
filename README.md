# SkillInquisitor

Security scanner for AI agent skill files. Detects prompt injection, malicious code, obfuscation, credential theft, data exfiltration, and other threats before installation. Works across all major AI coding agent platforms that support the [Agent Skills](https://agentskills.io) standard — Claude Code, Cursor, GitHub Copilot, Codex CLI, Gemini CLI, and 25+ others.

## How It Works

SkillInquisitor runs a three-layer detection pipeline on each skill directory:

1. **Deterministic rules** — Fast pattern matching across 54 rule families for known attack signatures
2. **ML prompt-injection ensemble** — 3 small classifier models with weighted soft voting
3. **LLM code analysis** — Local GGUF models via llama-server for semantic code review

Each layer feeds into a risk scoring engine that produces a 0-100 score and a verdict (SAFE, LOW RISK, MEDIUM RISK, HIGH RISK, CRITICAL).

## Requirements

- Python 3.13+
- `uv` (package manager)
- `llama-server` for LLM layer (install via `brew install llama.cpp` on macOS, or use Docker)
- `git`

## Setup

```bash
uv sync --group dev
uv run skillinquisitor models download
```

## Quick Start

```bash
# Scan a local skill directory
uv run skillinquisitor scan path/to/skill/

# Scan a directory containing multiple skills in parallel
uv run skillinquisitor scan path/to/skill-catalog --workers 4

# Scan from a GitHub URL
uv run skillinquisitor scan https://github.com/org/repo

# Scan from stdin
cat SKILL.md | uv run skillinquisitor scan -

# Output as JSON or SARIF
uv run skillinquisitor scan path/to/skill --format json
uv run skillinquisitor scan path/to/skill --format sarif > results.sarif
```

Exit codes: `0` = SAFE, `1` = risk detected, `2` = error.

## CLI Reference

```
skillinquisitor scan <target> [OPTIONS]
  --format        text | json | sarif (default: text)
  --checks        Enable specific rule IDs
  --skip          Disable specific rule IDs
  --severity      Minimum severity to report
  --config        Path to config YAML
  --quiet         Exit code only, no output
  --verbose       Per-model scores, timing, scoring details
  --llm-group     Force LLM model group: tiny | balanced | large
  --workers       Parallelize multi-skill scans (default: 1)

skillinquisitor models list          # Show model status
skillinquisitor models download      # Download all configured models
skillinquisitor rules list           # List all deterministic rules
skillinquisitor rules test <ID> <target>  # Test one rule against a target

skillinquisitor benchmark run [OPTIONS]
  --tier          smoke | standard | full (default: standard)
  --layer         deterministic | ml | llm (repeatable, default: all)
  --threshold     Binary decision threshold (default: 60.0)
  --dataset-profile  real_world | safe_only | malicious_only (default: real_world)
  --concurrency   Maximum concurrent benchmark workers (default: 1)
  --timeout       Per-skill timeout in seconds (default: 120)
  --dataset       Path to manifest.yaml
  --output        Output directory
  --baseline      Baseline for regression comparison

skillinquisitor benchmark compare <run-a> <run-b>
skillinquisitor benchmark bless <run-dir> --name <name>
```

---

## Architecture

### Data Model

Every scan operates on a hierarchy: **Skill -> Artifact -> Segment**.

- **Skill** — A directory containing `SKILL.md` and optional `scripts/`, `references/`, `assets/`
- **Artifact** — A single file within the skill. Frontmatter is parsed, binary signatures are detected.
- **Segment** — An atomic unit of analysis derived from an artifact:
  - `ORIGINAL` — raw file content
  - `DERIVED` — extracted from encoding layers (Base64 decoded, ROT13 transformed, HTML comments, code fences)
  - `NORMALIZED` — security-aware view with Unicode steganography cleared and homoglyphs folded

Each segment carries a provenance chain recording every transformation applied to it.

### Detection Pipeline

```
Input (file / directory / GitHub URL / stdin)
  |
  v
resolve_input() -> list[Skill]
  |
  v
normalize_artifact() -> Segments with provenance
  |
  v
Layer 1: Deterministic Rules (54 rules, ~0.1s per skill)
  |
  v
Layer 2: ML Prompt-Injection Ensemble (3 models, ~3s per skill)
  |
  v
Layer 3: LLM Code Analysis (4 models via llama-server, ~10s per skill)
  |
  v
Risk Scoring -> Score (0-100) + Verdict
  |
  v
Formatter -> Console / JSON / SARIF output
```

### Layer 1: Deterministic Rules

54 built-in rules organized into 10 threat categories. Rules run per-segment, per-artifact, or per-skill depending on scope.

#### Unicode & Steganography

| Rule | Severity | Description |
|------|----------|-------------|
| D-1A | CRITICAL | Unicode tag characters (U+E0000 range) — invisible text encoding |
| D-1B | HIGH | Zero-width characters splitting keywords |
| D-1C | HIGH | Variation selector abuse — **soft** |
| D-1D | CRITICAL | Right-to-left override (RTLO) filename spoofing |
| D-2A | HIGH | Mixed-script homoglyphs (e.g., Cyrillic in Latin context) — **soft** |
| D-6A | HIGH | Dangerous keyword splitting (e.g., `e.v.a.l`) |
| NC-3A | MEDIUM | Security-relevant normalization delta detected — **soft** |

#### Encoding & Obfuscation

| Rule | Severity | Description |
|------|----------|-------------|
| D-3A | HIGH | Suspicious Base64 payload (decodes to executable/injection content) |
| D-4A | MEDIUM | ROT13 reference detected |
| D-4B | HIGH | ROT13-transformed suspicious content |
| D-5A | HIGH | Hex-encoded payload — **soft** |
| D-5B | HIGH | XOR construct detected |
| D-5C | HIGH | Multi-layer encoding chain |
| D-21A | MEDIUM | Suspicious content in HTML comment |
| D-22A | MEDIUM | Suspicious content in code fence — **soft** |
| D-23 | MEDIUM | Display density anomaly (high encoded-to-text ratio) |

#### Credential Theft & Secrets

| Rule | Severity | Description |
|------|----------|-------------|
| D-7A | HIGH | Sensitive credential path reference (~/.aws, ~/.ssh, .env, etc.) |
| D-7B | HIGH | Cloud metadata endpoint (169.254.169.254) |
| D-8A | HIGH | Known secret environment variable (API keys, tokens) |
| D-8B | MEDIUM | Broad environment enumeration — **soft** |

#### Data Exfiltration & Execution

| Rule | Severity | Description |
|------|----------|-------------|
| D-9A | MEDIUM | Outbound network send (curl, requests.post, fetch) |
| D-10A | HIGH | Dynamic/shell execution (eval, exec, subprocess) — **soft** |

#### Behavior Chains

| Rule | Severity | Description |
|------|----------|-------------|
| D-19A | CRITICAL | Data exfiltration chain (read sensitive + send outbound) |
| D-19B | CRITICAL | Credential theft chain (read sensitive + execute dynamically) |
| D-19C | CRITICAL | Cloud metadata SSRF chain (metadata endpoint + send outbound) |

Chains synthesize component findings across multiple files into higher-severity composite findings.

#### Prompt Injection & Suppression

| Rule | Severity | Description |
|------|----------|-------------|
| D-11A | HIGH | Instruction-hierarchy override ("ignore previous instructions") |
| D-11B | MEDIUM | Role rebinding ("you are now...") |
| D-11C | HIGH | System-prompt disclosure request |
| D-11D | HIGH | Delimiter injection (`</instructions>`) |
| D-11E | MEDIUM | System-prompt mimicry (fake `<system>` tags) |
| D-11F | MEDIUM | Canonical jailbreak signatures (DAN, developer mode) |
| D-12A-D | MEDIUM | Suppression directives (non-disclosure, skip confirmation) — **D-12B, D-12C soft** |
| D-13A-E | LOW-HIGH | Frontmatter validation (anchors, aliases, field injection) |

#### Structural & Supply Chain

| Rule | Severity | Description |
|------|----------|-------------|
| D-14 | LOW-MEDIUM | Skill structure validation (missing SKILL.md, nested skills, unexpected files) — **D-14B, D-14C, D-14D soft** |
| D-15 | LOW-MEDIUM | URL classification (shortened URLs, non-HTTPS, actionable URLs) — **D-15C, D-15E, D-15G soft** |
| D-20A-F | MEDIUM-HIGH | Supply chain (typosquatting, registry override, dependency confusion) |

#### Persistence & Cross-Agent

| Rule | Severity | Description |
|------|----------|-------------|
| D-16A-C | MEDIUM-HIGH | Time-bomb / environment-gated / counter conditionals |
| D-17A | HIGH | Persistence target writes (cron, bashrc, git hooks) |
| D-18A | HIGH | Cross-agent targeting (writes to other agent config dirs) |
| D-18C | MEDIUM | Overly broad auto-invocation description — **soft rule** |

#### Soft Rules

Rules marked **soft** require LLM majority consensus (3 of 4 models must confirm) before counting in the risk score. This eliminates false positives on legitimate skills while preserving detection of real threats. Confirmed soft findings receive a 1.5x scoring boost. When the LLM layer is disabled, soft findings are dropped by default (configurable per-rule fallback confidence).

16 default soft rules:

| Rule | Why Soft |
|------|----------|
| D-10A | Security tools legitimately use subprocess for linters, analyzers |
| D-14B | Multi-skill repos have nested SKILL.md files |
| D-14C | Real skills have config files, READMEs, licenses |
| D-14D | Real skills have complex directory structures |
| D-15C | Shortened URLs appear in social media documentation |
| D-15E | Real skills reference many external domains in docs |
| D-15G | HTTP URLs appear legitimately in docs and localhost refs |
| D-18C | Legitimate tools have broad descriptions |
| D-22A | Code fences contain documentation examples, not attacks |
| D-5A | Hex strings are common in Dockerfiles, hashes, color codes |
| D-2A | Mixed scripts appear in multilingual documentation |
| D-12B | Non-interactive tools suppress output legitimately |
| D-12C | CI/CD automation uses --yes and non-interactive flags |
| D-8B | Config tools read PORT, LOG_LEVEL, and other safe env vars |
| D-1C | Variation selectors appear naturally in emoji and fonts |
| NC-3A | Minor normalization differences are common in real text |

Borderline ML findings (ensemble score < 0.85) are also automatically marked soft — the LLM consensus gate verifies them before they count. Each rule provides its own detailed LLM verification prompt with specific MALICIOUS vs SAFE criteria for that detection pattern.

### Layer 2: ML Prompt-Injection Ensemble

Three small classifier models with weighted soft voting detect prompt injection in text segments:

| Model | Parameters | Weight | Type |
|-------|-----------|--------|------|
| protectai/deberta-v3-base-prompt-injection-v2 | 184M | 0.40 | DeBERTa v3 |
| patronus-studio/wolf-defender-prompt-injection | 308M | 0.35 | ModernBERT |
| madhurjindal/Jailbreak-Detector | 66M | 0.25 | DistilBERT |

Features:
- Sequential load-one-run-unload cycle to preserve memory
- Long-text chunking (1800 chars with 3-line overlap)
- Configurable threshold (default 0.5)
- Borderline findings (score < 0.85) marked soft for LLM consensus verification
- Graceful degradation when models are unavailable
- `_meta.yaml` and non-skill files excluded from ML analysis

### Layer 3: LLM Code Analysis

SkillInquisitor ships local GGUF model groups for semantic code review via `llama-server` (from llama.cpp):

The current runtime is memory-safe by default. `scan --workers` and `benchmark run --concurrency` can overlap input resolution, normalization, deterministic analysis, and other non-heavy work across skills, while ML and LLM heavy sections remain globally single-flight by default unless the runtime config is raised.

**Tiny** (default / CPU-first)

| Model | Quant | Weight |
|-------|-------|--------|
| Qwen3.5-0.8B | Q8_0 | 0.25 |
| Llama-3.2-1B-Instruct | Q8_0 | 0.25 |
| Gemma-2-2b-it | Q4_K_M | 0.25 |
| Qwen3.5-2B | Q4_K_M | 0.25 |

**Balanced** (auto-selected at `>= 8 GB` VRAM)

| Model | Quant | Weight |
|-------|-------|--------|
| NVIDIA-Nemotron-3-Nano-4B | Q8_0 | 0.33 |
| OmniCoder-9B | Q4_K_M | 0.33 |
| Qwen3.5-9B | Q4_K_M | 0.33 |

The LLM layer performs:
- **General analysis** — review each code file for malicious behavior
- **Targeted verification** — confirm or dispute specific deterministic and ML findings
- **Soft finding consensus** — 3 of 4 models must confirm soft findings before they count
- **Per-rule prompts** — each of the 54 deterministic rules provides specific MALICIOUS vs SAFE criteria to guide the LLM's verification decision

Models run locally via `llama-server` subprocess (native install or Docker). No cloud APIs required. Qwen3.5 models use thinking mode for improved analysis quality. Supports native llama-server (homebrew) with automatic fallback to Docker (`ghcr.io/ggml-org/llama.cpp:server`).

---

## Risk Scoring

SkillInquisitor uses a subtractive scoring model starting from 100 (SAFE).

### Scoring Algorithm

1. **Chain absorption** — Chain findings (D-19) absorb component deductions to avoid double-counting
2. **Soft finding gate** — Soft deterministic findings and borderline ML findings without LLM consensus confirmation are dropped (zero score impact)
3. **Cross-layer dedup** — Same segment + category flagged by multiple layers: keep higher confidence
4. **LLM adjustment** — Dispute reduces effective confidence; confirm boosts deduction
5. **Diminishing returns** — Within each severity tier, findings decay geometrically (factor 0.7)
6. **Soft-confirmed boost** — LLM-confirmed soft findings get 1.5x deduction multiplier
7. **Suppression amplifier** — If D-12 (suppression) is present, all other deductions multiply by 1.5x
8. **Severity floors** — Undisputed CRITICAL caps score at 39; undisputed HIGH caps at 59

### Severity Weights

| Severity | Base Deduction |
|----------|---------------|
| CRITICAL | 30 points |
| HIGH | 20 points |
| MEDIUM | 10 points |
| LOW | 5 points |
| INFO | 0 points |

### Verdict Mapping

| Score | Verdict | Exit Code |
|-------|---------|-----------|
| 80-100 | SAFE | 0 |
| 60-79 | LOW RISK | 1 |
| 40-59 | MEDIUM RISK | 1 |
| 20-39 | HIGH RISK | 1 |
| 0-19 | CRITICAL | 1 |

---

## Output Formats

**Console** (default) — Human-readable output grouped by file with severity sorting, chain cross-references, absorbed finding annotations, and summary footer. Use `--verbose` for per-model scores and timing.

**JSON** (`--format json`) — Machine-readable output with findings, summary stats, and version field. Raw file content is excluded for security.

**SARIF** (`--format sarif`) — SARIF 2.1.0 for GitHub Code Scanning and VS Code. Chain findings use `relatedLocations`, severities map to SARIF levels.

---

## Configuration

Config sources merge in order (later overrides earlier):

1. Hardcoded defaults
2. Global `~/.skillinquisitor/config.yaml`
3. Project `.skillinquisitor/config.yaml`
4. Environment variables (`SKILLINQUISITOR_*`)
5. CLI flags

### Example Config

```yaml
layers:
  deterministic:
    enabled: true
    # 16 default soft rules — require LLM consensus to count
    soft_rules:
      - D-10A   # Dynamic exec
      - D-14B   # Nested SKILL.md
      - D-14C   # Unexpected top-level files
      - D-14D   # Unexpected nested files
      - D-15C   # Shortened URLs
      - D-15E   # Unknown external hosts
      - D-15G   # Non-HTTPS URLs
      - D-18C   # Broad auto-invocation
      - D-22A   # Code fence content
      - D-5A    # Hex payloads
      - D-2A    # Mixed-script homoglyphs
      - D-12B   # Output suppression
      - D-12C   # Skip confirmation
      - D-8B    # Generic env enumeration
      - D-1C    # Variation selectors
      - NC-3A   # Normalization delta
    soft_fallback_confidence: 0.0  # Drop soft findings when LLM disabled
  ml:
    enabled: true
    threshold: 0.5
    auto_download: true
    models:
      - id: protectai/deberta-v3-base-prompt-injection-v2
        weight: 0.40
      - id: patronus-studio/wolf-defender-prompt-injection
        weight: 0.35
      - id: madhurjindal/Jailbreak-Detector
        weight: 0.25
  llm:
    enabled: true
    default_group: tiny
    auto_select_group: true
    auto_download: true

scoring:
  decay_factor: 0.7
  suppression_multiplier: 1.5
  soft_confirmed_boost: 1.5           # 1.5x boost for LLM-confirmed soft findings
  soft_confirmation_threshold: 0.75   # 3 of 4 models must confirm
  severity_floors:
    critical: 39
    high: 59
```

---

## Benchmark

SkillInquisitor includes a benchmark framework for measuring detection quality against a labeled real-world dataset.

### Dataset

75 labeled real-world safe skills under `benchmark/dataset/skills/`, sourced from [`obra/superpowers`](https://github.com/obra/superpowers) and [`trailofbits/skills`](https://github.com/trailofbits/skills). The current shipped benchmark is a real-world safe-baseline corpus while the malicious real-world set is rebuilt from curated in-the-wild sources.

Benchmark entries currently use stable repo-derived IDs such as `obra-brainstorming` and `tob-gh-cli`.

| Category | Count | Sources |
|----------|-------|---------|
| Safe | 75 | Real GitHub skill repositories from Obra and Trail of Bits |

Smoke currently includes 20 safe skills, standard includes 50 safe skills, and full includes all 75 shipped safe skills.

Fixtures and synthetic skills remain in `tests/fixtures/` for regression testing, but they are no longer part of the benchmark scorecard. Malicious real-world benchmark entries will be reintroduced only from curated in-the-wild sources.

### Current Safe-Baseline Result

The current best full safe-corpus benchmark run is:

- `benchmark/results/20260319-170229-a0cfa4e-dirty`
- `TN=75`
- `FP=0`
- `75/75` safe skills classified `not_malicious`

Because the shipped corpus is temporarily all-safe, the meaningful benchmark metric right now is false-positive rate rather than F1. In other words: the benchmark currently answers "does SkillInquisitor incorrectly convict legitimate real-world skills?"

The precision work that got the safe corpus to `FP=0` was mostly context and adjudication hardening rather than detector removal:

- ML prompt-injection findings no longer convict on their own; they act as medium-risk evidence unless corroborated.
- Reference examples, handbooks, troubleshooting docs, and best-practices guides stay visible as evidence but no longer escalate final malicious classification by themselves.
- Docker/devcontainer/PATH setup flows are modeled as benign bootstrap context instead of malicious persistence.
- Workflow-capture and approval-bypass rules now recognize self-limiting and headless/non-interactive safety language.
- Precision regex fixes avoid accidental matches like `CODEX_CI` -> `CI`, `encounter` -> `counter`, and person-name `Dan` -> jailbreak token `DAN`.

### Running Benchmarks

```bash
# Quick smoke test on the real-world corpus
uv run skillinquisitor benchmark run --tier smoke --layer deterministic

# Standard tier, all layers, real-world corpus
uv run skillinquisitor benchmark run --tier standard

# Safe-only benchmarking pass
uv run skillinquisitor benchmark run --dataset-profile safe_only

# Full dataset, all layers
uv run skillinquisitor benchmark run --tier full --timeout 300

# Compare two runs
uv run skillinquisitor benchmark compare run-a/summary.json run-b/summary.json

# Bless a run as regression baseline
uv run skillinquisitor benchmark bless benchmark/results/<run-id> --name v1
```

### Benchmark Report

Generated as Markdown with: executive summary, confusion matrix, per-category detection rates with bar visualization, latency percentiles, and error analysis (false negative/positive breakdowns with examples). On the current safe-only shipped corpus, reports are most useful for tracking `TN` / `FP` progression and identifying which legitimate skills are still being over-flagged.

---

## Development

```bash
# Install dependencies
uv sync --group dev

# Run the test suite (466 tests)
./scripts/run-test-suite.sh

# Run specific test files
uv run pytest tests/test_scoring.py -v
uv run pytest tests/test_deterministic.py -v

# Check CLI
uv run python -m skillinquisitor --help
```

### Adding Detection Rules

1. Create the rule evaluator function in the appropriate module under `src/skillinquisitor/detectors/rules/`
2. Register it in the module's `register_*_rules()` function with:
   - `llm_verification_prompt=` — specific MALICIOUS vs SAFE criteria for LLM verification
   - `soft=True` if the rule has high false-positive risk on legitimate skills
3. Add fixture coverage in `tests/fixtures/` (both positive and negative cases)
4. Add an `expected.yaml` with the exact findings contract
5. Update `tests/fixtures/manifest.yaml`

### Regression Harness

- Self-contained fixture directories under `tests/fixtures/`
- Each fixture owns an `expected.yaml` with exact behavior contracts
- Scoped exactness: focused fixtures don't break when new layers activate
- See `docs/testing/regression-harness.md` for full guide

### Project Structure

```
src/skillinquisitor/
├── cli.py              # Typer CLI
├── models.py           # Pydantic data model (Skill/Artifact/Segment/Finding)
├── config.py           # YAML config loading, merging, validation
├── input.py            # Input resolution (local/GitHub/stdin)
├── normalize.py        # Segment extraction & security-aware normalization
├── pipeline.py         # Async three-layer pipeline orchestration
├── scoring.py          # Risk scoring with diminishing returns
├── policies.py         # Built-in policy data (typosquatting, URLs)
├── detectors/
│   ├── rules/          # 7 deterministic rule modules + engine + registry
│   │   ├── engine.py   # Rule registry, execution, soft-finding tagging
│   │   ├── unicode.py  # D-1, D-2, D-6, NC-3
│   │   ├── encoding.py # D-3, D-4, D-5, D-21, D-22, D-23
│   │   ├── secrets.py  # D-7, D-8
│   │   ├── behavioral.py # D-9, D-10, D-19 chains
│   │   ├── injection.py  # D-11, D-12, D-13
│   │   ├── structural.py # D-14, D-15, D-20
│   │   └── temporal.py   # D-16, D-17, D-18
│   ├── ml/             # ML prompt-injection ensemble
│   │   ├── ensemble.py # Weighted voting aggregator
│   │   ├── models.py   # HuggingFace model wrappers
│   │   └── download.py # Cache/download helpers
│   └── llm/            # LLM code analysis
│       ├── judge.py    # LLM orchestrator + soft consensus
│       ├── models.py   # llama-server subprocess backend
│       ├── prompts.py  # General + targeted prompt builders
│       └── download.py # GGUF cache/download
├── formatters/
│   ├── console.py      # Grouped-by-file text output
│   ├── json.py         # Findings-focused JSON
│   └── sarif.py        # SARIF 2.1.0
└── benchmark/
    ├── dataset.py      # Manifest loading, filtering
    ├── metrics.py      # Confusion matrix, per-category recall
    ├── runner.py       # Async benchmark orchestration
    └── report.py       # Markdown report generation
```
