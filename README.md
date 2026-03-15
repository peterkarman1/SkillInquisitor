# SkillInquisitor

Security scanner for AI agent skills. SkillInquisitor analyzes `SKILL.md`-style skill directories before installation and now ships a working three-layer pipeline: deterministic checks, an ML prompt-injection ensemble, and LLM code analysis for executable artifacts.

Epics 1-11 are now in place:
- async-first Python scaffold
- shared `Skill -> Artifact -> Segment` data model
- config loading and merge precedence
- local file, directory, stdin, and GitHub URL input resolution
- schema-first regression harness with self-contained fixtures and exact matching
- safe baseline fixture corpus plus future-facing scoring suite entrypoint
- deterministic normalization with typed transformation records
- metadata-driven deterministic rule engine with built-in and custom regex rules
- Epic 3 Unicode/steganography detections: Unicode tags, zero-width characters, variation selectors, bidi overrides, mixed-script homoglyphs, and dangerous keyword splitting
- Epic 4 recursive segment expansion for markdown comments, code fences, Base64 payloads, and ROT13-derived content
- Epic 4 deterministic encoding detections for Base64, ROT13 references, hex payloads, XOR-style constructs, contextual hidden-content findings, and bounded recursive traversal
- Epic 5 deterministic secret and exfiltration detections for sensitive file reads, metadata endpoint references, known secret environment variables, suspicious environment enumeration, outbound send behavior, and dynamic execution
- Epic 5 skill-level behavior chain analysis with built-in default chains for data exfiltration, credential theft, and cloud metadata SSRF
- Epic 6 deterministic injection and suppression detections for instruction overrides, role rebinding, system-prompt disclosure, delimiter and mimicry signatures, canonical jailbreaks, suppression directives, and structured YAML frontmatter validation
- Epic 7 structural and metadata detections for skill structure validation, context-sensitive URL classification, package and skill-name typosquatting, and large hidden-content/text-density anomalies
- Epic 8 persistence and cross-agent detections for time-based or environment-gated behavior, persistence target writes, cross-agent skill/config writes, and broad auto-invocation descriptions
- Epic 9 ML prompt-injection ensemble with Prompt Guard 2 86M plus open fallback profiles, weighted soft voting, confidence/uncertainty/max-risk reporting, bounded model concurrency, graceful per-model failure handling, and segment-level findings for original, derived, and long-chunked text content
- Epic 10 LLM code analysis with llama.cpp-backed local inference, hardware-aware `tiny` / `balanced` / `large` model groups, sequential model loading, deterministic-targeted verification prompts, optional `repomix` whole-skill review under a token budget, and fixture-backed confirm/dispute coverage
- frontmatter-aware normalization with parsed `SKILL.md` metadata, duplicate-key/parser observations, binary/executable artifact preservation, and skill-scope deterministic rules
- fixture-local config overrides plus `action_flags`, `details`, referenced-rule, and confidence assertions in the regression harness
- real deterministic scan findings in the main pipeline
- working `rules list`, `rules test`, `models list`, and `models download` commands across ML and LLM model configuration
- Epic 11 risk scoring engine with subtractive scoring, diminishing returns, confidence weighting, chain absorption, cross-layer dedup, LLM confirm/dispute adjustments, suppression amplifier, severity floors, and verdict mapping
- Epic 11 console, JSON, and SARIF 2.1.0 output formatters with `--format sarif` CLI support and verdict-based exit codes

## Requirements

- `asdf`
- Python `3.13.12`
- `uv`
- `git`

## Setup

```bash
asdf install python 3.13.12
asdf set python 3.13.12
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync --group dev
uv sync --extra ml --group dev
uv sync --extra llm --group dev
```

## Usage

Scan a local skill directory:

```bash
uv run skillinquisitor scan tests/fixtures/local/basic-skill
```

Scan a local file:

```bash
uv run skillinquisitor scan path/to/SKILL.md
```

Scan a GitHub repository:

```bash
uv run skillinquisitor scan https://github.com/pallets/click
```

Emit JSON:

```bash
uv run skillinquisitor scan tests/fixtures/local/basic-skill --format json
```

List configured ML and LLM models and cache status:

```bash
uv run skillinquisitor models list
```

Pre-download the configured ML ensemble plus the selected LLM group:

```bash
uv run skillinquisitor models download
uv run skillinquisitor models download --llm-group tiny
```

Force the LLM layer to use a specific model group:

```bash
uv run skillinquisitor scan tests/fixtures/local/basic-skill --llm-group tiny
```

List deterministic rules:

```bash
uv run skillinquisitor rules list
```

Test a single deterministic rule against a file:

```bash
uv run skillinquisitor rules test D-1B tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md
```

Test a behavior-chain rule against a skill directory:

```bash
uv run skillinquisitor rules test D-19A tests/fixtures/deterministic/secrets/D-19-read-send-chain
```

Test a structural or persistence rule against a skill:

```bash
uv run skillinquisitor rules test D-14 tests/fixtures/deterministic/structural/D-14-structure-validation
uv run skillinquisitor rules test D-17A tests/fixtures/deterministic/temporal/D-17-persistence-write
```

Example ML config:

```yaml
layers:
  ml:
    enabled: true
    threshold: 0.5
    auto_download: true
    max_concurrency: 1
    max_batch_size: 8
    min_segment_chars: 12
    chunk_max_chars: 1800
    chunk_overlap_lines: 3
    models:
      - id: meta-llama/Llama-Prompt-Guard-2-86M
        weight: 0.30
      - id: patronus-studio/wolf-defender-prompt-injection
        weight: 0.30
      - id: vijil/vijil_dome_prompt_injection_detection
        weight: 0.25
      - id: protectai/deberta-v3-base-prompt-injection-v2
        weight: 0.15
```

Example LLM config:

```yaml
layers:
  llm:
    enabled: true
    runtime: llama_cpp
    default_group: tiny
    auto_select_group: true
    gpu_min_vram_gb_for_balanced: 8.0
    auto_download: true
    max_output_tokens: 512
    repomix:
      enabled: true
      max_tokens: 30000
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
      balanced: []
      large: []
```

Auto-selection behavior:

- CPU-only systems default to the `tiny` group.
- Systems with a GPU and at least `8 GB` VRAM prefer `balanced` when that group is configured; otherwise they fall back to `tiny`.
- `large` is always opt-in through config or `--llm-group`, and the shipped config leaves `balanced` / `large` empty until you choose those models.

## Risk Scoring

SkillInquisitor uses a subtractive scoring model starting from a base score of 100. Each finding deducts points based on severity, with diminishing returns within the same severity tier (geometric decay factor of 0.7). The scoring engine applies:

- **Confidence weighting** — ML and LLM findings contribute proportional to their confidence scores.
- **Chain absorption** — Chain findings (e.g., D-19 behavior chains) absorb the deductions of their component findings to avoid double-counting.
- **Cross-layer dedup** — When the same segment and category are flagged by multiple layers, the deduction is taken once at the higher confidence.
- **LLM adjustment** — A dispute from the LLM layer reduces a deterministic finding's deduction and lifts its severity floor; a confirm boosts the deduction.
- **Suppression amplifier** — If any suppression directive (D-12) is present, all other deductions are multiplied by 1.5x.
- **Severity floors** — Undisputed CRITICAL findings cap the score at 39; undisputed HIGH findings cap at 59.

**Verdict mapping:**

| Score | Verdict | Exit Code |
|-------|---------|-----------|
| 80-100 | SAFE | 0 |
| 60-79 | LOW RISK | 1 |
| 40-59 | MEDIUM RISK | 1 |
| 20-39 | HIGH RISK | 1 |
| 0-19 | CRITICAL | 1 |

## Output Formats

SkillInquisitor supports three output formats via `--format`:

**Console** (default) — Human-readable output grouped by file with severity sorting (CRITICAL first), chain cross-references, absorbed finding annotations, suppression indicators, and a summary footer. Use `--verbose` for per-model scores and timing.

**JSON** (`--format json`) — Machine-readable output with findings, summary stats, and a version field. Raw file content is excluded for security. The schema is stable for tooling integration.

**SARIF** (`--format sarif`) — SARIF 2.1.0 compliant output for GitHub Code Scanning and VS Code integration. Chain findings use `relatedLocations`, severities map to SARIF levels, and custom properties are namespaced.

```bash
uv run skillinquisitor scan path/to/skill --format sarif > results.sarif
```

## Development

Run the regression suite:

```bash
./scripts/run-test-suite.sh
```

Check the CLI entrypoint:

```bash
uv run python -m skillinquisitor --help
```

Run the full suite directly with optional pytest arguments:

```bash
./scripts/run-test-suite.sh
./scripts/run-test-suite.sh tests/test_deterministic.py -v
```

Regression harness workflow:

- Add or update fixture coverage in `tests/fixtures/` for meaningful scanner behavior changes.
- Keep `tests/fixtures/manifest.yaml` as the fixture index and `expected.yaml` as the fixture-local source of truth.
- Use fixture-local `config_override` when a rule depends on allowlists or policy tuning, and use `action_flags_contains`, `details_contains`, `references_contains`, and `confidence_at_least` for metadata-heavy assertions.
- See `docs/testing/regression-harness.md` for fixture layout, matching semantics, and authoring guidance.
