# SkillInquisitor

Security scanner for AI agent skills. SkillInquisitor analyzes `SKILL.md`-style skill directories before installation and now ships a working two-layer pipeline: deterministic checks plus an ML prompt-injection ensemble, with LLM code analysis planned next.

Epics 1-9 are now in place:
- async-first Python scaffold
- shared `Skill -> Artifact -> Segment` data model
- config loading and merge precedence
- local file, directory, stdin, and GitHub URL input resolution
- schema-first regression harness with self-contained fixtures and exact matching
- safe baseline fixture corpus plus future-facing ML, LLM, and scoring suite entrypoints
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
- frontmatter-aware normalization with parsed `SKILL.md` metadata, duplicate-key/parser observations, binary/executable artifact preservation, and skill-scope deterministic rules
- fixture-local config overrides plus `action_flags` / `details` assertions in the regression harness
- real deterministic scan findings in the main pipeline
- working `rules list`, `rules test`, `models list`, and `models download` commands

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

List configured ML models and cache status:

```bash
uv run skillinquisitor models list
```

Pre-download the configured ML ensemble:

```bash
uv run skillinquisitor models download
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
- Use fixture-local `config_override` when a rule depends on allowlists or policy tuning, and use `action_flags_contains` / `details_contains` for metadata-heavy assertions.
- See `docs/testing/regression-harness.md` for fixture layout, matching semantics, and authoring guidance.
