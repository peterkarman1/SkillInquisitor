# SkillInquisitor

Security scanner for AI agent skills. SkillInquisitor analyzes `SKILL.md`-style skill directories before installation and is growing toward a three-layer pipeline: deterministic checks, ML prompt-injection detection, and LLM code analysis.

Epics 1-4 are now in place:
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
- real deterministic scan findings in the main pipeline
- working `rules list` and `rules test` commands

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

List deterministic rules:

```bash
uv run skillinquisitor rules list
```

Test a single deterministic rule against a file:

```bash
uv run skillinquisitor rules test D-1B tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md
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
- See `docs/testing/regression-harness.md` for fixture layout, matching semantics, and authoring guidance.
