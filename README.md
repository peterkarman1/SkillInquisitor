# SkillInquisitor

Security scanner for AI agent skills. SkillInquisitor analyzes `SKILL.md`-style skill directories before installation and is designed to grow into a three-layer pipeline: deterministic checks, ML prompt-injection detection, and LLM code analysis.

Epic 1 is now in place:
- async-first Python scaffold
- shared `Skill -> Artifact -> Segment` data model
- config loading and merge precedence
- local file, directory, stdin, and GitHub URL input resolution
- passthrough normalization
- empty pipeline with text and JSON output
- stubbed `models`, `rules`, and `benchmark` command groups

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

## Development

Run the Epic 1 test suite:

```bash
uv run pytest tests -v
```

Check the CLI entrypoint:

```bash
uv run python -m skillinquisitor --help
```
