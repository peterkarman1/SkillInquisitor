# SkillInquisitor

Security scanning tool for AI agent skill files. Detects prompt injection, malicious code, obfuscation, credential theft, data exfiltration, and other threats before installation.

## Project Structure

```
docs/
├── requirements/
│   ├── architecture.md          # Architecture & epic roadmap (the implementation guide)
│   └── business-requirements.md # Business requirements document
└── research/
    ├── agent-skill-attack-vectors.md  # Threat model & attack registry
    ├── agent-skills-comparison.md     # Cross-platform skill system comparison
    ├── promptforest-architecture.md   # PromptForest competitive analysis
    └── skillsentry-architecture.md    # SkillSentry competitive analysis
```

## Documentation Rules

- **Keep the BRD and architecture doc up to date.** When implementation decisions diverge from what's documented in `docs/requirements/business-requirements.md` or `docs/requirements/architecture.md`, update those documents to reflect reality. These are living documents, not historical artifacts.
- **Do the requirements sync at the end of relevant work.** Before considering any relevant change complete, re-read `docs/requirements/business-requirements.md` and `docs/requirements/architecture.md` and sync them with the final implementation, behavior, and terminology from that change.
- **Document all changes in CHANGELOG.md.** Every meaningful change (new features, bug fixes, breaking changes, epic completions) gets an entry. Follow [Keep a Changelog](https://keepachangelog.com/) format.
- **Keep the README up to date.** As features land, update `README.md` with current installation instructions, usage examples, and capabilities.
- **Always update TODO.md.** When starting or completing work on any epic task, check the box in `TODO.md` and fill in the implementation notes (files changed, key decisions, deviations). This is the primary progress tracker. *(Remove this rule when TODO.md is fully complete.)*

## Testing Rules

- **Any meaningful code change must add or update relevant tests.** Do not treat test coverage as optional follow-up work.
- **Use the regression harness by default for scanner behavior changes.** If a change affects scanner behavior, findings, verdicts, scoring, formatting, config behavior, or pipeline routing, add or update fixture-driven regression coverage unless the harness clearly does not apply.
- **New detection logic requires both positive and negative coverage.** Add fixtures that should trigger the behavior and safe fixtures that should not.
- **Safe and false-positive coverage is required.** Do not add only malicious-path tests.
- **Intentional behavior changes must update fixtures and docs in the same change.** If scanner behavior changes, update `expected.yaml`, harness docs, and any affected requirements text together.

## Build & Test

```bash
uv sync --group dev                 # Base deterministic development environment
uv sync --extra ml --group dev      # With ML prompt injection ensemble deps
uv sync --extra llm --group dev     # With LLM code analysis deps
uv sync --all-extras --group dev    # Everything
./scripts/run-test-suite.sh         # Run full regression suite
```

## Architecture

The system uses a three-layer detection pipeline operating on a **Skill -> Artifact -> Segment** data model:

1. **Deterministic checks** — Rule-based pattern matching (Layer 1)
2. **ML prompt injection ensemble** — Small classifier models with sequential loading and weighted voting (Layer 2)
3. **LLM code analysis** — Semantic code review with general + targeted verification driven by deterministic findings (Layer 3)

The LLM layer uses deterministic findings to ask targeted follow-up questions (e.g., tracing data flow from a flagged sensitive file read to a network call).

Configuration is foundational — the full YAML config system (schema, merging, validation) is part of the initial scaffold. See `docs/requirements/architecture.md` for the complete epic roadmap.
