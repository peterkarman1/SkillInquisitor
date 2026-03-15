# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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

### Changed
- Local development baseline is now Python `3.13.12` managed through `asdf`
- Project setup and execution docs now use `uv` instead of `pip install -e`
- Repository instructions now require relevant tests for meaningful code changes and direct scanner behavior changes toward the regression harness

### Fixed
- GitHub repository scans now skip `.git` metadata and non-UTF8/binary artifacts instead of crashing during input collection
