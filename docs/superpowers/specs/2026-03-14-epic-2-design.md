# Epic 2 Design: Regression Test Harness

**Date:** 2026-03-14
**Status:** Approved for planning
**Epic:** Epic 2 — Regression Test Harness

## Goal

Build a schema-first regression harness that becomes the behavioral contract for SkillInquisitor. After Epic 2, the project should have a durable fixture system, exact finding comparison against the real scan pipeline, safe baseline coverage, and explicit repository guidance requiring meaningful changes to carry relevant tests.

This epic establishes three long-lived foundations:
- a fixture-based regression harness under `tests/`
- contributor policy in `CLAUDE.md` requiring relevant tests for meaningful changes
- a maintained guide describing harness principles, authoring, and usage

## Approved Constraints

- Optimize for robustness and long-term clarity, not minimum initial code.
- Keep fixture expectations separate from aggregate fixture indexing.
- Use exact matching for findings, but support opt-in scoped exactness by layer and/or check subset.
- Run the real `pipeline.py` in tests rather than creating a separate scanner path.
- Treat safe and false-positive fixtures as first-class coverage, not secondary nice-to-haves.

## Non-Goals

Epic 2 does not implement new detection logic. Specifically out of scope:
- deterministic rule engines or new detection checks
- ML or LLM inference behavior
- benchmark dataset generation
- snapshotting complete `ScanResult` JSON payloads
- broad CI platform work beyond ensuring `pytest tests/` remains the project gate

## Approach

The approved approach is a **schema-first harness with local fixture truth**.

Each fixture directory is self-contained and scanable on its own. The fixture's `expected.yaml` is the authoritative contract for expected behavior. `tests/fixtures/manifest.yaml` is an index and coverage/reporting layer only; it does not duplicate or override expectations.

The harness executes the real scan pipeline, projects actual findings into a normalized comparable shape, and performs exact comparison against the expected contract. Exactness applies to the full result unless a fixture explicitly narrows scope. This keeps tests strict without forcing future ML, LLM, or scoring work to rewrite unrelated deterministic fixtures.

Compared with thin ad hoc pytest helpers, this adds more up-front structure but prevents the harness from becoming inconsistent as later epics add new layers, richer findings, and more complex output behavior.

## Deliverables

Epic 2 should produce these deliverables:

- `tests/conftest.py`
  - Shared harness helpers for fixture discovery, schema validation, scan execution, finding normalization, and assertions.
- `tests/fixtures/manifest.yaml`
  - Index of fixtures, their suites, coverage metadata, and status.
- `tests/fixtures/`
  - Fixture corpus with self-contained directories and authoritative `expected.yaml` files.
- `tests/test_deterministic.py`
  - Deterministic fixture runner.
- `tests/test_ml.py`
  - Future-facing ML fixture runner.
- `tests/test_llm.py`
  - Future-facing LLM fixture runner.
- `tests/test_scoring.py`
  - Future-facing scoring fixture runner.
- `tests/test_pipeline.py`
  - Integration coverage confirming the harness uses the real pipeline.
- `CLAUDE.md`
  - Repository testing policy updated to require relevant tests for meaningful changes.
- `docs/testing/regression-harness.md`
  - Durable guide describing harness principles, structure, workflow, and extension rules.

## Harness Architecture

### Shared Harness Responsibilities

`tests/conftest.py` should become infrastructure only. It should own:

1. fixture discovery
2. fixture metadata loading from `manifest.yaml`
3. `expected.yaml` loading and schema validation
4. helper functions to run the real scanner pipeline for a fixture path
5. finding normalization into a stable comparable representation
6. comparison and assertion helpers with readable diffs

It should not become a miscellaneous dumping ground for unrelated helper code.

### Test Suite Responsibilities

The suite layout should be future-shaped now:

- `tests/test_pipeline.py`
  - Verifies harness integration with the real `pipeline.py`
  - Covers end-to-end fixture execution basics
  - Retains scaffold-level pipeline behavior tests
- `tests/test_deterministic.py`
  - Runs active safe and deterministic fixtures
- `tests/test_ml.py`
  - Reserved for Epic 9 fixture coverage
- `tests/test_llm.py`
  - Reserved for Epic 10 fixture coverage
- `tests/test_scoring.py`
  - Reserved for Epic 11 fixture coverage

In Epic 2, ML, LLM, and scoring suites may exist with no active fixtures yet, but their structure should be established now so future epics extend stable files and conventions instead of creating divergent patterns.

## Fixture Layout

The fixture tree should support later growth while keeping Epic 2 focused:

```text
tests/fixtures/
├── manifest.yaml
├── safe/
├── templates/
├── deterministic/
├── ml/
├── llm/
└── compound/
```

### Fixture Directory Rules

Each fixture directory must:

- be runnable as an independent scan target
- include the scanned files directly in the fixture directory
- include its own `expected.yaml`
- avoid depending on shared fixture content elsewhere

Self-contained fixtures are slightly more verbose but much easier to debug, move, and review.

### Epic 2 Initial Corpus

Epic 2 should include:

- at least 5 active safe baseline fixtures that currently produce zero findings
- at least 1 reusable fixture template
- top-level directories for deterministic, ML, LLM, and compound fixtures

Epic 2 should not invent fake malicious fixtures for checks that do not exist yet. Real malicious fixtures should begin landing with Epic 3 and grow with later epics.

## Fixture Contract

`expected.yaml` is the authoritative per-fixture contract.

### Required Shape

The contract should be versioned and intentionally narrow:

```yaml
schema_version: 1
verdict: SAFE
match_mode: exact
findings: []
forbid_findings: []
```

### Scoped Exactness

Fixtures may optionally narrow exact matching scope:

```yaml
schema_version: 1
verdict: MALICIOUS
match_mode: exact
scope:
  layers: [deterministic]
  checks: [D-1]
findings:
  - rule_id: D-1
    layer: deterministic
    category: steganography
    severity: critical
    message: Unicode tag characters detected
    location:
      file_path: SKILL.md
      start_line: 47
      end_line: 47
forbid_findings:
  - rule_id: D-11
```

Rules:

- If `scope` is omitted, exactness applies to all findings in the scan result.
- If `scope` is present, exactness applies only within that layer/check subset.
- Findings outside the scoped subset are ignored unless explicitly listed in `forbid_findings`.
- `forbid_findings` remains available to block known-bad unrelated detections.

This preserves strictness while allowing older fixtures to coexist with later pipeline expansion.

## Finding Comparison Model

The harness should compare a normalized finding projection rather than raw Pydantic dumps.

### Compared Fields

Exact comparison should include:

- `rule_id`
- `layer`
- `category`
- `severity`
- `message`
- `location.file_path`
- `location.start_line`
- `location.end_line`

### Ignored by Default

The harness should ignore unstable or future-expanding fields unless a later epic explicitly adds richer assertions:

- generated finding IDs
- `confidence`
- `details`
- `references`
- other non-contract metadata

This keeps the harness exact on behavior while avoiding unnecessary coupling to unstable internals.

## Manifest Role

`tests/fixtures/manifest.yaml` is the aggregate index. It should answer:

- which fixtures exist
- where they live
- which suite owns them
- whether they are active, pending, or template-only
- which check IDs or tags they are meant to cover

Example shape:

```yaml
fixtures:
  - id: safe-simple-formatter
    path: safe/simple-formatter
    suite: deterministic
    status: active
    expected: expected.yaml
    checks: []
    tags: [safe, baseline]
  - id: template-deterministic-minimal
    path: templates/deterministic-minimal
    suite: deterministic
    status: template
    expected: expected.yaml
    checks: []
    tags: [template]
```

The manifest must not repeat full expected findings. That duplication would create two competing sources of truth.

## Failure Output

Harness failures must be easy to diagnose. Assertion helpers should report:

- verdict mismatches
- expected findings missing from actual output
- unexpected actual findings inside the applicable scope
- forbidden findings that appeared

Each diff should make it obvious whether the failure came from:

- wrong rule firing
- message drift
- severity/category drift
- location drift
- scope configuration mistakes

Readable failure output is part of the harness design, not a later polish task.

## Repository Policy Update

`CLAUDE.md` should be updated with a broad testing rule:

- any meaningful code change must add or update relevant tests
- when a change affects scanner behavior, findings, verdicts, scoring, formatting, config behavior, or pipeline routing, the regression harness should be used unless it clearly does not apply
- new detection logic should land with both positive and negative fixture coverage
- safe and false-positive coverage is required, not optional
- intentional behavior changes must update fixtures and related docs in the same change

This turns the harness into an enforced engineering practice rather than an optional tool.

## Test Harness Guide

Epic 2 should add `docs/testing/regression-harness.md` as the durable guide for contributors.

The guide should cover:

- why the harness exists
- fixture layout and directory anatomy
- `expected.yaml` schema and examples
- `manifest.yaml` purpose
- exact matching semantics
- scoped exactness behavior
- how to add a fixture
- how safe, malicious, and compound fixtures differ
- how future epics should extend the harness
- common failure modes and debugging workflow

This guide should be written as project documentation, not as implementation notes hidden in tests.

## Acceptance Criteria

- `pytest tests/` runs and passes
- fixture discovery loads active fixtures from `manifest.yaml`
- each active fixture has a validated `expected.yaml`
- the harness executes the real pipeline against fixture directories
- exact finding comparison works on the normalized finding projection
- scoped exactness is supported for future fixtures
- at least 5 safe baseline fixtures exist and pass with zero findings
- at least 1 reusable fixture template exists
- `tests/test_deterministic.py`, `tests/test_ml.py`, `tests/test_llm.py`, and `tests/test_scoring.py` exist with stable roles
- `CLAUDE.md` contains the approved broad testing policy
- `docs/testing/regression-harness.md` documents principles and workflow clearly enough for future contributors

## Risks and Mitigations

### Risk: Harness becomes too brittle

Exact matching can create maintenance cost when wording or line attribution changes.

Mitigation:
- compare normalized contract fields only
- keep ignored fields explicit
- support scoped exactness rather than weakening matching globally

### Risk: Contributors bypass the harness

Without clear repository policy, future changes may add narrow unit tests while skipping behavioral regression coverage.

Mitigation:
- add the explicit testing rule to `CLAUDE.md`
- document when the harness is the default required path

### Risk: Fixture sprawl becomes hard to understand

Large fixture trees become confusing if naming and metadata are inconsistent.

Mitigation:
- make `manifest.yaml` the single fixture index
- require self-contained fixture directories
- establish templates early

## Planning Notes

When this epic moves into implementation planning, the plan should keep these workstreams separate:

1. harness infrastructure and schema validation
2. fixture corpus and manifest
3. suite file organization
4. contributor policy and documentation

That separation keeps the work understandable and testable without mixing infrastructure code, fixture content, and repo-policy changes into a single vague task.
