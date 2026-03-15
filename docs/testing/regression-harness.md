# Regression Harness Guide

SkillInquisitor uses a fixture-based regression harness to lock scanner behavior to explicit contracts. The harness exists to make detector, pipeline, scoring, and formatting changes prove their behavior against realistic scan targets instead of relying on ad hoc assertions.

## Principles

- Use the real scanner pipeline. Tests should execute `resolve_input(...)` and `run_pipeline(...)`, not a parallel implementation.
- Keep fixture truth local. Each fixture directory owns its `expected.yaml`.
- Keep aggregate metadata separate. `tests/fixtures/manifest.yaml` indexes fixtures, but does not duplicate expected findings.
- Prefer exact behavior contracts. The harness compares normalized findings exactly unless a fixture explicitly narrows scope.
- Safe fixtures matter as much as malicious fixtures. False-positive coverage is required.

## Fixture Layout

Each fixture is a self-contained scan target under `tests/fixtures/`:

```text
tests/fixtures/
├── manifest.yaml
├── safe/
├── deterministic/
├── ml/
├── llm/
├── compound/
└── templates/
```

Each fixture directory should contain:

- the files that get scanned, such as `SKILL.md`, scripts, references, or assets
- an `expected.yaml` contract when the fixture is active

Fixtures should not depend on shared content elsewhere. Keeping them self-contained makes failures easier to understand and review.

## `manifest.yaml`

`tests/fixtures/manifest.yaml` is the fixture index. It records:

- fixture `id`
- relative `path`
- owning `suite`
- `status` such as `active` or `template`
- expectation filename
- check coverage metadata
- tags such as `safe` or `baseline`

The manifest is for discovery and coverage reporting. It is not the source of truth for expected findings.

## `expected.yaml`

`expected.yaml` defines the fixture-local behavior contract.

Safe example:

```yaml
schema_version: 1
verdict: SAFE
match_mode: exact
findings: []
forbid_findings: []
```

Scoped exactness example:

```yaml
schema_version: 1
verdict: MEDIUM RISK
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

## Exact Matching

The harness compares a normalized finding projection, not raw serialized `ScanResult` objects.

Compared fields:

- `rule_id`
- `layer`
- `category`
- `severity`
- `message`
- `location.file_path`
- `location.start_line`
- `location.end_line`

Ignored by default:

- generated finding IDs
- `confidence` unless asserted via `confidence_at_least`
- `details` unless asserted via `details_contains`
- `references` unless asserted via `references_contains`

This keeps the contract strict on behavior while avoiding churn from unstable metadata.

## Scoped Exactness

Exact matching applies to the full result unless `scope` is declared.

When `scope` is present:

- only findings in the listed layers are considered in-scope
- only findings with listed rule IDs are considered in-scope
- findings outside that scope are ignored
- `forbid_findings` can still ban specific unrelated findings

Use scoped exactness when future layers should not invalidate a fixture that is intentionally focused on one behavior.

## Fixture Types

- Safe fixtures: benign skills that should remain clean. Use these to guard against false positives.
- Deterministic fixtures: targeted checks for one rule or rule family.
- ML fixtures: text-oriented prompt injection cases for the ensemble layer.
- LLM fixtures: code-oriented semantic analysis cases.
- Compound fixtures: multi-vector or multi-layer cases, especially useful for scoring and chain behavior.

## Adding a Fixture

1. Choose the correct suite directory under `tests/fixtures/`.
2. Create a self-contained scan target directory.
3. Add or update the `manifest.yaml` entry.
4. Write `expected.yaml` with the exact normalized findings you expect.
5. Add or update the relevant suite test if new harness behavior is being introduced.
6. Run the smallest relevant pytest target first, then `uv run pytest tests -v`.

Use `tests/fixtures/templates/deterministic-minimal/` as the copy starting point for new deterministic fixtures.

## Debugging Failures

Common failure categories:

- Verdict mismatch: the pipeline result changed more broadly than expected.
- Missing expected findings: the rule stopped firing, the fixture drifted, or normalization changed.
- Unexpected in-scope findings: behavior expanded or a rule started over-firing.
- Forbidden findings present: a known false-positive guard regressed.
- Scope mistakes: the fixture is broader or narrower than intended.

When a failure is noisy, tighten the normalized contract or the fixture scope. Do not weaken the harness globally just to make a single change easier.
