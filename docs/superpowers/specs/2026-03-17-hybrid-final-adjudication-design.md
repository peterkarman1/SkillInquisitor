# Hybrid Final Adjudication — Design Spec

## Problem

The current decision policy is built around a subtractive `0-100` risk score in [scoring.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/scoring.py). That score has become a second system layered on top of better raw evidence:

- deterministic rules emit structured findings
- the ML ensemble emits prompt-injection findings
- targeted and repo-level LLM analysis emit semantic findings and confirm/dispute signals
- the final product decision is still driven by point arithmetic, decay, multipliers, and severity floors

This creates three problems:

1. The score is hard to reason about. A skill can contain strong malicious evidence and still land in the wrong band because deductions, soft gates, and floors interact in surprising ways.
2. The score is overfit to the current corpus. Benchmark tuning has focused on deduction math instead of improving the evidence model.
3. The benchmark contract is partially tied to legacy mechanics. Binary classification currently depends on `risk_score < threshold` in [metrics.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/benchmark/metrics.py), even though the user-facing reality is the final risk label and supporting evidence.

The redesign goal is to make evidence primary and scoring secondary or nonexistent:

- no `SAFE` verdict
- final runtime output is a flexible risk label: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- binary benchmark evaluation stays `malicious` vs `not_malicious`
- a final adjudication layer decides the overall label from structured evidence
- hard guardrails still enforce minimum severity for obviously dangerous cases

## Recommended Approach

Adopt a hybrid final-adjudication model.

- Deterministic, ML, and targeted/repo LLM analysis continue to collect evidence.
- Numeric subtractive scoring stops being the source of truth for the final verdict.
- A new final adjudicator consumes all evidence and returns:
  - `risk_label`: `LOW | MEDIUM | HIGH | CRITICAL`
  - `summary`: concise risk explanation
  - `drivers`: the strongest evidence that determined the label
  - `guardrails_triggered`: any hard floors or forced escalations
- Hard guardrails can force a minimum label.
- The final LLM adjudicator can also escalate beyond the floor based on the combined evidence.

This preserves explainability and defense-in-depth while removing the fragile point model.

## Non-Goals

- This change does not remove individual findings, rule IDs, or categories.
- This change does not stop targeted LLM verification.
- This change does not eliminate deterministic or ML layers in favor of an end-to-end LLM-only scan.
- This change does not immediately delete the synthetic dataset. It removes it from primary benchmark authority and keeps it only as secondary regression coverage until explicitly retired.

## Desired Output Contract

### Runtime Output

Every scan returns:

- `risk_label`: `LOW | MEDIUM | HIGH | CRITICAL`
- `binary_label`: `not_malicious | malicious`
- `findings`: all structured findings as today
- `adjudication`: structured final decision payload

The scanner no longer emits `SAFE`.

`binary_label` must be derived from `risk_label` through configurable policy. It is not an independently chosen model output.

The initial binary mapping should remain configurable. The default mapping will be:

- `LOW` -> `not_malicious`
- `MEDIUM` -> `not_malicious`
- `HIGH` -> `malicious`
- `CRITICAL` -> `malicious`

This mapping must live in configuration rather than code constants so the project can adjust policy later without redesigning the runtime again.

### Benchmark Output

Primary benchmark success remains binary:

- malicious skill classified as `malicious` -> TP
- malicious skill classified as `not_malicious` -> FN
- safe skill classified as `not_malicious` -> TN
- safe skill classified as `malicious` -> FP

The benchmark also records:

- predicted `risk_label`
- expected or reviewed severity label when available
- per-category finding coverage
- rule coverage only as secondary analysis, not the primary benchmark contract

## Architecture

### 1. Evidence Collection Stays Layered

The current pipeline in [pipeline.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/pipeline.py) remains layered:

1. deterministic rules
2. ML prompt-injection ensemble
3. targeted/repo LLM analysis

Those layers still produce findings because they are useful independently:

- they explain why a skill was flagged
- they drive targeted LLM follow-ups
- they support category-level benchmarking
- they allow hard guardrails without depending on a single final prompt

### 2. Add a Final Adjudication Stage

After the existing evidence layers finish, the pipeline adds a new stage:

`final_adjudicate(findings, skills, layer_metadata, config) -> AdjudicationResult`

This stage is responsible for the final risk label.

It receives:

- all findings
- skill and artifact context
- layer metadata
- hard-guardrail summary
- optional repo bundle summary

It returns:

```python
@dataclass(frozen=True)
class AdjudicationResult:
    risk_label: str                 # LOW | MEDIUM | HIGH | CRITICAL
    summary: str
    rationale: str
    drivers: list[EvidenceDriver]
    categories: list[str]
    guardrails_triggered: list[str]
    adjudicator: str                # heuristic | llm | hybrid
    confidence: float | None = None
```

`EvidenceDriver` should capture:

- rule IDs
- categories
- artifact path
- segment IDs when applicable
- a short plain-English explanation

After adjudication returns `risk_label`, a separate policy resolver computes:

```python
binary_label = map_risk_label_to_binary(
    risk_label,
    cutoff=config.decision_policy.binary_cutoff,
)
```

This avoids contradictory outputs such as `MEDIUM` plus `malicious`, while keeping the binary mapping flexible.

### 3. Introduce a Structured Evidence Packet

The final adjudicator should not receive raw free-form findings only. It should receive a normalized evidence packet derived from findings.

Example shape:

```python
@dataclass(frozen=True)
class EvidencePacket:
    highest_guardrail_floor: str | None
    confirmed_categories: list[str]
    disputed_categories: list[str]
    high_signal_findings: list[EvidenceDriver]
    chain_findings: list[EvidenceDriver]
    ml_signals: list[EvidenceDriver]
    llm_confirmations: list[EvidenceDriver]
    llm_disputes: list[EvidenceDriver]
    artifact_summary: list[ArtifactEvidenceSummary]
```

This keeps the final adjudicator flexible:

- initial version can be partly heuristic plus LLM
- later versions can add additional models or richer summaries
- the benchmark does not depend on one exact prompt shape

### 4. Hard Guardrails Become Floors, Not Full Policy

Some findings are strong enough that the final adjudicator must not downgrade below a minimum label.

Examples:

- confirmed credential theft
- confirmed data exfiltration
- confirmed persistence plus execution chain
- confirmed RCE chain
- confirmed stealth/suppression paired with exfiltration or credential access

Guardrails should be policy-driven and configurable.

Example:

```yaml
decision_policy:
  binary_cutoff: HIGH
  hard_guardrails:
    - when:
        confirmed_categories: [credential_theft, data_exfiltration]
      minimum_label: CRITICAL
    - when:
        rule_ids: [D-19A, D-19B, D-19C]
        categories: [persistence, behavioral]
      minimum_label: HIGH
```

The final adjudicator can still escalate beyond the floor, but it cannot go below it.

### 5. Final Adjudicator Is Hybrid, Not LLM-Only

The final adjudicator should run in two passes:

1. Build the evidence packet and determine guardrail floors deterministically.
2. Ask a final adjudicator model to choose the final label using the evidence packet and skill summary.

The model prompt must require:

- choose exactly one label from `LOW | MEDIUM | HIGH | CRITICAL`
- cite the strongest evidence drivers
- explain why weaker or disputed evidence did not dominate
- avoid inventing evidence not present in the packet

If the LLM adjudicator is unavailable:

- fall back to a deterministic heuristic adjudicator using guardrails and evidence counts
- record `adjudicator: heuristic_fallback`

That fallback should be intentionally conservative but stable, so the tool still works without LLM runtime support.

## Migration Strategy

### Phase 1: Parallel Contract

Add final adjudication alongside the current numeric score.

- keep `risk_score` for compatibility
- add `risk_label`, `binary_label`, and `adjudication`
- keep current formatters working
- add new formatter output fields

This phase allows side-by-side benchmark comparison between:

- old score policy
- new adjudication policy

### Phase 2: Switch Primary Decision Policy

Make final adjudication the default source of truth for:

- CLI verdict output
- JSON output primary verdict fields
- SARIF severity mapping
- benchmark binary classification

Keep `risk_score` only as legacy metadata during migration.

### Phase 3: Retire Numeric Scoring

Once the new policy is stable:

- remove threshold-based benchmark classification
- demote `risk_score` to optional debug output or remove it entirely
- simplify [scoring.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/scoring.py) into:
  - guardrail floor extraction
  - evidence summarization helpers
  - heuristic fallback adjudication

## Benchmark and Dataset Changes

### 1. Primary Benchmark Contract

The primary benchmark should evaluate only:

- binary classification correctness
- predicted risk-label distribution
- category coverage
- latency and runtime stability

Primary benchmark success should no longer depend on:

- numeric threshold tuning
- exact expected rule hits

Rule coverage remains useful as a diagnostic metric, not a release gate.

### 2. Real Dataset Becomes Primary

The real dataset should become the benchmark authority.

The synthetic dataset should be:

- removed from the main benchmark scorecards
- retained only for secondary regression tests where it still covers detector mechanics
- eventually retired case-by-case if real examples replace the coverage

### 3. Human Review Status for Benchmark Skills

Each benchmark skill should gain review metadata such as:

- `review_status`: `unreviewed | reviewed | disputed`
- `reviewer`
- `review_notes`
- optional `expected_risk_label`

This allows the benchmark to evolve as the team audits the corpus and corrects mislabeled skills.

### 4. Binary Classification Must Be Flexible

Binary mapping from risk labels must be explicit config, not hardcoded benchmark behavior.

Initial default:

- `LOW`, `MEDIUM` => `not_malicious`
- `HIGH`, `CRITICAL` => `malicious`

But the benchmark engine must support alternate mappings for experiments.

## Configuration Changes

Add or evolve configuration under a decision-policy section:

```yaml
decision_policy:
  mode: hybrid_final_adjudication
  binary_cutoff: HIGH
  keep_legacy_score: true
  hard_guardrails:
    ...

layers:
  llm:
    final_adjudicator:
      enabled: true
      model_group: balanced
      prompt_variant: v1
      max_tokens: 512
```

This keeps the redesign easy to evolve:

- alternate prompt variants
- different binary cutoffs
- heuristic-only fallback mode
- future adjudicator models

## Files Expected To Change

Core runtime:

- [pipeline.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/pipeline.py)
- [scoring.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/scoring.py)
- [policies.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/policies.py)
- [models.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/models.py)

LLM layer:

- [judge.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/detectors/llm/judge.py)
- new prompt helpers for final adjudication

Benchmarking:

- [runner.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/benchmark/runner.py)
- [metrics.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/benchmark/metrics.py)
- benchmark manifest/data schema

Formatters:

- console/json/sarif formatters

Tests:

- scoring and policy tests
- pipeline tests
- benchmark metrics tests
- formatter tests
- dataset schema tests

Docs:

- [README.md](/Users/peterkarman/git/SkillInquisitor/README.md)
- [docs/requirements/architecture.md](/Users/peterkarman/git/SkillInquisitor/docs/requirements/architecture.md)
- [docs/requirements/business-requirements.md](/Users/peterkarman/git/SkillInquisitor/docs/requirements/business-requirements.md)
- [TODO.md](/Users/peterkarman/git/SkillInquisitor/TODO.md)
- [CHANGELOG.md](/Users/peterkarman/git/SkillInquisitor/CHANGELOG.md)

## Risks

- A final adjudicator can become too prompt-sensitive if the evidence packet is underspecified.
- Removing `SAFE` changes UX and may require formatter changes in multiple downstream consumers.
- Benchmark comparability will temporarily get noisier while both systems coexist.
- If guardrails are too broad, the system recreates hardcoded score behavior under a different name.

## Success Criteria

The redesign is successful when:

1. Final runtime output no longer depends on subtractive numeric scoring.
2. Binary benchmark classification is driven by explicit risk-label mapping.
3. Benchmarks prioritize real reviewed skills over synthetic authority.
4. The final adjudication output is explainable, testable, and configurable.
5. The system can evolve risk policy without another major architecture rewrite.
