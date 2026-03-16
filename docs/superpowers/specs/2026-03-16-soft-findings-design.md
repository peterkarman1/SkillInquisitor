# Soft Findings with LLM Confirmation Gate — Design Spec

## Problem

The benchmark revealed 5 deterministic rules with high false positive rates on real-world skills:

| Rule | FPs | Description |
|------|-----|-------------|
| D-18C | 15 | Broad auto-invocation description |
| D-14C | 17 | Unexpected top-level files |
| D-15G | 6 | Non-HTTPS URL |
| D-15E | 4 | Actionable URL patterns |
| D-10A | 5 | Dynamic/shell execution |

These rules detect real threats but also trigger on legitimate patterns. The fix is not to weaken or remove them — it's to require LLM confirmation before they count.

## Design

### 1. Rule Definition: `soft` Flag

Add a `soft` field to `RuleDefinition`:

```python
@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    scope: str
    category: Category
    severity: Severity
    description: str
    evaluator: SegmentRuleEvaluator | ArtifactRuleEvaluator | SkillRuleEvaluator
    family_id: str | None = None
    enabled_by_default: bool = True
    origin: str = "builtin"
    soft: bool = False                      # NEW: requires LLM confirmation
    soft_fallback_confidence: float = 0.0   # NEW: confidence when LLM disabled (0.0 = drop)
```

Any rule — builtin or custom — can be marked soft. This is a first-class property, not a hack.

### 2. Configuration

```yaml
checks:
  # Rules that require LLM confirmation (overrides builtin defaults)
  soft_rules:
    - D-18C
    - D-14C
    - D-15G
    - D-15E
    - D-10A

  # Default fallback confidence when LLM is disabled (0.0 = drop soft findings)
  soft_fallback_confidence: 0.0

  # Per-rule overrides for fallback confidence
  soft_overrides:
    D-10A:
      soft_fallback_confidence: 0.15

scoring:
  # Multiplier on deduction for soft findings confirmed by LLM consensus
  soft_confirmed_boost: 1.5

  # Fraction of LLM models that must confirm (3/4 = 0.75)
  soft_confirmation_threshold: 0.75
```

Config merging: `soft_rules` in config adds to (or overrides) the builtin defaults. A rule can be made non-soft by adding it to a `hard_rules` list if needed.

### 3. Finding Annotation

When a deterministic rule with `soft=True` produces a finding, the finding gets:

```python
finding.details["soft"] = True
finding.details["soft_status"] = "pending"  # pending | confirmed | rejected
```

This is metadata — the finding exists in the findings list from the deterministic layer but is tagged as requiring confirmation.

### 4. LLM Confirmation Gate

The existing LLM targeted verification flow already sends deterministic findings to the LLM for analysis. The change:

**Current flow:** Each targeted finding goes to one LLM model, gets a confirm/dispute response, and the scoring engine adjusts the deduction by a small factor.

**New flow for soft findings:** Each soft finding goes to ALL loaded LLM models (not just one). A consensus function evaluates the responses:

```python
def evaluate_soft_consensus(
    responses: list[dict],      # One response per LLM model
    threshold: float = 0.75,    # Fraction that must confirm
) -> str:
    """Returns 'confirmed' or 'rejected'."""
    confirm_count = sum(1 for r in responses if r.get("disposition") == "confirm")
    if confirm_count / len(responses) >= threshold:
        return "confirmed"
    return "rejected"
```

With 4 LLM models and threshold 0.75: need 3 of 4 to confirm.

After consensus:
- **Confirmed:** `finding.details["soft_status"] = "confirmed"` — finding participates in scoring with the boost
- **Rejected:** `finding.details["soft_status"] = "rejected"` and `finding.absorbed_by = "llm_soft_rejection"` — finding is excluded from scoring

### 5. Scoring Integration

**Soft-confirmed findings get a boost.** The rationale: if the deterministic rule was uncertain enough to be soft, but 3 independent LLMs all confirmed it, that's stronger signal than an unverified hard finding.

```python
# In compute_score, when processing a soft-confirmed finding:
if finding.details.get("soft_status") == "confirmed":
    deduction *= config.scoring.soft_confirmed_boost  # default 1.5
```

This applies before diminishing returns and severity floors.

**Soft-rejected findings are dropped.** They contribute zero to the score.

**When LLM is disabled:**
- Default (`soft_fallback_confidence: 0.0`): soft findings are dropped entirely — zero score impact
- If a rule has a non-zero `soft_fallback_confidence`, the finding is included at that reduced confidence level instead of its natural confidence

### 6. Pipeline Flow

```
Deterministic rules fire → all findings produced as normal
  ↓
Tag soft findings: finding.details["soft"] = True based on rule.soft flag
  ↓
LLM layer receives ALL targeted candidates (existing behavior)
  PLUS soft findings explicitly queued for multi-model verification
  ↓
For each soft finding:
  → Send to ALL loaded LLM models (not just one)
  → Collect responses from each model
  → evaluate_soft_consensus(responses, threshold=0.75)
  → Tag finding as confirmed or rejected
  ↓
Scoring engine:
  → Skip findings with soft_status == "rejected"
  → Apply soft_confirmed_boost to confirmed soft findings
  → If LLM disabled: apply soft_fallback_confidence (default: drop)
```

### 7. Default Soft Rules

These rules ship with `soft: True` in the builtin registry:

| Rule | Builtin soft | Fallback confidence |
|------|-------------|-------------------|
| D-18C | True | 0.0 (drop) |
| D-14C | True | 0.0 (drop) |
| D-15G | True | 0.0 (drop) |
| D-15E | True | 0.0 (drop) |
| D-10A | True | 0.0 (drop) |

### 8. What Doesn't Change

- Hard findings (the default) work exactly as today
- Existing LLM targeted verification for hard findings is untouched — it still does single-model confirm/dispute with the existing small adjustment factor
- ML ensemble is completely unaffected
- Config can promote any rule to soft or demote any soft rule to hard
- Custom regex rules can also be marked soft via config

### 9. Benchmark Impact

Expected effect on the benchmark FP offenders:
- D-14C (17 FPs): Most will be rejected by LLM consensus → FP drops significantly
- D-18C (15 FPs): Broad descriptions in real-world skills will be rejected → FP drops
- D-15G (6 FPs): Legitimate HTTP URLs in real-world skills rejected → FP drops
- D-15E (4 FPs): Legitimate actionable URLs rejected → FP drops
- D-10A (5 FPs): Legitimate subprocess usage rejected → FP drops

True positives that currently trigger these rules should still be confirmed by LLM consensus — the malicious patterns are obvious enough for small models to recognize.

### 10. Files Changed

- `src/skillinquisitor/detectors/rules/engine.py` — Add `soft` and `soft_fallback_confidence` to `RuleDefinition`
- `src/skillinquisitor/detectors/rules/structural.py` — Mark D-14C, D-15E, D-15G, D-18C as soft
- `src/skillinquisitor/detectors/rules/behavioral.py` — Mark D-10A as soft
- `src/skillinquisitor/detectors/llm/judge.py` — Multi-model consensus for soft findings
- `src/skillinquisitor/scoring.py` — Soft finding filtering and boost
- `src/skillinquisitor/models.py` — Add scoring config fields
- Tests for each changed module
