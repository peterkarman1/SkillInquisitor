# Soft Findings with LLM Confirmation Gate — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** High-FP deterministic rules require LLM majority consensus (3/4 models) before counting in the risk score. Confirmed soft findings get a 1.5x scoring boost.

**Architecture:** Add `soft` flag to RuleDefinition, tag findings, send soft findings to all LLM models for consensus, filter/boost in scoring engine.

**Tech Stack:** Python, Pydantic, existing rule engine + LLM judge + scoring engine

**Spec:** `docs/superpowers/specs/2026-03-16-soft-findings-design.md`

---

## Chunk 1: Rule Definition + Config + Finding Tagging

### Task 1: Add `soft` fields to RuleDefinition

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/engine.py:26-36`
- Modify: `src/skillinquisitor/detectors/rules/engine.py:43-56`

- [ ] **Step 1: Add `soft` and `soft_fallback_confidence` to RuleDefinition**

In `engine.py`, update the dataclass:

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
    soft: bool = False
    soft_fallback_confidence: float = 0.0
```

- [ ] **Step 2: Update `RuleRegistry.register` to accept new fields**

```python
def register(self, **kwargs) -> None:
    evaluator = kwargs.get("evaluator", lambda *args, **inner_kwargs: [])
    rule = RuleDefinition(
        rule_id=kwargs["rule_id"],
        scope=kwargs["scope"],
        category=_coerce_category(kwargs["category"]),
        severity=_coerce_severity(kwargs.get("severity", Severity.LOW)),
        description=kwargs.get("description", ""),
        evaluator=evaluator,
        family_id=kwargs.get("family_id"),
        enabled_by_default=kwargs.get("enabled_by_default", True),
        origin=kwargs.get("origin", "builtin"),
        soft=kwargs.get("soft", False),
        soft_fallback_confidence=kwargs.get("soft_fallback_confidence", 0.0),
    )
    self._rules[rule.rule_id] = rule
```

- [ ] **Step 3: Tag soft findings in `run_registered_rules`**

After each finding is produced by a rule, check if the rule is soft and tag the finding. Add this helper and call it in the main loop:

```python
def _tag_soft_findings(findings: list[Finding], registry: RuleRegistry, config: ScanConfig) -> None:
    """Tag findings from soft rules with soft metadata."""
    soft_rule_ids = set(config.layers.deterministic.soft_rules) if hasattr(config.layers.deterministic, 'soft_rules') else set()
    for finding in findings:
        rule = registry.get(finding.rule_id)
        is_soft = (rule is not None and rule.soft) or finding.rule_id in soft_rule_ids
        if is_soft:
            finding.details["soft"] = True
            finding.details["soft_status"] = "pending"
```

Call `_tag_soft_findings(findings, registry, config)` before the return in `run_registered_rules`.

### Task 2: Add config fields

**Files:**
- Modify: `src/skillinquisitor/models.py` — `CheckConfig` and `ScoringConfig`

- [ ] **Step 1: Add soft fields to CheckConfig**

```python
class CheckConfig(BaseModel):
    enabled: bool = True
    checks: dict[str, bool] = Field(default_factory=dict)
    categories: dict[str, bool] = Field(default_factory=dict)
    soft_rules: list[str] = Field(default_factory=list)
    soft_fallback_confidence: float = 0.0
    soft_overrides: dict[str, dict[str, float]] = Field(default_factory=dict)
    # ... rest unchanged
```

- [ ] **Step 2: Add soft fields to ScoringConfig**

```python
class ScoringConfig(BaseModel):
    weights: ScoringWeightsConfig = Field(default_factory=ScoringWeightsConfig)
    suppression_multiplier: float = 1.5
    chain_absorption: bool = True
    decay_factor: float = 0.7
    severity_floors: dict[str, int] = Field(
        default_factory=lambda: {"critical": 39, "high": 59}
    )
    llm_dispute_factor: float = 0.5
    llm_confirm_factor: float = 0.15
    soft_confirmed_boost: float = 1.5
    soft_confirmation_threshold: float = 0.75
```

### Task 3: Mark default soft rules

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/behavioral.py:67-74`
- Modify: `src/skillinquisitor/detectors/rules/structural.py` (D-14C, D-15E, D-15G registrations)
- Modify: `src/skillinquisitor/detectors/rules/temporal.py:95-101` (D-18C)

- [ ] **Step 1: Mark D-10A as soft in behavioral.py**

Add `soft=True` to the D-10A registration:

```python
registry.register(
    rule_id="D-10A",
    family_id="D-10",
    scope="segment",
    category=Category.BEHAVIORAL,
    severity=Severity.HIGH,
    description="Dynamic or shell execution behavior detected",
    evaluator=_detect_dynamic_exec,
    soft=True,
)
```

- [ ] **Step 2: Mark D-14C as soft in structural.py**

Find the D-14C registration and add `soft=True`. D-14C is emitted inline (not via registry.register) — it's created directly as a Finding in `_evaluate_skill_structure`. For inline findings, the tagging in `_tag_soft_findings` will handle it via the `soft_rules` config list or the registry lookup. We need D-14C in the registry with `soft=True`.

If D-14C is not registered via `registry.register` (it's emitted as a finding directly), add it to the default `soft_rules` list in CheckConfig:

```python
class CheckConfig(BaseModel):
    soft_rules: list[str] = Field(
        default_factory=lambda: ["D-10A", "D-14C", "D-15E", "D-15G", "D-18C"]
    )
```

This way the tagging function catches all 5 rules regardless of whether they use `registry.register` with `soft=True` or emit findings directly.

- [ ] **Step 3: Mark D-18C as soft in temporal.py**

Add `soft=True` to the D-18C registration:

```python
registry.register(
    rule_id="D-18C",
    family_id="D-18",
    scope="artifact",
    category=Category.BEHAVIORAL,
    severity=Severity.MEDIUM,
    description="Overly broad auto-invocation description",
    evaluator=_detect_auto_invocation_abuse,
    soft=True,
)
```

### Task 4: Tests for Chunk 1

**Files:**
- Create: `tests/test_soft_findings.py`

- [ ] **Step 1: Write tests**

```python
"""Tests for soft finding tagging and configuration."""
from skillinquisitor.detectors.rules.engine import RuleDefinition, RuleRegistry
from skillinquisitor.models import Category, CheckConfig, ScanConfig, ScoringConfig, Severity


class TestRuleDefinitionSoftFlag:
    def test_default_not_soft(self):
        rule = RuleDefinition(
            rule_id="TEST", scope="segment", category=Category.STRUCTURAL,
            severity=Severity.LOW, description="test",
            evaluator=lambda *a, **k: [],
        )
        assert rule.soft is False
        assert rule.soft_fallback_confidence == 0.0

    def test_soft_rule(self):
        rule = RuleDefinition(
            rule_id="TEST", scope="segment", category=Category.STRUCTURAL,
            severity=Severity.LOW, description="test",
            evaluator=lambda *a, **k: [],
            soft=True, soft_fallback_confidence=0.15,
        )
        assert rule.soft is True
        assert rule.soft_fallback_confidence == 0.15

    def test_registry_accepts_soft(self):
        registry = RuleRegistry()
        registry.register(
            rule_id="SOFT-TEST", scope="segment", category="structural",
            severity="low", description="test", soft=True,
        )
        rule = registry.get("SOFT-TEST")
        assert rule is not None
        assert rule.soft is True


class TestCheckConfigSoftRules:
    def test_default_soft_rules(self):
        config = CheckConfig()
        assert "D-10A" in config.soft_rules
        assert "D-14C" in config.soft_rules
        assert "D-18C" in config.soft_rules

    def test_custom_soft_rules(self):
        config = CheckConfig(soft_rules=["D-1A", "D-2A"])
        assert config.soft_rules == ["D-1A", "D-2A"]


class TestScoringConfigSoftFields:
    def test_defaults(self):
        config = ScoringConfig()
        assert config.soft_confirmed_boost == 1.5
        assert config.soft_confirmation_threshold == 0.75
```

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/test_soft_findings.py -v`
Expected: All pass

- [ ] **Step 3: Commit**

```
git add src/skillinquisitor/detectors/rules/engine.py src/skillinquisitor/models.py \
  src/skillinquisitor/detectors/rules/behavioral.py \
  src/skillinquisitor/detectors/rules/structural.py \
  src/skillinquisitor/detectors/rules/temporal.py \
  tests/test_soft_findings.py
git commit -m "feat(rules): add soft finding flag and default soft rules"
```

---

## Chunk 2: LLM Multi-Model Consensus for Soft Findings

### Task 5: Add consensus evaluation function

**Files:**
- Modify: `src/skillinquisitor/detectors/llm/judge.py`

- [ ] **Step 1: Add `evaluate_soft_consensus` function**

```python
def evaluate_soft_consensus(
    responses: list[dict[str, object]],
    threshold: float = 0.75,
) -> str:
    """Evaluate multi-model consensus for a soft finding.

    Returns 'confirmed' if at least threshold fraction of models confirm.
    Returns 'rejected' otherwise.
    """
    if not responses:
        return "rejected"
    confirm_count = sum(
        1 for r in responses
        if str(r.get("disposition", "")).lower() in ("confirm", "confirmed")
    )
    if confirm_count / len(responses) >= threshold:
        return "confirmed"
    return "rejected"
```

### Task 6: Route soft findings to all models

**Files:**
- Modify: `src/skillinquisitor/detectors/llm/judge.py`

- [ ] **Step 1: Update `_build_prompt_jobs` to flag soft finding jobs**

Add a `soft` field to `PromptJob` and set it when the deterministic finding has `soft=True`:

```python
@dataclass(frozen=True)
class PromptJob:
    key: str
    prompt_kind: str
    target: LLMTarget
    prompt: str
    rule_id: str
    category: Category
    references: tuple[str, ...] = ()
    deterministic_finding: Finding | None = None
    soft: bool = False  # NEW
```

In `_build_prompt_jobs`, when creating targeted jobs:

```python
for finding in targeted_findings:
    is_soft = finding.details.get("soft", False)
    jobs.append(
        PromptJob(
            key=f"targeted:{target.artifact_path}:{finding.id}",
            prompt_kind="targeted",
            target=target,
            prompt=build_targeted_prompt(target=target, finding=finding),
            rule_id=_targeted_rule_id(finding),
            category=_targeted_category(finding),
            references=(finding.id,),
            deterministic_finding=finding,
            soft=is_soft,
        )
    )
```

- [ ] **Step 2: Update `analyze` to send soft jobs to all models**

In the `LLMCodeJudge.analyze` method (or equivalent orchestrator), when processing jobs:

- For regular (non-soft) jobs: existing behavior — send to one model, get one response
- For soft jobs: send to ALL loaded models, collect all responses, call `evaluate_soft_consensus`

After consensus:
- If confirmed: update `finding.details["soft_status"] = "confirmed"`
- If rejected: update `finding.details["soft_status"] = "rejected"` and set `finding.absorbed_by = "llm_soft_rejection"`

The exact implementation depends on the analyze method structure. The key change: soft jobs get dispatched to every model in the group, not just one.

### Task 7: Tests for consensus

**Files:**
- Modify: `tests/test_soft_findings.py`

- [ ] **Step 1: Add consensus tests**

```python
from skillinquisitor.detectors.llm.judge import evaluate_soft_consensus


class TestEvaluateSoftConsensus:
    def test_all_confirm(self):
        responses = [{"disposition": "confirm"}, {"disposition": "confirm"}, {"disposition": "confirm"}, {"disposition": "confirm"}]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_three_of_four_confirm(self):
        responses = [{"disposition": "confirm"}, {"disposition": "confirm"}, {"disposition": "confirm"}, {"disposition": "dispute"}]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_two_of_four_reject(self):
        responses = [{"disposition": "confirm"}, {"disposition": "confirm"}, {"disposition": "dispute"}, {"disposition": "dispute"}]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"

    def test_all_dispute(self):
        responses = [{"disposition": "dispute"}] * 4
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"

    def test_empty_responses(self):
        assert evaluate_soft_consensus([], threshold=0.75) == "rejected"

    def test_case_insensitive(self):
        responses = [{"disposition": "Confirm"}, {"disposition": "CONFIRM"}, {"disposition": "confirmed"}, {"disposition": "dispute"}]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_custom_threshold(self):
        responses = [{"disposition": "confirm"}, {"disposition": "dispute"}]
        assert evaluate_soft_consensus(responses, threshold=0.5) == "confirmed"
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"
```

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/test_soft_findings.py -v`

- [ ] **Step 3: Commit**

```
git add src/skillinquisitor/detectors/llm/judge.py tests/test_soft_findings.py
git commit -m "feat(llm): add multi-model consensus gate for soft findings"
```

---

## Chunk 3: Scoring Integration

### Task 8: Filter and boost soft findings in scoring

**Files:**
- Modify: `src/skillinquisitor/scoring.py`

- [ ] **Step 1: Add soft finding handling to `compute_score`**

At the beginning of `compute_score`, after the existing chain absorption and dedup steps, add soft finding filtering:

```python
# Filter soft findings based on LLM confirmation status
llm_enabled = config.layers.llm.enabled
soft_fallback = config.layers.deterministic.soft_fallback_confidence

effective_findings = []
soft_rejected_count = 0
soft_confirmed_count = 0

for f in findings:
    if not f.details.get("soft", False):
        effective_findings.append(f)
        continue

    status = f.details.get("soft_status", "pending")
    if status == "confirmed":
        soft_confirmed_count += 1
        effective_findings.append(f)
    elif status == "rejected":
        soft_rejected_count += 1
        f.absorbed_by = "llm_soft_rejection"
        # Don't add to effective_findings
    elif not llm_enabled:
        # LLM disabled — apply fallback
        rule_override = config.layers.deterministic.soft_overrides.get(f.rule_id, {})
        fallback = rule_override.get("soft_fallback_confidence", soft_fallback)
        if fallback > 0.0:
            f.confidence = fallback
            effective_findings.append(f)
        else:
            soft_rejected_count += 1
            f.absorbed_by = "llm_disabled_soft_drop"
    else:
        # LLM enabled but status still pending (shouldn't happen in normal flow)
        effective_findings.append(f)
```

Then use `effective_findings` instead of `findings` for the rest of the scoring.

- [ ] **Step 2: Apply soft_confirmed_boost to deductions**

In the deduction calculation loop, when computing the base deduction for a finding:

```python
base_deduction = severity_weight * confidence * (decay ** position)

# Boost soft-confirmed findings
if finding.details.get("soft_status") == "confirmed":
    base_deduction *= config.scoring.soft_confirmed_boost
```

- [ ] **Step 3: Add soft stats to scoring_details**

```python
scoring_details["soft_confirmed_count"] = soft_confirmed_count
scoring_details["soft_rejected_count"] = soft_rejected_count
```

### Task 9: Tests for soft scoring

**Files:**
- Modify: `tests/test_soft_findings.py`

- [ ] **Step 1: Add scoring tests**

```python
from skillinquisitor.models import DetectionLayer, Finding, Location, ScanConfig
from skillinquisitor.scoring import compute_score


def _soft_finding(rule_id="D-14C", severity="low", soft_status="confirmed"):
    return Finding(
        severity=severity, category="structural", layer=DetectionLayer.DETERMINISTIC,
        rule_id=rule_id, message="test", location=Location(file_path="test.md"),
        details={"soft": True, "soft_status": soft_status},
    )


def _hard_finding(rule_id="D-1A", severity="high"):
    return Finding(
        severity=severity, category="steganography", layer=DetectionLayer.DETERMINISTIC,
        rule_id=rule_id, message="test", location=Location(file_path="test.md"),
    )


class TestSoftFindingScoring:
    def test_rejected_soft_finding_no_impact(self):
        config = ScanConfig()
        result = compute_score([_soft_finding(soft_status="rejected")], config)
        assert result.risk_score == 100  # No deduction

    def test_confirmed_soft_finding_deducts(self):
        config = ScanConfig()
        result = compute_score([_soft_finding(soft_status="confirmed")], config)
        assert result.risk_score < 100  # Deduction applied

    def test_confirmed_soft_finding_boosted(self):
        config = ScanConfig()
        # Compare: hard finding vs soft-confirmed finding at same severity
        hard_result = compute_score([_hard_finding(severity="low")], config)
        soft_result = compute_score([_soft_finding(severity="low", soft_status="confirmed")], config)
        # Soft-confirmed should deduct MORE (1.5x boost)
        assert soft_result.risk_score < hard_result.risk_score

    def test_soft_pending_when_llm_disabled(self):
        config = ScanConfig()
        config.layers.llm.enabled = False
        # Default fallback is 0.0 = drop
        result = compute_score([_soft_finding(soft_status="pending")], config)
        assert result.risk_score == 100  # Dropped
```

- [ ] **Step 2: Run all tests**

Run: `uv run pytest tests/test_soft_findings.py tests/test_scoring.py -v`

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest tests/ -q`
Expected: All pass, no regressions

- [ ] **Step 4: Commit**

```
git add src/skillinquisitor/scoring.py tests/test_soft_findings.py
git commit -m "feat(scoring): filter soft findings and apply confirmation boost"
```

---

## Chunk 4: Integration + Benchmark Verification

### Task 10: End-to-end integration test

**Files:**
- Modify: `tests/test_soft_findings.py`

- [ ] **Step 1: Add integration test scanning a skill with soft rules**

```python
import asyncio
from skillinquisitor.input import resolve_input
from skillinquisitor.pipeline import run_pipeline
from skillinquisitor.models import ScanConfig


class TestSoftFindingIntegration:
    def test_soft_findings_tagged_in_pipeline(self):
        """Scan a skill that triggers D-14C (soft) and verify tagging."""
        config = ScanConfig()
        config.layers.ml.enabled = False
        config.layers.llm.enabled = False
        skills = asyncio.run(resolve_input("benchmark/dataset/skills/skill-0051"))
        result = asyncio.run(run_pipeline(skills=skills, config=config))

        soft_findings = [f for f in result.findings if f.details.get("soft")]
        # With LLM disabled and fallback=0.0, soft findings should be dropped in scoring
        # but still present in the findings list with soft_status
        for f in soft_findings:
            assert f.details.get("soft_status") in ("pending", "rejected")
```

### Task 11: Run benchmark and compare

- [ ] **Step 1: Run deterministic-only benchmark**

```bash
uv run skillinquisitor benchmark run --tier smoke --layer deterministic \
  --dataset benchmark/manifest.yaml --output benchmark/results/soft-det-only
```

Compare FP count against the pre-soft baseline.

- [ ] **Step 2: Run full benchmark with all layers**

```bash
uv run skillinquisitor benchmark run --tier smoke --timeout 300 \
  --dataset benchmark/manifest.yaml --output benchmark/results/soft-all-layers
```

Verify:
- FP count decreases for D-14C, D-18C, D-15G, D-15E, D-10A
- TP count stays the same or increases (soft-confirmed boost)
- Precision improves

### Task 12: Update docs and commit

- [ ] **Step 1: Update CHANGELOG.md**

Add entry for soft findings feature.

- [ ] **Step 2: Update README.md**

Add soft findings to the Risk Scoring section.

- [ ] **Step 3: Final commit and push**

```bash
git add -A
git commit -m "feat: soft findings with LLM confirmation gate

Deterministic rules can be marked soft — their findings require LLM
majority consensus (3/4 models) before counting in the risk score.
Confirmed soft findings get a 1.5x scoring boost.

Default soft rules: D-10A, D-14C, D-15E, D-15G, D-18C (the top FP
offenders from the benchmark). When LLM is disabled, soft findings
are dropped by default (configurable per-rule fallback confidence)."

git push origin main
```
