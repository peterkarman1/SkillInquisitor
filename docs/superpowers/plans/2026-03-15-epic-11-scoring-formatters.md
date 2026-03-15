# Epic 11 — Risk Scoring & Output Formatters Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement risk scoring with diminishing returns, confidence weighting, and severity floors, plus console/JSON/SARIF output formatters.

**Architecture:** Scoring is a pure function in `scoring.py` that takes findings + config and returns score/verdict. Formatters consume `ScanResult` and produce strings. Pipeline calls scoring after all layers complete, then passes results to formatters.

**Tech Stack:** Python 3.13, Pydantic, pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-15-epic-11-scoring-formatters-design.md`

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `src/skillinquisitor/scoring.py` | Risk score calculation: chain absorption, cross-layer dedup, LLM adjustment, diminishing returns, suppression amplifier, severity floors, verdict mapping |
| Modify | `src/skillinquisitor/models.py` | Add `decay_factor`, `severity_floors`, `llm_dispute_factor`, `llm_confirm_factor` to `ScoringConfig` |
| Modify | `src/skillinquisitor/pipeline.py` | Call `compute_score()` after layer runs, populate `risk_score` and `verdict` on `ScanResult` |
| Rewrite | `src/skillinquisitor/formatters/console.py` | Grouped-by-file console output with severity sorting, chain cross-references, summary footer |
| Rewrite | `src/skillinquisitor/formatters/json.py` | Findings-focused JSON (no raw content), summary stats |
| Create | `src/skillinquisitor/formatters/sarif.py` | SARIF 2.1.0 output with relatedLocations for chains |
| Modify | `src/skillinquisitor/cli.py` | Wire SARIF format option, pass verbose flag to formatters |
| Rewrite | `tests/test_scoring.py` | Comprehensive scoring tests covering all algorithm steps and edge cases |
| Modify | `tests/conftest.py` | Update `_assert_matches` to use scored verdicts (score-based, not finding-count-based) |
| Modify | `tests/fixtures/*/expected.yaml` | Update verdict values in fixtures to match scoring algorithm output |
| Create | `tests/test_formatters.py` | Tests for console, JSON, and SARIF formatters |

---

## Chunk 1: Scoring Engine

### Task 1: Add scoring config fields to models.py

**Files:**
- Modify: `src/skillinquisitor/models.py:296-307`
- Test: `tests/test_scoring.py`

- [ ] **Step 1: Add new fields to ScoringConfig**

In `src/skillinquisitor/models.py`, update `ScoringConfig`:

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
```

- [ ] **Step 2: Verify existing tests still pass**

Run: `pytest tests/test_config.py tests/test_pipeline.py -x -q`
Expected: All pass (new fields have defaults, backward compatible)

- [ ] **Step 3: Commit**

```bash
git add src/skillinquisitor/models.py
git commit -m "feat(scoring): add diminishing returns and severity floor config fields"
```

### Task 2: Implement scoring.py — core algorithm

**Files:**
- Create: `src/skillinquisitor/scoring.py`
- Test: `tests/test_scoring.py`

- [ ] **Step 1: Write failing tests for the scoring function**

Replace the placeholder in `tests/test_scoring.py` with comprehensive unit tests. Test the `compute_score` function directly — it takes `findings: list[Finding]` and `config: ScanConfig` and returns a dataclass with `risk_score`, `verdict`, and `scoring_details`.

```python
"""Scoring engine tests for Epic 11."""
from __future__ import annotations

import pytest

from skillinquisitor.models import (
    Category,
    DetectionLayer,
    Finding,
    Location,
    ScanConfig,
    Severity,
)
from skillinquisitor.scoring import compute_score


def _finding(
    *,
    severity: Severity = Severity.MEDIUM,
    category: Category = Category.STRUCTURAL,
    layer: DetectionLayer = DetectionLayer.DETERMINISTIC,
    rule_id: str = "D-TEST",
    confidence: float = 1.0,
    action_flags: list[str] | None = None,
    references: list[str] | None = None,
    details: dict | None = None,
    segment_id: str | None = None,
    finding_id: str | None = None,
) -> Finding:
    f = Finding(
        severity=severity,
        category=category,
        layer=layer,
        rule_id=rule_id,
        message="test",
        location=Location(file_path="test.md", start_line=1, end_line=1),
        confidence=confidence,
        action_flags=action_flags or [],
        references=references or [],
        details=details or {},
        segment_id=segment_id,
    )
    if finding_id:
        f = f.model_copy(update={"id": finding_id})
    return f


class TestBasicScoring:
    def test_no_findings_returns_safe(self):
        result = compute_score([], ScanConfig())
        assert result.risk_score == 100
        assert result.verdict == "SAFE"

    def test_single_low_finding(self):
        findings = [_finding(severity=Severity.LOW)]
        result = compute_score(findings, ScanConfig())
        assert result.risk_score == 95
        assert result.verdict == "SAFE"

    def test_single_medium_finding(self):
        findings = [_finding(severity=Severity.MEDIUM)]
        result = compute_score(findings, ScanConfig())
        assert result.risk_score == 90
        assert result.verdict == "SAFE"

    def test_single_info_finding(self):
        findings = [_finding(severity=Severity.INFO)]
        result = compute_score(findings, ScanConfig())
        assert result.risk_score == 100
        assert result.verdict == "SAFE"

    def test_single_critical_triggers_severity_floor(self):
        findings = [_finding(severity=Severity.CRITICAL)]
        result = compute_score(findings, ScanConfig())
        assert result.risk_score == 39
        assert result.verdict == "HIGH RISK"

    def test_single_high_triggers_severity_floor(self):
        findings = [_finding(severity=Severity.HIGH)]
        result = compute_score(findings, ScanConfig())
        assert result.risk_score == 59
        assert result.verdict == "LOW RISK"


class TestDiminishingReturns:
    def test_two_criticals_second_is_less(self):
        findings = [
            _finding(severity=Severity.CRITICAL),
            _finding(severity=Severity.CRITICAL),
        ]
        result = compute_score(findings, ScanConfig())
        # First: 30, second: 30*0.7=21, total=51, raw=49, floor=39
        assert result.risk_score <= 39

    def test_twenty_low_findings_stay_safe(self):
        findings = [_finding(severity=Severity.LOW) for _ in range(20)]
        result = compute_score(findings, ScanConfig())
        # Geometric series: 5 * sum(0.7^i for i in 0..19) ≈ 5 * 3.28 = 16.4
        # Score ≈ 83.6 → SAFE
        assert result.risk_score >= 80
        assert result.verdict == "SAFE"

    def test_fifty_info_findings_remain_100(self):
        findings = [_finding(severity=Severity.INFO) for _ in range(50)]
        result = compute_score(findings, ScanConfig())
        assert result.risk_score == 100


class TestChainAbsorption:
    def test_chain_absorbs_component_deductions(self):
        comp_a = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-7A",
            finding_id="comp-a",
            action_flags=["READ_SENSITIVE"],
        )
        comp_b = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-9A",
            finding_id="comp-b",
            action_flags=["NETWORK_SEND"],
        )
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=["comp-a", "comp-b"],
            category=Category.DATA_EXFILTRATION,
        )
        # With absorption: only chain deducts (CRITICAL=30), components absorbed
        # Without absorption: 30 + 10 + 10 = 50
        result_with = compute_score([comp_a, comp_b, chain], ScanConfig())
        no_absorb_config = ScanConfig(
            scoring=ScanConfig().scoring.model_copy(
                update={"chain_absorption": False}
            )
        )
        result_without = compute_score([comp_a, comp_b, chain], no_absorb_config)
        assert result_with.risk_score > result_without.risk_score


class TestSuppressionAmplifier:
    def test_suppression_amplifies_other_deductions(self):
        suppression = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-12A",
            category=Category.SUPPRESSION,
            action_flags=["SUPPRESSION_PRESENT"],
        )
        other = _finding(severity=Severity.MEDIUM, rule_id="D-7A")
        result_with = compute_score([suppression, other], ScanConfig())
        result_without = compute_score([other], ScanConfig())
        # Suppression should make score worse
        assert result_with.risk_score < result_without.risk_score

    def test_suppression_does_not_amplify_itself(self):
        suppression = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-12A",
            category=Category.SUPPRESSION,
            action_flags=["SUPPRESSION_PRESENT"],
        )
        result = compute_score([suppression], ScanConfig())
        # Just the suppression finding itself: 100 - 10 = 90
        assert result.risk_score == 90


class TestLLMAdjustment:
    def test_llm_dispute_reduces_deduction(self):
        det = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            finding_id="det-1",
        )
        dispute = _finding(
            severity=Severity.CRITICAL,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-TGT",
            confidence=0.90,
            references=["det-1"],
            details={"disposition": "dispute"},
        )
        result_disputed = compute_score([det, dispute], ScanConfig())
        result_undisputed = compute_score([det], ScanConfig())
        # Disputed should have higher score (less severe)
        assert result_disputed.risk_score > result_undisputed.risk_score

    def test_llm_dispute_lifts_severity_floor(self):
        det = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            finding_id="det-1",
        )
        dispute = _finding(
            severity=Severity.CRITICAL,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-TGT",
            confidence=0.90,
            references=["det-1"],
            details={"disposition": "dispute"},
        )
        result = compute_score([det, dispute], ScanConfig())
        # Disputed CRITICAL should NOT trigger the CRITICAL floor (39)
        assert result.risk_score > 39

    def test_llm_confirm_increases_deduction(self):
        det = _finding(
            severity=Severity.HIGH,
            rule_id="D-10A",
            finding_id="det-1",
        )
        confirm = _finding(
            severity=Severity.HIGH,
            layer=DetectionLayer.LLM_ANALYSIS,
            rule_id="LLM-TGT",
            confidence=0.85,
            references=["det-1"],
            details={"disposition": "confirm"},
        )
        result_confirmed = compute_score([det, confirm], ScanConfig())
        result_alone = compute_score([det], ScanConfig())
        # Confirmed should have lower score (more severe)
        assert result_confirmed.risk_score <= result_alone.risk_score


class TestCrossLayerDedup:
    def test_same_segment_different_layers_deduped(self):
        det = _finding(
            severity=Severity.MEDIUM,
            rule_id="D-11A",
            segment_id="seg-1",
            category=Category.PROMPT_INJECTION,
        )
        ml = _finding(
            severity=Severity.MEDIUM,
            layer=DetectionLayer.ML_ENSEMBLE,
            rule_id="ML-INJ",
            segment_id="seg-1",
            category=Category.PROMPT_INJECTION,
            confidence=0.85,
        )
        result_both = compute_score([det, ml], ScanConfig())
        result_det = compute_score([det], ScanConfig())
        # Both should deduct roughly the same as one (single deduction at higher conf)
        # Not double the deduction
        assert result_both.risk_score >= result_det.risk_score - 5


class TestVerdictMapping:
    @pytest.mark.parametrize(
        "score,verdict",
        [
            (100, "SAFE"),
            (80, "SAFE"),
            (79, "LOW RISK"),
            (60, "LOW RISK"),
            (59, "MEDIUM RISK"),
            (40, "MEDIUM RISK"),
            (39, "HIGH RISK"),
            (20, "HIGH RISK"),
            (19, "CRITICAL"),
            (0, "CRITICAL"),
        ],
    )
    def test_verdict_boundaries(self, score, verdict):
        from skillinquisitor.scoring import _score_to_verdict

        assert _score_to_verdict(score) == verdict
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scoring.py -x -q`
Expected: ImportError (scoring module doesn't exist yet)

- [ ] **Step 3: Implement scoring.py**

Create `src/skillinquisitor/scoring.py`:

```python
"""Risk scoring engine.

Implements: subtractive scoring with diminishing returns, confidence weighting,
chain absorption, cross-layer dedup, LLM adjustment, suppression amplification,
and severity floors.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from skillinquisitor.models import (
    DetectionLayer,
    Finding,
    ScanConfig,
    Severity,
)

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEVERITY_WEIGHT_ATTR = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: None,
}


@dataclass(frozen=True)
class ScoredResult:
    risk_score: int
    verdict: str
    scoring_details: dict[str, object] = field(default_factory=dict)


def compute_score(findings: list[Finding], config: ScanConfig) -> ScoredResult:
    if not findings:
        return ScoredResult(risk_score=100, verdict="SAFE")

    scoring = config.scoring
    weights = scoring.weights

    def _weight_for(severity: Severity) -> int:
        attr = SEVERITY_WEIGHT_ATTR.get(severity)
        return getattr(weights, attr) if attr else 0

    # Step 1: identify chain component IDs for absorption
    absorbed_ids: set[str] = set()
    if scoring.chain_absorption:
        for f in findings:
            if f.references:
                absorbed_ids.update(f.references)

    # Step 2: identify LLM adjustment findings
    llm_adjustments: dict[str, Finding] = {}  # referenced_id -> LLM finding
    for f in findings:
        if f.layer == DetectionLayer.LLM_ANALYSIS and f.references and f.details.get("disposition") in ("dispute", "confirm"):
            for ref_id in f.references:
                llm_adjustments[ref_id] = f

    # Step 3: cross-layer dedup by segment_id + category overlap
    seen_segments: dict[tuple[str, str], Finding] = {}  # (segment_id, category) -> best finding
    dedup_ids: set[str] = set()
    for f in findings:
        if f.id in absorbed_ids:
            continue
        if f.layer == DetectionLayer.LLM_ANALYSIS and f.details.get("disposition") in ("dispute", "confirm"):
            continue  # LLM adjustment findings don't contribute their own deduction
        if f.segment_id:
            key = (f.segment_id, f.category.value)
            if key in seen_segments:
                existing = seen_segments[key]
                existing_conf = existing.confidence if existing.confidence is not None else 1.0
                new_conf = f.confidence if f.confidence is not None else 1.0
                if new_conf > existing_conf:
                    dedup_ids.add(existing.id)
                    seen_segments[key] = f
                else:
                    dedup_ids.add(f.id)
            else:
                seen_segments[key] = f

    # Step 4: build effective findings list
    effective: list[Finding] = []
    disputed_ids: set[str] = set()
    for f in findings:
        if f.id in absorbed_ids or f.id in dedup_ids:
            continue
        if f.layer == DetectionLayer.LLM_ANALYSIS and f.details.get("disposition") in ("dispute", "confirm"):
            continue
        effective.append(f)

    # Step 5: compute per-finding effective confidence with LLM adjustments
    effective_confidences: dict[str, float] = {}
    effective_deduction_multipliers: dict[str, float] = {}
    for f in effective:
        base_conf = f.confidence if f.confidence is not None else 1.0
        mult = 1.0
        if f.id in llm_adjustments:
            adj = llm_adjustments[f.id]
            adj_conf = adj.confidence if adj.confidence is not None else 0.5
            if adj.details.get("disposition") == "dispute":
                base_conf = base_conf * (1.0 - scoring.llm_dispute_factor * adj_conf)
                disputed_ids.add(f.id)
            elif adj.details.get("disposition") == "confirm":
                mult = 1.0 + scoring.llm_confirm_factor * adj_conf
        effective_confidences[f.id] = max(0.0, base_conf)
        effective_deduction_multipliers[f.id] = mult

    # Step 6: check for suppression
    has_suppression = any("SUPPRESSION_PRESENT" in f.action_flags for f in findings)
    is_suppression_finding = {
        f.id for f in effective if "SUPPRESSION_PRESENT" in f.action_flags
    }

    # Step 7: group by severity tier, sort by confidence desc within tier
    tiers: dict[Severity, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in effective:
        tiers[f.severity].append(f)
    for tier_findings in tiers.values():
        tier_findings.sort(key=lambda f: -(effective_confidences.get(f.id, 1.0)))

    # Step 8: compute deductions with diminishing returns
    total_deduction = 0.0
    decay = scoring.decay_factor
    for severity in SEVERITY_ORDER:
        base_weight = _weight_for(severity)
        if base_weight == 0:
            continue
        for position, f in enumerate(tiers[severity]):
            conf = effective_confidences.get(f.id, 1.0)
            mult = effective_deduction_multipliers.get(f.id, 1.0)
            deduction = base_weight * conf * (decay ** position) * mult
            # Apply suppression amplifier to non-suppression findings
            if has_suppression and f.id not in is_suppression_finding:
                deduction *= scoring.suppression_multiplier
            total_deduction += deduction

    # Step 9: compute raw score
    raw_score = max(0, min(100, round(100.0 - total_deduction)))

    # Step 10: apply severity floors (only for undisputed findings)
    score = raw_score
    worst_undisputed = _worst_undisputed_severity(effective, disputed_ids)
    if worst_undisputed is not None:
        floor_key = worst_undisputed.value
        if floor_key in scoring.severity_floors:
            floor_value = scoring.severity_floors[floor_key]
            if score > floor_value:
                score = floor_value

    verdict = _score_to_verdict(score)
    return ScoredResult(
        risk_score=score,
        verdict=verdict,
        scoring_details={
            "raw_score": raw_score,
            "total_deduction": round(total_deduction, 2),
            "absorbed_count": len(absorbed_ids),
            "deduped_count": len(dedup_ids),
            "disputed_count": len(disputed_ids),
            "suppression_active": has_suppression,
            "severity_floor_applied": score != raw_score,
            "effective_finding_count": len(effective),
        },
    )


def _worst_undisputed_severity(
    effective: list[Finding], disputed_ids: set[str]
) -> Severity | None:
    for severity in SEVERITY_ORDER:
        for f in effective:
            if f.severity == severity and f.id not in disputed_ids:
                return severity
    return None


def _score_to_verdict(score: int) -> str:
    if score >= 80:
        return "SAFE"
    if score >= 60:
        return "LOW RISK"
    if score >= 40:
        return "MEDIUM RISK"
    if score >= 20:
        return "HIGH RISK"
    return "CRITICAL"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scoring.py -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/scoring.py tests/test_scoring.py
git commit -m "feat(scoring): implement risk scoring with diminishing returns and severity floors"
```

### Task 3: Wire scoring into pipeline.py

**Files:**
- Modify: `src/skillinquisitor/pipeline.py:61-72`
- Modify: `src/skillinquisitor/cli.py` (rules test path)

- [ ] **Step 1: Update pipeline to call compute_score**

In `src/skillinquisitor/pipeline.py`, replace the static `risk_score=100` and `verdict=...` lines:

```python
from skillinquisitor.scoring import compute_score

# ... inside run_pipeline, after findings.extend(llm_findings):

    scored = compute_score(findings, config)

    return ScanResult(
        skills=normalized_skills,
        findings=findings,
        risk_score=scored.risk_score,
        verdict=scored.verdict,
        layer_metadata={
            "deterministic": {"enabled": config.layers.deterministic.enabled, "findings": len(deterministic_findings)},
            "ml": ml_metadata,
            "llm": llm_metadata,
            "scoring": scored.scoring_details,
        },
        total_timing=0.0,
    )
```

Also update `_run_rules_test` in `cli.py` to use `compute_score` instead of static values.

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: Some fixture verdicts may now differ — this is expected since scoring changed from "SAFE if 0 findings else MEDIUM RISK" to the real algorithm.

- [ ] **Step 3: Update fixture expected.yaml verdicts to match new scoring**

For each failing fixture, compute the expected verdict under the new scoring algorithm and update the `verdict` field in `expected.yaml`. Key changes:
- Fixtures with a CRITICAL finding (e.g., D-19A chains) → verdict changes from "MEDIUM RISK" to "HIGH RISK" (severity floor at 39)
- Fixtures with a HIGH finding → verdict changes to "LOW RISK" (severity floor at 59)
- Safe fixtures remain "SAFE"
- Fixtures with only MEDIUM/LOW findings → "SAFE" (scores 80+)

Run the test suite after each update to track progress.

- [ ] **Step 4: Run full test suite and verify all pass**

Run: `pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/pipeline.py src/skillinquisitor/cli.py tests/fixtures/
git commit -m "feat(pipeline): wire scoring engine into pipeline and update fixture verdicts"
```

---

## Chunk 2: Console Formatter

### Task 4: Implement grouped-by-file console formatter

**Files:**
- Rewrite: `src/skillinquisitor/formatters/console.py`
- Create: `tests/test_formatters.py`

- [ ] **Step 1: Write failing tests for console formatter**

Create `tests/test_formatters.py`:

```python
"""Tests for output formatters."""
from __future__ import annotations

import json

import pytest

from skillinquisitor.models import (
    Category,
    DetectionLayer,
    Finding,
    Location,
    ScanConfig,
    ScanResult,
    Severity,
    Skill,
)
from skillinquisitor.formatters.console import format_console


def _result(
    findings: list[Finding] | None = None,
    risk_score: int = 100,
    verdict: str = "SAFE",
) -> ScanResult:
    return ScanResult(
        skills=[Skill(path="/test/skill", name="test-skill")],
        findings=findings or [],
        risk_score=risk_score,
        verdict=verdict,
        layer_metadata={},
        total_timing=1.23,
    )


def _finding(
    *,
    severity: Severity = Severity.MEDIUM,
    rule_id: str = "D-TEST",
    category: Category = Category.STRUCTURAL,
    message: str = "test finding",
    file_path: str = "SKILL.md",
    start_line: int = 1,
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        severity=severity,
        category=category,
        layer=DetectionLayer.DETERMINISTIC,
        rule_id=rule_id,
        message=message,
        location=Location(file_path=file_path, start_line=start_line, end_line=start_line),
        references=references or [],
    )


class TestConsoleFormatter:
    def test_empty_findings_shows_safe(self):
        output = format_console(_result())
        assert "SAFE" in output
        assert "100" in output
        assert "0 findings" in output or "Summary" in output

    def test_findings_grouped_by_file(self):
        result = _result(
            findings=[
                _finding(file_path="SKILL.md", start_line=1),
                _finding(file_path="scripts/run.py", start_line=5),
                _finding(file_path="SKILL.md", start_line=10),
            ],
            risk_score=70,
            verdict="LOW RISK",
        )
        output = format_console(result)
        # Both SKILL.md findings should appear before scripts/run.py
        skill_pos = output.find("SKILL.md")
        scripts_pos = output.find("scripts/run.py")
        assert skill_pos < scripts_pos

    def test_severity_sorted_within_file(self):
        result = _result(
            findings=[
                _finding(severity=Severity.LOW, file_path="SKILL.md", start_line=10),
                _finding(severity=Severity.CRITICAL, file_path="SKILL.md", start_line=5),
            ],
            risk_score=39,
            verdict="HIGH RISK",
        )
        output = format_console(result)
        crit_pos = output.find("CRITICAL")
        low_pos = output.find("LOW")
        assert crit_pos < low_pos

    def test_summary_section_present(self):
        result = _result(
            findings=[_finding(severity=Severity.HIGH)],
            risk_score=59,
            verdict="LOW RISK",
        )
        output = format_console(result)
        assert "Summary" in output or "severity" in output.lower()

    def test_chain_cross_references_shown(self):
        comp = _finding(rule_id="D-7A", file_path="scripts/a.py", start_line=5)
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=[comp.id],
        )
        result = _result(
            findings=[comp, chain],
            risk_score=39,
            verdict="HIGH RISK",
        )
        output = format_console(result)
        assert "D-19A" in output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_formatters.py -x -q`
Expected: Failures (current formatter doesn't group by file)

- [ ] **Step 3: Implement the console formatter**

Rewrite `src/skillinquisitor/formatters/console.py`:

```python
"""Human-readable console output grouped by file, sorted by severity."""
from __future__ import annotations

from collections import defaultdict

from skillinquisitor.models import Finding, ScanResult, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def format_console(result: ScanResult, *, verbose: bool = False) -> str:
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append(f"  Verdict: {result.verdict}    Score: {result.risk_score}/100")
    skill_names = [s.name or s.path for s in result.skills]
    file_count = sum(len(s.artifacts) for s in result.skills)
    lines.append(f"  Scanned: {file_count} files in {', '.join(skill_names)}")
    lines.append("")

    if not result.findings:
        lines.append("  No findings.")
        lines.append("")
        return "\n".join(lines)

    # Build absorbed set for annotation
    absorbed_ids: set[str] = set()
    chain_map: dict[str, str] = {}  # absorbed_id -> chain rule_id
    for f in result.findings:
        if f.references:
            for ref_id in f.references:
                absorbed_ids.add(ref_id)
                chain_map[ref_id] = f.rule_id

    # Group findings by file
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[f.location.file_path].append(f)

    # Sort files, then sort findings within each file by severity
    for file_path in sorted(by_file.keys()):
        file_findings = sorted(
            by_file[file_path],
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.location.start_line or 0),
        )
        lines.append(f"  {file_path}")
        lines.append("")

        findings_by_id = {f.id: f for f in result.findings}
        for f in file_findings:
            sev = SEVERITY_LABELS.get(f.severity, f.severity.value.upper())
            line_num = f.location.start_line or 1
            lines.append(
                f"  {sev:<10}{f.rule_id:<8}{f.category.value:<22}{f.message:<50}:{line_num}"
            )

            # Show chain component references
            if f.references:
                ref_findings = [findings_by_id[r] for r in f.references if r in findings_by_id]
                for i, ref in enumerate(ref_findings):
                    connector = "└─" if i == len(ref_findings) - 1 else "├─"
                    ref_line = ref.location.start_line or 1
                    lines.append(
                        f"            {connector} {ref.rule_id} {ref.message} at {ref.location.file_path}:{ref_line}"
                    )

            # Show absorbed annotation
            if f.id in absorbed_ids:
                lines.append(f"            -> Absorbed by chain {chain_map[f.id]}")

            # Show suppression indicator
            if "SUPPRESSION_PRESENT" in f.action_flags:
                lines.append(f"            ! Suppression amplifier active")

        lines.append("")

    # Summary
    lines.append("  Summary")
    lines.append("")

    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    layer_counts: dict[str, int] = defaultdict(int)
    cat_counts: dict[str, int] = defaultdict(int)
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        layer_counts[f.layer.value] += 1
        cat_counts[f.category.value] += 1

    sev_parts = [f"{count} {SEVERITY_LABELS[s]}" for s, count in sev_counts.items()]
    lines.append(f"  By severity:  {', '.join(sev_parts)}")
    layer_parts = [f"{count} {layer}" for layer, count in sorted(layer_counts.items())]
    lines.append(f"  By layer:     {', '.join(layer_parts)}")
    cat_parts = [f"{count} {cat}" for cat, count in sorted(cat_counts.items())]
    lines.append(f"  By category:  {', '.join(cat_parts)}")
    lines.append("")

    if verbose:
        scoring_meta = result.layer_metadata.get("scoring", {})
        if isinstance(scoring_meta, dict) and scoring_meta:
            lines.append("  Scoring details")
            for key, value in scoring_meta.items():
                lines.append(f"    {key}: {value}")
            lines.append("")

    return "\n".join(lines)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_formatters.py -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/formatters/console.py tests/test_formatters.py
git commit -m "feat(console): implement grouped-by-file console formatter"
```

---

## Chunk 3: JSON and SARIF Formatters

### Task 5: Implement findings-focused JSON formatter

**Files:**
- Rewrite: `src/skillinquisitor/formatters/json.py`
- Modify: `tests/test_formatters.py`

- [ ] **Step 1: Write failing tests for JSON formatter**

Add to `tests/test_formatters.py`:

```python
from skillinquisitor.formatters.json import format_json


class TestJSONFormatter:
    def test_valid_json_output(self):
        output = format_json(_result())
        parsed = json.loads(output)
        assert parsed["verdict"] == "SAFE"
        assert parsed["risk_score"] == 100

    def test_includes_summary(self):
        result = _result(
            findings=[_finding(severity=Severity.HIGH)],
            risk_score=59,
            verdict="LOW RISK",
        )
        output = format_json(result)
        parsed = json.loads(output)
        assert "summary" in parsed
        assert parsed["summary"]["by_severity"]["high"] == 1

    def test_no_raw_content_in_output(self):
        result = _result()
        output = format_json(result)
        assert "raw_content" not in output
        assert "normalized_content" not in output
        assert "segments" not in output

    def test_skills_have_path_and_name_only(self):
        result = _result()
        parsed = json.loads(format_json(result))
        for skill in parsed["skills"]:
            assert set(skill.keys()) == {"path", "name"}

    def test_version_field_present(self):
        parsed = json.loads(format_json(_result()))
        assert parsed["version"] == "1.0"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_formatters.py::TestJSONFormatter -x -q`
Expected: Failures

- [ ] **Step 3: Implement the JSON formatter**

Rewrite `src/skillinquisitor/formatters/json.py`:

```python
"""Findings-focused JSON output. No raw file content for security."""
from __future__ import annotations

import json
from collections import defaultdict

from skillinquisitor.models import ScanResult


def format_json(result: ScanResult) -> str:
    sev_counts: dict[str, int] = defaultdict(int)
    layer_counts: dict[str, int] = defaultdict(int)
    cat_counts: dict[str, int] = defaultdict(int)
    for f in result.findings:
        sev_counts[f.severity.value] += 1
        layer_counts[f.layer.value] += 1
        cat_counts[f.category.value] += 1

    output = {
        "version": "1.0",
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "skills": [{"path": s.path, "name": s.name} for s in result.skills],
        "findings": [
            {
                "id": f.id,
                "severity": f.severity.value,
                "category": f.category.value,
                "layer": f.layer.value,
                "rule_id": f.rule_id,
                "message": f.message,
                "location": {
                    "file_path": f.location.file_path,
                    "start_line": f.location.start_line,
                    "end_line": f.location.end_line,
                    "start_col": f.location.start_col,
                    "end_col": f.location.end_col,
                },
                "confidence": f.confidence,
                "action_flags": f.action_flags,
                "references": f.references,
                "details": f.details,
            }
            for f in result.findings
        ],
        "summary": {
            "by_severity": dict(sev_counts),
            "by_layer": dict(layer_counts),
            "by_category": dict(cat_counts),
        },
        "layer_metadata": result.layer_metadata,
        "total_timing": result.total_timing,
    }
    return json.dumps(output, indent=2, default=str)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_formatters.py::TestJSONFormatter -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/formatters/json.py tests/test_formatters.py
git commit -m "feat(json): implement findings-focused JSON formatter"
```

### Task 6: Implement SARIF formatter

**Files:**
- Create: `src/skillinquisitor/formatters/sarif.py`
- Modify: `src/skillinquisitor/formatters/__init__.py`
- Modify: `tests/test_formatters.py`

- [ ] **Step 1: Write failing tests for SARIF formatter**

Add to `tests/test_formatters.py`:

```python
from skillinquisitor.formatters.sarif import format_sarif


class TestSARIFFormatter:
    def test_valid_sarif_structure(self):
        output = format_sarif(_result())
        parsed = json.loads(output)
        assert parsed["$schema"] == "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

    def test_tool_driver_info(self):
        parsed = json.loads(format_sarif(_result()))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "SkillInquisitor"

    def test_findings_map_to_results(self):
        result = _result(
            findings=[_finding(severity=Severity.HIGH, rule_id="D-10A")],
            risk_score=59,
            verdict="LOW RISK",
        )
        parsed = json.loads(format_sarif(result))
        results = parsed["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "D-10A"
        assert results[0]["level"] == "error"

    def test_severity_to_level_mapping(self):
        findings = [
            _finding(severity=Severity.CRITICAL, rule_id="R1"),
            _finding(severity=Severity.HIGH, rule_id="R2", start_line=2),
            _finding(severity=Severity.MEDIUM, rule_id="R3", start_line=3),
            _finding(severity=Severity.LOW, rule_id="R4", start_line=4),
            _finding(severity=Severity.INFO, rule_id="R5", start_line=5),
        ]
        result = _result(findings=findings, risk_score=20, verdict="HIGH RISK")
        parsed = json.loads(format_sarif(result))
        results = parsed["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in results}
        assert levels["R1"] == "error"
        assert levels["R2"] == "error"
        assert levels["R3"] == "warning"
        assert levels["R4"] == "note"
        assert levels["R5"] == "note"

    def test_chain_includes_related_locations(self):
        comp = _finding(
            rule_id="D-7A",
            file_path="scripts/a.py",
            start_line=15,
            message="Sensitive read",
        )
        chain = _finding(
            severity=Severity.CRITICAL,
            rule_id="D-19A",
            references=[comp.id],
            message="Data exfil chain",
        )
        result = _result(findings=[comp, chain], risk_score=39, verdict="HIGH RISK")
        parsed = json.loads(format_sarif(result))
        chain_result = [r for r in parsed["runs"][0]["results"] if r["ruleId"] == "D-19A"][0]
        assert "relatedLocations" in chain_result
        assert len(chain_result["relatedLocations"]) >= 1

    def test_rules_array_populated(self):
        result = _result(
            findings=[_finding(rule_id="D-11A")],
            risk_score=90,
            verdict="SAFE",
        )
        parsed = json.loads(format_sarif(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "D-11A"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_formatters.py::TestSARIFFormatter -x -q`
Expected: ImportError

- [ ] **Step 3: Implement SARIF formatter**

Create `src/skillinquisitor/formatters/sarif.py`:

```python
"""SARIF 2.1.0 output for GitHub Code Scanning and VS Code."""
from __future__ import annotations

import json

from skillinquisitor.models import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def format_sarif(result: ScanResult) -> str:
    findings_by_id = {f.id: f for f in result.findings}
    rule_ids_seen: set[str] = set()
    rules: list[dict] = []
    results: list[dict] = []

    for f in result.findings:
        if f.rule_id not in rule_ids_seen:
            rule_ids_seen.add(f.rule_id)
            rules.append(_build_rule(f))
        results.append(_build_result(f, findings_by_id))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillInquisitor",
                        "informationUri": "https://github.com/skillinquisitor/skillinquisitor",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "skillinquisitor": {
                                "verdict": result.verdict,
                                "risk_score": result.risk_score,
                            }
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)


def _build_rule(finding: Finding) -> dict:
    return {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.message},
        "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(finding.severity, "note")},
        "properties": {
            "skillinquisitor": {
                "category": finding.category.value,
                "severity": finding.severity.value,
            }
        },
    }


def _build_result(finding: Finding, findings_by_id: dict[str, Finding]) -> dict:
    result: dict = {
        "ruleId": finding.rule_id,
        "level": SEVERITY_TO_LEVEL.get(finding.severity, "note"),
        "message": {"text": finding.message},
        "locations": [_build_location(finding)],
        "properties": {
            "skillinquisitor": {
                "severity": finding.severity.value,
                "category": finding.category.value,
                "layer": finding.layer.value,
            }
        },
    }

    if finding.confidence is not None:
        result["rank"] = round(finding.confidence * 100, 1)

    if finding.action_flags:
        result["properties"]["skillinquisitor"]["action_flags"] = finding.action_flags

    if finding.details:
        result["properties"]["skillinquisitor"]["details"] = finding.details

    # Related locations for chain findings
    if finding.references:
        related = []
        for ref_id in finding.references:
            ref = findings_by_id.get(ref_id)
            if ref:
                related.append({
                    "id": len(related),
                    "message": {"text": f"{ref.rule_id}: {ref.message}"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": ref.location.file_path},
                        "region": _build_region(ref),
                    },
                })
        if related:
            result["relatedLocations"] = related

    return result


def _build_location(finding: Finding) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.location.file_path},
            "region": _build_region(finding),
        }
    }


def _build_region(finding: Finding) -> dict:
    region: dict = {}
    if finding.location.start_line is not None:
        region["startLine"] = finding.location.start_line
    if finding.location.end_line is not None:
        region["endLine"] = finding.location.end_line
    if finding.location.start_col is not None:
        region["startColumn"] = finding.location.start_col
    if finding.location.end_col is not None:
        region["endColumn"] = finding.location.end_col
    return region
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_formatters.py::TestSARIFFormatter -v`
Expected: All pass

- [ ] **Step 5: Wire SARIF into CLI**

In `src/skillinquisitor/cli.py`, update the format routing in the `scan` command:

```python
    if effective_config.default_format == "json":
        typer.echo(format_json(result))
    elif effective_config.default_format == "sarif":
        from skillinquisitor.formatters.sarif import format_sarif
        typer.echo(format_sarif(result))
    else:
        typer.echo(format_console(result, verbose=verbose))
```

- [ ] **Step 6: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/skillinquisitor/formatters/sarif.py src/skillinquisitor/formatters/__init__.py src/skillinquisitor/cli.py tests/test_formatters.py
git commit -m "feat(sarif): implement SARIF 2.1.0 formatter with relatedLocations for chains"
```

---

## Chunk 4: Integration, Docs, and Cleanup

### Task 7: Update docs and changelog

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `TODO.md`
- Modify: `docs/requirements/architecture.md` (update Epic 11 to reflect scope changes)
- Modify: `docs/requirements/business-requirements.md` (note deferred items)

- [ ] **Step 1: Update CHANGELOG.md with Epic 11 entry**

Add an Epic 11 section documenting: scoring engine, console/JSON/SARIF formatters, deferred items.

- [ ] **Step 2: Update README.md**

Add scoring algorithm summary, output format examples, SARIF integration info.

- [ ] **Step 3: Update TODO.md**

Check off Epic 11 tasks. Note deferred items (alerts, delta mode, remediation guidance).

- [ ] **Step 4: Update architecture.md**

Update Epic 11 section to reflect: webhook alerts moved to Epic 15, delta mode moved to Epic 15, actual algorithm implemented.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md README.md TODO.md docs/
git commit -m "docs: update docs for epic 11 risk scoring and formatters"
```

### Task 8: Final integration test

- [ ] **Step 1: Run the full regression suite**

Run: `./scripts/run-test-suite.sh`
Expected: All tests pass

- [ ] **Step 2: Run a manual CLI scan to verify output**

Run: `uv run skillinquisitor scan tests/fixtures/deterministic/secrets/D-19-read-send-chain`
Expected: Grouped-by-file console output with HIGH RISK verdict, chain cross-references, summary

Run: `uv run skillinquisitor scan tests/fixtures/safe/simple-formatter --format json`
Expected: Clean JSON with SAFE verdict, risk_score=100, no findings

Run: `uv run skillinquisitor scan tests/fixtures/deterministic/secrets/D-19-read-send-chain --format sarif`
Expected: Valid SARIF with relatedLocations on chain finding

- [ ] **Step 3: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: integration fixes for epic 11"
```
