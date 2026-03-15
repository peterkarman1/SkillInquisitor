# Epic 11 — Risk Scoring & Output Formatters Design

**Date:** 2026-03-15
**Status:** Approved
**Epic:** 11
**Scope:** Risk scoring engine, console formatter, JSON formatter, SARIF formatter
**Out of scope (moved to Epic 15):** Webhook alerts, delta/baseline mode, remediation guidance

---

## 1. Scoring Algorithm

### Overview

"Subtractive with Diminishing Returns, Confidence Weighting, and Severity Floors"

The algorithm starts at 100 and deducts points per finding. It incorporates five modifiers that interact in a defined order: chain absorption, cross-layer dedup, LLM adjustment, diminishing returns within severity tiers, and suppression amplification. Severity floors ensure that undisputed CRITICAL or HIGH findings produce appropriately severe verdicts.

### Algorithm Steps

```
 1. Start score = 100
 2. Chain absorption: mark component findings (referenced by chain findings) as absorbed
 3. Cross-layer dedup: when multiple layers flag the same issue (matched by segment_id
    and overlapping category), keep a single effective finding at the max confidence
 4. LLM adjustment:
    a. Disputed findings: multiply effective confidence by (1 - dispute_factor * dispute_confidence)
       Default dispute_factor = 0.5. A strong dispute (conf=0.90) reduces a finding's
       effective confidence from 1.0 to 0.55.
    b. Confirmed findings: multiply effective deduction by (1 + confirm_factor * confirm_confidence)
       Default confirm_factor = 0.15.
    c. A disputed finding no longer triggers its original severity floor.
 5. Build the effective findings list (excluding absorbed findings)
 6. Group effective findings by severity tier
 7. Within each tier, sort by confidence descending, then compute deductions:
      deduction_n = severity_weight * effective_confidence * decay_factor^(position_in_tier)
      Default decay_factor = 0.7
 8. Suppression amplifier: if any finding has SUPPRESSION_PRESENT in action_flags,
    multiply all non-suppression deductions by suppression_multiplier (default 1.5)
 9. Sum all deductions, subtract from 100, clamp to [0, 100]
10. Severity floors: if worst undisputed finding is CRITICAL and score > 39, set score = 39
                     if worst undisputed finding is HIGH and score > 59, set score = 59
11. Map score to verdict
```

### Verdict Mapping

| Score   | Verdict     | Exit Code |
|---------|-------------|-----------|
| 80-100  | SAFE        | 0         |
| 60-79   | LOW RISK    | 1         |
| 40-59   | MEDIUM RISK | 1         |
| 20-39   | HIGH RISK   | 1         |
| 0-19    | CRITICAL    | 1         |

### Config Additions

New fields on `ScoringConfig`:

```python
decay_factor: float = 0.7
severity_floors: dict[str, int] = {"critical": 39, "high": 59}
llm_dispute_factor: float = 0.5
llm_confirm_factor: float = 0.15
```

### Key Scenarios

| Scenario | Expected Score | Expected Verdict |
|----------|---------------|-----------------|
| 0 findings | 100 | SAFE |
| 1 LOW finding | 95 | SAFE |
| D-19A chain (CRITICAL) absorbing D-7A + D-9A | 70 raw, floored to 39 | HIGH RISK |
| D-12 suppression + D-7A sensitive read | ~75 raw, amplified + HIGH floor → ≤59 | MEDIUM RISK |
| D-11 deterministic + ML injection same segment | ~80 (single deduction, higher conf) | SAFE |
| D-19A (CRITICAL) + LLM disputes (conf=0.90) | ~84 (floor lifted) | SAFE |
| 20 LOW findings | ~84 (diminishing returns) | SAFE |

---

## 2. Console Formatter

### Layout: Grouped by File, Sorted by Severity

```
═══════════════════════════════════════════════════════
  SkillInquisitor Scan Results
═══════════════════════════════════════════════════════

  Verdict: HIGH RISK    Score: 34/100
  Scanned: 3 files in skill "data-helper"

───────────────────────────────────────────────────────
  SKILL.md
───────────────────────────────────────────────────────
  CRITICAL  D-19A  data_exfiltration  Behavior chain: Data Exfiltration            :1
            ├─ D-7A sensitive read at scripts/helper.py:15
            └─ D-9A network send at scripts/helper.py:42

  MEDIUM    D-12A  suppression        Suppression directive: concealment            :23
            ⚠ Suppression amplifier active

  MEDIUM    D-11A  prompt_injection    Instruction override pattern detected         :8

───────────────────────────────────────────────────────
  scripts/helper.py
───────────────────────────────────────────────────────
  MEDIUM    D-7A   credential_theft   Sensitive file path reference detected        :15
            → Absorbed by chain D-19A

  MEDIUM    D-9A   data_exfiltration  Outbound network send behavior detected       :42
            → Absorbed by chain D-19A

═══════════════════════════════════════════════════════
  Summary
═══════════════════════════════════════════════════════
  By severity:  1 CRITICAL  0 HIGH  3 MEDIUM  0 LOW  0 INFO
  By layer:     5 deterministic  0 ml  0 llm
  By category:  2 data_exfiltration  1 credential_theft  1 suppression  1 prompt_injection
```

### Modes

- **Default**: As shown above.
- **`--quiet`**: No output, exit code only.
- **`--verbose`**: Adds per-model ML scores, LLM disposition/evidence, provenance chains on derived-segment findings, per-layer timing, effective config summary, suppression amplifier status.

---

## 3. JSON Formatter

### Findings-Focused (No Raw Content)

The JSON output is the machine API contract for Epic 13. It excludes raw file contents for security (prevents malicious payloads traveling through JSON to LLM consumers) and for size.

```json
{
  "version": "1.0",
  "verdict": "HIGH RISK",
  "risk_score": 34,
  "skills": [
    {"path": "/path/to/skill", "name": "data-helper"}
  ],
  "findings": [
    {
      "id": "uuid",
      "severity": "critical",
      "category": "data_exfiltration",
      "layer": "deterministic",
      "rule_id": "D-19A",
      "message": "Behavior chain detected: Data Exfiltration",
      "location": {"file_path": "SKILL.md", "start_line": 1, "end_line": 1},
      "confidence": 1.0,
      "action_flags": [],
      "references": ["uuid-d7a", "uuid-d9a"],
      "details": {}
    }
  ],
  "summary": {
    "by_severity": {"critical": 1, "high": 0, "medium": 3, "low": 0, "info": 0},
    "by_layer": {"deterministic": 5, "ml_ensemble": 0, "llm_analysis": 0},
    "by_category": {"data_exfiltration": 2}
  },
  "layer_metadata": {},
  "total_timing": 1.23
}
```

Skills list includes `path` and `name` only — no artifacts, segments, or content.

---

## 4. SARIF Formatter

### SARIF 2.1.0 Compliance

Key mappings:
- **tool.driver.name**: `"SkillInquisitor"`
- **tool.driver.rules**: Built from unique rule_ids in findings, with id, shortDescription, defaultConfiguration.level, and properties (category, family_id)
- **Severity → SARIF level**: CRITICAL/HIGH → `"error"`, MEDIUM → `"warning"`, LOW/INFO → `"note"`
- **Finding → result**: Maps rule_id, level, message, physicalLocation (file_path, region with startLine/endLine/startColumn/endColumn)
- **confidence → rank**: `confidence * 100` (for spec compliance)
- **Chain findings**: Include `relatedLocations` pointing to component findings via `references`
- **ML/LLM details**: Go in `result.properties.skillinquisitor` namespace
- **Exact severity**: Preserved in `properties.skillinquisitor.severity`

---

## 5. Pipeline Integration

`scoring.py` is called by `pipeline.py` after all three layers complete. It receives the full findings list and the `ScanConfig`, and returns a `ScoredResult` containing `risk_score`, `verdict`, and a `scoring_details` dict for verbose output.

The pipeline passes `ScoredResult` values into `ScanResult` before handing to formatters.

---

## 6. Exit Code Logic

After scoring:
- `--quiet` with score >= 80 (SAFE): exit 0
- `--quiet` with score < 80: exit 1
- Normal mode: exit 0 if verdict == "SAFE", else exit 1
- Scan error: exit 2
