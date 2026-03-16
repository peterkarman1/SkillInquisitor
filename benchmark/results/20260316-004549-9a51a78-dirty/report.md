# SkillInquisitor Benchmark Report

## Run Metadata

| Field | Value |
|---|---|
| Run ID | 20260316-004549-9a51a78-dirty |
| Git SHA | 9a51a78e60d4fdef5255a7156511d34a27f4c862-dirty |
| Timestamp | 2026-03-16T00:45:49.136667+00:00 |
| Dataset version | 1.0.0 |
| Layers | deterministic |
| Tier | smoke |
| Threshold | 60.0 |
| Wall clock | 1.4s |
| Total skills | 48 |

## Executive Summary

- **Precision**: 66.7%
- **Recall**: 78.3%
- **F1 Score**: 72.0%
- **TP**: 18  **FP**: 9  **TN**: 11  **FN**: 5
- **Ambiguous (excluded)**: 5
- **Weakest category**: behavioral (0.0% recall, 0/1)

## Confusion Matrix

|                  | Predicted Positive | Predicted Negative |
|------------------|-------------------:|-------------------:|
| Actually Positive|                 18 |                  5 |
| Actually Negative|                  9 |                 11 |

- Precision: 66.7%
- Recall: 78.3%
- F1: 72.0%
- FPR: 45.0%

### Ambiguous Distribution

| Verdict | Count |
|---|---:|
| LOW RISK | 1 |
| MEDIUM RISK | 1 |
| SAFE | 3 |

## Per-Category Detection Rates

| Category | Detected | Total | Recall | Bar |
|---|---:|---:|---:|---|
| behavioral | 0 | 1 | 0.0% | ░░░░░░░░░░ |
| cross_agent | 0 | 1 | 0.0% | ░░░░░░░░░░ |
| data_exfiltration | 2 | 5 | 40.0% | ████░░░░░░ |
| prompt_injection | 4 | 6 | 66.7% | ███████░░░ |
| obfuscation | 7 | 8 | 87.5% | █████████░ |
| credential_theft | 5 | 5 | 100.0% | ██████████ |
| persistence | 3 | 3 | 100.0% | ██████████ |
| steganography | 3 | 3 | 100.0% | ██████████ |
| supply_chain | 1 | 1 | 100.0% | ██████████ |
| suppression | 2 | 2 | 100.0% | ██████████ |

**Worst categories**: behavioral (0.0%), cross_agent (0.0%), data_exfiltration (40.0%)

## Performance

### Overall Latency

- p50: 20.1 ms
- p95: 466.9 ms
- p99: 792.2 ms
- Throughput: 13.24 skills/sec

### Top 5 Slowest Skills

| Skill | Total (ms) |
|---|---:|
| skill-0183 | 792.2 |
| skill-0180 | 562.1 |
| skill-0177 | 466.9 |
| skill-0181 | 308.1 |
| skill-0175 | 273.5 |

## Error Analysis

### False Negatives

**cross_agent** (1 missed)

- `skill-0039`

**obfuscation** (3 missed)

- `skill-0113`
- `skill-0114`
- `skill-0118`

**suppression** (1 missed)

- `skill-0023`

### False Positives

**D-10A** (1 false triggers)

- `skill-0182`

**D-13A** (1 false triggers)

- `skill-0176`

**D-14B** (1 false triggers)

- `skill-0174`

**D-15C** (1 false triggers)

- `skill-0055`

**D-15E** (2 false triggers)

- `skill-0177`
- `skill-0181`

**D-18C** (3 false triggers)

- `skill-0175`
- `skill-0180`
- `skill-0183`

### Top 10 Most Concerning Failures

| Skill | Ground Truth | Risk Score | Verdict |
|---|---|---:|---|
| skill-0175 | SAFE | 0 | CRITICAL |
| skill-0177 | SAFE | 0 | CRITICAL |
| skill-0183 | SAFE | 0 | CRITICAL |
| skill-0118 | MALICIOUS | 78 | LOW RISK |
| skill-0023 | MALICIOUS | 71 | LOW RISK |
| skill-0181 | SAFE | 20 | HIGH RISK |
| skill-0182 | SAFE | 28 | HIGH RISK |
| skill-0174 | SAFE | 36 | HIGH RISK |
| skill-0113 | MALICIOUS | 85 | SAFE |
| skill-0114 | MALICIOUS | 85 | SAFE |

