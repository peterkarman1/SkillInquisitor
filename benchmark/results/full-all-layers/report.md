# SkillInquisitor Benchmark Report

## Run Metadata

| Field | Value |
|---|---|
| Run ID | 20260316-011602-4bb392b-dirty |
| Git SHA | 4bb392b1f157a0cd5b90d65d9da5ff4a6a010097-dirty |
| Timestamp | 2026-03-16T01:16:02.426409+00:00 |
| Dataset version | 1.0.0 |
| Layers | deterministic, ml, llm |
| Tier | full |
| Threshold | 60.0 |
| Wall clock | 13m 33s |
| Total skills | 266 |

## Executive Summary

- **Precision**: 66.9%
- **Recall**: 86.4%
- **F1 Score**: 75.4%
- **TP**: 121  **FP**: 60  **TN**: 35  **FN**: 19
- **Ambiguous (excluded)**: 31
- **Weakest category**: data_exfiltration (30.6% recall, 11/36)

## Confusion Matrix

|                  | Predicted Positive | Predicted Negative |
|------------------|-------------------:|-------------------:|
| Actually Positive|                121 |                 19 |
| Actually Negative|                 60 |                 35 |

- Precision: 66.9%
- Recall: 86.4%
- F1: 75.4%
- FPR: 63.2%

### Ambiguous Distribution

| Verdict | Count |
|---|---:|
| LOW RISK | 1 |
| MEDIUM RISK | 15 |
| SAFE | 15 |

## Per-Category Detection Rates

| Category | Detected | Total | Recall | Bar |
|---|---:|---:|---:|---|
| data_exfiltration | 11 | 36 | 30.6% | ███░░░░░░░ |
| credential_theft | 16 | 35 | 45.7% | █████░░░░░ |
| cross_agent | 2 | 4 | 50.0% | █████░░░░░ |
| supply_chain | 3 | 6 | 50.0% | █████░░░░░ |
| behavioral | 19 | 34 | 55.9% | ██████░░░░ |
| obfuscation | 16 | 25 | 64.0% | ██████░░░░ |
| suppression | 4 | 6 | 66.7% | ███████░░░ |
| persistence | 10 | 14 | 71.4% | ███████░░░ |
| steganography | 12 | 16 | 75.0% | ████████░░ |
| structural | 7 | 9 | 77.8% | ████████░░ |
| prompt_injection | 50 | 53 | 94.3% | █████████░ |
| jailbreak | 1 | 1 | 100.0% | ██████████ |

**Worst categories**: data_exfiltration (30.6%), credential_theft (45.7%), cross_agent (50.0%)

## Performance

### Overall Latency

- p50: 2624.8 ms
- p95: 6311.6 ms
- p99: 10705.6 ms
- Throughput: 0.33 skills/sec

### Top 5 Slowest Skills

| Skill | Total (ms) |
|---|---:|
| skill-0206 | 12217.0 |
| skill-0184 | 11292.4 |
| skill-0183 | 10705.6 |
| skill-0188 | 9573.9 |
| skill-0260 | 9252.8 |

## Error Analysis

### False Negatives

**behavioral** (6 missed)

- `skill-0006`
- `skill-0146`
- `skill-0207` — Real-world malicious skill. Patterns: External Transmission; Remote Code Execution; Behavior Manipulation
- ... and 3 more

**credential_theft** (3 missed)

- `skill-0133`
- `skill-0215` — Real-world malicious skill. Patterns: Context Leakage; Data Exfiltration; Network sniffing / Credential theft
- `skill-0224` — Real-world malicious skill. Patterns: Network sniffing / Credential theft

**data_exfiltration** (5 missed)

- `skill-0038`
- `skill-0044`
- `skill-0135`
- ... and 2 more

**obfuscation** (1 missed)

- `skill-0006`

**persistence** (1 missed)

- `skill-0038`

**prompt_injection** (4 missed)

- `skill-0020`
- `skill-0044`
- `skill-0207` — Real-world malicious skill. Patterns: External Transmission; Remote Code Execution; Behavior Manipulation
- ... and 1 more

**structural** (5 missed)

- `skill-0028`
- `skill-0029`
- `skill-0139`
- ... and 2 more

**suppression** (1 missed)

- `skill-0124`

### False Positives

**D-10A** (5 false triggers)

- `skill-0058`
- `skill-0061`
- `skill-0075`
- ... and 2 more

**D-11A** (1 false triggers)

- `skill-0057`

**D-13A** (3 false triggers)

- `skill-0176`
- `skill-0201`
- `skill-0261`

**D-13C** (1 false triggers)

- `skill-0203`

**D-14B** (1 false triggers)

- `skill-0174`

**D-14C** (17 false triggers)

- `skill-0056`
- `skill-0059`
- `skill-0066`
- ... and 14 more

**D-15C** (1 false triggers)

- `skill-0055`

**D-15E** (4 false triggers)

- `skill-0177`
- `skill-0181`
- `skill-0190`
- ... and 1 more

**D-15G** (6 false triggers)

- `skill-0189`
- `skill-0191`
- `skill-0192`
- ... and 3 more

**D-18C** (16 false triggers)

- `skill-0175`
- `skill-0179`
- `skill-0180`
- ... and 13 more

**D-19A** (1 false triggers)

- `skill-0187`

**D-22A** (1 false triggers)

- `skill-0069`

**D-7A** (1 false triggers)

- `skill-0053`

**D-7B** (1 false triggers)

- `skill-0052`

**D-8A** (1 false triggers)

- `skill-0051`

### Top 10 Most Concerning Failures

| Skill | Ground Truth | Risk Score | Verdict |
|---|---|---:|---|
| skill-0215 | MALICIOUS | 71 | LOW RISK |
| skill-0006 | MALICIOUS | 70 | LOW RISK |
| skill-0038 | MALICIOUS | 70 | LOW RISK |
| skill-0044 | MALICIOUS | 77 | LOW RISK |
| skill-0175 | SAFE | 0 | CRITICAL |
| skill-0176 | SAFE | 0 | CRITICAL |
| skill-0177 | SAFE | 0 | CRITICAL |
| skill-0179 | SAFE | 0 | CRITICAL |
| skill-0180 | SAFE | 0 | CRITICAL |
| skill-0181 | SAFE | 0 | CRITICAL |

