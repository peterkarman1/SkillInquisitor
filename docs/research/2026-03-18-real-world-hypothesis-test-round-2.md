# Real-World Hypothesis Test Round 2

Date: 2026-03-18

Baseline corpus:

- real-world-only benchmark
- 92 skills total
- 43 safe GitHub skills
- 49 malicious real-world skills

Baseline run:

- source: `benchmark/results/real-world-standard-20260318a`
- precision: `56.2%`
- recall: `36.7%`
- F1: `44.4%`
- confusion matrix: `TP=18 FP=14 TN=29 FN=31`

This round tested five distinct hypotheses against that saved result set and the current benchmark corpus. The goal was not to bless a final fix yet, but to find the highest-leverage directions before changing the scanner.

## H1. Lower The Binary Cutoff To `MEDIUM`

Hypothesis:

- The current `HIGH` binary cutoff is too strict for the real-world corpus.
- Many real malicious skills already land in `MEDIUM`, so treating `MEDIUM` as malicious should improve binary performance immediately.

Test:

- Offline replay over `benchmark/results/real-world-standard-20260318a/results.jsonl`
- Prediction rule: malicious if `risk_label in {MEDIUM, HIGH, CRITICAL}`

Result:

- precision: `51.8%`
- recall: `59.2%`
- F1: `55.2%`
- confusion matrix: `TP=29 FP=27 TN=16 FN=20`

Read:

- This is a strong lift over baseline for almost no engineering cost.
- It confirms that the current label policy is leaving real malicious skills on the floor.
- It is not sufficient on its own because false positives jump sharply.

## H2. Promote Dangerous `MEDIUM+` Evidence

Hypothesis:

- We are already detecting dangerous evidence but failing to promote it.
- Any `MEDIUM+` finding in a dangerous category should count as malicious evidence.

Replay rule:

- Mark malicious if any finding has:
  - category in `credential_theft`, `data_exfiltration`, `behavioral`, `prompt_injection`, `persistence`, `cross_agent`, `jailbreak`
  - and severity in `medium`, `high`, or `critical`
- Also always promote these explicit high-signal rules:
  - `D-19A`
  - `D-19B`
  - `D-19C`
  - `D-11A`
  - `D-11C`
  - `D-11D`

Result:

- precision: `53.7%`
- recall: `73.5%`
- F1: `62.1%`
- confusion matrix: `TP=36 FP=31 TN=12 FN=13`

Read:

- This was the strongest single hypothesis in the round.
- It supports the idea that the current main bottleneck is adjudication policy, not total detector failure.
- It should be implemented with guardrails, because the FP cost is real.

## H3. Context-Aware Downgrading For Documentation Noise

Hypothesis:

- Many false positives come from broad rules firing on README/reference/example content.
- Downgrading those rule clusters in documentation-heavy contexts should improve precision.

Replay rule:

- Start from H2.
- If all triggered rules for a skill are inside this doc-noise set, downgrade to not malicious:
  - `D-15E`
  - `D-14C`
  - `D-22A`
  - `NC-3A`
  - `D-5A`
  - `D-17A`
  - `D-18A`
  - `D-14B`
  - `ML-PI`
- Do not downgrade if any stronger dangerous categories are present.

Result:

- precision: `51.6%`
- recall: `65.3%`
- F1: `57.7%`
- confusion matrix: `TP=32 FP=30 TN=13 FN=17`

Read:

- This helped compared to baseline, but it was worse than H2 alone.
- The lesson is that naive “doc noise” suppression throws away too many real malicious skills.
- Context-aware downgrading is still worth exploring, but it must use file role and instruction/execution context, not only rule IDs.

## H4. Expanded Secret-Handling Detector Prototype

Hypothesis:

- Real-world misses include secret files and credential materials that the current rules do not model well enough.
- A broader secret detector should recover real malicious skills, especially in credential theft and exfiltration cases.

Prototype:

- Corpus-wide regex sweep over all 92 benchmark skills
- Signals included:
  - secret-like file references such as `secrets`, `credentials`, `tokens`, `keys`, `.env`
  - secret materials such as `api_key`, `access_token`, `bearer`, `client_secret`, `password`, `recovery key`
  - paired with read/use verbs or outbound-send verbs

Best tested combination:

- `baseline OR secret_prototype`

Result:

- precision: `50.0%`
- recall: `53.1%`
- F1: `51.5%`
- confusion matrix: `TP=26 FP=26 TN=17 FN=23`

Read:

- This is a real improvement over baseline, so the gap is not imaginary.
- The prototype is still too broad and drags in too many safe skills.
- The important takeaway is that broader credential-material coverage is probably necessary, but it must be paired with better context and chaining.

## H5. Reference-Aware Chain / Bootstrap Prototype

Hypothesis:

- Current chain logic is too same-file and proximity-biased for real-world skill layouts.
- A prototype that notices secret references, external sends, or out-of-tree bootstrap execution should recover many real malicious skills.

Prototype:

- Corpus-wide sweep over all 92 benchmark skills
- Signals included:
  - `SKILL.md` references to secret/config files paired with any external send signal anywhere in the skill
  - out-of-tree or vendor-controlled path execution
  - remote/bootstrap/install behaviors such as `curl | bash`, `wget | bash`, prerelease `npx`, or setup hooks

Best tested combination:

- `baseline OR reference_chain_prototype`

Result:

- precision: `52.2%`
- recall: `71.4%`
- F1: `60.3%`
- confusion matrix: `TP=35 FP=32 TN=11 FN=14`

Read:

- This was the second strongest result in the round.
- It strongly suggests that cross-file reference resolution and bootstrap/install detection are high-value missing capabilities.
- This path looks especially promising because it directly targets the weak real-world categories: supply chain, credential theft, and exfiltration.

## Ranking

1. `H2 Dangerous Medium Promotion` -> `62.1% F1`
2. `H5 Reference-Aware Chain / Bootstrap Prototype` -> `60.3% F1`
3. `H3 Context-Aware Downgrading` -> `57.7% F1`
4. `H1 Medium Cutoff` -> `55.2% F1`
5. `H4 Expanded Secret Detector` -> `51.5% F1`

## Current Read

The best near-term path looks like a hybrid of two ideas:

- implement dangerous-category promotion in adjudication
- add real reference-aware chain and bootstrap detection so more malicious skills reach that promotion path with the right categories

The failed or weaker experiments matter too:

- lowering the binary cutoff helps, but it is too blunt
- doc-noise downgrading cannot be done with crude rule-ID suppression
- broader secret detection helps, but only when paired with context/chaining

## Recommended Next Step

Implement these in this order:

1. dangerous-category promotion in `adjudication.py`
2. reference-aware chain/bootstrap detection in deterministic rules
3. broader secret-source and credential-material coverage
4. only then revisit context-aware FP downgrading with file-role awareness
