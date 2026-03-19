# Malicious Skill Detection Research: Five Hypotheses

Date: 2026-03-18

## Purpose

This note answers a focused question:

How should SkillInquisitor change if the goal is to catch more malicious skills without simply turning every security-adjacent skill into a false positive?

I approached this in three steps:

1. Review current external research on malicious skills, prompt injection, and agent tool misuse.
2. Map that research onto SkillInquisitor's current architecture and latest benchmark behavior.
3. Test five concrete detection hypotheses against the scanner's current evidence stream.

## External Research Takeaways

The outside literature is fairly consistent about what "malicious skill" attacks look like.

- The largest skill-at-scale study I found reports that 26.1% of skills contain at least one vulnerability, with data exfiltration and privilege escalation leading the pack, and executable-script skills being 2.12x more likely to be vulnerable than instruction-only skills. Source: [Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale](https://arxiv.org/abs/2601.10338)
- Indirect prompt injection work shows that retrieved content can blur the line between data and instructions, allowing hostile content to remotely steer tools, API calls, and data exposure. Source: [Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://i.blackhat.com/BH-US-23/Presentations/US-23-Greshake-Not-what-youve-signed-up-for-whitepaper.pdf)
- OpenAI's Operator system card explicitly calls out prompt injection on third-party content as a primary risk for agentic systems and recommends layered safety checks plus isolation and monitoring. Source: [Operator System Card](https://cdn.openai.com/operator_system_card.pdf)
- MCP's own prompt documentation includes prompt injection in its security considerations, which reinforces that any reusable instruction bundle should be treated as potentially adversarial content. Source: [Model Context Protocol Prompts](https://modelcontextprotocol.io/legacy/concepts/prompts)
- Recent defense work like IPIGuard argues that prompt-only defenses are not enough; structure matters, especially tool and dependency relationships. Source: [IPIGuard](https://arxiv.org/abs/2508.15310)

From those sources, the dominant malicious-skill archetypes are:

- Instruction hijackers: prompt injection, delimiter mimicry, hidden text, stealth directives, skill description abuse
- Data thieves: read secrets, collect files, send externally, dynamically execute payloads, persistence for repeat access
- Security-adjacent but benign skills: defensive/security workflows that contain many dangerous-looking examples and code snippets without actually being malware

That last class matters because it matches the scanner's current false-positive profile very closely.

## Current SkillInquisitor Read

The present pipeline is:

1. Normalization and derived segment extraction
2. Deterministic rules
3. ML prompt-injection ensemble
4. Targeted/general/repo LLM analysis
5. Final risk labeling via heuristic + optional final adjudication

Relevant implementation anchors:

- [pipeline.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/pipeline.py)
- [adjudication.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/adjudication.py)
- [behavioral.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/detectors/rules/behavioral.py)
- [injection.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/detectors/rules/injection.py)
- [judge.py](/Users/peterkarman/git/SkillInquisitor/src/skillinquisitor/detectors/llm/judge.py)

The most useful current benchmark artifact for replay experiments is:

- [standard-primary-balanced-20260317a/summary.json](/Users/peterkarman/git/SkillInquisitor/benchmark/results/standard-primary-balanced-20260317a/summary.json)
- [standard-primary-balanced-20260317a/results.jsonl](/Users/peterkarman/git/SkillInquisitor/benchmark/results/standard-primary-balanced-20260317a/results.jsonl)

That run uses the current full stack on the curated `primary` dataset profile:

- 153 total skills
- 89 malicious
- 64 safe
- current baseline: precision 75.9%, recall 49.4%, F1 59.9%

I also broke out the `real_only` subset inside that same run:

- 92 total skills
- 49 malicious
- 43 safe
- current baseline there is materially worse: precision 56.2%, recall 36.7%, F1 44.4%

## What The Current Misses Look Like

False negatives are concentrated in:

- `prompt_injection`
- `behavioral`
- `credential_theft`
- `data_exfiltration`

False positives are dominated by:

- `D-15E` unknown external host
- `D-12C` output suppression
- `D-10A` dynamic execution
- `ML-PI`
- `D-22A` code-fence content

Those patterns strongly suggest:

- recall is being lost because medium-severity malicious primitives are not being promoted soon enough
- precision is being lost because security-adjacent documentation and examples are being over-trusted as executable intent

Representative false-negative fixtures:

- [skill-0127](/Users/peterkarman/git/SkillInquisitor/benchmark/dataset/skills/skill-0127/SKILL.md): "Execute generated code."
- [skill-0133](/Users/peterkarman/git/SkillInquisitor/benchmark/dataset/skills/skill-0133/SKILL.md): "Inspect environment variables for debugging."
- [skill-0135](/Users/peterkarman/git/SkillInquisitor/benchmark/dataset/skills/skill-0135/SKILL.md): "Post captured output to a remote endpoint."

Representative false-positive safe skill:

- [skill-0194](/Users/peterkarman/git/SkillInquisitor/benchmark/dataset/skills/skill-0194/SKILL.md)

That safe skill contains lots of dangerous-looking instructional content and examples, which is exactly the kind of artifact a malicious-skill detector must learn to separate from actual hostile intent.

## Experimental Method

These experiments are not fresh rescans. They are policy replays over the current benchmark evidence stream in:

- [results.jsonl](/Users/peterkarman/git/SkillInquisitor/benchmark/results/standard-primary-balanced-20260317a/results.jsonl)

That means each test answers this narrower question:

If we changed how the scanner interprets its current findings, would classification improve?

This is still useful, because it isolates whether our next bottleneck is:

- evidence generation
- or final policy/adjudication

## The Five Hypotheses

### H1. Medium Cutoff

Hypothesis:
Treat `MEDIUM`, `HIGH`, and `CRITICAL` as malicious instead of only `HIGH` and `CRITICAL`.

Why:
Many malicious skills only surface one or two medium-strength signals.

Result:

- `primary`: precision 63.4%, recall 66.3%, F1 64.8%
- `real_only`: precision 51.8%, recall 59.2%, F1 55.2%

Read:
This helps recall immediately, but it pays for it with too many safe skills crossing the line.

### H2. Dangerous-Category Promotion

Hypothesis:
Any medium-or-higher finding in a dangerous category should count as malicious evidence, even if the current final label stayed below `HIGH`.

Dangerous categories used in the replay:

- `credential_theft`
- `data_exfiltration`
- `behavioral`
- `prompt_injection`
- `persistence`
- `cross_agent`
- `jailbreak`

Also always promote explicit high-signal rules:

- `D-19A`
- `D-19B`
- `D-19C`
- `D-11A`
- `D-11C`
- `D-11D`

Result:

- `primary`: precision 63.1%, recall 73.0%, F1 67.7%
- `real_only`: precision 53.7%, recall 73.5%, F1 62.1%

Read:
This was the strongest single change. It says our current bottleneck is not "we found nothing", but "we found something dangerous and then failed to promote it."

### H3. Prompt/Steganography Early Promotion

Hypothesis:
Prompt injection and steganography should need less corroboration than generic behavioral evidence because they often *are* the attack.

Replay rule:

- if prompt injection or steganography is present, treat `MEDIUM+` as malicious
- otherwise keep the existing `HIGH+` threshold

Result:

- `primary`: precision 62.9%, recall 62.9%, F1 62.9%
- `real_only`: precision 51.9%, recall 57.1%, F1 54.4%

Read:
This helps, but not enough. It likely captures real content-based attacks, but too narrowly to fix the overall recall gap.

### H4. Doc-Like Quarantine

Hypothesis:
Structural, suppression, obfuscation, and steganography findings that appear without stronger corroboration should not be allowed to drive a malicious verdict on their own.

Why:
The biggest false positives look like "security education skills that discuss dangerous things."

Replay rule:

- block malicious classification when evidence is only doc-like families
- unless explicit override/chain rules are present

Result:

- `primary`: precision 75.0%, recall 47.2%, F1 57.9%
- `real_only`: precision 56.2%, recall 36.7%, F1 44.4%

Read:
This did not help. The current false positives are not merely "structural-only"; many safe skills already trip dangerous categories because examples and scripts are being interpreted as live hostile behavior.

### H5. Pairwise Primitive Corroboration

Hypothesis:
Instead of using accumulated score, only classify as malicious when at least one dangerous pair is present, for example:

- secret read + external send
- prompt injection + suppression
- behavioral + data/credential theft
- steganography + behavioral or prompt injection

Result:

- `primary`: precision 55.0%, recall 24.7%, F1 34.1%
- `real_only`: precision 43.8%, recall 28.6%, F1 34.6%

Read:
This was clearly too strict. It misses too many real malicious skills that expose only one high-signal primitive.

## Best Combined Variant

I also tested one combined replay policy that stacks the two most promising ideas:

- promote medium-or-higher dangerous categories
- separately allow `MEDIUM+` promotion for prompt injection and steganography
- always promote explicit injection override and behavior-chain rules

Result:

- `primary`: precision 64.5%, recall 77.5%, F1 70.4%
- `real_only`: precision 53.7%, recall 73.5%, F1 62.1%

This is meaningfully better than the current baseline on the same evidence stream:

| Policy | Primary Precision | Primary Recall | Primary F1 | Real-Only Precision | Real-Only Recall | Real-Only F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Current `HIGH+` | 75.9% | 49.4% | 59.9% | 56.2% | 36.7% | 44.4% |
| H1 Medium cutoff | 63.4% | 66.3% | 64.8% | 51.8% | 59.2% | 55.2% |
| H2 Dangerous-category promotion | 63.1% | 73.0% | 67.7% | 53.7% | 73.5% | 62.1% |
| H3 Prompt/steg early promotion | 62.9% | 62.9% | 62.9% | 51.9% | 57.1% | 54.4% |
| H4 Doc-like quarantine | 75.0% | 47.2% | 57.9% | 56.2% | 36.7% | 44.4% |
| H5 Pairwise corroboration | 55.0% | 24.7% | 34.1% | 43.8% | 28.6% | 34.6% |
| Best combined variant | 64.5% | 77.5% | 70.4% | 53.7% | 73.5% | 62.1% |

## What I Believe Now

### 1. The main near-term problem is policy, not raw evidence generation

The replay experiments improved F1 materially without changing the underlying findings at all.

That means the scanner is already surfacing a lot of useful evidence, but the final interpretation layer is too conservative about malicious intent when the evidence is medium-severity but semantically dangerous.

### 2. Medium-strength dangerous evidence needs promotion

The current decision path over-discounts:

- prompt injection
- credential access
- outbound send behavior
- dynamic execution
- cross-agent control

In real malicious skills, those are often the whole attack.

### 3. False positives are more about example attribution than about score thresholds

The doc-like quarantine hypothesis failed because many safe skills are not "structural only"; they are security and tooling skills with dangerous examples that currently look semantically live.

That points toward a different next step:

- better example/code-fence attribution
- better segment intent typing
- better distinction between "describing" and "instructing"

### 4. Chain-only thinking is too strict

The pairwise-only approach collapsed recall. A malicious skill does not need to present a full source-to-sink chain in one artifact to be dangerous enough to block.

## Recommended Next Build Steps

If the goal is to improve the actual product rather than just the replay score, I would prioritize:

1. Implement dangerous-category promotion in the real adjudication layer.
2. Add example-aware evidence typing so code fences, samples, and quoted attack strings do not count the same as executable instructions.
3. Lower the corroboration bar specifically for prompt injection, data exfiltration, credential theft, and dynamic execution when they appear in instruction-bearing segments.
4. Split "security-adjacent educational content" from "operational instructions" using segment role metadata, not just raw token matching.
5. Re-run smoke and standard on `primary` and `real_only` after the policy change, because the replay results suggest there is real headroom before touching new models.

## Bottom Line

The strongest result from this pass is simple:

SkillInquisitor is probably missing more malicious skills because it is under-promoting dangerous medium-strength evidence than because it lacks detectors entirely.

The biggest next opportunity is not "add another model first." It is:

- promote dangerous categories earlier
- stop treating security examples like live intent
- then measure again
