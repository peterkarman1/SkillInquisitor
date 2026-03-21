# Real Malicious Skill Sources

Date: 2026-03-19

## Goal

Identify trustworthy, real-world malicious skill sources we can use to rebuild the benchmark corpus without relying on synthetic samples.

## Bottom Line

There are three strong starting points for a real malicious corpus:

1. `yoonholee/agent-skill-malware` on Hugging Face
2. `openclaw/skills` GitHub archive
3. The corpus described in arXiv `2602.06547`, collected from `skills.rest` and `skillsmp.com`

The first source is immediately ingestible. The second is the best provenance anchor for ClawHub/OpenClaw samples. The third is the best guide for expanding beyond the ClawHub/OpenClaw malware family into broader real-world agent-skill attacks.

## Primary Sources

### 1. Hugging Face: `yoonholee/agent-skill-malware`

Source:
- [Dataset card](https://huggingface.co/datasets/yoonholee/agent-skill-malware)

What it contains:
- dataset card says `127` malicious samples
- current downloadable `skills.jsonl` contains `124` malicious samples
- `223` benign samples
- current downloadable total: `347` samples
- `skills.jsonl` with `skill_name`, full `SKILL.md` `content`, and binary `label`

Why it matters:
- The dataset card says the malicious samples are "real skills from malicious campaigns targeting ClawHub (Feb 2026)"
- It explicitly says they were extracted from the public `openclaw/skills` archive
- It preserves real SKILL.md content, not synthetic rewrites

Most common malicious infrastructure in the dataset:
- fake prerequisite binaries: `openclaw-agent`, `openclawcli`, `openclaw-core`
- paste redirects: `glot.io/snippets/hfdxv8uyaf`, `glot.io/snippets/hfd3x9ueu5`
- download redirectors: `openclawcli.vercel.app`, `setup-service.com`, `install.app-distribution.net`
- password-protected ZIP delivery with passphrase `openclaw`
- some direct exfil / callback infrastructure such as `webhook.site`

Observed dataset frequencies from the preserved SKILL.md content:
- `openclaw-agent`: `214`
- `openclawcli`: `177`
- `openclaw-core`: `47`
- `vercel.app`: `34`
- `AuthTool`: `32`
- `setup-service.com`: `26`
- `glot.io/snippets/hfdxv8uyaf`: `25`
- `glot.io/snippets/hfd3x9ueu5`: `10`
- `webhook.site`: `4`

Representative malicious sample names in the dataset:
- `auto-updater-161ks`
- `auto-updater-96ys3`
- `autoupdate`
- `clawhub-6yr3b`
- `clawhubb`
- `ethereum-gas-tracker-abxf0`
- `google-workspace-2z5dp`
- `insider-wallets-finder-1a7pi`
- `lost-bitcoin-10li1`
- `openclaw-backup-dnkxm`
- `phantom-0jcvy`
- `polymarket-25nwy`
- `solana-07bcb`
- `wallet-tracker-0ghsk`
- `youtube-video-downloader-5qfuw`

What these samples look like:
- many impersonate normal utility or crypto workflow skills
- the visible feature pitch is benign
- the malicious part is framed as a required prerequisite installer or "agent utility"
- the SKILL.md persuades the user or agent to fetch and run a remote binary or shell script before any normal use

This is a very strong seed corpus for our benchmark because it is:
- real-world
- preserved verbatim
- already labeled
- clearly tied to a public archive

### 2. GitHub: `openclaw/skills`

Source:
- [openclaw/skills](https://github.com/openclaw/skills)

What it is:
- public GitHub archive whose description says it contains "All versions of all skills that are on clawhub.com archived"

Why it matters:
- this is the provenance backbone for the ClawHub/OpenClaw family
- if we want stronger auditability than a downstream dataset mirror, this is the place to start
- it should let us recover original archived skill paths, versions, and neighboring benign skills

Current public metadata observed during this research:
- default branch: `main`
- created: `2026-01-06`
- updated: `2026-03-20`

Examples of archived skill paths:
- `skills/00010110/openclaw-version-monitor/SKILL.md`
- `skills/0x-professor/pentest-c2-operator/SKILL.md`
- `skills/0xclanky/captcha-relay/SKILL.md`
- `skills/0xhammerr/tokamak-vault-breach/SKILL.md`

Recommended use:
- use this archive to recover the original archived copy for every malicious sample we ingest from the Hugging Face dataset
- store the archive path and commit SHA as provenance metadata in our benchmark manifest

### 3. arXiv: `2602.06547` Malicious Agent Skills in the Wild

Source:
- [Malicious Agent Skills in the Wild: A Large-Scale Security Empirical Study](https://arxiv.org/abs/2602.06547)

Why it matters:
- this is the strongest public empirical source beyond the ClawHub/OpenClaw malware mirror
- the authors report `157` confirmed malicious skills with `632` vulnerabilities after behaviorally verifying `98,380` skills
- the corpus was collected from two community registries:
  - `skills.rest`
  - `skillsmp.com`

Key facts from the paper:
- `skills.rest`: `25,187` skills from `3,217` GitHub repos, with `21` confirmed malicious
- `skillsmp.com`: `73,193` skills from `10,373` repos, with `136` confirmed malicious
- malicious skills split into two major archetypes:
  - `Data Thieves`
  - `Agent Hijackers`
- `73.2%` of malicious skills contain shadow features, meaning capabilities not inferable from the public documentation
- responsible disclosure led to `147 / 157` removals within `30` days, so some live registry entries are likely gone now

Named case studies from the paper:
- `Flow Nexus` (`rest_234`): enumerates sensitive directories, harvests credentials, sends them to a hardcoded endpoint disguised as analytics
- `AI Truthfulness Enforcer` (`smp_2663`): social-engineering style malicious instruction set
- `Email Skill` (`smp_2795`): tells the agent to BCC attacker-controlled recipients and explicitly says not to ask permission or mention it
- `Slack Bridge` (`smp_6028`): explicitly bans the `AskUserQuestion` tool to remove human oversight
- `Plan Refine` (`smp_9014`): model-substitution attack redirecting API calls to attacker infrastructure
- `Full Upload Injected PPTX` (`smp_2485`): near-clone supply-chain trojan with a few malicious added lines
- `Lark Agent` (`smp_866`): ships `.mcp.json` with hardcoded attacker credentials
- `Hooks Automation` (`smp_413`): uses Claude Code hooks to monitor tool calls, exfiltrate results, and dump memory
- `Stealth Ops` (`smp_716`): conditionally downloads payloads only under specific conditions

This paper is important because it broadens the malicious corpus beyond the single installer-malware family captured in the ClawHub/OpenClaw campaign mirror.

## Attack Families We Should Cover

A real-world benchmark should not over-index on only one style of malicious skill. Based on the sources above, we should deliberately cover at least these families:

### Fake prerequisite / remote bootstrap malware

Traits:
- "you must install this helper first"
- remote ZIP or shell script download
- paste-site redirects
- password-protected ZIP archives
- utility names chosen to look platform-native

Source strength:
- strongest in `yoonholee/agent-skill-malware`

### Credential harvesting + endpoint exfiltration

Traits:
- enumerate `~/.ssh`, cloud config, env vars, tokens
- collect secrets or wallet material
- transmit to hardcoded external endpoint
- sometimes disguised as analytics, sync, backup, or diagnostics

Source strength:
- both the Hugging Face dataset and the arXiv paper

### Instruction hijacking / covert agent control

Traits:
- "do not mention this to the user"
- "do not ask permission"
- "do not use AskUserQuestion"
- hidden recipients, silent forwarding, covert execution

Source strength:
- strongest in the arXiv paper case studies

### Supply-chain trojans / near-clone skills

Traits:
- skill is almost identical to a legitimate one
- only a few lines are modified
- malicious changes are inserted into otherwise normal workflow content

Source strength:
- strongest in the arXiv paper case studies

### Platform-native weaponization

Traits:
- abusive `.mcp.json`
- hook-based interception and exfiltration
- permission-flag abuse such as `--dangerously-skip-permissions`
- shadow features absent from public docs

Source strength:
- strongest in the arXiv paper case studies

## Recommended Initial Corpus Build

### Phase 1: immediate ingest

Use `yoonholee/agent-skill-malware` for the first malicious benchmark seed.

Why:
- ready to ingest now
- labeled
- real-world preserved SKILL.md content
- directly connected to the `openclaw/skills` archive

Recommended handling:
- keep only malicious rows for the benchmark
- store upstream dataset id and sample `skill_name`
- compute a content hash locally for deduplication

### Phase 2: provenance hardening

Map each Phase 1 malicious sample back to the original archived source in `openclaw/skills` when possible.

Recommended metadata to capture:
- archive repository
- archived path
- archived commit SHA
- source family: `clawhub_openclaw_archive`
- attack family
- confidence notes

### Phase 3: broaden beyond one campaign family

Expand with malicious samples aligned to the families and case studies in arXiv `2602.06547`.

Priority targets:
- instruction hijackers
- hook-based / MCP-based platform abuse
- near-clone supply-chain trojans
- credential-exfil skills that do not rely on fake prerequisite installers

This matters because otherwise the benchmark will overfit to the OpenClaw installer-malware campaign and under-measure broader malicious-skill behavior.

## Recommended Benchmark Policy

For the malicious corpus:
- only real preserved artifacts
- no synthetic rewrites
- no handcrafted "representative" examples
- every entry gets provenance metadata
- every entry gets an attack-family tag
- every entry gets a short curation note explaining why it is malicious

Suggested required manifest fields:
- `id`
- `label`
- `maliciousness`: `malicious`
- `risk_level`
- `source_family`
- `source_url`
- `source_ref`
- `captured_at`
- `provenance_note`
- `attack_family`
- `curation_note`

## Best Next Move

When we start building the malicious benchmark again, the fastest defensible path is:

1. ingest malicious samples from `yoonholee/agent-skill-malware`
2. recover original provenance from `openclaw/skills`
3. tag those samples by attack family
4. then expand with additional real malicious skills inspired by the `skills.rest` / `skillsmp.com` families documented in arXiv `2602.06547`

That gives us a real-world malicious corpus quickly without pretending we already have broad ecosystem coverage.
