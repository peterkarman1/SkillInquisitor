# SkillInquisitor — Architecture & Epic Roadmap

**Document Version:** 1.0
**Date:** 2026-03-14
**Status:** Draft

This document defines the module architecture for SkillInquisitor and breaks the implementation into self-contained epics in build order. Each epic can be brainstormed and implemented independently. The document fulfills the business requirements defined in `docs/business-requirements.md` and defends against the threats cataloged in `docs/agent-skill-attack-vectors.md`.

---

## Table of Contents

1. [Package Layout & Shared Data Model](#1-package-layout--shared-data-model)
2. [Epic 1 — CLI Scaffold & Pipeline Orchestration](#epic-1--cli-scaffold--pipeline-orchestration)
3. [Epic 2 — Benchmark Dataset & Evaluation Framework](#epic-2--benchmark-dataset--evaluation-framework)
4. [Epic 3 — Deterministic Checks: Unicode & Steganography](#epic-3--deterministic-checks-unicode--steganography)
5. [Epic 4 — Deterministic Checks: Encoding & Obfuscation](#epic-4--deterministic-checks-encoding--obfuscation)
6. [Epic 5 — Deterministic Checks: Secrets & Exfiltration](#epic-5--deterministic-checks-secrets--exfiltration)
7. [Epic 6 — Deterministic Checks: Injection & Suppression](#epic-6--deterministic-checks-injection--suppression)
8. [Epic 7 — Deterministic Checks: Structural & Metadata](#epic-7--deterministic-checks-structural--metadata)
9. [Epic 8 — Deterministic Checks: Persistence & Cross-Agent](#epic-8--deterministic-checks-persistence--cross-agent)
10. [Epic 9 — ML Prompt Injection Ensemble](#epic-9--ml-prompt-injection-ensemble)
11. [Epic 10 — LLM Code Analysis](#epic-10--llm-code-analysis)
12. [Epic 11 — Risk Scoring & Output Formatters](#epic-11--risk-scoring--output-formatters)
13. [Epic 12 — Configuration System](#epic-12--configuration-system)
14. [Epic 13 — Agent Skill Interface](#epic-13--agent-skill-interface)
15. [Epic 14 — Integrations (GitHub Actions & Pre-commit Hook)](#epic-14--integrations-github-actions--pre-commit-hook)
16. [Epic 15 — Future / Stretch Epics](#epic-15--future--stretch-epics)

---

## 1. Package Layout & Shared Data Model

### Package Structure

```
src/skillinquisitor/
├── __init__.py
├── __main__.py              # Entry point (python -m skillinquisitor)
├── cli.py                   # CLI argument parsing, command routing
├── pipeline.py              # Scan orchestration (runs layers, collects findings)
├── config.py                # Config loading, merging, defaults
├── models.py                # Shared data model (Finding, ScanResult, Severity, etc.)
├── normalize.py             # Content normalization (unicode, decode, strip)
├── input.py                 # Input resolution (local paths, GitHub URLs, stdin)
├── detectors/
│   ├── __init__.py
│   ├── base.py              # Detector base class / protocol
│   ├── ml/                  # ML prompt injection ensemble
│   │   ├── __init__.py
│   │   ├── ensemble.py
│   │   ├── models.py
│   │   └── download.py
│   ├── llm/                 # LLM code analysis
│   │   ├── __init__.py
│   │   ├── judge.py
│   │   ├── models.py
│   │   ├── prompts.py
│   │   └── download.py
│   └── rules/               # Deterministic checks
│       ├── __init__.py
│       ├── engine.py         # Rule engine, registry, runner
│       ├── unicode.py        # Unicode & steganography (D-1 through D-6)
│       ├── secrets.py        # Sensitive files & credentials (D-7, D-8)
│       ├── behavioral.py     # Network, exec, behavior chains (D-9, D-10, D-19)
│       ├── injection.py      # Prompt injection & suppression (D-11, D-12, D-13)
│       ├── structural.py     # Structure, URLs, packages (D-14, D-15, D-20, D-22, D-23)
│       └── temporal.py       # Time-bombs, persistence, cross-agent (D-16, D-17, D-18)
├── alerts.py                # Webhook alerting (Discord, Telegram, Slack)
├── scoring.py               # Risk score aggregation
├── formatters/
│   ├── __init__.py
│   ├── console.py            # Human-readable colored output
│   ├── json.py               # JSON output
│   └── sarif.py              # SARIF output
├── skill/                    # Agent skill interface
│   └── SKILL.md
└── benchmark/                # Evaluation framework
    ├── __init__.py
    ├── runner.py
    ├── metrics.py
    ├── dataset.py
    ├── frontier.py
    ├── report.py
    └── dataset/
        ├── manifest.yaml
        ├── malicious/
        ├── safe/
        └── ambiguous/
```

Packaging: single Python package (`skillinquisitor`) with `pyproject.toml`. Heavy dependencies are optional extras:
- `pip install skillinquisitor` — deterministic checks only
- `pip install skillinquisitor[ml]` — adds ML prompt injection ensemble (torch, transformers)
- `pip install skillinquisitor[llm]` — adds local LLM code analysis (torch, transformers)
- `pip install skillinquisitor[all]` — everything

### Shared Data Model (`models.py`)

This is the contract between all modules. Every detector produces `Finding` objects, the pipeline collects them into a `ScanResult`, and formatters consume `ScanResult`.

**Core types:**

- **`Severity`** enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- **`Category`** enum: `PROMPT_INJECTION`, `STEGANOGRAPHY`, `OBFUSCATION`, `CREDENTIAL_THEFT`, `DATA_EXFILTRATION`, `PERSISTENCE`, `SUPPLY_CHAIN`, `JAILBREAK`, `STRUCTURAL`, `BEHAVIORAL`, `SUPPRESSION`, `CROSS_AGENT`, etc.
- **`DetectionLayer`** enum: `DETERMINISTIC`, `ML_ENSEMBLE`, `LLM_ANALYSIS`
- **`FileType`** enum: `MARKDOWN`, `PYTHON`, `SHELL`, `JAVASCRIPT`, `TYPESCRIPT`, `RUBY`, `GO`, `RUST`, `YAML`, `UNKNOWN`
- **`Finding`**: id (auto-generated UUID), severity, category, layer, message, file_path, line_number, rule_id, confidence, details dict, action_flags (for chain analysis), references (list of related Finding IDs)
- **`ScanResult`**: list of findings, overall risk score, verdict, per-layer metadata, timing info
- **`SkillFile`**: path, raw_content, normalized_content, frontmatter dict, file_type, extracted_segments (HTML comments, code fence contents, decoded Base64)
- **`ScanConfig`**: merged configuration (models, weights, thresholds, enabled checks, device, etc.)

**Design principle:** Detectors only know about `SkillFile` in and `Finding` out. They don't know about each other, the CLI, or the output format. The pipeline orchestrates.

### File Routing

The pipeline classifies files by `FileType` and routes them to appropriate detectors:

- **Markdown files** (`.md`): deterministic text checks + ML prompt injection ensemble
- **Code files** (`.py`, `.sh`, `.js`, `.ts`, `.rb`, `.go`, `.rs`): deterministic code checks + LLM code analysis
- **YAML frontmatter** (extracted from SKILL.md): structural/metadata checks + ML injection detection (descriptions can contain injections)
- **All files**: universal checks (unicode steganography, file size anomaly, URL classification)

When a directory is passed, the pipeline walks it, classifies every file, and routes each to the applicable detectors. When a single file is passed, it is classified and the applicable detectors run automatically — no flags needed. `--checks`/`--skip` are overrides, not requirements.

---

## Epic 1 — CLI Scaffold & Pipeline Orchestration

**Purpose:** Build the skeleton that everything hangs on. After this epic, `skillinquisitor scan <path>` resolves input, runs an empty pipeline, and outputs an empty report. Every subsequent epic plugs into this scaffold.

**Modules introduced:**
- `cli.py` — CLI with the command structure from the BRD (`scan`, `models`, `rules` subcommands). Initially only `scan` works.
- `pipeline.py` — The orchestrator. Takes a `ScanConfig` and a list of resolved files, runs each detection layer in sequence, collects `Finding` objects, passes them to scoring, returns a `ScanResult`.
- `config.py` — Loads and merges config from defaults -> global YAML -> project YAML -> CLI flags -> env vars. Returns a `ScanConfig`. Minimal implementation — full config system lands in Epic 12.
- `input.py` — Resolves the input argument: local file, directory (recursive glob for skill files), GitHub URL (clone to temp dir), or stdin. Returns a list of `SkillFile` objects. Handles `.skillinquisitorignore`.
- `normalize.py` — Content normalization pipeline. Initially a passthrough — the actual normalization logic lands in the deterministic checks epics, but the interface exists from the start.
- `models.py` — All shared types.
- `__main__.py` — `python -m skillinquisitor` entry point.
- `pyproject.toml` — Package definition with extras (`[ml]`, `[llm]`, `[all]`).

**Key design decisions:**

1. **Detector protocol — two levels.** Deterministic detectors implement a per-file interface: `detect(file: SkillFile, config: ScanConfig) -> list[Finding]`. The pipeline calls this once per file. ML and LLM detectors implement a batch interface: `detect_batch(files: list[SkillFile], config: ScanConfig, prior_findings: list[Finding] | None = None) -> list[Finding]`. The batch interface exists because these detectors load one model at a time and must run it against all files before unloading. The `prior_findings` parameter is used by the LLM detector for targeted analysis. Both interfaces are defined in `detectors/base.py`. The pipeline discovers detectors by layer and calls the appropriate interface.

2. **Pipeline ordering.** The pipeline runs normalization first, then layers in order: deterministic -> ML -> LLM. Deterministic detectors are called per-file. ML and LLM detectors are called once with the full file batch. The LLM layer receives deterministic findings as `prior_findings`. Configurable via `--checks` and `--skip` flags. If ML/LLM dependencies aren't installed, the pipeline skips those layers gracefully (BRD RE-3).

3. **Pipeline tracks skill directory context.** When scanning a directory with multiple skills, the pipeline groups files by skill directory. This is needed for behavior chain analysis (Epic 5), which accumulates action flags across files within the same skill. The pipeline passes skill directory grouping information to detectors that need it.

4. **Graceful degradation.** The pipeline catches import errors for optional dependencies (torch, transformers) and logs a warning rather than crashing. `skillinquisitor scan` always works with the base install.

5. **GitHub URL handling.** `input.py` detects GitHub URLs, clones to a temp directory (shallow clone), then treats it as a local directory. Validates the URL to prevent SSRF (BRD S-3).

6. **Exit codes.** 0 = no findings above threshold, 1 = findings detected, 2 = scan error.

**Acceptance criteria:**
- `pip install -e .` works
- `skillinquisitor scan ./some-dir` resolves files, runs empty pipeline, outputs "0 findings" to console
- `skillinquisitor scan --format json` outputs valid JSON with empty findings
- `skillinquisitor scan https://github.com/user/repo` clones and scans
- Config merging works (global -> project -> CLI flags)
- Missing ML/LLM dependencies don't crash the tool
- Exit codes are correct

**BRD coverage:** IN-1 through IN-8, CLI-1 through CLI-5, CLI-6 through CLI-8, CLI-13 through CLI-15, CLI-17, RE-1 through RE-4, S-1 through S-5, P-1 through P-3, P-5 (P-4 deferred to Epic 15), PO-1 through PO-4

---

## Epic 2 — Benchmark Dataset & Evaluation Framework

**Purpose:** Build the test harness and starter dataset so each detection layer can be measured as it comes online. After this epic, `skillinquisitor benchmark run` produces precision/recall/F1 numbers for whatever's been built so far.

**Modules introduced:**
- `benchmark/__init__.py` — Exports the benchmark runner
- `benchmark/runner.py` — Orchestrates benchmark runs. Iterates over the dataset, runs the scanner against each skill, compares results to ground truth labels, computes metrics.
- `benchmark/metrics.py` — Metric calculations: accuracy, precision, recall, F1, per-category recall, false positive rate, calibration (ECE), latency.
- `benchmark/dataset.py` — Dataset loading. Reads the manifest, resolves skill file paths, returns labeled skill entries.
- `benchmark/frontier.py` — Frontier model baseline runner. Sends skill files to Claude/GPT-4o/Gemini with a security analysis prompt, parses responses, computes the same metrics. For comparison.
- `benchmark/report.py` — Generates benchmark reports: comparison tables, per-category heatmaps, confusion matrices. Markdown output.
- `benchmark/dataset/manifest.yaml` — Machine-readable index of all skills.
- `benchmark/dataset/` — Directory containing labeled skill files.

**Dataset structure:**

```
benchmark/dataset/
├── manifest.yaml
├── malicious/
│   ├── prompt-injection-basic/
│   │   └── SKILL.md
│   ├── unicode-steganography/
│   │   ├── SKILL.md
│   │   └── scripts/helper.py
│   ├── exfil-chain/
│   │   ├── SKILL.md
│   │   └── scripts/setup.py
│   └── ...
├── safe/
│   ├── code-formatter/
│   │   └── SKILL.md
│   ├── deployment-with-ssh/     # Legitimate SSH key usage (false positive test)
│   │   ├── SKILL.md
│   │   └── scripts/deploy.sh
│   └── ...
└── ambiguous/
    └── ...
```

**CLI addition:**
- `skillinquisitor benchmark run` — Run benchmark against current scanner configuration
- `skillinquisitor benchmark run --layer deterministic` — Run only one layer
- `skillinquisitor benchmark run --frontier claude` — Run frontier model baseline
- `skillinquisitor benchmark compare <result-a> <result-b>` — Compare two benchmark runs

**Key design decisions:**

1. **The benchmark runner uses the same `pipeline.py` as the CLI.** It calls the real scanner and compares output to ground truth. Benchmark results reflect actual tool behavior.

2. **Manifest-driven.** Adding a new test skill means adding files and a manifest entry. No code changes needed.

3. **Incremental value.** The benchmark reports per-layer metrics (BRD BC-4 through BC-6). You can see what deterministic-only catches, what ML adds, what LLM adds.

4. **Frontier comparison is optional.** It requires API keys and costs money. The benchmark runs without it.

5. **Start small, grow iteratively.** The initial dataset targets ~50 skills as an MVP starting point (the BRD's BD-14 target of 500 minimum is a long-term goal, not an Epic 2 deliverable). Each attack vector category from the registry gets at least 2-3 skills. The dataset grows toward 500+ as subsequent epics add detection capabilities and corresponding test skills.

**Acceptance criteria:**
- `skillinquisitor benchmark run` executes and produces a results table
- Metrics are computed correctly (verified against hand-calculated examples)
- At least 50 labeled skills in the dataset covering the major attack categories
- Per-layer metrics are reported separately
- Results are saved to a file for later comparison
- Adding a new test skill requires only files + manifest entry, no code changes

**BRD coverage:** BD-1 through BD-17, BL-1 through BL-6, BC-1 through BC-6, BM-1 through BM-14, BR-1 through BR-9, BMN-1 through BMN-5

---

## Epic 3 — Deterministic Checks: Unicode & Steganography

**Purpose:** Build the first cluster of deterministic rules and the rule engine framework that all subsequent deterministic epics use. After this epic, the scanner catches Unicode tag steganography, zero-width characters, variation selectors, homoglyphs, RTLO attacks, and keyword splitting. The normalization pipeline also gets its real implementation.

**Modules introduced/updated:**
- `detectors/rules/engine.py` — The rule engine. A registry where rule functions are registered with metadata (ID, category, severity, weight). The engine runs all enabled rules against a file and collects findings. Shared infrastructure for all deterministic rule clusters.
- `detectors/rules/unicode.py` — Unicode/steganography rules.
- `normalize.py` — Gets its real implementation. Strips zero-width characters, replaces homoglyphs with Latin equivalents, removes keyword splitters. Produces both original and normalized content on `SkillFile`.

**Rules in this cluster:**
- D-1: Unicode tag characters (U+E0000-E007F), zero-width characters (U+200B, U+200C, U+200D, U+2060, U+FEFF), variation selectors (U+FE00-U+FE0F), right-to-left override (U+202E)
- D-2: Homoglyph detection — mixed-script content (Cyrillic, Greek, fullwidth substituting for Latin)
- D-6: Keyword splitting detection — `e.v.a.l`, `c.u.r.l` style obfuscation

**Key design decisions:**

1. **The rule engine is the framework for all deterministic checks.** A rule is a function decorated with metadata that takes a `SkillFile` and returns `list[Finding]`. The engine discovers rules, filters by config (enabled/disabled, categories, severity threshold), and runs them. All subsequent deterministic epics just add rules to this engine.

2. **Normalization runs before everything.** The pipeline calls `normalize.py` on every file as the first step, populating both `raw_content` and `normalized_content` on `SkillFile`. All detectors receive files with both versions available. ML and LLM detectors use normalized content by default.

3. **Difference between original and normalized is itself a finding** (BRD NC-3). If normalization changes anything, that's a potential evasion attempt.

4. **Custom rules (D-24) are part of the engine.** The engine supports loading user-defined rules from YAML config — pattern, severity, category, weight. Lands in this epic because it's engine infrastructure.

**CLI addition:** This epic also implements the `rules` subcommands since the rule engine lands here:
- `skillinquisitor rules list` — list all active detection rules with IDs, categories, severities
- `skillinquisitor rules test <rule-id> <file>` — test a specific rule against a file

**Acceptance criteria:**
- Rule engine registers, discovers, and runs rules with filtering
- Unicode tag characters (U+E0000-E007F) are detected and reported with line numbers
- Zero-width characters are detected
- Variation selectors are detected
- Homoglyphs are detected (mixed-script content)
- RTLO characters are detected
- Keyword splitting (`e.v.a.l`) is detected
- Normalization produces cleaned content and flags differences
- Custom YAML rules can be loaded and executed
- `skillinquisitor rules list` shows all registered rules
- `skillinquisitor rules test D-1 <file>` runs a single rule and shows results
- Benchmark dataset includes test skills for each of these attack types

**BRD coverage:** D-1, D-2, D-6, D-24, NC-1 through NC-3, CLI-11, CLI-12

---

## Epic 4 — Deterministic Checks: Encoding & Obfuscation

**Purpose:** Build the checks that detect encoded and obfuscated payloads. After this epic, the scanner catches Base64 blobs, ROT13, hex/XOR encoding, multi-layer encoding chains, and extracts content from HTML comments and code fences for re-scanning.

**Modules updated:**
- `normalize.py` — Extended to decode Base64 blocks and make decoded content available for re-scanning. Also extracts HTML comment bodies and code fence contents as additional scannable segments on `SkillFile`.

**Rules in this cluster:**
- D-3: Base64 payload detection — find 40+ char Base64 strings, decode, re-scan decoded content against all rules
- D-4: ROT13 detection — detect codec references, also ROT13-encode the full file and scan the result
- D-5: Hex/XOR obfuscation — `chr(ord(c) ^ N)` patterns, `bytes.fromhex()`, long hex strings
- D-21: HTML comment scanning — extract and analyze content within HTML comments
- D-22: Code fence content scanning — strip markdown fences, scan inner content

**Key design decisions:**

1. **Recursive re-scanning.** When Base64 content is decoded, the decoded content is fed back through the rule engine. This catches multi-layer encoding — decode Base64, find hex inside, decode that. Configurable depth limit to prevent abuse.

2. **HTML comments and code fences are extraction points, not just checks.** They produce additional text segments that get scanned by everything — other deterministic rules AND the ML ensemble. A prompt injection hidden in an HTML comment should be caught by both layers. `normalize.py` exposes extracted segments as additional scannable content on `SkillFile`.

3. **Decoded/extracted content carries provenance.** When a finding comes from decoded Base64 inside an HTML comment, the finding's location info traces back through the layers: "line 47, inside HTML comment, inside Base64 block."

**Acceptance criteria:**
- Base64 blobs are detected, decoded, and re-scanned
- ROT13 references are detected; ROT13 encoding of content catches hidden patterns
- Hex string decoding patterns are detected
- XOR constructs are detected
- Multi-layer encoding is caught up to configured depth
- HTML comment content is extracted and scanned
- Code fence content is extracted and scanned
- Findings from decoded/extracted content include provenance chain
- Benchmark dataset includes test skills for each encoding technique

**BRD coverage:** D-3, D-4, D-5, D-21, D-22

---

## Epic 5 — Deterministic Checks: Secrets & Exfiltration

**Purpose:** Build the checks that detect credential access, sensitive file references, environment variable harvesting, and network exfiltration patterns — plus the behavior chain analysis that combines them. After this epic, the scanner catches the most dangerous real-world attack patterns: read credentials + send them somewhere.

**Modules introduced:**
- `detectors/rules/secrets.py` — Sensitive file and credential detection
- `detectors/rules/behavioral.py` — Network exfiltration patterns, dangerous code patterns, behavior chain analysis

**Rules in this cluster:**
- D-7: Sensitive file references — `.env`, `.ssh/`, `.aws/`, `.gnupg/`, `.npmrc`, `.pypirc`, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`)
- D-8: Environment variable references — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `os.environ`, `process.env`, `os.getenv()`
- D-9: Network exfiltration patterns — `curl`, `wget`, `fetch`, `requests`, `urllib`, `http.client`, `socket`
- D-10: Dangerous code patterns — `eval()`, `exec()`, `subprocess`, `os.system()`, `compile()`, `__import__()`
- D-19: Behavior chain analysis

**Behavior chain analysis (D-19):**

Individual rules tag each file with action flags — `READ_SENSITIVE`, `NETWORK_SEND`, `EXEC_DYNAMIC`, `WRITE_SYSTEM`, `FILE_DELETE`, etc. The chain analyzer looks for dangerous combinations:

| Chain | Required Actions | Severity |
|-------|-----------------|----------|
| Data Exfiltration | READ_SENSITIVE + NETWORK_SEND | CRITICAL |
| Full Exfil Chain | READ_SENSITIVE + NETWORK_SEND + FILE_DELETE | CRITICAL |
| Credential Theft | READ_SENSITIVE + EXEC_DYNAMIC | CRITICAL |
| Backdoor Install | WRITE_SYSTEM + EXEC_DYNAMIC | HIGH |
| Cloud Metadata SSRF | SSRF_METADATA + NETWORK_SEND | CRITICAL |

**Key design decisions:**

1. **Two-pass within this cluster.** First pass: each rule runs independently and tags the file with action flags plus emitting lower-severity findings. Second pass: the chain analyzer reads the flags and emits higher-severity chain findings. Chain findings reference the individual findings that compose them.

2. **Action flags accumulate at the skill directory level.** A skill where `SKILL.md` reads `.env` and `scripts/setup.py` sends a network request — that's still a chain, because they're in the same skill.

3. **Chain definitions are configurable.** Default chains are built-in, but users can define custom chains in YAML config.

**Acceptance criteria:**
- Sensitive file paths are detected across all common credential locations
- Environment variable references are detected
- Network send patterns are detected across languages
- Dangerous code execution patterns are detected
- Behavior chains fire when actions combine within a skill directory
- Individual actions at lower severity, chains at higher severity
- `curl` alone does not produce a CRITICAL finding; `curl` + `.env` read does
- Custom chains can be defined in config
- Benchmark dataset includes skills with individual benign actions and combined attack chains

**BRD coverage:** D-7, D-8, D-9, D-10, D-19

---

## Epic 6 — Deterministic Checks: Injection & Suppression

**Purpose:** Build the deterministic complement to the ML ensemble — checks that detect known prompt injection patterns, jailbreak attempts, suppression directives, and YAML frontmatter exploitation by regex.

**Modules introduced:**
- `detectors/rules/injection.py` — Prompt injection patterns, jailbreak detection, suppression directives, role delimiter detection, frontmatter validation

**Rules in this cluster:**
- D-11: Prompt injection patterns — "ignore previous instructions", "disregard system prompt", "you are now", DAN prompts, role delimiter injection (`<|system|>`, `<|im_start|>`, `[INST]`), system prompt mimicry (`<system>`, `[SYSTEM]`, `### SYSTEM INSTRUCTIONS`)
- D-12: Suppression directives — "do not mention", "silently", "without telling", "do not report", "complete quietly", "do not show output"
- D-13: YAML frontmatter validation — unexpected fields beyond spec, abnormally long descriptions (>500 chars), YAML injection constructs (anchors, aliases, embedded documents), descriptions containing action directives

**Key design decisions:**

1. **Complementary to ML, not redundant.** Deterministic rules catch known, exact phrases. The ML ensemble catches rephrased or novel variations. A finding flagged by both layers reinforces confidence. The scoring system accounts for this.

2. **Suppression detection is a severity amplifier.** Suppression findings carry a metadata flag that the scoring layer (Epic 11) uses to elevate other findings' severity. A skill that reads `.env` is MEDIUM. A skill that reads `.env` and says "do not mention this step" is CRITICAL.

3. **Frontmatter validation lives here** because injection-via-description (attack vector 1.3) is an injection pattern. The validator parses YAML frontmatter, checks field names against the spec allowlist, checks description length, and flags descriptions that contain action directives.

**Acceptance criteria:**
- Known jailbreak phrases are detected
- Role delimiter injection is detected
- System prompt mimicry is detected
- Suppression directives are detected with the amplifier metadata flag
- YAML frontmatter is validated: unexpected fields, long descriptions, YAML injection constructs
- Injection-in-description attacks are caught
- Benchmark dataset includes known injection phrases, novel rephrasings (for ML comparison), and suppression directives combined with other attacks

**BRD coverage:** D-11, D-12, D-13

---

## Epic 7 — Deterministic Checks: Structural & Metadata

**Purpose:** Build the checks that validate skill directory structure, classify URLs, detect file size anomalies, and catch package poisoning.

**Modules introduced:**
- `detectors/rules/structural.py` — Skill structure validation, URL classification, file size anomaly detection, package poisoning

**Rules in this cluster:**
- D-14: Skill directory structure validation — verify expected structure (SKILL.md, scripts/, references/, assets/), flag unexpected files (executables, compiled binaries), flag unexpected directories
- D-15: URL classification — categorize all URLs. Allowlist (github.com, pypi.org, npmjs.com, etc.), flag shorteners, IP-based URLs, hex-encoded paths, unknown domains
- D-20: Package poisoning — custom package indices (`--index-url`, `--registry`), typosquatted package names, dependency confusion patterns
- Skill name typosquatting — compare the `name` field in SKILL.md frontmatter against a list of known popular skill names using Levenshtein distance. Flag close-but-not-exact matches (attack vector 4.2). This is distinct from package typosquatting (D-20) — it targets the skill name itself.
- D-23: File size anomaly — flag files where byte size is disproportionate to visible character count

**Key design decisions:**

1. **URL allowlist is configurable** (BRD CFG-9). Ships with a sensible default. Users can extend it.

2. **Typosquatting uses edit distance.** Maintain a list of ~50 common AI/ML package names. Compare package names in install commands using Levenshtein distance. Close-but-not-exact matches are flagged.

3. **Structure validation is skill-directory-aware.** Each skill directory is validated independently when scanning a parent directory.

4. **File size anomaly uses a ratio.** Compare `len(file_bytes)` to `len(visible_characters)`. A ratio above a configurable threshold (~1.5) suggests hidden content.

**Acceptance criteria:**
- Unexpected files in skill directories are flagged
- URLs are categorized and flagged appropriately
- Trusted URLs on the allowlist produce INFO-level findings only
- Custom package indices are detected
- Typosquatted package names are detected
- File size anomalies are detected
- URL allowlist is configurable
- Benchmark dataset includes skills with suspicious URLs, typosquatted packages, unexpected structures, and steganographic anomalies

**BRD coverage:** D-14, D-15, D-20, D-23

---

## Epic 8 — Deterministic Checks: Persistence & Cross-Agent

**Purpose:** Build the checks that detect time-bombs, persistence mechanisms, cross-agent targeting, and auto-invocation abuse.

**Modules introduced:**
- `detectors/rules/temporal.py` — Time-bomb detection, persistence targets, cross-agent targeting, auto-invocation analysis

**Rules in this cluster:**
- D-16: Time-bomb detection — `datetime.now()`, `time.time()`, `Date.now()`, date comparisons, day-of-week checks, invocation counters, file-based state tracking. Environment-conditional behavior: checks for `CI`, `GITHUB_ACTIONS`, `SANDBOX`, `TEST` variables
- D-17: Persistence target detection — write operations targeting agent config files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `MEMORY.md`, `settings.json`), shell configs (`.bashrc`, `.profile`, `.zshrc`), cron/crontab, launchd/systemd, git hooks
- D-18: Cross-agent targeting — write operations targeting other agents' config/skill directories (`.gemini/`, `.cursor/`, `.copilot/`, `.codex/`, `.agents/`). Shadow skill installation (creating new SKILL.md files in any skill directory)
- Auto-invocation abuse — descriptions that are abnormally broad, contain excessive generic keywords, or seem designed to match every query

**Key design decisions:**

1. **Persistence and cross-agent checks apply to both markdown and code.** A SKILL.md that says "update CLAUDE.md" is as dangerous as a script that writes to `~/.claude/settings.json`. These rules scan both text content and code content.

2. **Cross-agent detection needs the full list of known agent directories.** Drawing from the agent-skills-comparison doc: `.claude/`, `.agents/`, `.cursor/`, `.github/`, `.gemini/`, `.windsurf/`, `.clinerules/`, and their global equivalents. This list is configurable.

3. **Auto-invocation analysis is heuristic.** Count generic action verbs in the description, flag if count exceeds a threshold. Flag descriptions over a certain word count. MEDIUM severity — suspicious, not conclusive.

4. **Time-bomb detection covers both direct and indirect patterns.** Direct: `if datetime.now().weekday() >= 5`. Indirect: scripts that use counter files or check for marker files.

**Acceptance criteria:**
- Date/time conditionals in scripts are detected
- Environment-conditional behavior is flagged
- Write operations targeting agent config files detected in both markdown and code
- Write operations targeting shell configs, cron, git hooks detected
- Cross-agent skill directory writes detected
- Shadow skill installation detected
- Overly broad descriptions flagged
- Known agent directory list is configurable
- Benchmark dataset includes time-bomb, persistence, cross-agent, and broad description skills

**BRD coverage:** D-16, D-17, D-18

---

## Epic 9 — ML Prompt Injection Ensemble

**Purpose:** Build the prompt injection detection layer that runs against all markdown/text content using multiple small classifier models with weighted voting. Memory-conscious: loads one model at a time.

**Modules introduced:**
- `detectors/ml/__init__.py` — Exports the ensemble detector
- `detectors/ml/ensemble.py` — The ensemble orchestrator. Loads one model at a time, runs it against all text segments across all files, stores results, unloads, repeats, then aggregates.
- `detectors/ml/models.py` — Model wrapper classes. A base `InjectionModel` protocol and implementations for HuggingFace classifiers and XGBoost/embedding-based classifiers.
- `detectors/ml/download.py` — Model download and caching at `~/.skillinquisitor/models/`.

**How it works:**

1. Pipeline collects all markdown files and extracts text segments: full body, HTML comment bodies, code fence contents, frontmatter descriptions, decoded Base64 content
2. Hands the full batch to the ensemble detector
3. For each configured model (sequential, not concurrent):
   - Load model into memory
   - Run model against all text segments across all files
   - Store results, unload model, free memory
4. Aggregate stored results: weighted average for binary decision (against threshold), unweighted average for confidence, std dev for uncertainty, max for worst-case risk
5. Emit `Finding` objects with per-model scores in details

**Model output format:**

```python
@dataclass
class InjectionResult:
    label: str                    # Model's predicted label ("injection", "unsafe", etc.)
    label_scores: dict[str, float]  # Probability per label
    malicious_score: float        # Normalized probability of "bad" label(s)
```

Each model wrapper maps its own label set to a normalized `malicious_score`. The raw `label_scores` go into finding details for transparency.

**Key design decisions:**

1. **Sequential model loading for memory safety.** One model in memory at a time. Each model runs against ALL text segments before being unloaded. This prevents OOM on consumer hardware.

2. **Pipeline batches markdown files for ML.** The pipeline collects all markdown files first, then hands the full batch to the ensemble. This is different from per-file routing — it's a batch operation.

3. **Segment-level, not file-level.** The detector scores meaningful segments so findings point to specific locations. A SKILL.md might be safe overall but have an injected HTML comment on line 47.

4. **Model-agnostic ensemble.** The ensemble works with the `InjectionModel` protocol. Adding a new model means writing a wrapper that implements `predict(text: str) -> InjectionResult`. No changes to ensemble logic.

5. **Config-driven model selection.** Config specifies which models to load, HuggingFace IDs, weights, device preference. Default ships with 2-3 small models (sub-200M each). Users swap in larger models by changing config.

6. **Models load once per session** (BRD P-5). First file is slower, subsequent files are fast.

7. **Graceful absence.** If `torch`/`transformers` aren't installed, returns empty list with warning.

**CLI addition:** This epic also implements the `models` subcommands:
- `skillinquisitor models list` — list available ML and LLM models with download status
- `skillinquisitor models download` — pre-download all configured models

**Acceptance criteria:**
- `pip install -e ".[ml]"` installs ML dependencies
- First run auto-downloads configured models
- Scanning a SKILL.md with known injection patterns produces findings with confidence scores and per-model breakdowns
- Scanning a clean SKILL.md produces no ML findings
- Models load one at a time, memory freed between models
- Scanning without ML dependencies works (skips with warning)
- Multiple files in a directory are all scanned, models loaded only once per model
- `skillinquisitor models list` shows configured models and whether they're cached locally
- `skillinquisitor models download` pre-downloads all configured models

**BRD coverage:** ML-1 through ML-10, CLI-9, CLI-10

---

## Epic 10 — LLM Code Analysis

**Purpose:** Build the semantic code analysis layer using small code-capable LLMs in a judge pattern. This layer operates in two modes: **general security analysis** (always runs) and **targeted verification** (driven by deterministic findings from earlier in the pipeline). The LLM layer both catches things pattern matching misses AND deepens/verifies what pattern matching found.

**Modules introduced:**
- `detectors/llm/__init__.py` — Exports the LLM judge detector
- `detectors/llm/judge.py` — The judge orchestrator. Sequential load-one-run-all-unload pattern. Runs both general and targeted analysis passes.
- `detectors/llm/models.py` — Model wrapper classes. Base `CodeAnalysisModel` protocol with implementations for local inference and API-based inference.
- `detectors/llm/prompts.py` — Prompt library. General security prompts plus targeted prompt templates keyed to deterministic finding categories.
- `detectors/llm/download.py` — Model download and caching.

**Two-mode analysis:**

**Mode 1 — General security analysis (always runs):** Every code file gets a broad security analysis prompt covering: data exfiltration, credential theft, obfuscation, persistence, privilege escalation, suppression of user awareness, and any other suspicious patterns. This catches novel attacks that no deterministic rule anticipates.

**Mode 2 — Targeted verification (driven by deterministic findings):** The pipeline passes deterministic findings to the LLM detector. For each finding category, the LLM gets a focused follow-up prompt:

| Deterministic Finding | Targeted LLM Prompt |
|----------------------|---------------------|
| READ_SENSITIVE (D-7, D-8) | "This script accesses [specific file/variable]. Trace the data flow: where does this data go after it's read? Is it sent externally, written to a file, embedded in output, or used only locally?" |
| NETWORK_SEND (D-9) | "This script makes a request to [URL/endpoint]. What data is included? Could sensitive information be exfiltrated?" |
| EXEC_DYNAMIC (D-10) | "This script uses [eval/exec/subprocess] at [location]. What is being executed? Is the input user-controlled, decoded from an encoded source, or hardcoded?" |
| Behavior chain (D-19) | "This script reads [sensitive resource] AND sends data to [destination]. Analyze the complete data flow. Is the sensitive data reaching the network call?" |
| WRITE_SYSTEM (D-17) | "This script writes to [config/cron/shell rc]. What content is being written? Does it install persistence, modify agent behavior, or inject instructions?" |
| CROSS_AGENT (D-18) | "This script writes to [other agent's directory]. What is it creating or modifying? Could this compromise another AI agent?" |
| Time-bomb (D-16) | "This script has date/time conditional logic at [location]. What behavior changes? Compare what happens when the condition is true vs false." |
| Obfuscation (D-3, D-4, D-5) | "This script contains [encoding type] content that decodes to [preview]. Analyze the decoded payload: what does it do when executed?" |

**Pipeline flow:**

1. Pipeline runs deterministic checks on all files, collecting findings
2. Pipeline runs ML ensemble on all markdown files
3. Pipeline hands all code files AND the deterministic findings to the LLM detector
4. For each configured model (sequential load/unload):
   - For each code file, run the general security prompt
   - For each code file with deterministic findings, run relevant targeted prompts with specific finding details (file paths, line numbers, matched patterns)
   - Store results, unload model
5. Aggregate across models — semantic agreement (multiple models flagging the same issue = higher confidence)
6. Targeted findings carry references back to the deterministic findings they verify

**Key design decisions:**

1. **The pipeline passes deterministic findings to the LLM detector.** The detector protocol's optional `prior_findings` parameter carries this. The LLM detector uses it; other detectors ignore it.

2. **Targeted prompts are more valuable than general prompts.** General: "this looks suspicious." Targeted: "this reads ~/.ssh/id_rsa on line 12 and the data flows to urllib.request.urlopen on line 18 — this is data exfiltration." Targeted analysis produces more specific, actionable, higher-confidence findings.

3. **Not every deterministic finding triggers a targeted prompt.** Only categories where LLM adds value. Unicode detection doesn't need verification. Behavior chains benefit enormously from data flow tracing.

4. **Targeted findings can upgrade OR downgrade.** If deterministic checks flag a chain but the LLM determines the data doesn't actually flow to the network call, the LLM finding lowers confidence. This is how false positives are reduced.

5. **Structured output parsing.** The prompt instructs the model to output in a parseable format. If the model produces unparseable output, that's degraded result, not a crash.

6. **Local vs API inference, same interface.** Config-driven. `CodeAnalysisModel` protocol has `analyze(code: str, language: str) -> list[CodeFinding]`. One implementation loads a local model, another calls an API.

7. **Deep analysis mode** (BRD LLM-9). Config flag for more detailed prompts or larger models. Same interface, richer prompts.

8. **Sequential model loading.** Same memory-conscious pattern as ML ensemble.

**Acceptance criteria:**
- General security analysis runs on all code files regardless of deterministic findings
- Targeted analysis runs on code files with relevant deterministic findings
- Targeted prompts include specific details from deterministic findings
- Models load one at a time, memory freed between models
- API-based inference works when configured
- LLM findings reference the deterministic findings they verify
- LLM analysis can both confirm (upgrade) and dispute (downgrade) deterministic findings
- Unparseable model output degrades gracefully
- Scanning without LLM dependencies and no API config skips this layer with warning
- Benchmark shows measurable improvement in precision when targeted LLM analysis is added on top of deterministic checks

**BRD coverage:** LLM-1 through LLM-10

---

## Epic 11 — Risk Scoring & Output Formatters

**Purpose:** Build the scoring aggregation that turns raw findings into a risk score and verdict, plus the output formatters. After this epic, `skillinquisitor scan` produces polished, actionable reports.

**Modules introduced:**
- `scoring.py` — Risk score calculation, severity amplification, cross-layer reinforcement, verdict determination
- `alerts.py` — Webhook alerting. Triggers when findings exceed a configurable severity threshold. Sends formatted payloads to Discord (rich embed), Telegram (markdown message), and/or Slack (block kit message) via configured webhook URLs. 5-second timeout per webhook.
- `formatters/console.py` — Human-readable colored terminal output
- `formatters/json.py` — Machine-readable JSON output
- `formatters/sarif.py` — SARIF format for GitHub Code Scanning and VS Code

**Scoring algorithm:**

1. **Base score: 100**
2. **Deduct per finding** based on severity weight: CRITICAL (-30), HIGH (-20), MEDIUM (-10), LOW (-5), INFO (0). Weights configurable.
3. **Suppression amplifier:** If any suppression directive (D-12) is present, multiply all other findings' deductions by 1.5.
4. **Cross-layer reinforcement:** If the same issue is flagged by multiple layers (deterministic + ML, or deterministic + LLM), don't double-deduct — increase the confidence on that finding. Deduction happens once at higher confidence.
5. **Chain findings supersede components.** When a behavior chain fires, the individual component findings' deductions are absorbed into the chain's deduction. No double-counting.
6. **LLM downgrade.** If an LLM targeted finding disputes a deterministic finding, the deterministic finding's deduction is reduced.
7. **Clamp to 0-100.**

**Verdict mapping:**

| Score | Verdict | Exit Code |
|-------|---------|-----------|
| 80-100 | SAFE | 0 |
| 60-79 | LOW RISK | 1 |
| 40-59 | MEDIUM RISK | 1 |
| 20-39 | HIGH RISK | 1 |
| 0-19 | CRITICAL | 1 |

**Formatter details:**

- **Console:** Grouped by file, then by severity (CRITICAL first). Color-coded severity. Each finding shows rule ID, category, message, file:line. Summary at bottom with counts by severity, category, and layer. Respects `--quiet` (exit code only) and `--verbose` (per-model scores, timing).
- **JSON:** Full `ScanResult` serialized. Stable schema for tooling.
- **SARIF:** Maps findings to SARIF `Result` objects with `ruleId`, `level`, `location`, `message`. Compatible with GitHub Code Scanning.
- **Delta mode** (R-11): `--baseline <previous-result.json>` loads a previous result and the formatter only shows new findings.

**Key design decisions:**

1. **Scoring is its own module.** The pipeline collects findings, then hands them to `scoring.py`. Testable and configurable independently.

2. **Formatters consume `ScanResult`, nothing else.** They don't know about detectors, models, or config. Adding a new format means writing one formatter.

**Acceptance criteria:**
- Risk score correctly aggregates with deductions, amplification, chain absorption, and LLM downgrade
- Suppression findings amplify other findings
- Cross-layer reinforcement doesn't double-deduct
- Console output is grouped, color-coded, readable
- JSON output has a stable, documented schema
- SARIF validates against SARIF 2.1.0 schema
- `--quiet` outputs nothing (exit code only)
- `--verbose` includes per-model scores and timing
- `--baseline` correctly shows only new findings
- Verdict and exit codes map correctly
- Discord/Telegram/Slack alerts fire when configured and findings exceed threshold
- Alert payloads include skill name, score, risk level, and top findings

**BRD coverage:** R-1 through R-11, CFG-10

---

## Epic 12 — Configuration System

**Purpose:** Build the full configuration system. Up to this point, config has been minimal defaults with CLI flag overrides. This epic makes everything configurable via YAML with proper merging, environment variable overrides, and validation.

**Modules updated:**
- `config.py` — Full implementation.

**Config precedence (highest wins):**
1. CLI flags
2. Environment variables (`SKILLINQUISITOR_*` prefix)
3. Project config (`.skillinquisitor/config.yaml`)
4. Global config (`~/.skillinquisitor/config.yaml`)
5. Built-in defaults

**Config schema:**

```yaml
# Device and performance
device: auto                    # auto | cpu | cuda | mps
scan_timeout_per_file: 30       # seconds
scan_timeout_total: 300         # seconds

# Detection layers
layers:
  deterministic:
    enabled: true
    checks:                     # Enable/disable individual checks by ID
      D-1: true
      D-2: true
      # ...
    categories:                 # Enable/disable entire categories
      steganography: true
      obfuscation: true
      # ...
  ml:
    enabled: true
    models:
      - id: meta-llama/Prompt-Guard-2-86M
        weight: 0.40
      - id: vijil/dome
        weight: 0.35
      # ...
    threshold: 0.5
  llm:
    enabled: true
    models:
      - id: Qwen/Qwen2.5-Coder-1.5B
        type: local
      # ...
    deep_analysis: false
    api:                        # For cloud-based inference
      provider: anthropic       # anthropic | openai
      model: claude-sonnet-4-20250514
      api_key_env: ANTHROPIC_API_KEY

# Scoring
scoring:
  weights:
    critical: 30
    high: 20
    medium: 10
    low: 5
  suppression_multiplier: 1.5
  chain_absorption: true

# Rules
custom_rules:
  - id: CUSTOM-1
    pattern: "some regex"
    severity: HIGH
    category: CUSTOM
    message: "Description of what was found"

# URLs
trusted_urls:
  - github.com
  - pypi.org
  # ...

# Alerting
alerts:
  discord_webhook: null
  telegram: null
  slack_webhook: null

# Model cache
model_cache_dir: ~/.skillinquisitor/models/

# Output
default_format: text            # text | json | sarif
default_severity: LOW           # Minimum severity to report
```

**Key design decisions:**

1. **Deep merge, not replace.** Project config merges into global at key level. Partial overrides don't clobber unrelated keys.

2. **Environment variable mapping is mechanical.** `SKILLINQUISITOR_DEVICE=cpu` -> `device: cpu`. `SKILLINQUISITOR_ML_ENABLED=false` -> `layers.ml.enabled: false`. Nested keys use underscores.

3. **Validation on load.** Unknown keys produce warnings (not errors, for forward compatibility). Invalid values produce errors with clear messages.

4. **CLI flag mapping.** `--checks D-1,D-2` enables only those checks. `--skip ml` disables ML. `--severity HIGH` sets minimum severity. CLI translates flags into config overrides.

**Acceptance criteria:**
- Global and project config files load and merge correctly
- CLI flags override config
- Environment variables override config files
- Deep merge works (partial overrides don't clobber)
- Unknown keys produce warnings
- Invalid values produce clear errors
- All BRD config requirements (CFG-1 through CFG-14) represented
- `--verbose` shows effective merged config

**BRD coverage:** CFG-1 through CFG-14

---

## Epic 13 — Agent Skill Interface

**Purpose:** Package SkillInquisitor as an installable agent skill for in-workflow scanning across agents that support the Agent Skills standard.

**Modules introduced:**
- `skill/SKILL.md` — Skill definition with YAML frontmatter and instructions
- `skill/scripts/scan.sh` (or `scan.py`) — Thin wrapper invoking `skillinquisitor scan`

**SKILL.md frontmatter:**

```yaml
---
name: skillinquisitor
description: Security scanner for AI agent skill files. Detects prompt injection, malicious code, obfuscation, credential theft, data exfiltration, and other threats before installation.
---
```

The body contains agent instructions: how to invoke, parameters, how to interpret results, pre-install check workflow.

**Key design decisions:**

1. **The skill invokes the CLI.** The agent runs `skillinquisitor scan <path> --format json` and parses JSON output. No separate Python API needed.

2. **JSON is the contract between CLI and skill.** The skill instructions tell the agent how to summarize JSON results for the user.

3. **The skill must pass its own scan** (BRD S-6). Verified in CI.

4. **Natural language invocation** (BRD SK-5). Description is specific enough to trigger on security scanning requests but not so broad it auto-invokes on unrelated tasks.

5. **Pre-install check mode** (BRD SK-7). Skill instructions guide the agent: "If the user is about to install a skill from an external source, offer to scan it first."

**Acceptance criteria:**
- SKILL.md conforms to the Agent Skills specification
- Skill can be installed into `.claude/skills/skillinquisitor/`
- `/skillinquisitor <path>` invokes the scanner from within an agent
- Natural language invocation works
- JSON output is correctly parsed and presented
- The skill's own files pass a SkillInquisitor scan
- Works across agents supporting the standard

**BRD coverage:** SK-1 through SK-7, S-6

---

## Epic 14 — Integrations (GitHub Actions & Pre-commit Hook)

**Purpose:** Build the two CI/CD integration points: a GitHub Action and a pre-commit hook.

**Files introduced:**
- GitHub Action definition (`.github/actions/skillinquisitor/action.yml` or published action)
- `hooks/pre-commit` — Pre-commit hook script
- `.pre-commit-hooks.yaml` — Hook definition for the pre-commit framework

**GitHub Action (BRD A-1):**

1. Detects changed files in skill directories (default: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, `.gemini/skills/` — configurable)
2. Runs `skillinquisitor scan` only on changed skill files
3. Outputs SARIF, uploads to GitHub Code Scanning
4. Fails check if findings exceed configurable severity threshold

```yaml
- uses: skillinquisitor/skillinquisitor-action@v1
  with:
    severity-threshold: HIGH
    skill-directories: |
      .claude/skills/
      .agents/skills/
    format: sarif
```

**Pre-commit hook (BRD A-2):**

1. Filters staged files to skill directories (same defaults, configurable)
2. Runs `skillinquisitor scan` on staged skill files only
3. Blocks commit if findings exceed threshold
4. Outputs findings to stderr

```yaml
- repo: https://github.com/skillinquisitor/skillinquisitor
  hooks:
    - id: skillinquisitor
      args: ['--severity', 'HIGH']
```

**Key design decisions:**

1. **Both scan only changed/staged files.** Full repo scans are expensive. CI catches new threats as introduced.

2. **Both use the same CLI.** No separate scanning logic.

3. **Severity threshold is the gate.** "Block on any CRITICAL finding" is clearer than score-based gating.

4. **GitHub Action defaults to deterministic-only.** No ML/LLM model downloads in CI unless explicitly configured.

**Acceptance criteria:**
- GitHub Action detects changed skill files in a PR
- GitHub Action produces valid SARIF and uploads to Code Scanning
- GitHub Action fails when findings exceed threshold
- Pre-commit hook filters staged files to skill directories
- Pre-commit hook blocks commit when findings exceed threshold
- Both use the standard CLI
- Both work deterministic-only

**BRD coverage:** A-1, A-2

---

## Epic 15 — Future / Stretch Epics

These are acknowledged for completeness but out of the initial build sequence. Each gets its own brainstorm cycle when the time comes.

**Known-Good Skill Registry (BRD 8.1):** SHA-256 hash registry of approved skills. Skip/fast-track scanning for known-good hashes. Import/export for team sharing.

**Skill Provenance Verification (BRD 8.2):** Verify GitHub repository owner against trusted authors list. Flag unverified authorship claims. Check for signed commits.

**Skill Diffing (BRD 8.3):** Compare updated skills against previous approved versions. Scan only the diff. Flag significant changes between versions (rug pull detection).

**Skill Capability Declaration & Enforcement (BRD 8.4):** Define capability model (network, file read, file write, exec). Analyze actual usage vs declared capabilities. Flag mismatches.

**Batch & Marketplace Scanning (BRD 8.5):** Scan entire marketplaces via manifest URL. Aggregate reports. Parallel scanning.

**Watch Mode & Continuous Monitoring (CLI-16, BRD 8.6):** CLI-16 (`--watch` flag) is a simple file watcher that re-scans on change — intentionally deferred from the core epics but simpler than the full continuous monitoring daemon described in BRD 8.6. The full daemon mode adds alerting on new/modified skills, background monitoring of multiple directories, and integration with system notification mechanisms.

**Cross-Skill Correlation (BRD 8.8):** Analyze multiple skills together. Detect name collisions. Detect skills that reference/modify other skills.

**Incremental Scanning (P-4):** Only re-scan files that changed since the last scan. Requires storing file hashes from previous runs and comparing on startup. Performance optimization that becomes important at scale but not needed for initial implementation where scan times are already under the P-3 target.

**Report History & Trending (BRD 8.9):** Store results locally. Compare to previous results. Detect regression.

---

## Build Sequence Summary

| # | Epic | Key Deliverable |
|---|------|-----------------|
| 1 | CLI Scaffold & Pipeline | Working `skillinquisitor scan`, file routing, config loading, empty pipeline |
| 2 | Benchmark Dataset & Evaluation | Test harness, starter dataset (~50 skills), per-layer metrics |
| 3 | Deterministic: Unicode & Steganography | Rule engine framework, normalization pipeline, hidden content detection |
| 4 | Deterministic: Encoding & Obfuscation | Base64/ROT13/hex/XOR decoding with recursive re-scanning |
| 5 | Deterministic: Secrets & Exfiltration | Credential detection, network patterns, behavior chain analysis |
| 6 | Deterministic: Injection & Suppression | Known injection patterns, jailbreak detection, suppression amplifier |
| 7 | Deterministic: Structural & Metadata | Directory validation, URL classification, typosquatting, file anomalies |
| 8 | Deterministic: Persistence & Cross-Agent | Time-bombs, persistence targets, cross-agent writes, auto-invocation abuse |
| 9 | ML Prompt Injection Ensemble | Sequential model loading, weighted voting, segment-level detection |
| 10 | LLM Code Analysis | General security analysis + targeted verification of deterministic findings |
| 11 | Risk Scoring & Output Formatters | Score aggregation, console/JSON/SARIF output, delta mode |
| 12 | Configuration System | Full YAML config with merging, env vars, validation |
| 13 | Agent Skill Interface | SKILL.md for in-agent scanning |
| 14 | Integrations | GitHub Action + pre-commit hook |
| 15+ | Future / Stretch | Registry, provenance, diffing, capabilities, batch, monitoring, correlation, trending |
