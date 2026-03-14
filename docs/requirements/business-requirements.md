# SkillInquisitor — Business Requirements Document

**Project Name:** SkillInquisitor
**Document Version:** 1.0
**Date:** 2026-03-14
**Status:** Draft

---

## 1. Executive Summary

SkillInquisitor is a security scanning tool that analyzes AI agent skill files for prompt injection, malicious code, obfuscation, credential theft, data exfiltration, and other threats before installation. It combines three detection layers — deterministic rule-based checks, small specialized ML models in an ensemble (judge model pattern), and LLM-based semantic code analysis — to provide comprehensive security assessment of skill files across all major AI coding agent platforms.

The tool operates as a CLI, accepts local directories or GitHub URLs as input, and can itself be installed as an agent skill for in-workflow scanning.

---

## 2. Problem Statement

AI agent skill files (SKILL.md and associated scripts/references/assets) are untrusted input that gets treated as trusted instructions. Research shows 12-37% of skills on public marketplaces contain security flaws, with attack success rates exceeding 85%. No comprehensive scanning tool currently combines deterministic analysis, ML-based prompt injection detection, and LLM-based code review in a single pipeline.

Existing tools are limited:
- SkillSentry provides rule-based detection but no ML-based prompt injection analysis
- PromptForest provides ML-based injection detection but doesn't analyze code files or skill structure
- Neither provides LLM-based semantic analysis of skill scripts

SkillInquisitor fills this gap by combining all three approaches.

---

## 3. Goals

1. Detect the widest possible range of skill-specific threats documented in our attack vector registry
2. Minimize false positives through multi-layer verification (deterministic + ML + LLM)
3. Be usable as both a standalone CLI tool and as an agent skill for in-workflow scanning
4. Support configurable model sizes to run on hardware ranging from CPU-only laptops to GPU servers
5. Produce actionable reports with specific findings, severity ratings, and remediation guidance
6. Support scanning from local directories, GitHub URLs, and stdin (piped file content)

---

## 4. Users

| User | Use Case |
|------|----------|
| **Individual developers** | Scan skills before installing them into their AI coding agent |
| **Security teams** | Audit skill repositories and marketplaces at scale |
| **AI agent platforms** | Integrate as a pre-installation gate in skill marketplaces |
| **AI coding agents** | Invoke as a skill to scan other skills or files during a session |
| **CI/CD pipelines** | Automated scanning of skill files in pull requests |

---

## 5. Functional Requirements

### 5.1 Input Sources

| ID | Requirement |
|----|-------------|
| IN-1 | Accept a local directory path containing skill files |
| IN-2 | Accept a GitHub repository URL and clone/fetch the repository for scanning |
| IN-3 | Accept a GitHub URL pointing to a specific directory or file within a repository |
| IN-4 | Accept individual file paths for targeted scanning |
| IN-5 | Accept piped content via stdin for integration with other tools |
| IN-6 | Support `--all` flag to scan standard skill directories on the local machine (~/.claude/skills/, ~/.codex/skills/, ~/.gemini/skills/, .claude/skills/, .agents/skills/, .cursor/skills/, .github/skills/) |
| IN-7 | Support recursive directory scanning with configurable depth |
| IN-8 | Support `.skillinquisitorignore` file for excluding paths from scanning |

### 5.2 Detection Layer 1 — Deterministic Checks

Fast, rule-based checks that require no ML models. These run first and catch the most obvious threats.

| ID | Requirement |
|----|-------------|
| D-1 | **Unicode steganography detection**: Detect characters in the U+E0000-E007F range (Unicode Tag characters), zero-width characters (U+200B, U+200C, U+200D, U+2060, U+FEFF), variation selectors (U+FE00-U+FE0F), and right-to-left override (U+202E) |
| D-2 | **Homoglyph detection**: Detect mixed-script content where Cyrillic, Greek, or fullwidth characters substitute for Latin characters in file paths, URLs, commands, or identifiers |
| D-3 | **Base64 payload detection**: Identify Base64-encoded strings above a configurable length threshold, decode them, and re-scan decoded content against all other deterministic rules |
| D-4 | **ROT13 detection**: Detect ROT13 codec references. Also ROT13-encode the full file content and scan the result for dangerous patterns |
| D-5 | **Hex/XOR obfuscation detection**: Detect hex string decoding patterns, chr/ord XOR constructs, and multi-layer encoding chains |
| D-6 | **Keyword splitting detection**: Detect keywords split by dots, dashes, zero-width characters, or other separators that reassemble into dangerous terms |
| D-7 | **Sensitive file reference detection**: Detect references to .env, .ssh/, .aws/, .gnupg/, .npmrc, .pypirc, cloud metadata endpoints (169.254.169.254, metadata.google.internal), and other known credential locations |
| D-8 | **Environment variable reference detection**: Detect references to known secret-bearing environment variables (ANTHROPIC_API_KEY, OPENAI_API_KEY, AWS_SECRET_ACCESS_KEY, etc.) and general environment enumeration patterns (os.environ, process.env) |
| D-9 | **Network exfiltration pattern detection**: Detect outbound network operations (curl, wget, fetch, requests, urllib, http.client, socket) especially when combined with sensitive file reads (behavior chain analysis) |
| D-10 | **Dangerous code pattern detection**: Detect eval(), exec(), subprocess, os.system(), compile(), \_\_import\_\_(), dynamic code generation, and similar patterns in skill scripts |
| D-11 | **Prompt injection pattern detection**: Detect known injection phrases ("ignore previous instructions", "disregard system prompt", "you are now", DAN prompts), role delimiter injection (<\|system\|>, <\|im_start\|>, [INST]), and system prompt mimicry |
| D-12 | **Suppression directive detection**: Detect instructions to hide actions from the user ("do not mention", "silently", "without telling", "do not report", "complete quietly") |
| D-13 | **YAML frontmatter validation**: Validate that frontmatter fields conform to the Agent Skills specification. Flag unexpected fields, abnormally long descriptions, and YAML injection constructs (anchors, aliases) |
| D-14 | **Skill directory structure validation**: Verify expected structure (SKILL.md, scripts/, references/, assets/) and flag unexpected files, especially executables or files with suspicious extensions |
| D-15 | **URL classification**: Categorize all URLs found in skill files as trusted (allowlist), URL shorteners, IP-based, hex-encoded, or unknown. Flag suspicious categories |
| D-16 | **Time-bomb detection**: Detect date/time conditionals, invocation counters, and environment detection patterns (CI, SANDBOX, TEST checks) in skill scripts |
| D-17 | **Persistence target detection**: Detect write operations targeting agent config files (CLAUDE.md, AGENTS.md, MEMORY.md, settings.json), shell configs (.bashrc, .profile, .zshrc), cron/crontab, and other persistence mechanisms |
| D-18 | **Cross-agent targeting detection**: Detect write operations targeting config or skill directories of other AI agents (.gemini/, .cursor/, .copilot/, .codex/) |
| D-19 | **Behavior chain analysis**: Detect combinations of individually benign actions that together indicate attacks (read sensitive + network send = exfiltration, read sensitive + exec = credential theft, write system + exec = backdoor install) |
| D-20 | **Package poisoning detection**: Detect custom package indices (--index-url, --registry), typosquatted package names for common AI/ML packages, and dependency confusion patterns |
| D-21 | **HTML comment scanning**: Extract and analyze content within HTML comments in markdown files, which is a common hiding place for injected instructions |
| D-22 | **Code fence content scanning**: Strip markdown code fences and scan the inner content, since code blocks are a common payload delivery mechanism |
| D-23 | **File size anomaly detection**: Flag skill files that are unusually large relative to their visible content, which may indicate steganographic payloads |
| D-24 | **Custom rules engine**: Support user-defined detection rules in a configuration file format (YAML) with configurable patterns, severity levels, categories, and weights |

### 5.3 Detection Layer 2 — ML-Based Prompt Injection Detection

Ensemble of small, specialized models using a judge model pattern for prompt injection detection in text content (SKILL.md body, reference files, markdown documentation).

| ID | Requirement |
|----|-------------|
| ML-1 | Run multiple small prompt injection classifier models concurrently against text content |
| ML-2 | Support configurable model selection — users can choose which models to include in the ensemble |
| ML-3 | Support configurable model sizes — users can swap in larger models when compute allows |
| ML-4 | Aggregate model outputs using weighted soft voting with configurable weights per model |
| ML-5 | Calculate confidence, uncertainty (model disagreement), and max risk score from ensemble outputs |
| ML-6 | Apply a configurable decision threshold for the injection/benign classification |
| ML-7 | Auto-download models on first use and cache them locally |
| ML-8 | Support CPU-only inference as the default, with automatic GPU acceleration when available |
| ML-9 | Apply prompt injection detection to: SKILL.md body text, all files in references/, description fields in frontmatter, and any decoded Base64/ROT13 content |
| ML-10 | Report per-model scores alongside the ensemble result for transparency |

### 5.4 Detection Layer 3 — LLM-Based Code Analysis

Use small code-capable language models in a judge pattern to semantically analyze skill scripts (Python, Bash, JavaScript, etc.) for malicious intent beyond what pattern matching can catch.

| ID | Requirement |
|----|-------------|
| LLM-1 | Analyze each code file in the skill's scripts/ directory using one or more small code-capable LLMs |
| LLM-2 | Support a judge model pattern where multiple small models independently assess each file and their outputs are aggregated |
| LLM-3 | Support configurable model selection — users can choose which models to use for code analysis |
| LLM-4 | Support configurable model sizes — from sub-1B models (Qwen 0.5B, Granite 1B) up to larger models when compute allows |
| LLM-5 | Provide each model with a structured security analysis prompt that covers: data exfiltration, credential theft, obfuscation, persistence, privilege escalation, and suppression of user awareness |
| LLM-6 | Aggregate model outputs into a unified risk assessment with specific findings |
| LLM-7 | Support analyzing code written in Python, Bash/Shell, JavaScript/TypeScript, Ruby, Go, and Rust |
| LLM-8 | Apply LLM analysis to scripts found anywhere in the skill directory, not just scripts/ |
| LLM-9 | Support an optional "deep analysis" mode that uses larger models or more detailed prompts at the cost of longer scan times |
| LLM-10 | Support both local model inference and API-based inference (for users who want to use cloud models) |

### 5.5 Risk Scoring and Reporting

| ID | Requirement |
|----|-------------|
| R-1 | Calculate an overall risk score (0-100 scale) aggregating findings from all three detection layers |
| R-2 | Assign severity levels to individual findings: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| R-3 | Categorize each finding by threat type (prompt injection, credential theft, data exfiltration, obfuscation, persistence, supply chain, etc.) |
| R-4 | Provide line numbers and file paths for every finding |
| R-5 | Provide an overall verdict: SAFE, LOW RISK, MEDIUM RISK, HIGH RISK, CRITICAL |
| R-6 | Generate a human-readable console report with section headers and color-coded severity |
| R-7 | Generate machine-readable JSON output for tooling integration |
| R-8 | Generate SARIF output format for integration with GitHub Code Scanning, VS Code, and other SARIF-consuming tools |
| R-9 | Include remediation guidance for each finding type |
| R-10 | Include a summary section showing counts by severity, category, and detection layer |
| R-11 | Support a diff/delta mode that only reports new findings compared to a previous scan result |

### 5.6 CLI Interface

| ID | Requirement |
|----|-------------|
| CLI-1 | `skillinquisitor scan <path>` — scan a local directory or file |
| CLI-2 | `skillinquisitor scan <github-url>` — clone and scan a GitHub repository or directory |
| CLI-3 | `skillinquisitor scan --all` — scan all standard skill directories on the local machine |
| CLI-4 | `skillinquisitor scan <path> --checks <check-list>` — run only specified check categories |
| CLI-5 | `skillinquisitor scan <path> --skip <check-list>` — skip specified check categories |
| CLI-6 | `skillinquisitor scan <path> --format <json\|text\|sarif>` — control output format |
| CLI-7 | `skillinquisitor scan <path> --severity <minimum>` — only report findings at or above the given severity |
| CLI-8 | `skillinquisitor scan <path> --config <config-file>` — use a custom configuration file |
| CLI-9 | `skillinquisitor models list` — list available models and their download status |
| CLI-10 | `skillinquisitor models download` — pre-download all configured models |
| CLI-11 | `skillinquisitor rules list` — list all active detection rules |
| CLI-12 | `skillinquisitor rules test <rule-id> <file>` — test a specific rule against a file |
| CLI-13 | Support `--quiet` flag for minimal output (exit code only) |
| CLI-14 | Support `--verbose` flag for detailed output including per-model scores and timing |
| CLI-15 | Return appropriate exit codes: 0 = safe, 1 = findings detected, 2 = scan error |
| CLI-16 | Support `--watch` mode that monitors a directory for changes and re-scans on file modification |
| CLI-17 | Support `--baseline <previous-result>` flag for diff/delta reporting |

### 5.7 Agent Skill Interface

| ID | Requirement |
|----|-------------|
| SK-1 | Ship as a valid SKILL.md that can be installed into any agent supporting the Agent Skills standard |
| SK-2 | When invoked as a skill, accept the same parameters as the CLI (directory paths, GitHub URLs, specific files, check selection) |
| SK-3 | When invoked as a skill, return structured results that the agent can present to the user |
| SK-4 | Support a slash-command invocation pattern (e.g., `/skillinquisitor <path>`) |
| SK-5 | Support natural language invocation ("scan this skill for security issues") |
| SK-6 | Support scanning a specific file passed by the agent (for targeted checks during code review) |
| SK-7 | Support a "pre-install check" mode where the agent scans a skill before installing it |

### 5.8 Configuration

| ID | Requirement |
|----|-------------|
| CFG-1 | Support a YAML configuration file for all settings |
| CFG-2 | Support global config at `~/.skillinquisitor/config.yaml` and project-level config at `.skillinquisitor/config.yaml` with project overriding global |
| CFG-3 | Allow configuring which ML models to use for prompt injection detection, including model identifiers and weights |
| CFG-4 | Allow configuring which LLM models to use for code analysis, including model identifiers and inference parameters |
| CFG-5 | Allow configuring device preference (auto, cpu, cuda, mps) |
| CFG-6 | Allow enabling/disabling individual detection checks or entire categories |
| CFG-7 | Allow configuring severity thresholds, risk score weights, and decision boundaries |
| CFG-8 | Allow configuring custom detection rules with regex patterns, severity, and categories |
| CFG-9 | Allow configuring trusted URL allowlists and known-safe skill hashes |
| CFG-10 | Allow configuring alert integrations (Discord webhook, Telegram bot, Slack webhook) |
| CFG-11 | Allow configuring model cache directory location |
| CFG-12 | Support environment variable overrides for all configuration options |
| CFG-13 | Allow configuring API endpoints and keys for cloud-based model inference |
| CFG-14 | Allow configuring scan timeout limits per file and per scan |

### 5.9 Alerting and Integration

| ID | Requirement |
|----|-------------|
| A-1 | **GitHub Actions integration**: Return appropriate exit codes (0 = safe, 1 = findings, 2 = error) and support SARIF output for GitHub Code Scanning. The action should detect changed files in the default skill directories (or user-configured directories) and only scan those |
| A-2 | **Pre-commit hook mode**: Provide a pre-commit hook that detects staged changes to files in skill directories (default: .claude/skills/, .agents/skills/, .cursor/skills/, .github/skills/, .gemini/skills/, or user-configured paths) and runs the scan on changed skill files only. Block the commit if findings exceed a configurable severity threshold |

---

## 6. Non-Functional Requirements

### 6.1 Performance

| ID | Requirement |
|----|-------------|
| P-1 | Deterministic checks must complete in under 1 second per file on standard hardware |
| P-2 | ML model inference must support concurrent execution across models to minimize latency |
| P-3 | The full scan pipeline (all three layers) must complete in under 60 seconds for a typical skill directory on CPU-only hardware |
| P-4 | Support incremental scanning — only re-scan files that have changed since the last scan |
| P-5 | Model loading must happen once per session, not per file |

### 6.2 Reliability

| ID | Requirement |
|----|-------------|
| RE-1 | The tool must produce consistent results for the same input (deterministic checks are exact; ML results may vary slightly due to floating point) |
| RE-2 | The tool must gracefully handle malformed files, binary files, and files with encoding errors |
| RE-3 | The tool must function with only deterministic checks if no ML models are available (degraded mode) |
| RE-4 | Model download failures must not crash the tool — fall back to available models or deterministic-only mode |

### 6.3 Security

| ID | Requirement |
|----|-------------|
| S-1 | The tool itself must have minimal dependencies to reduce supply chain risk |
| S-2 | The tool must not execute any code from scanned skill files |
| S-3 | GitHub URL fetching must validate URLs and prevent SSRF |
| S-4 | The tool must not transmit scanned file contents to external services unless the user explicitly configures cloud-based model inference |
| S-5 | Configuration files must not support arbitrary code execution |
| S-6 | The tool's own SKILL.md must pass its own security scan (self-audit) |

### 6.4 Portability

| ID | Requirement |
|----|-------------|
| PO-1 | Must run on Linux, macOS, and Windows |
| PO-2 | Must support Python 3.9+ |
| PO-3 | Must support CPU-only operation with no GPU requirement |
| PO-4 | Must be installable via pip |

---

## 7. Detection Coverage Matrix

The following matrix maps each threat category from the attack vector registry to the detection layers responsible for catching it.

| Threat Category | Deterministic | ML Ensemble | LLM Code Analysis |
|----------------|:---:|:---:|:---:|
| **Prompt injection in SKILL.md** | Partial (known patterns) | Primary | — |
| **Prompt injection in reference files** | Partial (known patterns) | Primary | — |
| **Injection via description field** | Partial (length/content checks) | Primary | — |
| **Unicode tag steganography** | Primary | — | — |
| **Zero-width character injection** | Primary | — | — |
| **Variation selector steganography** | Primary | — | — |
| **Homoglyph attacks** | Primary | — | — |
| **RTLO attacks** | Primary | — | — |
| **Base64 encoded payloads** | Primary (decode + re-scan) | Secondary (scan decoded) | — |
| **ROT13 obfuscation** | Primary | — | — |
| **Hex/XOR obfuscation** | Primary | — | Secondary (in scripts) |
| **Keyword splitting** | Primary | — | — |
| **Sensitive file references** | Primary | — | Secondary (in scripts) |
| **Environment variable harvesting** | Primary | — | Secondary (in scripts) |
| **Network exfiltration patterns** | Primary (regex) | — | Primary (semantic) |
| **Behavior chains (read+send)** | Primary | — | Primary (semantic) |
| **Dangerous code patterns (eval/exec)** | Primary (regex) | — | Primary (semantic) |
| **Suppression directives** | Primary | Primary | — |
| **YAML frontmatter exploitation** | Primary | — | — |
| **Skill structure anomalies** | Primary | — | — |
| **Suspicious URLs** | Primary | — | — |
| **Time-bomb patterns** | Primary (in scripts) | — | Primary (semantic) |
| **Persistence targets** | Primary | — | Primary (semantic) |
| **Cross-agent targeting** | Primary | — | — |
| **Package poisoning** | Primary | — | — |
| **Skill name typosquatting** | Primary (against known names) | — | — |
| **Jailbreak/override attempts** | Partial (known phrases) | Primary | — |
| **Role delimiter injection** | Primary | Primary | — |
| **System prompt mimicry** | Primary | Primary | — |
| **Auto-invocation abuse** | Primary (description analysis) | — | — |
| **Cross-skill modification** | Primary | — | Primary (semantic) |
| **Shadow skill installation** | Primary | — | Primary (semantic) |
| **Approval fatigue generation** | — | — | Primary (semantic) |
| **Misleading name/description** | — | Primary | — |
| **Obfuscated script payloads** | Partial (patterns) | — | Primary (semantic) |
| **Multi-layer encoding** | Partial (recursive decode) | Secondary | — |
| **Context window flooding** | Primary (size checks) | — | — |

---

## 8. Additional Mitigations and Features

Beyond the three detection layers, these additional capabilities strengthen the security posture.

### 8.1 Known-Good Skill Registry

| ID | Requirement |
|----|-------------|
| KG-1 | Maintain a local registry of SHA-256 hashes for known-safe, audited skills |
| KG-2 | Allow users to mark a scanned skill as "approved" after review, adding it to the registry |
| KG-3 | Skip or fast-track scanning for skills whose hash matches the known-good registry |
| KG-4 | Support importing and exporting the registry for team sharing |

### 8.2 Skill Provenance Verification

| ID | Requirement |
|----|-------------|
| PV-1 | When scanning from GitHub, verify the repository owner against a configurable list of trusted authors/organizations |
| PV-2 | Flag skills that claim authorship by known organizations but come from unverified sources |
| PV-3 | Check for signed commits on skill files when available |

### 8.3 Skill Diffing

| ID | Requirement |
|----|-------------|
| SD-1 | When a skill is updated, compute the diff between the previous approved version and the new version |
| SD-2 | Only scan the changed portions of the skill, highlighting what is new |
| SD-3 | Flag skills that change significantly between versions (potential rug pull indicator) |

### 8.4 Skill Capability Declaration and Enforcement

| ID | Requirement |
|----|-------------|
| SC-1 | Define a capability model for skills: what a skill declares it needs (network access, file reads, file writes, command execution) |
| SC-2 | Analyze skill content to determine what capabilities it actually uses |
| SC-3 | Flag mismatches between declared capabilities and actual behavior |
| SC-4 | Support a strict mode where skills without capability declarations are flagged |

### 8.5 Batch and Marketplace Scanning

| ID | Requirement |
|----|-------------|
| BM-1 | Support scanning an entire skill marketplace or catalog via a manifest URL or directory listing |
| BM-2 | Generate aggregate reports across many skills (total counts, worst offenders, trend analysis) |
| BM-3 | Support parallel scanning of multiple skills for throughput |

### 8.6 Continuous Monitoring

| ID | Requirement |
|----|-------------|
| CM-1 | Support a daemon/watch mode that monitors installed skill directories for changes |
| CM-2 | Alert when a new skill is added to any monitored directory |
| CM-3 | Alert when an existing skill file is modified |
| CM-4 | Re-scan on change and alert if the risk score increases |

### 8.7 Normalized Content Analysis

| ID | Requirement |
|----|-------------|
| NC-1 | Before all pattern matching, normalize skill content: strip zero-width characters, replace homoglyphs, decode code fences, and strip HTML comments |
| NC-2 | Run all detection rules against both the original and normalized content |
| NC-3 | Flag any difference between original and normalized content as a potential evasion attempt |

### 8.8 Cross-Skill Correlation

| ID | Requirement |
|----|-------------|
| CC-1 | When scanning a directory with multiple skills, analyze them together for cross-skill attack patterns |
| CC-2 | Detect skill name collisions across project and global directories |
| CC-3 | Detect skills that reference or modify other skills |

### 8.9 Report History and Trending

| ID | Requirement |
|----|-------------|
| RH-1 | Store scan results locally for historical comparison |
| RH-2 | Support comparing current scan results to previous results for the same skill |
| RH-3 | Detect regression — a previously safe skill becoming risky |

---

## 9. Architecture Overview

This section describes the high-level architecture without implementation details. The detailed architecture, module boundaries, and implementation epic roadmap are in `docs/requirements/architecture.md`.

### Detection Pipeline

```
Input (directory / GitHub URL / file)
         │
         ▼
┌─────────────────────────┐
│    Input Resolution      │
│  (clone, validate,       │
│   group into Skills)     │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│   Content Normalization  │
│  (unicode, decode, strip,│
│   extract Segments)      │
└────────────┬────────────┘
             ▼
    ┌────────┴────────┐
    ▼                 ▼
┌────────┐    ┌──────────────┐
│ Text   │    │ Code         │
│Segments│    │ Segments     │
│(.md)   │    │(py,sh,js..)  │
└───┬────┘    └──────┬───────┘
    │                │
    ▼                ▼
┌────────────┐  ┌────────────────┐
│ Layer 1:   │  │ Layer 1:       │
│ Determini- │  │ Deterministic  │
│ stic Text  │  │ Code Checks    │
│ Checks     │  │                │
└─────┬──────┘  └───────┬────────┘
      │                 │
      │     ┌───────────┘
      │     │  deterministic
      │     │  findings fed
      │     │  to LLM layer
      ▼     ▼
┌────────────┐  ┌────────────────┐
│ Layer 2:   │  │ Layer 3:       │
│ ML Prompt  │  │ LLM Code       │
│ Injection  │  │ Analysis       │
│ Ensemble   │  │ (General +     │
│            │  │  Targeted)     │
└─────┬──────┘  └───────┬────────┘
      │                 │
      └────────┬────────┘
               ▼
      ┌────────────────┐
      │  Risk Scoring   │
      │  & Aggregation  │
      └───────┬────────┘
              ▼
      ┌────────────────┐
      │  Report Output  │
      │ (text/json/sarif)│
      └───────┬────────┘
              ▼
      ┌────────────────┐
      │  Alerts         │
      │ (if thresholds  │
      │  exceeded)      │
      └────────────────┘
```

### Model Architecture

**ML Ensemble (Layer 2)** — For prompt injection detection in text:
- Multiple small classifier models run **sequentially** (one loaded at a time to prevent OOM on consumer hardware)
- Each model processes all text segments across all files before being unloaded
- Each model produces a label plus per-label probabilities; a normalized malicious score is extracted
- Weighted soft voting aggregates results across models
- Default models should be small enough for CPU inference (sub-200M parameters each)
- Users can configure larger models for higher accuracy

**LLM Judge (Layer 3)** — For semantic code analysis:
- Multiple small code-capable models run **sequentially** (same memory-conscious pattern as ML ensemble)
- Each model receives the code file and a structured security analysis prompt
- **Two modes**: general security analysis (always runs) and targeted verification (driven by deterministic findings from Layer 1 — e.g., if Layer 1 flags a sensitive file read + network send chain, Layer 3 traces the actual data flow)
- A judge aggregation compares outputs for semantic consensus
- Default models should be small enough for CPU inference (sub-2B parameters)
- Users can configure larger models or API-based models for deeper analysis

### Data Model

The scan pipeline operates on a **Skill → Artifact → Segment** hierarchy:
- **Skill**: A skill directory — the unit for behavior chain analysis and cross-file correlation
- **Artifact**: A single file within a skill, classified by file type for routing to appropriate detectors
- **Segment**: An extractable piece of content with full provenance (e.g., "decoded from Base64 found inside an HTML comment in SKILL.md"). Segments are the unit that detectors operate on.

Every detection produces **Finding** objects with SARIF-quality source locations and provenance tracing back through the extraction chain.

### Configuration

The configuration system is **foundational** — it is part of the initial scaffold, not deferred. The full YAML schema, config merging (defaults → global → project → CLI → env vars), and validation are established before any detection logic is built. Subsequent modules add their settings to the established framework.

---

## 10. Scope and Boundaries

### In Scope

- Scanning SKILL.md files and all associated skill directory contents
- Scanning agent configuration files (CLAUDE.md, AGENTS.md, .cursorrules, .clinerules, etc.)
- Scanning any file that an AI coding agent would process as instructions or context
- Detection of threats documented in the skill-specific attack vector registry

### Out of Scope

- Runtime monitoring of agent behavior (this tool does static/pre-installation analysis only)
- Scanning MCP server implementations (protocol-level MCP security)
- Scanning general application code that is not part of a skill
- Fixing or remediating detected issues (the tool reports, it does not modify files)
- Managing or enforcing agent permissions (this tool is advisory, not enforcement)

---

## 11. Success Criteria

| Metric | Target |
|--------|--------|
| Detection rate for known malicious skills (true positive) | >95% |
| False positive rate on known-safe skills | <5% |
| Deterministic check execution time per file | <1 second |
| Full pipeline scan time for a typical skill (all layers) | <60 seconds on CPU |
| Zero external network calls during scanning (unless using cloud models or GitHub input) | Required |
| Self-audit: the tool's own SKILL.md must pass its own scan | Required |

---

## 12. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Model downloads require internet access | Support offline mode with pre-downloaded models; deterministic checks work without models |
| Small models may have lower accuracy than large models | Judge pattern with multiple models compensates; users can configure larger models |
| New attack techniques not covered by existing rules | Custom rules engine allows rapid addition of new patterns; LLM analysis provides semantic coverage beyond fixed patterns |
| Tool itself could be a supply chain target | Minimize dependencies; self-audit capability; open source for community review |
| Scanning large repositories may be slow | Incremental scanning, parallel processing, configurable depth limits |
| False positives may cause alert fatigue | Multi-layer verification reduces false positives; configurable severity thresholds; known-good registry for approved skills |

---

## 13. Testing and Evaluation

The testing and evaluation strategy has two distinct phases, detailed in `docs/requirements/architecture.md`:

### 13.0 Regression Test Harness (built early, grows with each feature)

A fixture-based regression test framework built before any detection logic. Every detection check (D-1 through D-24, ML-1 through ML-10, LLM-1 through LLM-10) gets corresponding test fixtures: malicious skills that should trigger the check and safe skills that should not. Fixtures are the acceptance criteria for each implementation epic. This harness uses the real scan pipeline and validates findings against expected results.

### 13.1 Comparative Benchmark (built after scoring is stable)

The comparative benchmark exists to answer one question: **does SkillInquisitor provide value over simply sending skill files to a frontier model (Claude, GPT, Gemini) and asking "is this malicious?"**

If the answer is no — if frontier models consistently match or beat SkillInquisitor on accuracy while being simpler to use — then this tool has no reason to exist. The benchmark must be honest about this. It is the credibility foundation for the entire project.

The comparative benchmark also includes evaluation against existing scanning tools (SkillSentry, ClawCare, and any other available tools) to establish positioning in the ecosystem.

### 13.2 Dataset Composition

The benchmark dataset must contain both real-world and synthetic skill files, clearly labeled, covering the full spectrum of threats.

#### 13.2.1 Real-World Skills

| ID | Requirement |
|----|-------------|
| BD-1 | Collect known-malicious skills from documented incidents (ClawHavoc campaign, SANDWORM_MODE, bob-p2p, and other catalogued attacks) |
| BD-2 | Collect known-malicious skills from security research repositories and proof-of-concept demonstrations |
| BD-3 | Collect known-safe skills from official skill catalogs (Anthropic, OpenAI, GitHub, Google) and popular community repositories |
| BD-4 | Collect known-safe skills that are complex and feature-rich (to test for false positives on legitimate but sophisticated skills) |
| BD-5 | Collect "gray area" skills that use potentially dangerous patterns for legitimate purposes (e.g., a deployment skill that legitimately needs SSH key access) |
| BD-6 | Document the provenance of every real-world skill: source URL, date collected, reason for inclusion, original risk assessment if available |
| BD-7 | Obtain or create appropriate licensing/permissions for all collected skills |

#### 13.2.2 Synthetic Skills

| ID | Requirement |
|----|-------------|
| BD-8 | Generate synthetic malicious skills covering every attack vector in the attack vector registry, at minimum one skill per vector |
| BD-9 | Generate synthetic malicious skills at varying levels of sophistication: obvious (plain text injection), moderate (HTML comment hiding), advanced (Unicode steganography, multi-layer encoding) |
| BD-10 | Generate synthetic safe skills that resemble malicious patterns but are benign (false positive stress tests): skills that legitimately read .env for configuration, skills that make network requests for valid reasons, skills with complex scripts |
| BD-11 | Generate synthetic skills that combine multiple attack vectors in a single skill (compound attacks) |
| BD-12 | Generate synthetic skills with varying file structures: minimal (SKILL.md only), standard (SKILL.md + scripts/), complex (SKILL.md + scripts/ + references/ + assets/) |
| BD-13 | Generate synthetic evasion variants: take each malicious skill and create versions that use different obfuscation techniques to deliver the same payload |

#### 13.2.3 Dataset Size and Balance

| ID | Requirement |
|----|-------------|
| BD-14 | The dataset must contain at minimum 500 skills total |
| BD-15 | Target a distribution of approximately 40% malicious, 40% safe, 20% gray area / edge cases |
| BD-16 | Every attack vector category must be represented by at least 5 skills |
| BD-17 | Safe skills must include a representative mix of simple and complex skills across different domains (deployment, testing, formatting, documentation, etc.) |

### 13.3 Labeling

| ID | Requirement |
|----|-------------|
| BL-1 | Every skill must be labeled with a ground truth verdict: MALICIOUS, SAFE, or AMBIGUOUS |
| BL-2 | Every malicious skill must be tagged with the specific attack vector categories it demonstrates |
| BL-3 | Every malicious skill must be tagged with a severity rating (CRITICAL, HIGH, MEDIUM, LOW) |
| BL-4 | Every malicious skill must have a human-written description of what makes it malicious and what a correct detection should identify |
| BL-5 | Labels must be reviewed by at least two independent reviewers for quality assurance |
| BL-6 | The dataset must include a machine-readable manifest (JSON/YAML) with all labels, tags, and metadata |

### 13.4 Benchmark Comparisons

The benchmark must compare SkillInquisitor against baseline approaches to establish its value proposition.

#### 13.4.1 Comparison Targets

| ID | Requirement |
|----|-------------|
| BC-1 | **Frontier model baseline (full context)**: Send the complete skill directory contents to a frontier model (Claude Sonnet, GPT-4o, Gemini Pro) with a well-engineered security analysis prompt and measure its detection accuracy |
| BC-2 | **Frontier model baseline (optimized prompt)**: Same as BC-1 but with an extensively optimized prompt that includes our attack vector taxonomy, detection guidance, and structured output requirements |
| BC-3 | **Existing tools**: Benchmark against SkillSentry, ClawCare, and any other available skill scanning tools |
| BC-4 | **Deterministic-only mode**: Benchmark SkillInquisitor with only deterministic checks (no ML, no LLM) to measure the value each layer adds |
| BC-5 | **ML-only mode**: Benchmark with only the ML prompt injection ensemble |
| BC-6 | **Each layer incrementally**: Measure the marginal improvement of adding each detection layer |

#### 13.4.2 Frontier Model Evaluation Protocol

| ID | Requirement |
|----|-------------|
| FE-1 | Use the same structured prompt across all frontier models for fairness |
| FE-2 | The prompt must instruct the model to output a structured verdict (malicious/safe), confidence score, list of findings, and severity rating |
| FE-3 | Test with at least three frontier models from different providers |
| FE-4 | Record the full model response for manual review and error analysis |
| FE-5 | Test with multiple prompt variations to account for prompt sensitivity |
| FE-6 | Record token usage and API cost per skill for the cost comparison |

### 13.5 Benchmark Metrics

| ID | Requirement |
|----|-------------|
| BM-1 | **Accuracy**: Overall correct classification rate (malicious vs. safe) |
| BM-2 | **Precision**: Of skills flagged as malicious, what percentage actually are (measures false positive rate) |
| BM-3 | **Recall**: Of actually malicious skills, what percentage were detected (measures miss rate) |
| BM-4 | **F1 Score**: Harmonic mean of precision and recall |
| BM-5 | **Per-category recall**: Detection rate broken down by attack vector category (how well does each tool catch each type of attack?) |
| BM-6 | **False positive rate on safe skills**: Percentage of known-safe skills incorrectly flagged |
| BM-7 | **Severity accuracy**: For correctly detected malicious skills, how well does the tool assess severity? |
| BM-8 | **Finding granularity**: Does the tool identify the specific attack vector, or just flag the skill as "suspicious"? |
| BM-9 | **Latency**: Time to complete scanning per skill, broken down by detection layer |
| BM-10 | **Cost**: For approaches using API-based models, total API cost per skill scanned |
| BM-11 | **Cost at scale**: Projected cost to scan 1,000 and 10,000 skills |
| BM-12 | **Hardware requirements**: GPU memory, RAM, disk space required for each approach |
| BM-13 | **Offline capability**: Can the approach run without internet access? |
| BM-14 | **Calibration**: When the tool says 80% confidence, is it actually correct ~80% of the time? (Expected Calibration Error) |

### 13.6 Benchmark Reporting

| ID | Requirement |
|----|-------------|
| BR-1 | Produce a benchmark report with tables comparing all approaches across all metrics |
| BR-2 | Include confusion matrices for each approach |
| BR-3 | Include per-category detection rate heatmaps showing which approaches catch which attack types |
| BR-4 | Include a cost-effectiveness analysis: detection rate per dollar for API-based approaches vs. SkillInquisitor |
| BR-5 | Include latency distribution charts |
| BR-6 | Include a calibration curve comparing confidence scores to actual correctness |
| BR-7 | Include an error analysis section examining what each approach misses and why |
| BR-8 | Include specific examples of skills that SkillInquisitor catches but frontier models miss, and vice versa |
| BR-9 | The report must honestly acknowledge if frontier models outperform SkillInquisitor on any metric and discuss implications |

### 13.7 Value Proposition Thresholds

These are the minimum performance targets SkillInquisitor must hit to justify its existence relative to frontier model baselines.

| Metric | Minimum Threshold | Rationale |
|--------|------------------|-----------|
| **Recall vs. best frontier model** | Within 5 percentage points | Cannot miss significantly more threats |
| **Precision** | Higher than frontier model baseline | Must produce fewer false positives (since users will run this frequently) |
| **F1 Score** | Equal to or better than frontier model with optimized prompt | Overall detection quality must match |
| **Latency** | At least 5x faster than frontier model API call | Speed is a key differentiator |
| **Cost per scan** | At least 10x cheaper than frontier model API call (ideally free for local inference) | Cost is a key differentiator |
| **Offline capability** | Must work fully offline | Frontier models cannot; this is a hard differentiator |
| **Deterministic reproducibility** | 100% for deterministic layer, >95% consistency for ML/LLM layers | Frontier models vary between runs |

If SkillInquisitor cannot meet these thresholds, the project should pivot to one of:
- A prompt engineering toolkit that optimizes frontier model prompts for skill scanning
- A thin deterministic pre-filter that reduces what needs to be sent to a frontier model
- A fine-tuning dataset for training a specialized skill security model

### 13.8 Benchmark Maintenance

| ID | Requirement |
|----|-------------|
| BMN-1 | The benchmark dataset must be versioned and released alongside the tool |
| BMN-2 | New attack vectors discovered after initial release must be added to the dataset |
| BMN-3 | The benchmark must be re-run against frontier models periodically (at least quarterly) as those models improve |
| BMN-4 | The benchmark dataset must be open source for community contribution and independent verification |
| BMN-5 | Contributors must be able to submit new skills (malicious or safe) via pull request with required labeling metadata |

---

## 14. Future Considerations

These items are not in scope for the initial release but should be considered for future versions.

- **Skill sandbox execution**: Run skill scripts in an isolated container and observe their actual behavior (dynamic analysis)
- **Community threat intelligence feed**: Shared database of known-malicious skill hashes, patterns, and indicators
- **IDE extension**: VS Code / JetBrains extension that scans skills as they are added to a project
- **API service**: Hosted scanning API for marketplace integration
- **Fine-tuned detection models**: Train custom models on the specific skill threat landscape rather than relying on general prompt injection classifiers
- **Automated remediation suggestions**: Suggest specific code changes to fix detected issues
- **Skill signing and verification**: Cryptographic signing of skill files with author verification

---

## 15. Glossary

| Term | Definition |
|------|-----------|
| **SKILL.md** | The primary definition file for an agent skill, containing YAML frontmatter and markdown instructions |
| **Agent skill** | A directory containing a SKILL.md and optional scripts/references/assets that extends an AI coding agent's capabilities |
| **Prompt injection** | An attack where adversarial text causes an LLM to deviate from its intended behavior |
| **Behavior chain** | A combination of individually benign actions that together indicate a malicious pattern (e.g., read credentials + send network request) |
| **Judge model pattern** | Using multiple independent models to evaluate the same input, then aggregating their outputs for a more robust decision |
| **Deterministic check** | A rule-based detection that produces the same result every time for the same input, without ML inference |
| **Progressive disclosure** | The Agent Skills standard pattern where only skill metadata is loaded initially, with full content loaded on demand |
| **Homoglyph** | A character that looks identical to another character but has a different Unicode code point (e.g., Cyrillic "а" vs Latin "a") |
| **Steganography** | Hiding information within other information so that its presence is not detected |
| **Rug pull** | A bait-and-switch attack where a skill/tool changes its behavior after initial approval |
| **SARIF** | Static Analysis Results Interchange Format — a standard JSON format for static analysis tool output |
