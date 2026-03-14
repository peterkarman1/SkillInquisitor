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
| A-1 | Support Discord webhook alerts for critical findings |
| A-2 | Support Telegram bot alerts for critical findings |
| A-3 | Support Slack webhook alerts for critical findings |
| A-4 | Support configurable alert thresholds (only alert at or above a given severity) |
| A-5 | Support GitHub Actions integration via exit codes and SARIF output |
| A-6 | Support a pre-commit hook mode for scanning skill files before they are committed |

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

This section describes the high-level architecture without implementation details.

### Detection Pipeline

```
Input (directory / GitHub URL / file)
         │
         ▼
┌─────────────────────────┐
│    Input Resolution      │
│  (clone, validate, list) │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│   Content Normalization  │
│  (unicode, decode, strip)│
└────────────┬────────────┘
             ▼
    ┌────────┴────────┐
    ▼                 ▼
┌────────┐    ┌──────────────┐
│ Text   │    │ Code Files   │
│ Files  │    │ (py,sh,js..) │
│(.md)   │    └──────┬───────┘
└───┬────┘           │
    │                │
    ▼                ▼
┌────────────┐  ┌────────────────┐
│ Layer 1:   │  │ Layer 1:       │
│ Determini- │  │ Deterministic  │
│ stic Text  │  │ Code Checks    │
│ Checks     │  │                │
└─────┬──────┘  └───────┬────────┘
      │                 │
      ▼                 ▼
┌────────────┐  ┌────────────────┐
│ Layer 2:   │  │ Layer 3:       │
│ ML Prompt  │  │ LLM Code       │
│ Injection  │  │ Analysis       │
│ Ensemble   │  │ (Judge Model)  │
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
- Multiple small classifier models run concurrently
- Each model produces a maliciousness probability (0.0-1.0)
- A judge model or weighted voting aggregates the results
- Default models should be small enough for CPU inference (sub-200M parameters each)
- Users can configure larger models for higher accuracy

**LLM Judge (Layer 3)** — For semantic code analysis:
- Multiple small code-capable models run concurrently
- Each model receives the code file and a structured security analysis prompt
- A judge aggregation compares outputs for consensus
- Default models should be small enough for CPU inference (sub-2B parameters)
- Users can configure larger models or API-based models for deeper analysis

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

## 13. Future Considerations

These items are not in scope for the initial release but should be considered for future versions.

- **Skill sandbox execution**: Run skill scripts in an isolated container and observe their actual behavior (dynamic analysis)
- **Community threat intelligence feed**: Shared database of known-malicious skill hashes, patterns, and indicators
- **IDE extension**: VS Code / JetBrains extension that scans skills as they are added to a project
- **API service**: Hosted scanning API for marketplace integration
- **Fine-tuned detection models**: Train custom models on the specific skill threat landscape rather than relying on general prompt injection classifiers
- **Automated remediation suggestions**: Suggest specific code changes to fix detected issues
- **Skill signing and verification**: Cryptographic signing of skill files with author verification

---

## 14. Glossary

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
