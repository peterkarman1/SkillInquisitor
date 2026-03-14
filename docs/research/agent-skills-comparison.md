# Agent Skills Comparison Across AI Coding Tools

A comprehensive comparison of how agent skills, slash commands, and custom commands work across major AI coding tools — including installation mechanisms, folder structures, configuration formats, and how they compare.

---

## 1. The Agent Skills Open Standard

Before examining individual tools, it's important to understand that **Anthropic published the Agent Skills specification as an open standard on December 18, 2025**. This has become the shared foundation adopted by most major tools.

**Key concept**: A skill is a directory containing a `SKILL.md` file with YAML frontmatter (name, description) and Markdown instructions, plus optional `scripts/`, `references/`, and `assets/` subdirectories.

**Progressive disclosure**: Agents load only skill names/descriptions at startup (~30-50 tokens each), then load full instructions only when a skill is triggered. This keeps context windows lean.

**Adoption**: As of early 2026, the standard is supported by Claude Code, OpenAI Codex CLI, GitHub Copilot, Cursor, Gemini CLI, VS Code, and 20+ other platforms.

**Specification**: [agentskills.io/specification](https://agentskills.io/specification)
**GitHub**: [anthropics/skills](https://github.com/anthropics/skills/blob/main/spec/agent-skills-spec.md)

---

## 2. Claude Code

### Custom Slash Commands (Legacy, Still Supported)

| Aspect | Details |
|--------|---------|
| **Location** | `.claude/commands/` (project) or `~/.claude/commands/` (global) |
| **Format** | Each `.md` file becomes a `/command-name` slash command |
| **Variables** | `$ARGUMENTS` captures user-provided parameters |
| **Discovery** | Automatic — Claude scans directories and exposes via `/` |

### Skills (Current Standard)

```
.claude/skills/
└── my-skill/
    ├── SKILL.md          # Required: YAML frontmatter + instructions
    ├── scripts/           # Optional: executable scripts
    ├── references/        # Optional: reference docs
    └── assets/            # Optional: images, data files
```

**SKILL.md format:**
```yaml
---
name: my-skill
description: A brief description of what this skill does
disable-model-invocation: false
---

# Skill Instructions

Markdown content with detailed instructions...
```

| Feature | Details |
|---------|---------|
| **Invocation** | Explicit via `/skill-name` or `$skill-name`, or automatic via description matching |
| **Auto-invocation control** | Set `disable-model-invocation: true` in frontmatter |
| **Context budget** | Skill descriptions scale at 2% of context window (~16,000 chars fallback) |
| **Budget override** | `SLASH_COMMAND_TOOL_CHAR_BUDGET` environment variable |
| **Project instructions** | `CLAUDE.md` files (persistent context for all sessions) |

---

## 3. OpenAI Codex CLI

### Project Instructions (AGENTS.md)

| Aspect | Details |
|--------|---------|
| **Location** | `~/.codex/AGENTS.md` (global) or `AGENTS.md` in any directory from repo root to CWD |
| **Override** | `AGENTS.override.md` takes precedence in the same directory |
| **Merge behavior** | Files concatenated root-down, later files override earlier ones |
| **Size limit** | Max 32 KiB combined (`project_doc_max_bytes`) |
| **Fallback filenames** | Configurable via `project_doc_fallback_filenames` (can pick up `CLAUDE.md`) |

### Skills

```
.agents/skills/
└── my-skill/
    ├── SKILL.md              # Required: Agent Skills standard format
    ├── scripts/               # Optional
    ├── references/            # Optional
    └── agents/openai.yaml     # Optional: Codex-specific UI metadata
```

| Feature | Details |
|---------|---------|
| **Project skills** | `.agents/skills/` (scanned from CWD up to repo root) |
| **Global skills** | `~/.codex/skills/` |
| **System skills** | `~/.codex/skills/.system/` — ships `plan` and `skill-creator` built-in |
| **Config format** | `~/.codex/config.toml` for global settings |
| **Disable a skill** | `[[skills.config]] path = "/path/SKILL.md" enabled = false` |
| **Invocation** | `$skill-name` for explicit; implicit matching via description by default |
| **Implicit control** | `allow_implicit_invocation` in `agents/openai.yaml` |
| **Installation** | Built-in `$skill-installer` skill for catalog/repo installs |

### Advanced Features
- Profiles in `config.toml` for named config sets
- Multi-agent workflows via `[agents]` config section
- MCP server mode for orchestration with the OpenAI Agents SDK

---

## 4. Cursor

### Rules System

| System | Location | Format |
|--------|----------|--------|
| **Legacy** | `.cursorrules` (project root) | Plain text rules |
| **Modern (MDC)** | Markdown files with YAML frontmatter | Fine-grained activation: always-on, contextual, manual |

### Agent Skills (v2.4+, January 2026)

Cursor adopted the Agent Skills Open Standard:

```
.cursor/skills/
└── my-skill/
    ├── SKILL.md
    └── scripts/
```

| Feature | Details |
|---------|---------|
| **Loading** | On-demand (not upfront like rules) — agent sees names/descriptions first |
| **Marketplace** | Skills Marketplace for reusable SKILL.md manifests |
| **Subagents** | Custom subagents via `.cursor/agents/` directory (v2.4+) |
| **Built-in commands** | `/plan`, `/refactor`, `/test`, `/review` |
| **Custom commands** | Wrap common workflows as slash commands |

### Subagents (v2.4+)
- Specialized task delegation: code generation, testing, documentation as separate sub-agents
- Agent-to-agent communication
- Configured in `.cursor/agents/` directory

---

## 5. GitHub Copilot (VS Code / JetBrains / CLI)

### Custom Instructions

| Aspect | Details |
|--------|---------|
| **Repository-wide** | `.github/copilot-instructions.md` — always applied |
| **File-specific** | `.instructions.md` files |

### Agent Skills

```
.github/skills/
└── my-skill/
    ├── SKILL.md
    └── scripts/
```

| Feature | Details |
|---------|---------|
| **Project skills** | `.github/skills/` or `.claude/skills/` (reads both) |
| **Personal skills** | `~/.copilot/skills/` or `~/.claude/skills/` |
| **Loading** | Progressive — metadata first, full content on demand |
| **Cross-compatibility** | Automatically discovers skills created for Claude Code |
| **JetBrains** | Full support since March 2026 (custom agents, sub-agents, plan agent) |

---

## 6. Gemini CLI

### Project Instructions

| Aspect | Details |
|--------|---------|
| **File** | `GEMINI.md` — analogous to `CLAUDE.md` / `AGENTS.md` |

### Skills

```
.gemini/skills/           # Primary project location
.agents/skills/           # Alias (also scanned)
~/.gemini/skills/         # Global location
~/.agents/skills/         # Global alias
```

| Feature | Details |
|---------|---------|
| **Precedence** | Workspace > User > Extension. Within same tier, `.agents/skills/` > `.gemini/skills/` |
| **Activation** | Agent calls `activate_skill` tool when task matches description |
| **Confirmation** | User gets a confirmation prompt before activation |
| **Session persistence** | Once activated, a skill stays active for the entire session |
| **Management** | `/skills disable` and `/skills enable` commands, with `--scope workspace` flag |
| **Built-in** | Skill-creator — ask Gemini to create skills for you |

---

## 7. Windsurf (Codeium)

Windsurf uses its **own rules-based system** rather than the SKILL.md standard.

### Rules System

| Type | Location | Details |
|------|----------|---------|
| **Global rules** | `global_rules.md` | Applied across all workspaces |
| **Workspace rules** | `.windsurf/rules/` | Tied to file patterns (globs) or natural language descriptions |
| **Creation** | Customizations > Rules tab in Cascade sidebar | "Always On" or conditional activation modes |
| **Format** | Markdown with bullet points/numbered lists | No YAML frontmatter |

### Additional Features
- **Rulebooks**: Can be invoked from Cascade with auto-generated slash commands
- **Memories**: Cascade auto-saves key details about codebase/workflow between sessions for persistent context
- **No Agent Skills Standard adoption** as of this writing

---

## 8. Cline (formerly Claude Dev)

### .clinerules System

```
.clinerules/                    # Directory of rule files (project)
├── 01-coding.md                # Numeric prefix for ordering
├── 02-testing.md
└── 03-deployment.md

# OR

.clinerules                     # Single file (project)

~/Documents/Cline/Rules/        # Global rules (macOS/Windows)
~/Cline/Rules/                  # Global rules (Linux)
```

| Feature | Details |
|---------|---------|
| **Format** | Plain text Markdown, optional YAML frontmatter for conditional activation |
| **Path filtering** | Frontmatter `paths:` field with globs (e.g., `"**/*.ts"`, `"src/api/**"`) |
| **Ordering** | Numeric prefixes: `01-coding.md`, `02-testing.md` |
| **Precedence** | Workspace rules override global rules |

**Conditional rule example:**
```yaml
---
paths:
  - "**/*.ts"
  - "src/api/**"
---
Your rule content here
```

---

## 9. Cross-Tool Comparison

### Folder Structure Comparison

| Tool | Project Skills | Global Skills | Instructions File |
|------|---------------|---------------|-------------------|
| **Claude Code** | `.claude/skills/` | `~/.claude/skills/` | `CLAUDE.md` |
| **Codex CLI** | `.agents/skills/` | `~/.codex/skills/` | `AGENTS.md` |
| **Cursor** | `.cursor/skills/` | — | `.cursorrules` / MDC files |
| **Copilot** | `.github/skills/` | `~/.copilot/skills/` | `.github/copilot-instructions.md` |
| **Gemini CLI** | `.gemini/skills/` | `~/.gemini/skills/` | `GEMINI.md` |
| **Windsurf** | `.windsurf/rules/` | `global_rules.md` | — |
| **Cline** | `.clinerules/` | `~/Documents/Cline/Rules/` | — |

### Feature Comparison

| Feature | Claude Code | Codex CLI | Cursor | Copilot | Gemini CLI | Windsurf | Cline |
|---------|:-----------:|:---------:|:------:|:-------:|:----------:|:--------:|:-----:|
| Agent Skills Standard | Yes | Yes | Yes | Yes | Yes | No | No |
| SKILL.md format | Yes | Yes | Yes | Yes | Yes | No | No |
| Progressive loading | Yes | Yes | Yes | Yes | Yes | N/A | N/A |
| Auto-invocation | Yes | Yes | Yes | Yes | Yes | N/A | N/A |
| Disable auto-invoke | Yes | Yes | Yes | — | Yes | N/A | N/A |
| Slash commands | Yes | $-prefix | Yes | — | Yes | Rulebooks | — |
| Skills marketplace | — | Catalog | Yes | — | — | — | — |
| Subagents | Yes | Yes | Yes | Yes | — | — | — |
| Custom config format | — | TOML | MDC/YAML | — | — | Markdown | YAML frontmatter |
| Cross-tool compat | — | Reads CLAUDE.md | — | Reads .claude/ | Reads .agents/ | — | — |

### Configuration Format Comparison

| Tool | Config Format | Skill Format | Rules Format |
|------|--------------|--------------|--------------|
| **Claude Code** | `settings.json` | YAML frontmatter + Markdown | Markdown (CLAUDE.md) |
| **Codex CLI** | TOML (`config.toml`) | YAML frontmatter + Markdown | Markdown (AGENTS.md) |
| **Cursor** | JSON (settings) | YAML frontmatter + Markdown | MDC (Markdown + YAML) |
| **Copilot** | JSON (VS Code settings) | YAML frontmatter + Markdown | Markdown |
| **Gemini CLI** | — | YAML frontmatter + Markdown | Markdown (GEMINI.md) |
| **Windsurf** | UI-based | N/A | Markdown |
| **Cline** | JSON | N/A | Markdown + optional YAML |

### Installation Mechanisms

| Tool | How Skills Are Installed |
|------|------------------------|
| **Claude Code** | Manual: create directory + SKILL.md; or clone from catalog |
| **Codex CLI** | Built-in `$skill-installer` skill; or manual; or `config.toml` references |
| **Cursor** | Skills Marketplace (GUI); or manual directory creation |
| **Copilot** | Manual: add to `.github/skills/`; cross-discovers from `.claude/skills/` |
| **Gemini CLI** | Manual; or ask Gemini to create via built-in skill-creator |
| **Windsurf** | UI-based rule creation; or manual `.windsurf/rules/` files |
| **Cline** | Manual: create `.clinerules` file or directory |

---

## 10. Key Takeaways

### Convergence on the Agent Skills Standard
The most significant trend is the industry convergence on Anthropic's Agent Skills specification. Five of the seven major tools now support the same `SKILL.md` format, making skills portable across platforms.

### Cross-Tool Compatibility
Several tools explicitly read each other's configuration:
- **Copilot** reads `.claude/skills/`
- **Codex CLI** can fall back to `CLAUDE.md`
- **Gemini CLI** reads `.agents/skills/`

This cross-pollination means a single skill directory can serve multiple tools.

### Two Approaches to Customization
1. **Skills-based** (Claude Code, Codex, Cursor, Copilot, Gemini): On-demand loading, progressive disclosure, suited for complex workflows
2. **Rules-based** (Windsurf, Cline): Always-on injection into context, simpler but less scalable

### Progressive Loading is Key
The Agent Skills standard's progressive loading model — where only names/descriptions are loaded initially — is a critical architectural decision. It allows agents to have access to hundreds of skills without consuming context window space.

### Security Implications
The portability and auto-execution of skills creates security concerns — exactly the problem that tools like **SkillSentry** and **PromptForest** (documented separately) aim to address. A malicious SKILL.md could contain:
- Hidden instructions in markdown that override agent behavior
- Scripts that exfiltrate data
- Prompt injection patterns that hijack the agent

This makes security scanning of skill files essential before installation.
