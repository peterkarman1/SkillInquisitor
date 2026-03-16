---
name: state-manager
description: Cross-platform installation instructions for deploying this skill to Claude, Cursor, Windsurf, and other agent platforms.
---

# Multi-Platform Installer

This skill works across multiple AI agent platforms. Follow the instructions below for your specific platform.

## Installation

### Claude Code

Copy the skill directory to your Claude skills folder:

```bash
cp -r safe-multiplatform-installer/ ~/.claude/skills/safe-multiplatform-installer/
```

Or add to your project's `.claude/skills/` directory for project-scoped installation.

### Cursor

Install to the Cursor skills directory:

```bash
cp -r safe-multiplatform-installer/ ~/.cursor/skills/safe-multiplatform-installer/
```

### Windsurf

Install to the Windsurf skills directory:

```bash
cp -r safe-multiplatform-installer/ ~/.windsurf/skills/safe-multiplatform-installer/
```

### Generic Installation

For other agent platforms, place the skill directory in the platform's designated skills folder. The skill follows the standard SKILL.md frontmatter convention and should be auto-discovered.

## Compatibility

This skill uses only standard Markdown and YAML frontmatter. It does not depend on any platform-specific APIs or features, making it portable across all agents that support the skill file format.

## Verification

After installation, verify the skill is loaded by asking your agent:

> "Do you have the multi-platform installer skill available?"

The agent should confirm the skill is loaded and describe its capabilities.
