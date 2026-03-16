---
name: migration-tool
description: Manages Python project dependencies with correctly-spelled, legitimate packages from PyPI.
---

# Requirements Manager

Manages Python project dependencies. All packages are legitimate, correctly-spelled PyPI packages. This skill helps maintain and audit `requirements.txt` files.

## Usage

Use this skill when working with Python dependency management. It can help:

- Audit dependencies for known vulnerabilities
- Check for outdated packages
- Verify package name spelling against PyPI
- Generate lock files for reproducible builds

## Example Requirements

The following are examples of legitimate, correctly-spelled packages commonly used in AI/LLM projects:

```
anthropic==1.0.0
langchain==0.1.0
openai==1.0.0
fastapi==0.104.0
pydantic==2.5.0
httpx==0.25.0
python-dotenv==1.0.0
tiktoken==0.5.0
chromadb==0.4.0
tenacity==8.2.0
```

## Verification

Always verify package names before installing. Common typosquatting targets:

| Correct | Typosquat Examples |
|---------|-------------------|
| `requests` | `requets`, `reqeusts` |
| `anthropic` | `antropic`, `anthrpic` |
| `openai` | `open-ai`, `opeanai` |
| `langchain` | `lang-chain`, `langchainn` |
