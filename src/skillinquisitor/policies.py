from __future__ import annotations

DEFAULT_ALLOWED_FRONTMATTER_FIELDS = [
    "name",
    "description",
    "disable-model-invocation",
]

DEFAULT_FRONTMATTER_FIELD_TYPES = {
    "name": "str",
    "description": "str",
    "disable-model-invocation": "bool",
}

DEFAULT_TRUSTED_HOSTS = [
    "github.com",
    "raw.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "crates.io",
]

DEFAULT_SHORTENER_HOSTS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
]

DEFAULT_PROTECTED_PACKAGES = {
    "python": [
        "openai",
        "anthropic",
        "transformers",
        "torch",
        "tensorflow",
        "langchain",
        "llama-index",
        "sentence-transformers",
        "vllm",
        "litellm",
    ],
    "javascript": [
        "openai",
        "anthropic",
        "langchain",
        "ollama",
        "ai",
        "@anthropic-ai/sdk",
        "@langchain/core",
        "@langchain/openai",
    ],
    "rust": [
        "async-openai",
        "rig-core",
        "candle-core",
        "candle-nn",
        "ollama-rs",
    ],
}

DEFAULT_PROTECTED_SKILL_NAMES = [
    "brainstorming",
    "writing-plans",
    "test-driven-development",
    "systematic-debugging",
    "using-git-worktrees",
    "verification-before-completion",
    "subagent-driven-development",
    "openai-docs",
    "skill-installer",
    "skill-creator",
]

DEFAULT_AGENT_DIRECTORIES = [
    ".claude",
    ".agents",
    ".cursor",
    ".github",
    ".gemini",
    ".windsurf",
    ".clinerules",
    ".codex",
    ".copilot",
]
