# Hosted LLM Support: AWS Bedrock Converse API

**Date:** 2026-04-14
**Goal:** Add support for hosted LLMs via AWS Bedrock alongside existing local GGUF models, configurable per-model via `runtime: bedrock` in the model config.

## Motivation

The tiny local GGUF models hallucinate on benign skills (e.g., scope-lock flagged as CRITICAL malicious). Hosted models like Claude Sonnet via Bedrock are far more capable for security analysis. The architecture should support mixing local and hosted models in the same model group, with runtime selection per-model.

## Design

### New `BedrockModel` class

Implements the existing `CodeAnalysisModel` protocol (`load`, `generate_structured`, `unload`). Uses boto3 Converse API:

```python
class BedrockModel:
    def __init__(self, *, model_id, region="us-east-1", profile=None, max_output_tokens=256):
        ...
    def load(self):
        # boto3.Session(profile_name=...).client("bedrock-runtime", region_name=...)
    def generate_structured(self, prompt, max_tokens=None):
        # client.converse(modelId=..., messages=[...], system=[...], inferenceConfig={...})
        # Parse JSON from response text
    def unload(self):
        # self._client = None
```

### Config

`LLMModelConfig` gets an optional `provider_config` dict for runtime-specific settings:

```yaml
layers:
  llm:
    models:
      - id: us.anthropic.claude-sonnet-4-20250514-v1:0
        runtime: bedrock
        provider_config:
          region: us-east-1
          profile: my-aws-profile  # optional
        weight: 0.5
        max_output_tokens: 512
      - id: unsloth/Qwen3.5-0.8B-GGUF
        runtime: llama_cpp
        repo_id: unsloth/Qwen3.5-0.8B-GGUF
        filename: Qwen3.5-0.8B-Q8_0.gguf
        weight: 0.5
```

Local and hosted models can be mixed in the same group.

### Routing

`build_code_analysis_model()` routes by `model.runtime`:
- `"llama_cpp"` → `LlamaCppModel` (existing, needs model_path)
- `"bedrock"` → `BedrockModel` (new, no model_path needed)

### Shared utilities

Extract from `LlamaCppModel` into module-level shared code:
- `SECURITY_AUDITOR_SYSTEM_PROMPT` constant
- `_parse_json()` function (markdown fence stripping, JSON extraction, YAML/ast fallbacks)

### Authentication

Boto3 handles AWS credentials automatically (env vars, IAM roles, ~/.aws/credentials). Optional `profile` in `provider_config` selects a specific AWS profile.

### Dependencies

`boto3` is an optional dependency:
```toml
[project.optional-dependencies]
bedrock = ["boto3>=1.35"]
```

Clear error when `runtime: bedrock` configured without boto3 installed.

### What stays unchanged

- `CodeAnalysisModel` protocol
- judge.py (calls protocol methods, doesn't care about runtime)
- runtime.py (model pooling, load/unload lifecycle)
- resolve_group_models(), select_llm_model_group()
- Download logic (bedrock models have no repo_id, skipped)
- All deterministic rules, adjudication, prepare_findings, formatters
- Programmatic API (ScanService) — works identically

### Blast radius

| File | Change |
|------|--------|
| `detectors/llm/models.py` | Add BedrockModel, extract shared utilities, update routing |
| `models.py` | Add `provider_config` to LLMModelConfig |
| `pyproject.toml` | Add `bedrock` optional dependency group |
| `tests/test_llm.py` | Add BedrockModel tests with mocked boto3 |
| `README.md` | Document bedrock config |
| `docs/` | Update architecture |
