# Remove Docker + llama-server, Add llama-cpp-python + python-repomix

**Date:** 2026-04-14
**Goal:** Eliminate subprocess and Docker dependencies by replacing llama-server with direct llama-cpp-python bindings and Node.js repomix with the Python repomix package.

## Motivation

The LLM layer currently spawns llama-server as a subprocess, binds an ephemeral port, polls a health endpoint, then makes HTTP requests to a localhost API. When llama-server isn't available, it falls back to launching a Docker container. This is fragile (GLIBC version mismatches, Docker daemon availability, port conflicts) and hard to debug.

Repomix currently requires Node.js/npm as a system dependency.

Both can be replaced with pure Python packages that load directly in-process.

## What Gets Deleted

- `Dockerfile.cpu`, `Dockerfile.cuda` — container image definitions
- `docker/entrypoint.sh`, `docker/skillinquisitor-container-config.yaml` — container config
- `.dockerignore`
- `LlamaCppCodeAnalysisModel` class in `detectors/llm/models.py` — ~280 lines of subprocess/port/HTTP/Docker logic
- Docker fallback in `_find_server_command()`
- All Docker/container references in README, architecture docs, config docs
- Node.js/npm system requirement

## What Gets Added

### llama-cpp-python (replaces llama-server subprocess)

New `LlamaCppModel` class implementing the same `CodeAnalysisModel` protocol:
- `load()` — `Llama(model_path=..., n_ctx=8192, n_gpu_layers=-1, verbose=False)`
- `generate_structured()` — `model.create_chat_completion(messages=[...], response_format={"type": "json_object"}, temperature=0.0, max_tokens=256)`
- `unload()` — `del self._model; gc.collect()`

GPU acceleration is automatic: `-1` for n_gpu_layers auto-offloads to Metal on macOS and CUDA on Linux. CPU fallback works without flags.

Installation notes for GPU:
- macOS Metal: `CMAKE_ARGS="-DGGML_METAL=on" uv pip install llama-cpp-python`
- Linux CUDA: `CMAKE_ARGS="-DGGML_CUDA=on" uv pip install llama-cpp-python`

### python-repomix (replaces Node.js repomix subprocess)

Replace subprocess call with Python API:
```python
from repomix import RepoProcessor
processor = RepoProcessor(directory=skill_path)
result = processor.process(write_output=False)
bundled_text = result.output_content
```

Package: `repomix>=0.5` on PyPI (AndersonBY/python-repomix, 153 stars, security reviewed clean).

### Dependencies in pyproject.toml

```toml
dependencies = [
    "llama-cpp-python>=0.3",
    "repomix>=0.5",
    # ... existing deps
]
```

## What Stays Unchanged

- `CodeAnalysisModel` protocol — judge.py calls the same interface
- judge.py — orchestrates models, builds prompts, aggregates responses
- runtime.py — model pooling and lifecycle (same load/unload pattern)
- download.py — GGUF model downloading from HuggingFace
- All deterministic rules
- All config structure (model groups, weights, context_window, max_output_tokens)
- `--llm-group` flag
- Adjudication, prepare_findings(), formatters

## Blast Radius

| File | Change |
|------|--------|
| `detectors/llm/models.py` | Rewrite LlamaCppCodeAnalysisModel → LlamaCppModel (direct bindings) |
| `detectors/llm/judge.py` | Update repomix calls from subprocess to Python API |
| `runtime.py` | Remove Docker-related checks, simplify model building |
| `models.py` | Remove Docker/container config fields if any remain |
| `cli.py` | Remove Docker references from help text |
| `pyproject.toml` | Add llama-cpp-python, repomix; remove npm references |
| `README.md` | Remove Docker sections, update install/setup |
| `docs/` | Update architecture and BRD |
| `tests/test_llm.py` | Update mocks for direct model calls instead of HTTP |
| `Dockerfile.*`, `docker/`, `.dockerignore` | Delete |
