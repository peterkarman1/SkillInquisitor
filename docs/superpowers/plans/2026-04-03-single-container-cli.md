# Single-Container CLI Images Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship self-contained CPU and CUDA container assets that preserve the existing `skillinquisitor` CLI UX, include the tiny LLM group plus ML ensemble models, and avoid nested Docker fallback for LLM inference.

**Architecture:** Add image-local config and container build assets rather than redesigning the scanner. Make the CLI honor host environment/config defaults consistently so a container entrypoint can point at a bundled config file, then add Dockerfiles/scripts that install the app, `llama-server`, `repomix`, and prefetch both LLM and ML models during image build.

**Tech Stack:** Python 3.13, Typer, Pydantic, pytest, Docker, llama.cpp `llama-server`, uv, Node/npm + repomix

---

## Chunk 1: CLI And Container Defaults

### Task 1: Add failing tests for CLI environment-backed config defaults

**Files:**
- Modify: `tests/test_cli.py`
- Modify: `src/skillinquisitor/cli.py`

- [ ] **Step 1: Write the failing tests**

Add tests that prove:
- CLI commands pass `os.environ` into `load_config(...)` instead of `{}`.
- The CLI can resolve a default global config path from an environment variable when `--config` is omitted.

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -q -k 'env or config_path'`
Expected: FAIL because the current CLI passes `{}` as `env` and has no helper for image-default config resolution.

- [ ] **Step 3: Write the minimal implementation**

Implement in `src/skillinquisitor/cli.py`:
- import `os`
- add a helper that resolves `--config` first and otherwise uses `SKILLINQUISITOR_CONFIG`
- pass `dict(os.environ)` into all CLI-side `load_config(...)` calls

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -q -k 'env or config_path'`
Expected: PASS

### Task 2: Add failing tests for required container assets

**Files:**
- Modify: `tests/test_cli.py`
- Create: `.dockerignore`
- Create: `docker/entrypoint.sh`
- Create: `docker/skillinquisitor-container-config.yaml`
- Create: `Dockerfile.cpu`
- Create: `Dockerfile.cuda`

- [ ] **Step 1: Write the failing tests**

Add tests that assert:
- the image-local config file exists and pins `tiny`, disables LLM auto-selection, and disables model auto-download
- the entrypoint exists and routes through `skillinquisitor`
- both Dockerfiles exist and declare an entrypoint
- the Dockerfiles reference the bundled config, `repomix`, and model-prefetch steps

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -q -k 'docker or container image or bundled config'`
Expected: FAIL because the files do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Create the container assets with the smallest viable layout:
- `.dockerignore`
- `docker/entrypoint.sh`
- `docker/skillinquisitor-container-config.yaml`
- `Dockerfile.cpu`
- `Dockerfile.cuda`

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -q -k 'docker or container image or bundled config'`
Expected: PASS

## Chunk 2: Build Flow And Documentation

### Task 3: Add build helper assets and container documentation

**Files:**
- Create or modify: `scripts/` build helper(s) if needed
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `TODO.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `docs/requirements/architecture.md`

- [ ] **Step 1: Write the failing docs-oriented test or asset existence test if a helper script is added**

If a new helper script is introduced, add a test that verifies it exists and references the intended Dockerfiles/tags.

- [ ] **Step 2: Run the targeted test to verify it fails**

Run the smallest relevant pytest selector for the helper test, or skip this step if no helper script is added.

- [ ] **Step 3: Update docs and tracker files**

Document:
- container-first usage examples for `tiny-cpu` and `tiny-cuda`
- requirement changes: self-contained container images with baked-in ML + tiny LLM models
- architecture changes: image-local config, no nested Docker fallback when `llama-server` is present in-image
- changelog entry
- TODO progress notes

- [ ] **Step 4: Re-read requirements docs and sync terminology**

Re-read:
- `docs/requirements/business-requirements.md`
- `docs/requirements/architecture.md`

Ensure the final implementation terminology matches shipped behavior.

## Chunk 3: Verification

### Task 4: Run focused verification and broader regression checks

**Files:**
- No code changes expected

- [ ] **Step 1: Run focused pytest coverage for the changed areas**

Run: `uv run pytest tests/test_cli.py tests/test_config.py -q`
Expected: PASS

- [ ] **Step 2: Run the broader regression suite for the feature surface**

Run: `uv run pytest tests/test_cli.py tests/test_config.py tests/test_input.py tests/test_llm.py tests/test_ml.py -q`
Expected: PASS

- [ ] **Step 3: Attempt a container-oriented verification command if the local Docker daemon is available**

Run:
```bash
docker version
```

If Docker is available, also run:
```bash
docker build -f Dockerfile.cpu -t skillinquisitor:tiny-cpu .
```

Expected: successful build if daemon is available. If the daemon is unavailable, record that limitation explicitly instead of claiming build verification.

- [ ] **Step 4: Summarize actual verification evidence**

Record:
- exact pytest commands run
- whether Docker build verification was possible in the local environment
- any residual risks, especially image-size and platform-specific runtime behavior
