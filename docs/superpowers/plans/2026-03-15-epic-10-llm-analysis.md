# Epic 10 LLM Analysis Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Epic 10 LLM code-analysis layer with llama.cpp-backed local inference, hardware-aware default model groups, targeted verification prompts, optional whole-skill `repomix` analysis, and regression coverage.

**Architecture:** Extend the existing deterministic-plus-ML pipeline with a new LLM orchestration layer that analyzes code artifacts file-by-file, escalates targeted prompts from deterministic findings, and optionally analyzes a packed whole-skill context when it fits within a bounded token budget. Keep runtime/model selection config-driven so tiny, balanced, and large groups can evolve without code changes.

**Tech Stack:** Python, Pydantic, Typer, llama.cpp via optional `llama-cpp-python`, Hugging Face cache/download helpers, pytest regression fixtures, optional `repomix` subprocess integration

---

## Chunk 1: Config And Contracts

### Task 1: Expand LLM configuration and model profile contracts

**Files:**
- Modify: `src/skillinquisitor/models.py`
- Test: `tests/test_llm.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests for config defaults and profile selection**
- [ ] **Step 2: Run targeted tests to verify failure**
- [ ] **Step 3: Add LLM runtime/profile/group/hardware config models**
- [ ] **Step 4: Re-run targeted tests to verify pass**

### Task 2: Add fixture-harness assertions needed for LLM verification

**Files:**
- Modify: `tests/conftest.py`
- Test: `tests/test_deterministic.py`
- Test: `tests/test_llm.py`

- [ ] **Step 1: Write failing tests for `references_contains` and confidence assertions**
- [ ] **Step 2: Run targeted tests to verify failure**
- [ ] **Step 3: Implement harness support with minimal schema changes**
- [ ] **Step 4: Re-run targeted tests to verify pass**

## Chunk 2: LLM Runtime And Prompting

### Task 3: Implement llama.cpp model/runtime adapters and model catalog

**Files:**
- Create: `src/skillinquisitor/detectors/llm/models.py`
- Create: `src/skillinquisitor/detectors/llm/download.py`
- Create: `src/skillinquisitor/detectors/llm/__init__.py`
- Modify: `src/skillinquisitor/detectors/ml/__init__.py`
- Modify: `src/skillinquisitor/cli.py`
- Modify: `pyproject.toml`
- Test: `tests/test_llm.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests for local dependency detection, hardware profile selection, model status listing, and downloads**
- [ ] **Step 2: Run targeted tests to verify failure**
- [ ] **Step 3: Implement runtime/model catalog, cache/download helpers, and CLI exposure**
- [ ] **Step 4: Re-run targeted tests to verify pass**

### Task 4: Implement prompt builders and structured response schema

**Files:**
- Create: `src/skillinquisitor/detectors/llm/prompts.py`
- Test: `tests/test_llm.py`

- [ ] **Step 1: Write failing tests for general prompts, targeted prompts, and whole-skill prompt shaping**
- [ ] **Step 2: Run targeted tests to verify failure**
- [ ] **Step 3: Implement prompt builders and schema helpers**
- [ ] **Step 4: Re-run targeted tests to verify pass**

## Chunk 3: Pipeline Integration

### Task 5: Implement the LLM judge orchestrator

**Files:**
- Create: `src/skillinquisitor/detectors/llm/judge.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Test: `tests/test_llm.py`
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for per-file analysis, sequential load/run/unload, targeted verification, and metadata reporting**
- [ ] **Step 2: Run targeted tests to verify failure**
- [ ] **Step 3: Implement the judge and integrate it into the pipeline**
- [ ] **Step 4: Re-run targeted tests to verify pass**

### Task 6: Implement optional `repomix` whole-skill analysis gating

**Files:**
- Modify: `src/skillinquisitor/detectors/llm/judge.py`
- Test: `tests/test_llm.py`
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for pack eligibility, token-budget gating, and graceful fallback when `repomix` is unavailable**
- [ ] **Step 2: Run targeted tests to verify failure**
- [ ] **Step 3: Implement `repomix` packaging and token estimation**
- [ ] **Step 4: Re-run targeted tests to verify pass**

## Chunk 4: Regression Coverage And Docs

### Task 7: Add Epic 10 regression fixtures

**Files:**
- Modify: `tests/fixtures/manifest.yaml`
- Create: `tests/fixtures/llm/exfil-script/...`
- Create: `tests/fixtures/llm/obfuscated-payload/...`
- Create: `tests/fixtures/llm/legitimate-network/...`
- Create: `tests/fixtures/llm/disputed-chain/...`
- Modify: `tests/test_llm.py`

- [ ] **Step 1: Write the fixture runner test expectations**
- [ ] **Step 2: Run the LLM fixture suite to verify failure**
- [ ] **Step 3: Add fixtures and activate the suite**
- [ ] **Step 4: Re-run the suite to verify pass**

### Task 8: Sync project docs and release notes

**Files:**
- Modify: `README.md`
- Modify: `TODO.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `docs/requirements/business-requirements.md`

- [ ] **Step 1: Re-read implementation and docs for divergences**
- [ ] **Step 2: Update docs, TODO, and changelog to reflect shipped behavior**
- [ ] **Step 3: Run full test suite**
- [ ] **Step 4: Fix any regressions and re-run verification**
