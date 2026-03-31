# Git URL Commit Scan Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--commit` support for remote git scans and generalize remote input handling from GitHub-only URLs to cloneable git remote URLs while preserving existing GitHub `tree`/`blob` behavior.

**Architecture:** Keep the current input pipeline centered in `input.py`, but replace the GitHub-only target model with a generic git-remote target that can carry an optional ref and subpath. The CLI will pass an optional `--commit` override into input resolution, and the clone helper will clone the remote, optionally check out a specific commit SHA, then resolve any GitHub-only subpath semantics against the checked-out worktree.

**Tech Stack:** Python 3.13+, Typer CLI, asyncio subprocess git invocations, pytest

---

## Chunk 1: Test-first remote target behavior

### Task 1: Add failing input parsing and resolve tests

**Files:**
- Modify: `tests/test_input.py`
- Test: `tests/test_input.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_parse_gitlab_repo_url():
    ...

def test_parse_ssh_git_remote_url():
    ...

@pytest.mark.asyncio
async def test_resolve_input_uses_generic_git_clone_with_commit(...):
    ...

def test_parse_github_tree_url_keeps_subpath():
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_input.py -q`
Expected: FAIL because the parser and resolver still only support GitHub-hosted HTTPS URLs and do not accept a commit override.

- [ ] **Step 3: Write minimal implementation**

Update `src/skillinquisitor/input.py` to parse generic git remote targets and thread an optional commit argument through resolution.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_input.py -q`
Expected: PASS

## Chunk 2: CLI wiring and clone behavior

### Task 2: Add failing CLI test for `--commit`

**Files:**
- Modify: `tests/test_cli.py`
- Modify: `src/skillinquisitor/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
def test_scan_command_accepts_commit_option(monkeypatch):
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -q`
Expected: FAIL because `scan` does not expose or pass through `--commit`.

- [ ] **Step 3: Write minimal implementation**

Add `--commit` to `scan()` and `_run_scan()` in `src/skillinquisitor/cli.py`, then pass it into `resolve_input()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cli.py -q`
Expected: PASS

## Chunk 3: Documentation and tracker sync

### Task 3: Sync user-facing docs and project trackers

**Files:**
- Modify: `README.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `docs/requirements/architecture.md`
- Modify: `CHANGELOG.md`
- Modify: `TODO.md`

- [ ] **Step 1: Update documentation**

Document `--commit` on `scan`, clarify generic git remote support, and note that GitHub `tree`/`blob` URLs still support subpath scanning.

- [ ] **Step 2: Run targeted verification**

Run: `uv run pytest tests/test_input.py tests/test_cli.py -q`
Expected: PASS

- [ ] **Step 3: Run broader regression command**

Run: `uv run pytest tests/test_pipeline.py tests/test_input.py tests/test_cli.py -q`
Expected: PASS

- [ ] **Step 4: Record completion notes**

Update `CHANGELOG.md` and `TODO.md` with the files changed, behavior added, and any deviations.
