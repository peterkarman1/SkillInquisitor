# Epic 1 Design: CLI Scaffold, Pipeline, and Configuration

**Date:** 2026-03-14
**Status:** Approved for planning
**Epic:** Epic 1 — CLI Scaffold, Pipeline & Configuration

## Goal

Build the initial SkillInquisitor scaffold as a usable but mostly empty scanner. After Epic 1, the project should install and run via `uv`, accept local paths, directories, stdin, and GitHub URLs, build the `Skill -> Artifact -> Segment` hierarchy, run an empty async pipeline, and emit empty scan results in text or JSON.

This epic establishes the long-lived foundations that later epics plug into:
- package layout
- async runtime model
- shared domain and config models
- input resolution
- config loading and merging
- pipeline orchestration
- formatter interfaces
- public CLI surface

## Approved Constraints

- Use a small-library core rather than an aggressively dependency-light implementation.
- Use `uv` to manage environments, dependencies, and lockfiles.
- Manage the Python runtime locally with `asdf`.
- Set the project baseline to **Python 3.13**.
- Design the internals async-first with `asyncio`.
- Implement GitHub URL scanning in Epic 1.
- Use the local `git` CLI for shallow clone/fetch behavior.
- Expose the full CLI tree now, with later commands stubbed cleanly.

## Non-Goals

Epic 1 does not implement real detection logic yet. Specifically out of scope:
- deterministic rule execution
- ML model loading or inference
- LLM model loading or inference
- SARIF output
- alert webhooks
- benchmark execution
- risk scoring beyond trivial empty-result behavior

## Approach

The approved approach is an **async-first core with a thin CLI shell**.

The CLI remains synchronous at the boundary for usability, but all internal orchestration is asynchronous. `cli.py` parses arguments and invokes async application services via `asyncio.run(...)`. This avoids a later sync-to-async rewrite once model downloads, local inference, remote API inference, and parallel file handling arrive in later epics.

Compared to a hybrid or sync-first scaffold, this approach adds a small amount of up-front structure but preserves a single execution model across the codebase.

## Package Boundaries

Epic 1 should create only the files that are immediately useful for the scaffold. Placeholder detector subpackages should not be created yet unless needed to satisfy imports.

Planned files:

- `pyproject.toml`
  - Project metadata, dependencies, optional extras, console script entrypoint, Python requirement.
- `.python-version`
  - Pins the `asdf` Python version.
- `src/skillinquisitor/__init__.py`
  - Package export surface and version marker.
- `src/skillinquisitor/__main__.py`
  - `python -m skillinquisitor` entrypoint.
- `src/skillinquisitor/cli.py`
  - `typer` application, public command tree, CLI option parsing, top-level exception handling.
- `src/skillinquisitor/models.py`
  - Shared domain models, result models, config models, enums, and serialization helpers.
- `src/skillinquisitor/config.py`
  - Defaults, YAML loading, env parsing, deep merge, validation, and effective config assembly.
- `src/skillinquisitor/input.py`
  - Async input resolution for local files, directories, stdin, GitHub URLs, and ignore filtering.
- `src/skillinquisitor/normalize.py`
  - Initial passthrough normalization that turns artifacts into base segments.
- `src/skillinquisitor/pipeline.py`
  - Async orchestration of normalization, detector routing, and empty finding aggregation.
- `src/skillinquisitor/detectors/base.py`
  - Shared detector interfaces/protocols for later epics.
- `src/skillinquisitor/formatters/console.py`
  - Minimal human-readable formatter for empty or populated results.
- `src/skillinquisitor/formatters/json.py`
  - Minimal stable JSON serialization path for `ScanResult`.

Directories to create:

- `src/skillinquisitor/`
- `src/skillinquisitor/detectors/`
- `src/skillinquisitor/formatters/`

## Runtime Architecture

### CLI Shape

Epic 1 should expose the full public command tree:

- `skillinquisitor scan`
- `skillinquisitor models`
- `skillinquisitor rules`
- `skillinquisitor benchmark`

Only `scan` is functional in Epic 1. The other commands should exist and fail cleanly with explicit "not implemented yet" messages and exit code `2`.

### Scan Flow

The approved runtime flow is:

1. Parse CLI arguments in `cli.py`
2. Load and validate merged config in `config.py`
3. Resolve input targets into `Skill` objects in `input.py`
4. Extract initial `Segment` objects in `normalize.py`
5. Run the async pipeline in `pipeline.py`
6. Format the `ScanResult` in text or JSON
7. Return exit code:
   - `0` for no findings above threshold
   - `1` for findings above threshold
   - `2` for config, input, or runtime scan errors

### Async Model

The internal code should be async-first even if much of Epic 1 is lightweight:

- CLI command handlers call `asyncio.run(...)`
- GitHub operations use `asyncio.create_subprocess_exec(...)`
- blocking filesystem work may use `asyncio.to_thread(...)` where useful
- pipeline and input service boundaries are async from day one

This makes later epics mechanically easier:
- model downloads
- local inference
- API-based inference
- parallel file handling
- large directory scans

## Shared Data Model

Epic 1 should implement the long-lived shared models now using **Pydantic v2** plus enums.

### Enums

Implement:
- `Severity`
- `Category`
- `DetectionLayer`
- `FileType`
- `SegmentType`

Even though Epic 1 does not use all enum values yet, defining them now stabilizes later interfaces.

### Core Domain Models

Implement:
- `Location`
- `ProvenanceStep`
- `Segment`
- `Artifact`
- `Skill`
- `Finding`
- `ScanResult`

### Config Models

Implement:
- `ScanConfig`
- nested layer/config sections needed to represent the full future schema

The goal is not to fully consume all config values in Epic 1. The goal is to validate and preserve the full configuration contract so later epics attach functionality without redesigning config structure.

### Modeling Notes

- Prefer explicit defaults over optional `None` where a real default exists.
- Use stable field names that will serialize cleanly to JSON later.
- Keep provenance present even in the passthrough stage so extracted child segments can slot in later without redesigning the models.

## Configuration Design

Epic 1 establishes the complete config system now.

### Merge Order

Approved merge order:

1. built-in defaults
2. global config at `~/.skillinquisitor/config.yaml`
3. project config at `.skillinquisitor/config.yaml`
4. environment variables with prefix `SKILLINQUISITOR_`
5. explicit CLI overrides

### Behavior

- Unknown config keys should warn, not fail.
- Invalid config values should fail fast and return exit code `2`.
- `--verbose` should be able to display the effective merged config.
- CLI overrides should be modeled explicitly rather than mutating ad hoc dictionaries throughout the code.

### Implementation Shape

`config.py` should separate these concerns:

1. raw ingestion from YAML/env/CLI
2. dictionary-level deep merge
3. normalization of override shapes
4. final validation into `ScanConfig`

This keeps config deterministic and testable.

## Input Resolution Design

`input.py` is an async service responsible for turning user input into the `Skill -> Artifact` hierarchy.

### Inputs Supported in Epic 1

- local file path
- local directory path
- stdin
- GitHub repository URL
- GitHub file URL
- GitHub directory URL

### Local Resolution

- A single file becomes a synthetic `Skill` with one `Artifact`.
- A directory is walked recursively and grouped into `Skill` objects according to the skill-directory boundaries established in the architecture doc.
- `.skillinquisitorignore` should be honored if present.

### GitHub Resolution

Epic 1 should support only GitHub HTTPS URLs and reject all other remote formats.

Allowed patterns:
- `https://github.com/<owner>/<repo>`
- `https://github.com/<owner>/<repo>/tree/<ref>/<path>`
- `https://github.com/<owner>/<repo>/blob/<ref>/<path>`

Implementation:

1. Validate the URL host and path shape.
2. Clone the repository shallowly with the local `git` CLI into a temp directory.
3. If a `tree` or `blob` path is specified, narrow the scan root to that resolved path.
4. Convert the scanned contents into local `Skill` objects.
5. Remove temporary clone data after completion.

### GitHub Safety Rules

- Only `https://github.com/...` URLs are valid.
- Never execute code from the cloned repository.
- Treat cloned repositories as read-only scan input.
- Return a clean scan error if a ref/path cannot be resolved.

## Normalization Design

`normalize.py` remains intentionally simple in Epic 1.

Responsibilities:
- classify artifacts enough to create initial base segments
- return a top-level `ORIGINAL` segment for each artifact
- preserve location/provenance structure required by later epics

It should be implemented as a passthrough interface, not a placeholder comment. The module should already define the contract that later normalization and extraction logic extends.

## Pipeline Design

`pipeline.py` is the async orchestration layer.

Responsibilities in Epic 1:
- accept merged config and resolved skills
- call normalization
- route artifacts/segments by type
- invoke detector interfaces with empty detector sets
- collect findings
- construct and return a `ScanResult`

Key rule: even though no detector logic exists yet, the pipeline should already own the orchestration contract. Later epics should add detectors to the existing pipeline rather than replacing it.

## Formatter Design

Epic 1 needs only two minimal formatters:

- console formatter
- JSON formatter

### Console Formatter

Should support:
- empty result output
- future populated result output shape
- quiet mode behavior
- concise summary for development

### JSON Formatter

Should serialize the full `ScanResult` through the Pydantic models so downstream tooling and the future skill wrapper can rely on a stable structure early.

SARIF is intentionally deferred.

## CLI Behavior

### `scan`

Flags to expose now:
- `--format`
- `--checks`
- `--skip`
- `--severity`
- `--config`
- `--quiet`
- `--verbose`
- `--baseline`

Not every flag needs full semantic power in Epic 1, but the public interface should exist and the flags should parse into the config layer cleanly.

### Stub Commands

These commands should exist but return a clear not-implemented response:
- `models list`
- `models download`
- `rules list`
- `rules test`
- `benchmark run`
- `benchmark compare`

This stabilizes the CLI contract while keeping Epic 1 scoped.

## Tooling and Environment

### Dependency Strategy

Approved core dependencies:
- `typer`
- `pydantic`
- `PyYAML`

Likely useful test/runtime support:
- `pytest`
- `pytest-asyncio`

### Python and Environment Management

- Python version managed via `asdf`
- project version pinned with `.python-version`
- dependencies and virtual environment managed with `uv`

If `uv` is missing on the local machine during implementation, installing it is an explicit prerequisite step for Epic 1.

## Documentation Updates Required by Epic 1

Epic 1 should update the current docs to reflect the approved implementation direction where it diverges from existing text:

- Python support baseline changes from `3.9+` to `3.13`
- `uv` becomes the default environment and dependency workflow
- local development expects `asdf` for Python management
- internal implementation is async-first

Files likely needing updates during implementation:
- `README.md`
- `CHANGELOG.md`
- `TODO.md`
- `docs/requirements/business-requirements.md`
- `docs/requirements/architecture.md`

## Acceptance Criteria

Epic 1 is complete when all of the following are true:

- `uv` project setup works end to end.
- base install succeeds with the approved core dependencies.
- `python -m skillinquisitor` works.
- `skillinquisitor scan <local-path>` works.
- `skillinquisitor scan <github-url>` works.
- stdin input works.
- the scanner resolves input into `Skill -> Artifact -> Segment`.
- normalization runs as a real passthrough stage.
- the async pipeline runs with no detector implementations and returns zero findings.
- text and JSON output both work for empty results.
- config merging works across defaults, global, project, env, and CLI.
- invalid config exits cleanly with code `2`.
- later command groups exist and fail cleanly as not implemented.
- exit codes follow the documented contract.

## Risks and Trade-Offs

### Async-First Overhead

Epic 1 will contain some async structure that is not strictly necessary for a zero-detector scaffold. This is intentional and preferred over a future rewrite.

### Config Surface Area

Implementing the full config schema in Epic 1 creates more initial code, but it prevents later ad hoc config growth and keeps the CLI/config contract stable.

### GitHub Input Complexity

Supporting GitHub `tree` and `blob` URLs in Epic 1 adds parsing and path resolution complexity. That complexity is justified because input resolution is a foundational subsystem in the architecture, not a bolt-on feature.

## Recommendation

Proceed with implementation planning for this exact design. The implementation plan should keep tasks small, test-first where feasible, and preserve the long-lived interfaces established here.
