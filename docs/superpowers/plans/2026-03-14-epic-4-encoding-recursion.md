# Epic 4 Encoding and Recursive Re-Scanning Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Epic 4's recursive extraction and decoding pipeline so SkillInquisitor can surface hidden content from markdown comments, code fences, Base64, ROT13, and text-like hex payloads and scan that content through the normal deterministic pipeline.

**Architecture:** Extend the shared `Segment` contract so every segment has stable provenance, raw source anchoring, and its own normalized analysis view. Keep `normalize.py` responsible for recursive segment expansion and candidate gating, then add `detectors/rules/encoding.py` for primary Epic 4 findings plus a deterministic post-processing pass for contextual and multi-layer findings.

**Tech Stack:** Python 3.13, Typer, Pydantic v2, pytest, existing deterministic rule engine, existing fixture harness

---

## File Structure

### Files to Create

- `src/skillinquisitor/detectors/rules/encoding.py`
- `docs/superpowers/plans/2026-03-14-epic-4-encoding-recursion.md`
- `tests/fixtures/deterministic/encoding/D-3-base64/SKILL.md`
- `tests/fixtures/deterministic/encoding/D-3-base64/expected.yaml`
- `tests/fixtures/deterministic/encoding/D-4-rot13/SKILL.md`
- `tests/fixtures/deterministic/encoding/D-4-rot13/expected.yaml`
- `tests/fixtures/deterministic/encoding/D-5-hex-xor/SKILL.md`
- `tests/fixtures/deterministic/encoding/D-5-hex-xor/expected.yaml`
- `tests/fixtures/deterministic/encoding/D-21-html-comments/SKILL.md`
- `tests/fixtures/deterministic/encoding/D-21-html-comments/expected.yaml`
- `tests/fixtures/deterministic/encoding/D-22-code-fences/SKILL.md`
- `tests/fixtures/deterministic/encoding/D-22-code-fences/expected.yaml`
- `tests/fixtures/deterministic/encoding/nested-encoding/SKILL.md`
- `tests/fixtures/deterministic/encoding/nested-encoding/expected.yaml`
- `tests/fixtures/deterministic/encoding/safe-benign-comments/SKILL.md`
- `tests/fixtures/deterministic/encoding/safe-benign-comments/expected.yaml`
- `tests/fixtures/deterministic/encoding/safe-benign-fences/SKILL.md`
- `tests/fixtures/deterministic/encoding/safe-benign-fences/expected.yaml`
- `tests/fixtures/deterministic/encoding/safe-base64-looking-text/SKILL.md`
- `tests/fixtures/deterministic/encoding/safe-base64-looking-text/expected.yaml`
- `tests/fixtures/deterministic/encoding/safe-hex-looking-text/SKILL.md`
- `tests/fixtures/deterministic/encoding/safe-hex-looking-text/expected.yaml`

### Files to Modify

- `src/skillinquisitor/models.py`
- `src/skillinquisitor/normalize.py`
- `src/skillinquisitor/config.py`
- `src/skillinquisitor/pipeline.py`
- `src/skillinquisitor/detectors/rules/__init__.py`
- `src/skillinquisitor/detectors/rules/engine.py`
- `tests/test_normalize.py`
- `tests/test_config.py`
- `tests/test_pipeline.py`
- `tests/test_deterministic.py`
- `tests/test_cli.py`
- `tests/fixtures/manifest.yaml`
- `README.md`
- `CHANGELOG.md`
- `TODO.md`

### Responsibilities

- `models.py`
  - Extend `Segment`, `Finding`, and `ScanConfig` with the explicit Epic 4 contracts used by recursive expansion and post-processing.
- `normalize.py`
  - Own recursive expansion, candidate ordering, truncation, extraction precedence, per-segment normalization, and deterministic segment IDs.
- `detectors/rules/encoding.py`
  - Register Epic 4 rules, emit primary findings from accepted derived segments or raw patterns, and run post-processing for `D-21A`, `D-22A`, and `D-5C`.
- `detectors/rules/engine.py`
  - Add the smallest hook needed for deterministic post-processing without teaching the whole engine about recursion internals.
- `pipeline.py`
  - Run the richer normalization output through the existing deterministic path and preserve stable layer metadata.
- `tests/test_normalize.py`
  - Cover segment creation, offsets, bounds, dedupe, and traversal rules directly.
- `tests/test_deterministic.py`
  - Lock Epic 4 rule behavior through the fixture harness.
- `tests/test_cli.py`
  - Extend CLI coverage to include Epic 4 rule visibility and single-rule testing.
- `tests/fixtures/deterministic/encoding/*`
  - Provide positive, negative, nested, and bounded cases for the full Epic 4 surface.

## Chunk 1: Shared Contract and Segment Expansion Foundation

### Task 1: Extend shared models for recursive segments and post-processing

**Files:**
- Modify: `src/skillinquisitor/models.py`
- Modify: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing model tests**

```python
from skillinquisitor.models import Artifact, FileType, Finding, Segment, SegmentType


def test_segment_supports_parent_linkage_and_normalized_view():
    segment = Segment(
        id="seg-1",
        content="payload",
        normalized_content="payload",
        segment_type=SegmentType.BASE64_DECODE,
        parent_segment_id="seg-0",
        parent_start_offset=10,
        parent_end_offset=25,
        depth=1,
    )

    assert segment.parent_segment_id == "seg-0"
    assert segment.normalized_content == "payload"


def test_finding_supports_segment_id_reference():
    finding = Finding(rule_id="D-3A", message="base64", segment_id="seg-1")
    assert finding.segment_id == "seg-1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_normalize.py -k "parent_linkage or segment_id_reference" -v`
Expected: FAIL because `Segment` and `Finding` do not support the Epic 4 fields yet.

- [ ] **Step 3: Write the minimal implementation**

```python
class Segment(BaseModel):
    id: str = ""
    content: str
    normalized_content: str | None = None
    segment_type: SegmentType = SegmentType.ORIGINAL
    location: Location = Field(default_factory=Location)
    provenance_chain: list[ProvenanceStep] = Field(default_factory=list)
    depth: int = 0
    parent_segment_id: str | None = None
    parent_start_offset: int | None = None
    parent_end_offset: int | None = None
    parent_segment_type: SegmentType | None = None
    details: dict[str, object] = Field(default_factory=dict)


class Finding(BaseModel):
    ...
    segment_id: str | None = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_normalize.py -k "parent_linkage or segment_id_reference" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/models.py tests/test_normalize.py
git commit -m "feat: add recursive segment model contract"
```

### Task 2: Add deterministic config defaults for Epic 4 traversal bounds

**Files:**
- Modify: `src/skillinquisitor/models.py`
- Modify: `src/skillinquisitor/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write the failing config test**

```python
from skillinquisitor.config import load_config


def test_load_config_exposes_epic4_deterministic_bounds(tmp_path):
    project_root = tmp_path
    config = load_config(project_root=project_root, env={}, cli_overrides={})

    assert config.layers.deterministic.max_derived_depth >= 1
    assert config.layers.deterministic.max_derived_segments_per_artifact >= 1
    assert config.layers.deterministic.max_decode_candidates_per_segment >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py::test_load_config_exposes_epic4_deterministic_bounds -v`
Expected: FAIL because the deterministic config shape does not include Epic 4 bounds.

- [ ] **Step 3: Write the minimal implementation**

```python
class CheckConfig(BaseModel):
    enabled: bool = True
    checks: dict[str, bool] = Field(default_factory=dict)
    categories: dict[str, bool] = Field(default_factory=dict)
    max_derived_depth: int = 3
    max_derived_segments_per_artifact: int = 64
    max_decode_candidates_per_segment: int = 8
    max_decoded_bytes: int = 4096
    base64_min_length: int = 40
    hex_min_length: int = 32
    require_rot13_signal: bool = True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_config.py::test_load_config_exposes_epic4_deterministic_bounds -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/models.py src/skillinquisitor/config.py tests/test_config.py
git commit -m "feat: add epic 4 traversal config defaults"
```

### Task 3: Refactor normalization helpers so per-segment normalized views are reusable

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing normalization-view test**

```python
from skillinquisitor.models import Artifact, FileType, SegmentType
from skillinquisitor.normalize import normalize_artifact


def test_original_segment_receives_normalized_view():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="e\u200bv\u200ba\u200bl",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)

    assert normalized.segments[0].segment_type == SegmentType.ORIGINAL
    assert normalized.segments[0].normalized_content == "eval"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_normalize.py::test_original_segment_receives_normalized_view -v`
Expected: FAIL because segments only carry raw content today.

- [ ] **Step 3: Write the minimal implementation**

```python
def _normalize_segment_text(content: str, path: str) -> tuple[str, list[NormalizationTransformation]]:
    ...


def normalize_artifact(artifact: Artifact) -> Artifact:
    normalized_content, transformations = _normalize_segment_text(artifact.raw_content, artifact.path)
    original_segment = _build_original_segment(artifact).model_copy(
        update={"normalized_content": normalized_content}
    )
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_normalize.py::test_original_segment_receives_normalized_view -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py tests/test_normalize.py
git commit -m "refactor: reuse normalization for per-segment views"
```

## Chunk 2: Recursive Extraction and Decoding in `normalize.py`

### Task 4: Implement deterministic segment IDs, parent offsets, and original-segment scaffolding

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing segment-ID test**

```python
from skillinquisitor.models import Artifact, FileType
from skillinquisitor.normalize import normalize_artifact


def test_original_segment_id_is_deterministic():
    artifact = Artifact(path="SKILL.md", raw_content="safe", file_type=FileType.MARKDOWN)

    first = normalize_artifact(artifact).segments[0].id
    second = normalize_artifact(artifact).segments[0].id

    assert first == second
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_normalize.py::test_original_segment_id_is_deterministic -v`
Expected: FAIL because segments do not get deterministic IDs.

- [ ] **Step 3: Write the minimal implementation**

```python
def _segment_id(*parts: str) -> str:
    digest = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def _build_original_segment(artifact: Artifact) -> Segment:
    ...
    return Segment(
        id=_segment_id(artifact.path, "original", "0", str(len(artifact.raw_content))),
        ...
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_normalize.py::test_original_segment_id_is_deterministic -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py tests/test_normalize.py
git commit -m "feat: add deterministic segment identifiers"
```

### Task 5: Extract HTML comments and fenced code blocks with precedence and overlap rules

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_normalize.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing extraction tests**

```python
from skillinquisitor.models import Artifact, FileType, SegmentType
from skillinquisitor.normalize import normalize_artifact


def test_markdown_comment_and_fence_content_become_child_segments():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="<!-- hidden -->\n```python\nprint('safe')\n```",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)
    segment_types = [segment.segment_type for segment in normalized.segments]

    assert SegmentType.HTML_COMMENT in segment_types
    assert SegmentType.CODE_FENCE in segment_types


def test_parent_markdown_does_not_extract_comment_inside_code_fence_twice():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="```md\n<!-- hidden -->\n```",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)
    comment_segments = [s for s in normalized.segments if s.segment_type == SegmentType.HTML_COMMENT]

    assert len(comment_segments) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_normalize.py -k "child_segments or extract_comment_inside_code_fence" -v`
Expected: FAIL because normalization only yields the original segment.

- [ ] **Step 3: Write the minimal implementation**

```python
def _extract_code_fence_segments(parent: Segment, artifact: Artifact, config: ScanConfig) -> list[Segment]:
    ...


def _extract_html_comment_segments(parent: Segment, artifact: Artifact, blocked_ranges: list[tuple[int, int]]) -> list[Segment]:
    ...


def _expand_segments(original: Segment, artifact: Artifact, config: ScanConfig) -> list[Segment]:
    ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_normalize.py -k "child_segments or extract_comment_inside_code_fence" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py tests/test_normalize.py tests/test_pipeline.py
git commit -m "feat: extract markdown comment and code fence segments"
```

### Task 6: Add bounded Base64, hex, and ROT13-derived segment expansion

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing decoding tests**

```python
from skillinquisitor.models import Artifact, FileType, SegmentType
from skillinquisitor.normalize import normalize_artifact


def test_base64_payload_decodes_into_child_segment():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)
    assert any(segment.segment_type == SegmentType.BASE64_DECODE for segment in normalized.segments)


def test_rot13_segment_is_created_once_per_parent():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="rot13 rot13",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)
    rot13_segments = [s for s in normalized.segments if s.segment_type == SegmentType.ROT13_TRANSFORM]
    assert len(rot13_segments) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_normalize.py -k "base64_payload_decodes or rot13_segment_is_created_once" -v`
Expected: FAIL because no derived decode segments exist.

- [ ] **Step 3: Write the minimal implementation**

```python
def _decode_base64_segments(parent: Segment, artifact: Artifact, config: ScanConfig) -> list[Segment]:
    ...


def _decode_hex_segments(parent: Segment, artifact: Artifact, config: ScanConfig) -> list[Segment]:
    ...


def _derive_rot13_segment(parent: Segment, artifact: Artifact, config: ScanConfig) -> list[Segment]:
    ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_normalize.py -k "base64_payload_decodes or rot13_segment_is_created_once" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py tests/test_normalize.py
git commit -m "feat: add bounded decode-derived segment expansion"
```

### Task 7: Enforce traversal bounds, slot accounting, and dedupe

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing bound-accounting tests**

```python
from skillinquisitor.models import Artifact, FileType, ScanConfig
from skillinquisitor.normalize import normalize_artifact


def test_rejected_decode_candidates_do_not_consume_decode_slots():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="AAAA AAAA aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==",
        file_type=FileType.MARKDOWN,
    )
    config = ScanConfig.model_validate(
        {
            "layers": {
                "deterministic": {
                    "max_decode_candidates_per_segment": 1,
                }
            }
        }
    )

    normalized = normalize_artifact(artifact, config=config)

    assert any(segment.segment_type.value == "base64_decode" for segment in normalized.segments)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_normalize.py::test_rejected_decode_candidates_do_not_consume_decode_slots -v`
Expected: FAIL because normalization does not yet enforce Epic 4 slot accounting or accept a config-aware path.

- [ ] **Step 3: Write the minimal implementation**

```python
def normalize_artifact(artifact: Artifact, config: ScanConfig | None = None) -> Artifact:
    effective_config = config or ScanConfig()
    ...
```

And then implement:
- left-to-right candidate ordering
- decode-slot accounting for accepted Base64/hex children only
- artifact-level derived child cap
- dedupe by parent, range, type, and content hash

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_normalize.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py tests/test_normalize.py
git commit -m "feat: enforce bounded recursive traversal"
```

## Chunk 3: Encoding Rules, Post-Processing, and Pipeline Wiring

### Task 8: Create the Epic 4 encoding rule module and register the new rules

**Files:**
- Create: `src/skillinquisitor/detectors/rules/encoding.py`
- Modify: `src/skillinquisitor/detectors/rules/__init__.py`
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing registry test**

```python
from skillinquisitor.detectors.rules import build_rule_registry
from skillinquisitor.models import ScanConfig


def test_rule_registry_includes_epic4_encoding_rules():
    registry = build_rule_registry(ScanConfig())
    assert registry.get("D-3A") is not None
    assert registry.get("D-22A") is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pipeline.py::test_rule_registry_includes_epic4_encoding_rules -v`
Expected: FAIL because the encoding rule module is not registered yet.

- [ ] **Step 3: Write the minimal implementation**

```python
def register_encoding_rules(registry: RuleRegistry) -> None:
    registry.register(rule_id="D-3A", ...)
    registry.register(rule_id="D-4A", ...)
    registry.register(rule_id="D-4B", ...)
    registry.register(rule_id="D-5A", ...)
    registry.register(rule_id="D-5B", ...)
    registry.register(rule_id="D-5C", ...)
    registry.register(rule_id="D-21A", ...)
    registry.register(rule_id="D-22A", ...)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_pipeline.py::test_rule_registry_includes_epic4_encoding_rules -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/__init__.py src/skillinquisitor/detectors/rules/engine.py src/skillinquisitor/detectors/rules/encoding.py tests/test_pipeline.py
git commit -m "feat: register epic 4 encoding rule family"
```

### Task 9: Implement primary segment findings for Base64, ROT13, hex, and XOR

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/encoding.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing primary-rule tests**

```python
from skillinquisitor.input import resolve_input
from skillinquisitor.models import ScanConfig
from skillinquisitor.pipeline import run_pipeline


async def test_pipeline_emits_primary_epic4_findings_for_base64_fixture():
    skills = await resolve_input("tests/fixtures/deterministic/encoding/D-3-base64")
    result = await run_pipeline(skills=skills, config=ScanConfig())

    assert any(finding.rule_id == "D-3A" for finding in result.findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_emits_primary_epic4_findings_for_base64_fixture -v`
Expected: FAIL because the rule evaluators do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

```python
def _detect_base64_payload(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    ...


def _detect_rot13_reference(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    ...


def _detect_xor_construct(segment: Segment, artifact: Artifact, skill: Skill, config: ScanConfig) -> list[Finding]:
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_emits_primary_epic4_findings_for_base64_fixture -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/encoding.py tests/test_pipeline.py
git commit -m "feat: add epic 4 primary encoding detections"
```

### Task 10: Add deterministic post-processing for `D-21A`, `D-22A`, and `D-5C`

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `src/skillinquisitor/detectors/rules/encoding.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing post-processing test**

```python
from skillinquisitor.input import resolve_input
from skillinquisitor.models import ScanConfig
from skillinquisitor.pipeline import run_pipeline


async def test_pipeline_emits_one_contextual_comment_finding_per_comment_segment():
    skills = await resolve_input("tests/fixtures/deterministic/encoding/D-21-html-comments")
    result = await run_pipeline(skills=skills, config=ScanConfig())

    comment_findings = [finding for finding in result.findings if finding.rule_id == "D-21A"]
    assert len(comment_findings) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_emits_one_contextual_comment_finding_per_comment_segment -v`
Expected: FAIL because contextual post-processing has not been added.

- [ ] **Step 3: Write the minimal implementation**

```python
def run_registered_rules(...):
    primary_findings = ...
    post_processed_findings = run_rule_postprocessors(skills, config, registry, primary_findings)
    return _sort_findings(primary_findings + post_processed_findings)
```

And implement post-processing helpers that:
- group findings by `segment_id`
- walk parent/child segment links
- emit one `D-21A` per qualifying comment segment
- emit one `D-22A` per qualifying code-fence segment
- emit one `D-5C` per qualifying suspicious leaf segment

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_emits_one_contextual_comment_finding_per_comment_segment -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/engine.py src/skillinquisitor/detectors/rules/encoding.py src/skillinquisitor/pipeline.py tests/test_pipeline.py
git commit -m "feat: add epic 4 contextual and chain post-processing"
```

### Task 11: Update CLI coverage for Epic 4 rules

**Files:**
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write the failing CLI assertions**

```python
def test_rules_list_outputs_registered_encoding_rules():
    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    assert "D-3A" in result.stdout
    assert "D-22A" in result.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py::test_rules_list_outputs_registered_encoding_rules -v`
Expected: FAIL because the rule registry output does not include Epic 4 rules yet.

- [ ] **Step 3: Write the minimal implementation**

```python
def test_rules_list_outputs_registered_encoding_rules():
    ...
```

No CLI code change should be needed if the registry wiring is correct.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cli.py::test_rules_list_outputs_registered_encoding_rules -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_cli.py
git commit -m "test: cover epic 4 rule visibility in cli"
```

## Chunk 4: Fixtures, Harness Contracts, and Documentation

### Task 12: Add the Epic 4 fixture corpus and manifest entries

**Files:**
- Create: `tests/fixtures/deterministic/encoding/*`
- Modify: `tests/fixtures/manifest.yaml`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write the failing fixture index test**

```python
def test_encoding_suite_indexes_positive_and_negative_epic4_fixtures(load_active_fixture_specs):
    specs = load_active_fixture_specs("deterministic")
    encoding_specs = [spec for spec in specs if spec.path.startswith("deterministic/encoding/")]

    assert {
        "deterministic/encoding/D-3-base64",
        "deterministic/encoding/D-4-rot13",
        "deterministic/encoding/D-5-hex-xor",
        "deterministic/encoding/D-21-html-comments",
        "deterministic/encoding/D-22-code-fences",
        "deterministic/encoding/nested-encoding",
    }.issubset({spec.path for spec in encoding_specs})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_deterministic.py::test_encoding_suite_indexes_positive_and_negative_epic4_fixtures -v`
Expected: FAIL because the Epic 4 fixtures are not indexed yet.

- [ ] **Step 3: Write the minimal implementation**

Create the fixtures and add exact `expected.yaml` contracts for:
- primary Base64 detection
- ROT13 trigger and transformed detection
- hex and XOR pattern findings
- contextual HTML comment and code-fence findings
- nested multi-layer findings
- safe non-triggering baselines

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_deterministic.py::test_encoding_suite_indexes_positive_and_negative_epic4_fixtures -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/manifest.yaml tests/fixtures/deterministic/encoding tests/test_deterministic.py
git commit -m "test: add epic 4 encoding fixture corpus"
```

### Task 13: Lock the fixture contracts through the real scanner pipeline

**Files:**
- Modify: `tests/test_deterministic.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing fixture-harness tests**

```python
import pytest


@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/encoding/D-3-base64",
        "deterministic/encoding/D-4-rot13",
        "deterministic/encoding/D-5-hex-xor",
        "deterministic/encoding/D-21-html-comments",
        "deterministic/encoding/D-22-code-fences",
        "deterministic/encoding/nested-encoding",
        "deterministic/encoding/safe-benign-comments",
        "deterministic/encoding/safe-benign-fences",
        "deterministic/encoding/safe-base64-looking-text",
        "deterministic/encoding/safe-hex-looking-text",
    ],
)
def test_encoding_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_deterministic.py::test_encoding_rule_fixtures -v`
Expected: FAIL until the fixture expectations and implementation line up.

- [ ] **Step 3: Write the minimal implementation**

Adjust code and fixture contracts until:
- positive fixtures match exactly
- safe fixtures stay clean
- contextual findings are one-per-ancestor
- multi-layer findings are one-per-suspicious-leaf

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_deterministic.py::test_encoding_rule_fixtures -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_deterministic.py tests/test_pipeline.py tests/fixtures/deterministic/encoding
git commit -m "test: lock epic 4 scanner behavior through harness"
```

### Task 14: Update project docs and verify the full suite

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `TODO.md`

- [ ] **Step 1: Update the user and project docs**

Add:
- README notes about recursive deterministic extraction and rule coverage
- CHANGELOG entries for Epic 4
- TODO updates marking Epic 4 complete with implementation notes

- [ ] **Step 2: Run the focused Epic 4 test targets**

Run: `uv run pytest tests/test_normalize.py tests/test_pipeline.py tests/test_deterministic.py tests/test_cli.py tests/test_config.py -v`
Expected: PASS

- [ ] **Step 3: Run the documented full suite**

Run: `./scripts/run-test-suite.sh`
Expected: PASS

- [ ] **Step 4: Review the final diff**

Run: `git status --short`
Expected: only the intended Epic 4 files are modified.

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md TODO.md src/skillinquisitor tests
git commit -m "feat: implement epic 4 encoding and recursive rescanning"
```
