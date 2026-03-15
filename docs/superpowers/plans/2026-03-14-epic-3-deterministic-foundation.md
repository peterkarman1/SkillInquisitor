# Epic 3 Deterministic Foundation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic rule engine, Unicode/steganography normalization pipeline, Epic 3 built-in rules, and `rules` CLI so later deterministic epics can plug into stable infrastructure.

**Architecture:** Add a pure normalization layer that records typed transformation metadata on each artifact, then execute registered deterministic rules through a metadata-driven engine that supports both segment and artifact scopes. Keep built-in and custom regex rules on the same execution path so `scan`, `rules list`, and `rules test` all reflect the same rule registry and filtering behavior.

**Tech Stack:** Python 3.13, Typer, Pydantic v2, PyYAML, pytest, existing fixture harness

---

## File Structure

### Files to Create

- `src/skillinquisitor/detectors/rules/__init__.py`
- `src/skillinquisitor/detectors/rules/engine.py`
- `src/skillinquisitor/detectors/rules/unicode.py`
- `tests/test_normalize.py`
- `tests/fixtures/deterministic/unicode/D-1A-unicode-tags/SKILL.md`
- `tests/fixtures/deterministic/unicode/D-1A-unicode-tags/expected.yaml`
- `tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md`
- `tests/fixtures/deterministic/unicode/D-1B-zero-width/expected.yaml`
- `tests/fixtures/deterministic/unicode/D-1C-variation-selector/SKILL.md`
- `tests/fixtures/deterministic/unicode/D-1C-variation-selector/expected.yaml`
- `tests/fixtures/deterministic/unicode/D-1D-rtlo/SKILL.md`
- `tests/fixtures/deterministic/unicode/D-1D-rtlo/expected.yaml`
- `tests/fixtures/deterministic/unicode/D-2A-homoglyph-command/SKILL.md`
- `tests/fixtures/deterministic/unicode/D-2A-homoglyph-command/expected.yaml`
- `tests/fixtures/deterministic/unicode/D-6A-split-keyword/SKILL.md`
- `tests/fixtures/deterministic/unicode/D-6A-split-keyword/expected.yaml`
- `tests/fixtures/deterministic/unicode/NC-3A-normalization-delta/SKILL.md`
- `tests/fixtures/deterministic/unicode/NC-3A-normalization-delta/expected.yaml`
- `tests/fixtures/deterministic/unicode/safe-mixed-language-prose/SKILL.md`
- `tests/fixtures/deterministic/unicode/safe-mixed-language-prose/expected.yaml`
- `tests/fixtures/deterministic/unicode/safe-ascii-skill/SKILL.md`
- `tests/fixtures/deterministic/unicode/safe-ascii-skill/expected.yaml`
- `tests/fixtures/deterministic/unicode/safe-code-like-words/SKILL.md`
- `tests/fixtures/deterministic/unicode/safe-code-like-words/expected.yaml`

### Files to Modify

- `src/skillinquisitor/models.py`
- `src/skillinquisitor/normalize.py`
- `src/skillinquisitor/config.py`
- `src/skillinquisitor/pipeline.py`
- `src/skillinquisitor/cli.py`
- `tests/conftest.py`
- `tests/test_deterministic.py`
- `tests/test_cli.py`
- `tests/test_pipeline.py`
- `tests/fixtures/manifest.yaml`
- `docs/requirements/architecture.md`
- `docs/requirements/business-requirements.md`
- `README.md`
- `CHANGELOG.md`
- `TODO.md`

### Responsibilities

- `models.py`
  - Add normalization-specific models and any deterministic rule metadata types that must be shared outside the engine.
- `normalize.py`
  - Transform raw artifact content into normalized views plus typed transformation records without emitting findings.
- `detectors/rules/engine.py`
  - Own rule registration, filtering, custom-rule compilation, and deterministic execution.
- `detectors/rules/unicode.py`
  - Register and implement Epic 3 built-in rules.
- `pipeline.py`
  - Normalize artifacts, execute deterministic rules, and return real findings.
- `cli.py`
  - Wire `rules list` and `rules test` to the real deterministic engine.
- `tests/test_normalize.py`
  - Cover normalization behavior directly where fixture-level tests would be too indirect.
- `tests/test_deterministic.py`
  - Assert fixture registration and deterministic result matching for Epic 3.
- `tests/test_cli.py`
  - Validate the new rule CLI behavior.
- `tests/fixtures/deterministic/unicode/*`
  - Provide positive and negative regression fixtures for each Epic 3 rule family.

## Chunk 1: Models and Normalization Foundation

### Task 1: Add typed normalization metadata to the shared model

**Files:**
- Modify: `src/skillinquisitor/models.py`
- Create: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing model test**

```python
from skillinquisitor.models import Artifact, NormalizationTransformation, NormalizationType


def test_artifact_supports_typed_normalization_transformations():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="eval",
        normalization_transformations=[
            NormalizationTransformation(
                transformation_type=NormalizationType.KEYWORD_SPLITTER_COLLAPSE,
                original_snippet="e.v.a.l",
                normalized_snippet="eval",
            )
        ],
    )

    assert artifact.normalization_transformations[0].normalized_snippet == "eval"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_normalize.py::test_artifact_supports_typed_normalization_transformations -v`
Expected: FAIL with an import or model validation error because the normalization types do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

```python
class NormalizationType(str, Enum):
    KEYWORD_SPLITTER_COLLAPSE = "keyword_splitter_collapse"


class NormalizationTransformation(BaseModel):
    transformation_type: NormalizationType
    original_snippet: str
    normalized_snippet: str
    location: Location | None = None
    details: dict[str, object] = Field(default_factory=dict)


class Artifact(BaseModel):
    ...
    normalization_transformations: list[NormalizationTransformation] = Field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_normalize.py::test_artifact_supports_typed_normalization_transformations -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/models.py tests/test_normalize.py
git commit -m "feat: add normalization transformation models"
```

### Task 2: Replace passthrough normalization with typed transformation recording

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_normalize.py`

- [ ] **Step 1: Write failing normalization tests**

```python
from skillinquisitor.models import Artifact, FileType
from skillinquisitor.normalize import normalize_artifact


def test_normalize_artifact_records_zero_width_removal():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="e\u200bv\u200ba\u200bl",
        file_type=FileType.MARKDOWN,
    )

    normalized = normalize_artifact(artifact)

    assert normalized.normalized_content == "eval"
    assert normalized.normalization_transformations


def test_normalize_artifact_keeps_original_segment_as_canonical_source():
    artifact = Artifact(path="SKILL.md", raw_content="safe", file_type=FileType.MARKDOWN)
    normalized = normalize_artifact(artifact)

    assert len(normalized.segments) == 1
    assert normalized.segments[0].content == "safe"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_normalize.py -v`
Expected: FAIL because normalization is still passthrough and records no transformations.

- [ ] **Step 3: Write the minimal implementation**

```python
def normalize_artifact(artifact: Artifact) -> Artifact:
    normalized_content = artifact.raw_content
    transformations: list[NormalizationTransformation] = []

    normalized_content, new_transformations = _remove_zero_width(normalized_content, artifact.path)
    transformations.extend(new_transformations)
    normalized_content, new_transformations = _remove_variation_selectors(normalized_content, artifact.path)
    transformations.extend(new_transformations)
    normalized_content, new_transformations = _fold_homoglyphs(normalized_content, artifact.path)
    transformations.extend(new_transformations)
    normalized_content, new_transformations = _collapse_keyword_splitters(normalized_content, artifact.path)
    transformations.extend(new_transformations)

    return artifact.model_copy(
        update={
            "normalized_content": normalized_content,
            "normalization_transformations": transformations,
            "segments": [_build_original_segment(artifact)],
        }
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_normalize.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py tests/test_normalize.py
git commit -m "feat: implement deterministic normalization pipeline"
```

## Chunk 2: Rule Engine and Registry

### Task 3: Add the deterministic rules package and registry-driven engine

**Files:**
- Create: `src/skillinquisitor/detectors/rules/__init__.py`
- Create: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing engine test**

```python
from skillinquisitor.detectors.rules.engine import RuleRegistry


def test_rule_registry_orders_rules_stably():
    registry = RuleRegistry()

    registry.register(rule_id="D-6A", scope="segment", category="obfuscation")
    registry.register(rule_id="D-1A", scope="segment", category="steganography")

    assert [rule.rule_id for rule in registry.list_rules()] == ["D-1A", "D-6A"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_pipeline.py::test_rule_registry_orders_rules_stably -v`
Expected: FAIL because the rules package and registry do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

```python
@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    family_id: str | None
    scope: str
    category: Category
    severity: Severity
    description: str
    evaluator: RuleEvaluator
    enabled_by_default: bool = True
    origin: str = "builtin"


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def register(self, **kwargs) -> None:
        rule = RuleDefinition(**kwargs)
        self._rules[rule.rule_id] = rule

    def list_rules(self) -> list[RuleDefinition]:
        return [self._rules[key] for key in sorted(self._rules)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_pipeline.py::test_rule_registry_orders_rules_stably -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/__init__.py src/skillinquisitor/detectors/rules/engine.py tests/test_pipeline.py
git commit -m "feat: add deterministic rule engine registry"
```

### Task 4: Support config-driven custom regex rules through the engine

**Files:**
- Modify: `src/skillinquisitor/config.py`
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write the failing custom-rule test**

```python
from skillinquisitor.config import load_config
from skillinquisitor.detectors.rules.engine import build_rule_registry


def test_custom_regex_rules_register_as_segment_rules(tmp_path):
    config = load_config(
        project_root=tmp_path,
        env={},
        cli_overrides={
            "custom_rules": [
                {
                    "id": "CUSTOM-1",
                    "pattern": "ignore previous instructions",
                    "severity": "high",
                    "category": "custom",
                    "message": "Custom detection",
                }
            ]
        },
    )

    registry = build_rule_registry(config)

    assert any(rule.rule_id == "CUSTOM-1" and rule.origin == "custom" for rule in registry.list_rules())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py::test_custom_regex_rules_register_as_segment_rules -v`
Expected: FAIL because the engine does not compile custom rules yet.

- [ ] **Step 3: Write the minimal implementation**

```python
def build_custom_rule(rule_config: CustomRuleConfig) -> RuleDefinition:
    pattern = re.compile(rule_config.pattern, re.IGNORECASE)

    def evaluator(segment: Segment, artifact: Artifact, config: ScanConfig) -> list[Finding]:
        ...

    return RuleDefinition(
        rule_id=rule_config.id,
        family_id=None,
        scope="segment",
        category=Category.CUSTOM,
        severity=rule_config.severity,
        description=rule_config.message,
        evaluator=evaluator,
        origin="custom",
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py::test_custom_regex_rules_register_as_segment_rules -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/config.py src/skillinquisitor/detectors/rules/engine.py tests/test_config.py
git commit -m "feat: load custom regex rules into deterministic engine"
```

## Chunk 3: Epic 3 Built-In Rules

### Task 5: Implement `D-1A` through `D-1D` and `NC-3A`

**Files:**
- Create: `src/skillinquisitor/detectors/rules/unicode.py`
- Modify: `src/skillinquisitor/detectors/rules/__init__.py`
- Modify: `tests/test_normalize.py`
- Modify: `tests/test_deterministic.py`
- Create: `tests/fixtures/deterministic/unicode/D-1A-unicode-tags/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/D-1A-unicode-tags/expected.yaml`
- Create: `tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/D-1B-zero-width/expected.yaml`
- Create: `tests/fixtures/deterministic/unicode/D-1C-variation-selector/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/D-1C-variation-selector/expected.yaml`
- Create: `tests/fixtures/deterministic/unicode/D-1D-rtlo/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/D-1D-rtlo/expected.yaml`
- Create: `tests/fixtures/deterministic/unicode/NC-3A-normalization-delta/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/NC-3A-normalization-delta/expected.yaml`
- Modify: `tests/fixtures/manifest.yaml`

- [ ] **Step 1: Add the failing fixtures and fixture tests**

```python
@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/unicode/D-1A-unicode-tags",
        "deterministic/unicode/D-1B-zero-width",
        "deterministic/unicode/D-1C-variation-selector",
        "deterministic/unicode/D-1D-rtlo",
        "deterministic/unicode/NC-3A-normalization-delta",
    ],
)
def test_unicode_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_deterministic.py -v`
Expected: FAIL because the fixtures expect deterministic findings that do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

```python
def register_unicode_rules(registry: RuleRegistry) -> None:
    registry.register(... rule_id="D-1A", evaluator=_detect_unicode_tags)
    registry.register(... rule_id="D-1B", evaluator=_detect_zero_width)
    registry.register(... rule_id="D-1C", evaluator=_detect_variation_selectors)
    registry.register(... rule_id="D-1D", evaluator=_detect_rtlo)
    registry.register(... rule_id="NC-3A", evaluator=_detect_security_relevant_normalization_delta)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_deterministic.py -v`
Expected: PASS for the new D-1 and NC-3 fixture coverage.

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/__init__.py src/skillinquisitor/detectors/rules/unicode.py tests/test_normalize.py tests/test_deterministic.py tests/fixtures/deterministic/unicode tests/fixtures/manifest.yaml
git commit -m "feat: add unicode and normalization delta rules"
```

### Task 6: Implement aggressive homoglyph detection `D-2A`

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/unicode.py`
- Modify: `tests/test_normalize.py`
- Modify: `tests/test_deterministic.py`
- Create: `tests/fixtures/deterministic/unicode/D-2A-homoglyph-command/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/D-2A-homoglyph-command/expected.yaml`
- Create: `tests/fixtures/deterministic/unicode/safe-mixed-language-prose/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/safe-mixed-language-prose/expected.yaml`
- Modify: `tests/fixtures/manifest.yaml`

- [ ] **Step 1: Add the failing fixture coverage**

```python
@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/unicode/D-2A-homoglyph-command",
        "deterministic/unicode/safe-mixed-language-prose",
    ],
)
def test_homoglyph_detection_fixture_contracts(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_deterministic.py::test_homoglyph_detection_fixture_contracts -v`
Expected: FAIL because no `D-2A` findings are produced yet.

- [ ] **Step 3: Write the minimal implementation**

```python
def _detect_homoglyphs(segment: Segment, artifact: Artifact, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for token, location in _iter_identifier_like_tokens(segment):
        if _token_looks_mixed_script(token):
            findings.append(_build_finding("D-2A", segment, location, "Mixed-script homoglyph pattern detected"))
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_deterministic.py::test_homoglyph_detection_fixture_contracts -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/unicode.py tests/test_normalize.py tests/test_deterministic.py tests/fixtures/deterministic/unicode tests/fixtures/manifest.yaml
git commit -m "feat: add aggressive homoglyph detection"
```

### Task 7: Implement dangerous keyword splitting `D-6A`

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/unicode.py`
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_normalize.py`
- Modify: `tests/test_deterministic.py`
- Create: `tests/fixtures/deterministic/unicode/D-6A-split-keyword/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/D-6A-split-keyword/expected.yaml`
- Create: `tests/fixtures/deterministic/unicode/safe-code-like-words/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/safe-code-like-words/expected.yaml`
- Modify: `tests/fixtures/manifest.yaml`

- [ ] **Step 1: Add the failing splitting tests**

```python
def test_keyword_splitter_collapses_dangerous_tokens_only():
    artifact = Artifact(path="SKILL.md", raw_content="Use e.v.a.l but not m.e.t.a", file_type=FileType.MARKDOWN)

    normalized = normalize_artifact(artifact)

    assert "eval" in normalized.normalized_content
    assert "meta" not in normalized.normalized_content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_normalize.py::test_keyword_splitter_collapses_dangerous_tokens_only -v`
Expected: FAIL because splitter collapsing is not yet driven by dangerous keyword families.

- [ ] **Step 3: Write the minimal implementation**

```python
DANGEROUS_KEYWORD_FAMILIES = {
    "execution": ["eval", "exec", "compile", "subprocess", "os.system"],
    "network": ["curl", "wget", "fetch", "requests", "urllib", "socket"],
    "secrets": ["os.environ", "process.env", "getenv", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
    "encoding": ["base64", "b64decode", "fromhex"],
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_normalize.py tests/test_deterministic.py -v`
Expected: PASS for normalization and `D-6A` fixtures.

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py src/skillinquisitor/detectors/rules/unicode.py tests/test_normalize.py tests/test_deterministic.py tests/fixtures/deterministic/unicode tests/fixtures/manifest.yaml
git commit -m "feat: add dangerous keyword splitting detection"
```

## Chunk 4: Pipeline and CLI Integration

### Task 8: Run deterministic rules in the real pipeline

**Files:**
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing pipeline test**

```python
from skillinquisitor.config import ScanConfig
from skillinquisitor.input import resolve_input
from skillinquisitor.pipeline import run_pipeline


@pytest.mark.asyncio
async def test_pipeline_returns_deterministic_findings_for_unicode_fixture():
    skills = await resolve_input("tests/fixtures/deterministic/unicode/D-1B-zero-width")
    result = await run_pipeline(skills=skills, config=ScanConfig())

    assert any(finding.rule_id == "D-1B" for finding in result.findings)
    assert result.layer_metadata["deterministic"]["findings"] >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_pipeline.py::test_pipeline_returns_deterministic_findings_for_unicode_fixture -v`
Expected: FAIL because the pipeline still returns an empty deterministic finding set.

- [ ] **Step 3: Write the minimal implementation**

```python
async def run_pipeline(skills: list[Skill], config: ScanConfig) -> ScanResult:
    normalized_skills = [_normalize_skill(skill) for skill in skills]
    rule_registry = build_rule_registry(config)
    findings = run_registered_rules(normalized_skills, config, rule_registry)
    return ScanResult(
        skills=normalized_skills,
        findings=findings,
        risk_score=100,
        verdict="SAFE" if not findings else "MEDIUM RISK",
        layer_metadata={
            "deterministic": {"enabled": config.layers.deterministic.enabled, "findings": len(findings)},
            "ml": {"enabled": config.layers.ml.enabled, "findings": 0},
            "llm": {"enabled": config.layers.llm.enabled, "findings": 0},
        },
        total_timing=0.0,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_pipeline.py::test_pipeline_returns_deterministic_findings_for_unicode_fixture -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/pipeline.py tests/test_pipeline.py
git commit -m "feat: execute deterministic rules in scan pipeline"
```

### Task 9: Implement `rules list` and `rules test`

**Files:**
- Modify: `src/skillinquisitor/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write the failing CLI tests**

```python
def test_rules_list_outputs_registered_unicode_rules():
    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    assert "D-1A" in result.stdout
    assert "D-6A" in result.stdout


def test_rules_test_runs_single_rule_against_normalized_file():
    result = runner.invoke(
        app,
        ["rules", "test", "D-1B", "tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md"],
    )

    assert result.exit_code == 1
    assert "D-1B" in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py::test_rules_list_outputs_registered_unicode_rules tests/test_cli.py::test_rules_test_runs_single_rule_against_normalized_file -v`
Expected: FAIL because the `rules` subcommands are still stubbed.

- [ ] **Step 3: Write the minimal implementation**

```python
@rules_app.command("list")
def rules_list() -> None:
    config = load_config(project_root=Path.cwd(), env={})
    registry = build_rule_registry(config)
    typer.echo(format_rule_listing(registry.list_rules()))


@rules_app.command("test")
def rules_test(rule_id: str, target: str) -> None:
    result = asyncio.run(_run_rules_test(rule_id=rule_id, target=target))
    typer.echo(format_console(result))
    raise typer.Exit(code=0 if not result.findings else 1)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS for the new `rules` CLI behavior and existing scan tests.

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/cli.py tests/test_cli.py
git commit -m "feat: add deterministic rules CLI commands"
```

## Chunk 5: Fixture Completion, Verification, and Docs

### Task 10: Finish fixture corpus and tighten deterministic harness assertions

**Files:**
- Modify: `tests/test_deterministic.py`
- Modify: `tests/conftest.py`
- Modify: `tests/fixtures/manifest.yaml`
- Create: `tests/fixtures/deterministic/unicode/safe-ascii-skill/SKILL.md`
- Create: `tests/fixtures/deterministic/unicode/safe-ascii-skill/expected.yaml`

- [ ] **Step 1: Write the failing fixture-index test**

```python
def test_unicode_suite_indexes_positive_and_negative_epic3_fixtures(load_active_fixture_specs):
    specs = load_active_fixture_specs("deterministic")
    unicode_specs = [spec for spec in specs if spec.path.startswith("deterministic/unicode/")]

    assert len(unicode_specs) >= 9
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_deterministic.py::test_unicode_suite_indexes_positive_and_negative_epic3_fixtures -v`
Expected: FAIL until the full Unicode suite is indexed.

- [ ] **Step 3: Write the minimal implementation**

```python
def test_unicode_suite_indexes_positive_and_negative_epic3_fixtures(load_active_fixture_specs):
    specs = load_active_fixture_specs("deterministic")
    unicode_specs = [spec for spec in specs if spec.path.startswith("deterministic/unicode/")]

    assert {
        "deterministic/unicode/D-1A-unicode-tags",
        "deterministic/unicode/D-1B-zero-width",
        "deterministic/unicode/D-1C-variation-selector",
        "deterministic/unicode/D-1D-rtlo",
        "deterministic/unicode/D-2A-homoglyph-command",
        "deterministic/unicode/D-6A-split-keyword",
        "deterministic/unicode/NC-3A-normalization-delta",
        "deterministic/unicode/safe-ascii-skill",
        "deterministic/unicode/safe-mixed-language-prose",
        "deterministic/unicode/safe-code-like-words",
    }.issubset({spec.path for spec in unicode_specs})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_deterministic.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/conftest.py tests/test_deterministic.py tests/fixtures/manifest.yaml tests/fixtures/deterministic/unicode
git commit -m "test: complete epic 3 deterministic fixture coverage"
```

### Task 11: Update project docs and verify the full Epic 3 slice

**Files:**
- Modify: `docs/requirements/architecture.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `TODO.md`

- [ ] **Step 1: Write the doc checklist into `TODO.md` before claiming completion**

```markdown
- [ ] Implement `src/skillinquisitor/detectors/rules/engine.py`
  > **Done:** ...
```

- [ ] **Step 2: Run the full Epic 3 verification commands**

Run: `pytest tests/test_normalize.py tests/test_config.py tests/test_pipeline.py tests/test_deterministic.py tests/test_cli.py -v`
Expected: PASS

Run: `python -m skillinquisitor rules list`
Expected: exits `0` and prints `D-1A`, `D-2A`, `D-6A`, and `NC-3A`

Run: `python -m skillinquisitor rules test D-1B tests/fixtures/deterministic/unicode/D-1B-zero-width/SKILL.md`
Expected: exits `1` and prints a `D-1B` finding

- [ ] **Step 3: Update the user-facing docs**

```markdown
README.md:
- add deterministic rule engine capabilities
- add `rules list` and `rules test` usage examples

CHANGELOG.md:
- record Epic 3 completion

docs/requirements/*.md:
- sync any implementation-level naming or modeling changes made during Epic 3
```

- [ ] **Step 4: Re-run verification after doc and TODO updates**

Run: `pytest tests/test_normalize.py tests/test_config.py tests/test_pipeline.py tests/test_deterministic.py tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add docs/requirements/architecture.md docs/requirements/business-requirements.md README.md CHANGELOG.md TODO.md
git commit -m "docs: record epic 3 deterministic foundation"
```

## Execution Notes

- Preserve the approved design boundary: normalization records transformations, rules emit findings.
- Keep all built-in rule registration inside `src/skillinquisitor/detectors/rules/`.
- Do not add child segments in Epic 3; save that for extraction-based epics.
- Keep custom rules regex-only even if richer extension ideas appear during implementation.
- Prefer adding small helpers over inflating `unicode.py` into an unstructured monolith.
- If verdict behavior needs temporary adjustment because scoring is not implemented yet, keep it minimal and document the decision in `docs/requirements/architecture.md` and `TODO.md`.
