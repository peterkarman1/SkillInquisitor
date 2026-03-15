# Epic 6/7 Injection and Structural Validation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the substrate, deterministic rules, fixture coverage, and docs sync for Epic 6 and Epic 7 so SkillInquisitor can validate frontmatter, detect prompt injection and suppression signatures, validate skill structure, classify URLs, catch package and skill-name typosquatting, and flag robust text-density anomalies.

**Architecture:** Land the work in strict dependency order. First add the missing substrate: exact model fields, non-text artifact preservation, frontmatter parsing and parser-event capture, skill-scope rule execution, fixture-local config overrides, and metadata assertions. Then implement Epic 6 in three passes: D-11 signatures, D-12 suppression, and D-13 frontmatter validation. Then implement Epic 7 in four passes: D-14 structure, D-15 URL classification, D-20 package and skill-name typosquatting, and D-23 density anomalies. Keep curated default datasets in `policies.py`, keep schema/default merging in `config.py`, and keep verification split between focused unit tests and fixture regressions.

**Tech Stack:** Python 3.13, Pydantic v2, pytest, Typer, PyYAML, existing deterministic rule engine, existing regression harness

---

## File Structure

### Files to Create

- `src/skillinquisitor/detectors/rules/injection.py`
- `src/skillinquisitor/detectors/rules/structural.py`
- `src/skillinquisitor/policies.py`
- `tests/fixtures/deterministic/injection/`
- `tests/fixtures/deterministic/structural/`

### Files to Modify

- `src/skillinquisitor/models.py`
- `src/skillinquisitor/input.py`
- `src/skillinquisitor/normalize.py`
- `src/skillinquisitor/pipeline.py`
- `src/skillinquisitor/config.py`
- `src/skillinquisitor/detectors/rules/engine.py`
- `tests/conftest.py`
- `tests/test_config.py`
- `tests/test_deterministic.py`
- `tests/test_pipeline.py`
- `tests/test_cli.py`
- `tests/fixtures/manifest.yaml`
- `README.md`
- `CHANGELOG.md`
- `TODO.md`
- `docs/requirements/business-requirements.md`
- `docs/requirements/architecture.md`

### Responsibilities

- `models.py`
  - Add exact artifact and skill metadata fields required by the approved spec.
- `input.py`
  - Preserve binary artifacts, classify signatures, detect executability by mode and shebang, and distinguish `declared_skill`, `synthetic_directory`, `synthetic_file`, and `stdin`.
- `normalize.py`
  - Parse leading `SKILL.md` frontmatter, hydrate `Artifact.frontmatter*`, emit `FRONTMATTER_DESCRIPTION`, and preserve frontmatter parser observations and spans.
- `pipeline.py`
  - Pass the active `ScanConfig` into normalization and update `Skill.name` from valid normalized frontmatter.
- `config.py`
  - Define `frontmatter_policy`, `url_policy`, and `typosquatting` schema/default merging, including `trusted_urls` compatibility behavior.
- `policies.py`
  - Hold the checked-in protected package lists, protected skill-name list, and exact default thresholds/datasets used by Epic 7.
- `engine.py`
  - Add `skill` scope, preserve execution order (`skill -> artifact -> segment`), and register Epic 6/7 rule families.
- `injection.py`
  - Implement D-11, D-12, and D-13 with frontmatter-aware dedupe.
- `structural.py`
  - Implement D-14, D-15, D-20, and D-23 with exact canonicalization and threshold logic.
- `tests/conftest.py`
  - Extend fixture schema with `config_override`, selector-based `action_flags_contains`, and selector-based `details_contains`.

## Chunk 1: Substrate and Harness

### Task 1: Add the exact Epic 6/7 model contract

**Files:**
- Modify: `src/skillinquisitor/models.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for the new model fields**

```python
def test_artifact_model_supports_epic6_and_epic7_metadata():
    artifact = Artifact(path="SKILL.md")
    assert artifact.byte_size == 0
    assert artifact.is_text is True
    assert artifact.frontmatter_observations == []


def test_skill_model_supports_scan_provenance():
    skill = Skill(path="skill")
    assert skill.scan_provenance == "declared_skill"
```

- [ ] **Step 2: Run the failing tests**

Run: `uv run pytest tests/test_pipeline.py -k "epic6_and_epic7_metadata or scan_provenance" -v`
Expected: FAIL because the new fields do not exist yet.

- [ ] **Step 3: Add the exact model fields from the approved spec**

Implement:
- `Artifact.byte_size`
- `Artifact.is_text`
- `Artifact.encoding`
- `Artifact.is_executable`
- `Artifact.binary_signature`
- `Artifact.frontmatter_raw`
- `Artifact.frontmatter_location`
- `Artifact.frontmatter_error`
- `Artifact.frontmatter_fields`
- `Artifact.frontmatter_observations`
- `Skill.scan_provenance`

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py -k "epic6_and_epic7_metadata or scan_provenance" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/models.py tests/test_pipeline.py
git commit -m "feat: add epic 6 and 7 model contracts"
```

### Task 2: Preserve non-text artifacts, provenance variants, executability, and signatures in input resolution

**Files:**
- Modify: `src/skillinquisitor/input.py`
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for artifact preservation and provenance**

```python
@pytest.mark.asyncio
async def test_resolve_input_keeps_binary_artifacts(tmp_path):
    ...


@pytest.mark.asyncio
async def test_resolve_input_marks_synthetic_directory_provenance(tmp_path):
    ...


@pytest.mark.asyncio
async def test_resolve_input_marks_synthetic_file_provenance(tmp_path):
    ...


@pytest.mark.asyncio
async def test_resolve_input_marks_stdin_provenance():
    ...


@pytest.mark.asyncio
async def test_resolve_input_detects_shebang_executable(tmp_path):
    ...


def test_normalize_artifact_skips_non_text_content():
    artifact = Artifact(path="payload.bin", is_text=False, raw_content="")
    normalized = normalize_artifact(artifact, config=ScanConfig())
    assert normalized.normalized_content is None
    assert normalized.segments == []
```

- [ ] **Step 2: Run the failing tests**

Run: `uv run pytest tests/test_pipeline.py -k "binary_artifacts or synthetic_directory_provenance or synthetic_file_provenance or stdin_provenance or shebang_executable or skips_non_text_content" -v`
Expected: FAIL because binary artifacts are skipped, provenance variants are missing, shebang detection does not exist, and normalization still assumes text artifacts.

- [ ] **Step 3: Implement the minimal input preservation and classification**

Implementation requirements:
- keep non-text files as `Artifact`s with `raw_content=""`, `normalized_content=None`, `segments=[]`
- set `scan_provenance` correctly for all four target types
- detect executability from mode bit or shebang
- classify common signatures used by D-14E
- make `normalize.py` skip text normalization and segment extraction when `is_text` is `False`

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py -k "binary_artifacts or synthetic_directory_provenance or synthetic_file_provenance or stdin_provenance or shebang_executable or skips_non_text_content" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/input.py src/skillinquisitor/normalize.py tests/test_pipeline.py
git commit -m "feat: preserve artifact provenance and executability"
```

### Task 3: Implement frontmatter extraction happy path

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for frontmatter extraction**

```python
def test_normalize_artifact_extracts_frontmatter_description_segment():
    ...


@pytest.mark.asyncio
async def test_pipeline_updates_skill_name_from_valid_frontmatter(tmp_path):
    ...
```

- [ ] **Step 2: Run the failing tests**

Run: `uv run pytest tests/test_pipeline.py -k "frontmatter_description_segment or valid_frontmatter" -v`
Expected: FAIL because frontmatter is not extracted or used.

- [ ] **Step 3: Implement happy-path frontmatter parsing**

Implementation requirements:
- parse only leading `SKILL.md` frontmatter beginning at byte 0
- hydrate `Artifact.frontmatter`, `frontmatter_raw`, `frontmatter_location`
- emit `FRONTMATTER_DESCRIPTION`
- update `Skill.name` only in `pipeline.py`

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py -k "frontmatter_description_segment or valid_frontmatter" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py src/skillinquisitor/pipeline.py tests/test_pipeline.py
git commit -m "feat: add frontmatter extraction happy path"
```

### Task 4: Implement frontmatter edge cases, parser events, and exact span handling

**Files:**
- Modify: `src/skillinquisitor/normalize.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for the frontmatter edge cases**

Add tests for:
- non-mapping YAML sets `frontmatter_error`
- duplicate `name` fields populate `frontmatter_observations`
- invalid frontmatter still allows later body scanning
- frontmatter field spans point at absolute file coordinates
- duplicate `name` does not update `Skill.name`

- [ ] **Step 2: Run the failing tests**

Run: `uv run pytest tests/test_pipeline.py -k "frontmatter_error or frontmatter_observations or absolute_file_coordinates or duplicate_name" -v`
Expected: FAIL because parser-event capture and edge-case handling are missing.

- [ ] **Step 3: Implement the exact frontmatter parse-result contract**

Implementation requirements:
- record `frontmatter_error`
- record `frontmatter_fields`
- record `frontmatter_observations`
- preserve last-key-wins parsed mapping for storage only
- require exactly one observed `name` field before updating `Skill.name` in `pipeline.py`

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py -k "frontmatter_error or frontmatter_observations or absolute_file_coordinates or duplicate_name" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/normalize.py src/skillinquisitor/pipeline.py tests/test_pipeline.py
git commit -m "feat: add frontmatter parser events and spans"
```

### Task 5: Add skill-scope execution order and harness schema support

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `tests/conftest.py`
- Modify: `tests/test_deterministic.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for the new substrate contracts**

Add tests for:
- rule execution order is `skill -> artifact -> segment`
- fixture expectations support `config_override`
- selector-based `action_flags_contains`
- selector-based `details_contains`

- [ ] **Step 2: Run the failing tests**

Run: `uv run pytest tests/test_deterministic.py tests/test_cli.py tests/test_pipeline.py -k "skill_scope or config_override or action_flags_contains or details_contains or execution_order" -v`
Expected: FAIL because the engine and fixture harness do not support the new contracts yet.

- [ ] **Step 3: Implement skill scope and fixture schema**

Implementation requirements:
- add `skill` scope to the engine
- preserve the execution order contract
- deep-merge `config_override` into `ScanConfig`
- resolve metadata assertions by selector (`rule_id`, `file_path`, `start_line`)

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_deterministic.py tests/test_cli.py tests/test_pipeline.py -k "skill_scope or config_override or action_flags_contains or details_contains or execution_order" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/engine.py tests/conftest.py tests/test_deterministic.py tests/test_cli.py tests/test_pipeline.py
git commit -m "feat: add skill scope and fixture contract support"
```

## Chunk 2: Epic 6 Injection and Suppression

### Task 6: Add complete Epic 6 fixture coverage before rule implementation

**Files:**
- Create: `tests/fixtures/deterministic/injection/`
- Modify: `tests/fixtures/manifest.yaml`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Create positive and safe fixtures for every Epic 6 sub-rule**

Required positives:
- `D-11A-instruction-override`
- `D-11B-role-rebinding`
- `D-11C-system-prompt-disclosure`
- `D-11D-role-delimiter`
- `D-11E-system-mimicry`
- `D-11F-canonical-jailbreak`
- `D-12A-nondisclosure`
- `D-12B-silent-execution`
- `D-12C-output-suppression`
- `D-12D-confirmation-bypass`
- `D-13A-unexpected-field`
- `D-13B-invalid-field-type`
- `D-13C-overlong-description`
- `D-13D-yaml-constructs`
- `D-13E-description-injection`

Required safe lookalikes:
- `safe-quoted-attack-example`
- `safe-benign-frontmatter`
- `safe-logging-silent-flag`
- `safe-long-description-without-directives`

- [ ] **Step 2: Add combo fixtures**

Required combos:
- `suppression-plus-secret-read`
- `description-injection-plus-epic5-behavior`

- [ ] **Step 3: Add fixture tests and run them red**

Run: `uv run pytest tests/test_deterministic.py -k "injection_rule_fixtures" -v`
Expected: FAIL because rule implementation is still missing.

- [ ] **Step 4: Ensure malicious Epic 6 fixtures are deterministic-scoped and D-12 fixtures use metadata assertions**

Use `action_flags_contains` and `details_contains` to assert:
- `SUPPRESSION_PRESENT`
- one specific suppression flag
- `amplifier_eligible: true`

Also require malicious Epic 6 `expected.yaml` files to include:
- `scope.layers: [deterministic]`
- `scope.checks: [...]`

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/deterministic/injection tests/fixtures/manifest.yaml tests/test_deterministic.py
git commit -m "test: add epic 6 fixture coverage"
```

### Task 7: Wire Epic 6 rule registration

**Files:**
- Create: `src/skillinquisitor/detectors/rules/injection.py`
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing registry and CLI tests**

Add tests proving:
- registry includes `D-11A` through `D-13E`
- `rules list` prints representative Epic 6 rules

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_cli.py tests/test_pipeline.py -k "epic6_rules" -v`
Expected: FAIL because Epic 6 rules are not registered.

- [ ] **Step 3: Scaffold `injection.py` and register it**

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_cli.py tests/test_pipeline.py -k "epic6_rules" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/injection.py src/skillinquisitor/detectors/rules/engine.py tests/test_cli.py tests/test_pipeline.py
git commit -m "feat: register epic 6 rule family"
```

### Task 8: Implement D-11 prompt injection signatures

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/injection.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write focused failing tests for D-11 coverage and dedupe**

Add unit tests for:
- exact signature matching
- markdown versus code conservatism
- frontmatter-description dedupe against `ORIGINAL`

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_11 or frontmatter_description_dedupe" -v`
Expected: FAIL because D-11 implementations are not complete.

- [ ] **Step 3: Implement D-11A through D-11F**

Keep them exact-signature and high-precision per the approved spec.

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_11 or frontmatter_description_dedupe" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/injection.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: implement D-11 prompt injection signatures"
```

### Task 9: Implement D-12 suppression directives and metadata emission

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/injection.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write focused failing tests for D-12 metadata**

Add tests for:
- `SUPPRESSION_PRESENT`
- `SUPPRESS_DISCLOSURE` / `SUPPRESS_OUTPUT` / `SUPPRESS_CONFIRMATION`
- `amplifier_eligible`
- safe handling of benign `--silent`

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_12 or suppression_present or amplifier_eligible" -v`
Expected: FAIL because D-12 metadata behavior is not fully implemented.

- [ ] **Step 3: Implement D-12A through D-12D**

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_12 or suppression_present or amplifier_eligible" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/injection.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: implement D-12 suppression directives"
```

### Task 10: Implement D-13 frontmatter validation

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/injection.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write focused failing tests for D-13 sub-rules**

Add unit tests for:
- unexpected field
- invalid field type
- overlong description
- YAML construct observations
- description injection on `FRONTMATTER_DESCRIPTION`

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_13 or frontmatter_validation" -v`
Expected: FAIL because D-13 is not fully implemented.

- [ ] **Step 3: Implement D-13A through D-13E**

Implementation notes:
- consume parsed frontmatter state instead of raw whole-file regex
- use token observations for D-13D
- preserve D-13E as frontmatter-contextual

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_13 or frontmatter_validation" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/injection.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: implement D-13 frontmatter validation"
```

## Chunk 3: Epic 7 Structural and Metadata Rules

### Task 11: Add complete Epic 7 fixture coverage before rule implementation

**Files:**
- Create: `tests/fixtures/deterministic/structural/`
- Modify: `tests/fixtures/manifest.yaml`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Create positive and safe fixtures for every Epic 7 sub-rule**

Required positives:
- `D-14A-nested-skill-manifest`
- `D-14B-unexpected-top-level-directory`
- `D-14C-unexpected-top-level-file`
- `D-14D-executable-outside-scripts`
- `D-14E-native-binary`
- `D-14F-archive-outside-assets`
- `D-14G-hidden-top-level-dotdir`
- `D-15A-allowlisted-host`
- `D-15B-shortener-url`
- `D-15C-ip-literal`
- `D-15D-obscured-ip`
- `D-15E-unknown-host-docs`
- `D-15F-userinfo-or-encoding-trick`
- `D-15G-non-https-url`
- `D-15H-punycode-host`
- `D-20A-python-index-override`
- `D-20B-javascript-registry-override`
- `D-20C-cargo-registry-override`
- `D-20D-python-typosquat`
- `D-20E-dependency-confusion`
- `D-20F-skill-name-typosquat`
- `D-23A-hidden-comment-inflation`
- `D-23B-invisible-unicode-mass`
- `D-23C-opaque-text-blob`

Required safe fixtures:
- `safe-top-level-manifests`
- `safe-assets-archive`
- `safe-allowlisted-url`
- `safe-private-like-package-name`
- `safe-multilingual-large-text`

- [ ] **Step 2: Add fixture-local config override cases**

Use `config_override` to prove:
- allowlisted hosts suppress or downgrade URL findings
- protected package and skill-name lists can be overridden safely

- [ ] **Step 3: Run fixture tests red**

Run: `uv run pytest tests/test_deterministic.py -k "structural_rule_fixtures" -v`
Expected: FAIL because Epic 7 rules are not implemented.

- [ ] **Step 4: Ensure malicious Epic 7 fixtures are deterministic-scoped and safe fixtures cover lookalikes**

Require malicious Epic 7 `expected.yaml` files to include:
- `scope.layers: [deterministic]`
- `scope.checks: [...]`

Add safe cases for:
- assets archives
- common manifests/lockfiles
- multilingual text that would fail a naive byte ratio
- scoped packages that are exact matches

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/deterministic/structural tests/fixtures/manifest.yaml tests/test_deterministic.py
git commit -m "test: add epic 7 fixture coverage"
```

### Task 12: Add `policies.py` and config support

**Files:**
- Create: `src/skillinquisitor/policies.py`
- Modify: `src/skillinquisitor/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write failing tests for config defaults and compatibility**

Add tests for:
- `frontmatter_policy`
- `url_policy`
- `typosquatting`
- `trusted_urls` compatibility merge

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_config.py -k "frontmatter_policy or url_policy or typosquatting or trusted_urls" -v`
Expected: FAIL because the new config schema is missing.

- [ ] **Step 3: Implement curated defaults and config models**

Ownership split:
- `policies.py` stores curated default datasets and exact threshold constants
- `config.py` stores schema, merging, validation, and compatibility behavior

- [ ] **Step 4: Re-run the config tests**

Run: `uv run pytest tests/test_config.py -k "frontmatter_policy or url_policy or typosquatting or trusted_urls" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/policies.py src/skillinquisitor/config.py tests/test_config.py
git commit -m "feat: add epic 7 policy and config defaults"
```

### Task 13: Implement D-14 structure validation

**Files:**
- Create: `src/skillinquisitor/detectors/rules/structural.py`
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write focused failing tests for D-14**

Add unit tests for:
- declared-skill-only layout checks
- nested `SKILL.md`
- executables detected by shebang or mode bit
- safe top-level allowlist behavior

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_14 or structure_validation" -v`
Expected: FAIL because D-14 is not implemented.

- [ ] **Step 3: Implement D-14A through D-14G**

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_14 or structure_validation" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/structural.py src/skillinquisitor/detectors/rules/engine.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: implement D-14 structure validation"
```

### Task 14: Implement URL canonicalization, dedupe, and D-15A through D-15H

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/structural.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write focused failing tests for D-15 contracts**

Add unit tests for:
- canonicalization of `hxxp` and `[.]`
- obscured IP detection
- context classification baselines
- dedupe of the same canonical URL across original and derived segments

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_15 or url_canonicalization or url_dedupe" -v`
Expected: FAIL because D-15 canonicalization and dedupe are not implemented.

- [ ] **Step 3: Implement D-15A through D-15H**

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_15 or url_canonicalization or url_dedupe" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/structural.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: implement D-15 url classification"
```

### Task 15: Implement D-20 package poisoning and skill-name typosquatting

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/structural.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write focused failing tests for D-20 contracts**

Add unit tests for:
- Python, JavaScript, and Cargo registry overrides
- scoped-package normalization
- short/medium/long name thresholds
- skill-name normalization and protected dataset lookup

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_20 or typosquatting_thresholds or scoped_package_normalization" -v`
Expected: FAIL because D-20 normalization and thresholds are not implemented.

- [ ] **Step 3: Implement D-20A through D-20F**

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_20 or typosquatting_thresholds or scoped_package_normalization" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/structural.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: implement D-20 package poisoning and typosquatting"
```

### Task 16: Implement D-23 density and anomaly rules

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/structural.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Write focused failing tests for D-23 math**

Add unit tests for:
- exact minimum thresholds
- `display_cells` math
- `D-23A` and `D-23B` ratios
- `D-23C` bytes-per-display-cell plus corroborator logic
- multilingual safe negative

- [ ] **Step 2: Run them red**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_23 or display_cells or bytes_per_display_cell" -v`
Expected: FAIL because D-23 math is not implemented.

- [ ] **Step 3: Implement D-23A through D-23C**

- [ ] **Step 4: Re-run the focused tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_deterministic.py -k "D_23 or display_cells or bytes_per_display_cell" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/structural.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: implement D-23 anomaly detection"
```

## Chunk 4: Docs and Verification

### Task 17: Sync docs and progress trackers with final Epic 6/7 behavior

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `TODO.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `docs/requirements/architecture.md`

- [ ] **Step 1: Re-read the approved design spec and final implementation**

Read:
- `docs/superpowers/specs/2026-03-14-epic-6-7-design.md`
- the final code changes
- the current requirements docs

- [ ] **Step 2: Update docs to reflect reality**

Document:
- exact Epic 6 and 7 rule IDs
- frontmatter parsing contract
- skill-scope deterministic rules
- exact config shapes
- exact D-23 thresholds

- [ ] **Step 3: Run doc-adjacent verification**

Run: `uv run pytest tests/test_cli.py tests/test_config.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md TODO.md docs/requirements/business-requirements.md docs/requirements/architecture.md
git commit -m "docs: sync epic 6 and 7 behavior"
```

### Task 18: Run final verification before handoff

**Files:**
- Modify: none

- [ ] **Step 1: Run the focused deterministic suite**

Run: `uv run pytest tests/test_deterministic.py tests/test_pipeline.py tests/test_cli.py tests/test_config.py -q`
Expected: all targeted tests PASS

- [ ] **Step 2: Run the full project suite**

Run: `./scripts/run-test-suite.sh`
Expected: full suite PASS with only the usual skips

- [ ] **Step 3: Verify the working tree is clean**

Run: `git status --short`
Expected: clean working tree

- [ ] **Step 4: Record verification evidence in the final handoff**

Include:
- focused pytest command and result
- full suite command and result
- final skip count

- [ ] **Step 5: Commit only if a final verification-only commit is truly needed**

```bash
git add -A
git commit -m "chore: finalize epic 6 and 7 verification"
```
