# Epic 3 Design: Deterministic Unicode, Steganography, and Rule Engine Foundation

**Date:** 2026-03-14
**Status:** Approved for planning
**Epic:** Epic 3 — Deterministic Checks: Unicode & Steganography

## Goal

Build the first real deterministic detection subsystem for SkillInquisitor and make it the long-lived foundation for all later deterministic epics.

After Epic 3, the project should have:
- a real deterministic rule engine with stable metadata and filtering
- a normalization pipeline that reveals hidden content without emitting findings directly
- built-in Unicode, homoglyph, and keyword-splitting detections
- a narrow but durable custom regex rule path
- working `rules list` and `rules test` CLI commands that use the same engine as normal scans

This epic is not only about shipping `D-1`, `D-2`, and `D-6`. It is the point where deterministic scanning becomes a framework rather than placeholder scaffolding.

## Approved Constraints

- Treat Epic 3 as foundational infrastructure, not a thin first-pass detector drop.
- Keep `normalize.py` pure: it transforms content and records security-relevant transformations, but does not emit findings.
- Keep findings owned by the deterministic rule engine.
- Support both segment-level and artifact-level built-in rules from Epic 3.
- Keep custom rules regex-only in Epic 3.
- Favor aggressive homoglyph detection for recall, with false-positive control handled by severity and fixtures rather than overly narrow heuristics.
- Keep the original segment as the canonical scannable source-mapped unit for Epic 3.
- Run `rules test` through the full Epic 3 normalization path before executing the named rule.
- Treat dangerous keyword splitting as language-agnostic and expandable, not shell-specific.

## Non-Goals

Epic 3 does not implement:
- recursive extraction or child segments for Base64, HTML comments, or code fences
- behavior chain analysis across files or skills
- ML or LLM inference
- final risk scoring behavior beyond integrating deterministic findings into the current scan result
- a full third-party plugin API for externally distributed rules

The engine should look plugin-ready internally, but external plugin/distribution mechanics are intentionally deferred.

## Approach

The approved approach is a **metadata-driven deterministic engine with pure normalization and typed transformation records**.

Normalization reveals suspicious content and captures how the raw file changed under security-oriented cleanup. The deterministic engine then evaluates original segments and normalized artifact views through registered rules. Built-in rules and custom regex rules share the same engine path, registry, metadata model, and filtering behavior.

This keeps the subsystem structurally extensible without overcommitting to a plugin platform before later rule families exist.

## Comparator Insight: SkillSentry

Epic 3 should learn from SkillSentry without copying its architectural shortcuts.

Useful patterns confirmed by the SkillSentry research doc and upstream implementation:
- normalize before matching
- keep rule metadata declarative where possible
- use reusable dangerous keyword and action vocabularies
- make custom rules simple and regex-first

Patterns not to copy:
- single-file scanner architecture
- stringly typed issue reporting
- direct whole-file regex scans as the only execution model
- blending normalization, detection, scoring, and reporting into one pass

SkillSentry validates the normalization-first strategy, but SkillInquisitor should implement it inside the existing `Skill -> Artifact -> Segment` architecture with typed models and provenance-aware locations.

## Deliverables

Epic 3 should produce these deliverables:

- `src/skillinquisitor/models.py`
  - Add typed normalization transformation metadata.
- `src/skillinquisitor/normalize.py`
  - Replace passthrough normalization with Unicode-, homoglyph-, and splitter-aware normalization.
- `src/skillinquisitor/detectors/rules/`
  - Add the deterministic rule subsystem package.
- `src/skillinquisitor/detectors/rules/engine.py`
  - Registry, rule metadata, filtering, execution, and custom-rule loading.
- `src/skillinquisitor/detectors/rules/__init__.py`
  - Built-in rule registration bootstrap.
- `src/skillinquisitor/detectors/rules/unicode.py`
  - Epic 3 built-in rule family registration and implementations.
- `src/skillinquisitor/pipeline.py`
  - Integrate deterministic rule execution into real scans.
- `src/skillinquisitor/cli.py`
  - Implement `rules list` and `rules test`.
- `src/skillinquisitor/config.py`
  - Ensure custom regex rules are validated and loaded into the engine.
- `tests/fixtures/deterministic/unicode/`
  - Positive and negative fixtures for the Epic 3 rule families.
- `tests/test_deterministic.py`
  - Grow harness coverage for Epic 3 findings and normalization behavior.
- `tests/test_cli.py`
  - Add coverage for `rules list` and `rules test`.

## Architecture

Epic 3 should introduce a deterministic subsystem with four layers:

1. `normalize.py`
   - preprocesses raw artifact content
   - records security-relevant transformations
   - updates normalized artifact state
   - does not emit findings
2. rule registry and engine
   - owns rule registration, metadata, filtering, and execution
3. rule modules
   - register built-in rules by family and scope
4. pipeline integration
   - normalizes artifacts, executes enabled deterministic rules, and returns findings in the normal `ScanResult`

### Execution Model

The deterministic engine should support two built-in rule scopes from day one:

- `segment`
  - runs once per segment
  - intended for content-level detections like Unicode or split keywords
- `artifact`
  - runs once per artifact
  - intended for file-level checks and future frontmatter, size, and path-aware rules

Skill-level aggregation remains outside the rule engine for now. Later epics can add skill-wide analyzers without forcing an Epic 3 redesign.

## Model Changes

Epic 3 should extend the shared data model with explicit normalization metadata rather than storing ad hoc dicts.

Recommended additions:

- `NormalizationType`
  - enum capturing transformation classes such as `ZERO_WIDTH_REMOVAL`, `UNICODE_TAG`, `VARIATION_SELECTOR`, `HOMOGLYPH_FOLD`, and `KEYWORD_SPLITTER_COLLAPSE`
- `NormalizationTransformation`
  - one structured transformation record with:
    - transformation type
    - original snippet
    - normalized snippet
    - source `Location`
    - optional details
- `Artifact`
  - add `normalization_transformations: list[NormalizationTransformation]`

Important constraint:
- the original `Segment` remains the canonical source-mapped segment for Epic 3
- normalization does not create derived segments yet
- later extraction-based epics can add child segments for HTML comments, code fences, and decoded payloads

## Normalization Design

`normalize.py` should become the preprocessing layer for deterministic analysis.

For each artifact, normalization should produce:
- `normalized_content`
- the original top-level segment
- typed transformation records describing security-relevant rewrites

### Epic 3 Transformations

Normalization should implement:

- Unicode tag detection-oriented capture
- zero-width and invisible control removal
- variation selector removal
- aggressive homoglyph folding toward a Latin-oriented comparable form
- suspicious keyword splitter collapsing

Normalization must be aggressive enough to reveal hidden dangerous text while preserving raw-content source mapping for findings.

### Design Boundary

Normalization records facts, not judgments.

Examples:
- "this zero-width character was removed"
- "this Cyrillic character was folded to a Latin lookalike"
- "this dotted token collapsed into `eval`"

Whether those changes are suspicious enough to report is the deterministic engine's job.

## Rule Engine Design

The deterministic engine should be metadata-driven.

Each rule should register:
- stable `rule_id`
- optional `family_id`
- category
- default severity
- scope: `segment` or `artifact`
- short description
- enabled-by-default flag

The engine should expose:
- registry/discovery of built-in rules
- runtime loading of custom regex rules
- filtering by enabled checks and categories
- deterministic execution order
- a path to list all active rules
- a path to execute exactly one named rule against normalized input

### Rule Authoring Model

Epic 3 should support two internal authoring styles:

- declarative metadata with regex-based evaluators where possible
- small Python evaluators where regex is insufficient

This is the correct middle ground between:
- "everything is hand-coded logic"
- "everything must fit in YAML regexes"

Examples:
- custom rules are regex-only
- zero-width and RTLO checks can be simple evaluators
- aggressive homoglyph detection should be a Python evaluator
- dangerous keyword reassembly should be a Python evaluator with explicit vocabulary data

### Execution Flow

1. pipeline normalizes artifacts
2. engine constructs the enabled rule set from built-ins plus custom regex rules
3. engine runs artifact rules per artifact
4. engine runs segment rules per segment
5. engine returns findings in a stable sorted order

### Filtering

The engine should honor:
- rule-level enable or disable flags from config
- category-level enable or disable flags from config
- named rule selection for `rules test`

Severity thresholds may be enforced either in engine output shaping or later in reporting, but the implementation should choose one path consistently rather than splitting that logic across rules.

## Custom Rule Design

Epic 3 custom rules should remain regex-only and segment-oriented.

The supported shape should remain simple:

```yaml
custom_rules:
  - id: CUSTOM-1
    pattern: "some regex"
    severity: HIGH
    category: CUSTOM
    message: "Description of what was found"
```

This is intentionally narrow:
- no artifact metadata conditions
- no path predicates
- no mini-language for chaining

That keeps `D-24` useful without overdesigning a rule DSL before later epics clarify the real extension needs.

## Epic 3 Rule Set

Epic 3 should register these built-in rules:

- `D-1A`
  - Unicode tag characters
- `D-1B`
  - zero-width and invisible control characters
- `D-1C`
  - variation selectors
- `D-1D`
  - right-to-left override and related bidi override characters
- `D-2A`
  - aggressive mixed-script and homoglyph detection
- `D-6A`
  - dangerous keyword splitting and separator obfuscation
- `NC-3A`
  - security-relevant normalization delta detected

### D-1 Family

The `D-1` family should be split into separate internal rules rather than a single umbrella detection. This improves rule testing, `rules test` usefulness, and later tuning.

### D-2A: Aggressive Homoglyph Detection

The approved posture is aggressive recall.

The implementation should favor detection of suspicious mixed-script tokens broadly, with emphasis on:
- identifiers
- commands
- file paths
- URLs
- dotted or snake/camel tokens

It should still avoid automatically treating ordinary multilingual prose as malicious. The practical way to do that is to target token shapes that resemble executable or referential content before broader free-form text.

### D-6A: Dangerous Keyword Splitting

Keyword splitting should be driven by configurable dangerous keyword families rather than a flat shell-only list.

Initial keyword families should include concepts like:
- execution
  - `eval`, `exec`, `compile`, `subprocess`, `os.system`
- network
  - `curl`, `wget`, `fetch`, `requests`, `urllib`, `socket`
- secrets and environment
  - `os.environ`, `process.env`, `getenv`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- encoding and obfuscation
  - `base64`, `b64decode`, `fromhex`

This keeps the rule language-agnostic and expandable for Python, shell, JavaScript, Go, and other skill-shipped languages.

### NC-3A: Normalization Delta Rule

Epic 3 should include a separate explicit evasion rule for security-relevant normalization deltas rather than folding that behavior into `D-1`, `D-2`, or `D-6`.

This rule should trigger only when security-oriented normalization materially changes content in a way that suggests concealment. It should not fire on every benign textual cleanup.

This separation gives clearer reporting:
- what concealment mechanism was found
- why the normalization delta matters

## Location Strategy

Epic 3 findings should provide line-accurate locations everywhere feasible.

Rules:
- line numbers are required for built-in rules
- columns are included only when cheap and reliable
- artifact-level rules may fall back to file-level or line-only locations where appropriate

The implementation should optimize for correctness and stable tests over exhaustive offset precision.

## CLI Design

Epic 3 should implement the `rules` subcommands on top of the same deterministic engine used by normal scans.

### `skillinquisitor rules list`

Should display registered active rules with:
- rule ID
- family
- category
- severity
- scope
- whether the rule is built-in or custom

### `skillinquisitor rules test <rule-id> <file>`

Should:
1. resolve the file into a synthetic skill/artifact
2. run the normal Epic 3 normalization path
3. execute only the named rule
4. report findings through the existing output path

It should not bypass normalization or use an alternate rule execution path.

## Pipeline Integration

`pipeline.py` should stop returning a placeholder deterministic layer summary and begin executing the real deterministic engine.

For Epic 3:
- normalize all artifacts
- execute deterministic built-in and custom rules
- return real deterministic findings
- preserve ML and LLM layer placeholders if those epics are still unimplemented

The deterministic layer metadata should start reflecting real rule execution and finding counts.

## Testing Strategy

Epic 3 should use the regression harness as the primary contract.

### Required Coverage

Add positive and negative fixtures for:
- Unicode tag characters
- zero-width characters
- variation selectors
- RTLO and bidi override characters
- aggressive homoglyph detection
- dangerous keyword splitting
- normalization-delta reporting

Each rule family needs both:
- fixtures that should trigger
- safe fixtures that should not trigger

### Test Types

- fixture-driven deterministic tests in `tests/test_deterministic.py`
- CLI tests for `rules list` and `rules test`
- targeted unit tests for normalization helpers where fixture coverage would be too indirect
- integration tests proving the normal scan path returns deterministic findings through `pipeline.py`

### Acceptance Standard

Epic 3 is done when:
- the deterministic engine is reusable for later rule modules
- built-in Epic 3 rules produce stable finding contracts through the harness
- custom regex rules run through the same engine path
- `rules list` and `rules test` work against the real engine
- later deterministic epics can add rule modules without changing core execution architecture

## Risks and Mitigations

- Risk: aggressive homoglyph detection creates noisy findings
  - Mitigation: control with severity, exact fixtures, and token-shape heuristics rather than weakening the architecture
- Risk: normalization logic leaks policy into preprocessing
  - Mitigation: keep normalization pure and findings engine-owned
- Risk: custom-rule design expands too quickly into a DSL
  - Mitigation: keep Epic 3 custom rules regex-only
- Risk: later epics force an engine redesign
  - Mitigation: support both segment and artifact rule scopes now, and keep rule metadata first-class

## Planning Notes

The implementation plan should likely split Epic 3 into a small number of tightly coupled phases:

1. model and normalization infrastructure
2. engine and registry
3. Epic 3 built-in rules
4. pipeline and CLI integration
5. fixture and test expansion

That sequence keeps the foundation stable before wiring in rule behavior and user-facing commands.
