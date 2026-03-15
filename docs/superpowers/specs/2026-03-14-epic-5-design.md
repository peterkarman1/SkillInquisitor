# Epic 5 Design: Deterministic Secrets, Exfiltration, and Behavior Chains

**Date:** 2026-03-14
**Status:** Approved for planning
**Epic:** Epic 5 — Deterministic Checks: Secrets & Exfiltration

## Goal

Build the first behavior-oriented deterministic subsystem for SkillInquisitor so the scanner can identify credential access, network exfiltration, and dynamic execution patterns as both individual signals and higher-risk multi-step attack chains.

After Epic 5, the project should have:
- detection coverage for sensitive local credential paths and cloud metadata endpoints
- detection coverage for known secret-bearing environment variables and suspicious environment enumeration
- detection coverage for outbound network-send behavior across markdown and code artifacts
- detection coverage for dynamic execution and shell execution primitives
- skill-level behavior chain analysis that combines otherwise lower-severity findings into higher-confidence attack findings
- regression fixtures that lock down both positive detections and false-positive boundaries for benign admin and developer workflows

Epic 5 is where the scanner starts reasoning about dangerous intent, not just hidden content. The design should preserve the current deterministic rule engine while adding the semantics later epics already assume: action flags, cross-file correlation, and chain findings with references.

## Approved Constraints

- Optimize for the architecture roadmap, not a one-off regex drop.
- Keep the current deterministic rule engine and postprocessor pattern.
- Preserve `Skill` as the unit of chain analysis.
- Keep component findings visible for transparency, debugging, and fixture precision.
- Treat chain findings as the primary risk signal without deleting the underlying evidence.
- Bias toward balanced detection: broad component coverage, but severe escalation only when combined behavior is convincing.
- Support both markdown and code/script artifacts, but distinguish their confidence.
- Use deterministic action flags as the contract between Epic 5 and later Epic 10 / Epic 11 work.
- Keep chain definitions configurable through existing `ScanConfig.chains`.

## Non-Goals

Epic 5 does not implement:
- full data-flow tracing within code files
- AST parsing or language-specific semantic analysis
- final scoring absorption logic for chain findings
- formatter changes that prominently group or collapse chain evidence
- persistence or cross-agent write detection from later epics
- runtime verification of whether a network request truly transmits secret material

Epic 5 should create a durable deterministic behavior model that later LLM analysis and scoring can refine. It should not attempt to become a full program analyzer.

## Approach

The approved approach is a **two-pass action-flag pipeline with skill-level chain synthesis**.

In pass one, deterministic Epic 5 rules emit normal findings plus normalized action semantics such as `READ_SENSITIVE`, `NETWORK_SEND`, `EXEC_DYNAMIC`, and `SSRF_METADATA`. These findings remain ordinary deterministic findings, anchored to the source artifact location and compatible with the existing fixture harness.

In pass two, a deterministic postprocessor groups component findings by skill, evaluates built-in and configured chain definitions, and emits `D-19` findings that reference the component findings they combine.

This preserves the project's intended boundaries:
- rule modules detect local evidence and emit component findings
- the rule engine remains the orchestrator for deterministic execution
- postprocessing handles context-sensitive escalation such as cross-file chains

The design consequence is important: Epic 5 should not try to make every component rule "smart enough" to decide whether a full attack exists. Component rules stay local and composable. Chains are the first place where the scanner reasons over combined behavior.

## Deliverables

Epic 5 should produce these deliverables:

- `src/skillinquisitor/detectors/rules/secrets.py`
  - Add Epic 5 rules for D-7 and D-8.
- `src/skillinquisitor/detectors/rules/behavioral.py`
  - Add Epic 5 rules for D-9, D-10, and D-19 postprocessing.
- `src/skillinquisitor/detectors/rules/engine.py`
  - Register the Epic 5 rule families and invoke the Epic 5 postprocessor alongside the existing Epic 4 postprocessing.
- `src/skillinquisitor/models.py`
  - Reuse existing `Finding.action_flags`, `Finding.references`, `Skill.action_flags`, and `ScanConfig.chains`; refine only if implementation exposes a small missing piece.
- `tests/fixtures/deterministic/secrets/`
  - Add positive, negative, same-file, and cross-file fixtures for Epic 5 rule families and chains.
- `tests/test_deterministic.py`
  - Add fixture-driven Epic 5 contracts.
- `tests/test_pipeline.py`
  - Add pipeline coverage proving chain findings can be synthesized across files within one skill.
- `tests/test_cli.py`
  - Prove Epic 5 rules surface through `rules list` and remain visible through `rules test`.
- `README.md`, `CHANGELOG.md`, `TODO.md`
  - Update when Epic 5 implementation lands.
- `docs/requirements/business-requirements.md`, `docs/requirements/architecture.md`
  - Sync only if implementation meaningfully refines the currently documented Epic 5 behavior.

## Architecture

Epic 5 should extend the deterministic subsystem without introducing a parallel analysis framework.

### Core Boundary

The approved ownership is:

- `secrets.py`
  - sensitive file and metadata endpoint patterns
  - known secret environment variable patterns
  - suspicious generic environment enumeration patterns
  - `READ_SENSITIVE` and `SSRF_METADATA` tagging
- `behavioral.py`
  - outbound network-send patterns
  - dynamic execution and shell execution patterns
  - `NETWORK_SEND` and `EXEC_DYNAMIC` tagging
  - behavior chain synthesis for D-19
- `engine.py`
  - registration of Epic 5 rule families
  - invocation order for Epic 5 postprocessing
- `pipeline.py`
  - unchanged high-level orchestration; deterministic findings become richer, but the pipeline contract stays stable

This split keeps local detection logic near the rule families that own it and avoids burying chain semantics inside generic engine code.

### Two-Pass Flow

For each scan:

1. normalize artifacts and produce segments as today
2. run Epic 3, Epic 4, and Epic 5 primary deterministic rules
3. collect component findings carrying action flags and supporting details
4. run deterministic postprocessors:
   - existing Epic 4 contextual findings
   - new Epic 5 chain synthesis
5. return the combined finding set

The Epic 5 postprocessor should operate on the final primary deterministic findings, not on raw segments alone. This guarantees that chain logic composes with future rule changes and that chain findings can cleanly reference the specific component findings that triggered them.

## Rule Taxonomy

Epic 5 should use family-scoped sub-rule IDs rather than one coarse rule per BRD requirement. The BRD families remain satisfied through these more precise outputs.

### D-7 Sensitive Resources

- `D-7A` Sensitive local credential path reference
  - Detect references to `.env`, `.ssh/`, `.aws/`, `.gnupg/`, `.npmrc`, `.pypirc`, kube config paths, and similar credential-bearing resources.
  - Direct code access is stronger than prose mention.
  - Carries `READ_SENSITIVE` when the pattern is operational rather than incidental.
- `D-7B` Cloud metadata endpoint reference or access
  - Detect `169.254.169.254`, `metadata.google.internal`, and similar metadata service identifiers.
  - Carries `SSRF_METADATA`.
  - Carries `READ_SENSITIVE` as well when the pattern indicates actual fetching or retrieval rather than mere mention.

### D-8 Environment Secrets

- `D-8A` Known secret environment variable reference
  - Detect explicit names such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and similar secret-bearing variables.
  - Carries `READ_SENSITIVE`.
- `D-8B` Suspicious generic environment access or enumeration
  - Detect `os.environ`, `process.env`, `os.getenv()`, `printenv`, `env`, and similar access only when usage appears broad, enumerative, or tied to secret-like names.
  - Plain application configuration reads such as `PORT` or `NODE_ENV` should not trigger this rule on their own.
  - Carries `READ_SENSITIVE` only when the usage passes the suspiciousness threshold.

### D-9 Network Send Behavior

- `D-9A` Outbound network send behavior
  - Detect `curl`, `wget`, `requests`, `urllib`, `fetch`, `http.client`, sockets, and equivalent imperative markdown patterns.
  - Carries `NETWORK_SEND`.
  - Should capture enough metadata in `Finding.details` to support later chain summaries and LLM prompts, such as a destination preview or API family.

### D-10 Dynamic and Shell Execution

- `D-10A` Dynamic or shell execution behavior
  - Detect `eval`, `exec`, `compile`, `__import__`, `subprocess`, `os.system`, `popen`, `bash -c`, `sh -c`, backticks, and executable command substitution.
  - Carries `EXEC_DYNAMIC`.

### D-19 Behavior Chains

- `D-19A` Data exfiltration chain
  - Required actions: `READ_SENSITIVE + NETWORK_SEND`
- `D-19B` Credential theft chain
  - Required actions: `READ_SENSITIVE + EXEC_DYNAMIC`
- `D-19C` Metadata exfiltration chain
  - Required actions: `SSRF_METADATA + NETWORK_SEND`

The implementation may support additional chains from config, but these three should be the built-in baseline for Epic 5.

## Confidence and Severity Policy

Epic 5 needs explicit policy to stay balanced instead of noisy.

### Source-Kind Weighting

The same operation should not carry identical confidence in all contexts.

- code or script behavior
  - strongest confidence
- imperative markdown instruction
  - medium confidence
- incidental prose mention
  - weakest confidence and often below finding threshold

This distinction should be implemented through rule heuristics and stored in `Finding.details`, not through a second severity system.

### Component Severity Guidance

The implementation does not need a mathematically perfect confidence model, but it should follow these guardrails:

- direct sensitive file or secret-variable access
  - typically `MEDIUM` or `HIGH`
- metadata fetch behavior
  - at least `HIGH`
- generic outbound network send alone
  - typically `MEDIUM`
- dynamic execution alone
  - typically `HIGH`
- incidental documentation mention
  - either no finding or a lower-confidence `LOW` / `MEDIUM` finding only when imperative enough to matter

### Chain Escalation Policy

The approved chain severity posture is:

- markdown-only chain
  - `HIGH`
- chain containing at least one code or script artifact
  - `CRITICAL`
- cross-file chain within the same skill
  - same severity as same-file chain
  - slightly lower confidence may be recorded in details, but severity does not drop

This avoids an evasion path where attackers split behavior across files while still respecting the higher ambiguity of markdown-only instructions.

### Cloud Metadata Special Handling

Cloud metadata access is not merely another sensitive read. It should retain a stronger semantic signal:

- metadata endpoint reference or access produces `SSRF_METADATA`
- metadata endpoint access by itself is a high-risk component finding
- metadata plus outbound send behavior can escalate directly to a `CRITICAL` chain

This keeps the semantics needed by later targeted LLM prompts and scoring logic.

## Chain Synthesis Design

Epic 5 chain analysis should follow a simple, explicit algorithm.

### Evidence Model

The chain analyzer consumes component findings, not raw text spans. Each component finding contributes:

- one or more `action_flags`
- source artifact path and location
- supporting details such as sensitive target, network primitive, or execution primitive

The analyzer groups findings by `Skill` and evaluates whether a built-in or configured chain's required action flags are all present within that skill.

### References and Transparency

Chain findings should never replace or erase the component findings in raw output.

Instead, each chain finding should:
- remain a separate `Finding`
- use `references` to point at the component findings it combines
- summarize the relevant files and component action types in `details`

This keeps the system transparent for tests, debugging, CLI review, and future scoring absorption.

### Chain Selection Rules

The chain analyzer should be deterministic and conservative:

- only one instance of a given built-in chain should be emitted per distinct supporting evidence set
- component findings may support more than one chain if the action mix truly warrants it
- a chain should prefer the strongest available component evidence when multiple findings contribute the same required action

The design does not require a complex graph solver. A stable, deterministic greedy selection keyed by action coverage is sufficient for Epic 5.

## Pattern Strategy

Epic 5 should remain regex- and heuristic-driven, but with policy-aware grouping.

### Sensitive Resource Detection

Sensitive resource patterns should cover:
- relative and absolute path forms
- quoted and unquoted code-like references
- shell command examples
- markdown fenced examples and imperative prose where clearly operational

The rule should distinguish:
- direct operational access such as `open(".env")` or `cat ~/.ssh/id_rsa`
- imperative instructions such as "read `~/.ssh/id_rsa` and send it"
- neutral mention such as documentation describing how `.env` works

### Environment Access Detection

Generic environment access requires additional context to avoid noise. Stronger triggers include:
- enumeration over all variables
- dumping environment content
- access to keys with secret-like names
- immediate piping or transport of environment-derived data

### Network Detection

Outbound network detection should focus on send-capable operations rather than every URL mention. A plain documentation URL should not become a D-9 finding. The signal should require an operational primitive or imperative instruction.

### Execution Detection

Execution detection should cover both language-native and shell-native forms. The intended rule family is about dynamic or dangerous execution behavior, not every command invocation. Straightforward fixed subprocess calls may still qualify, but should be less severe than decoded or dynamic execution patterns.

## Fixture and Test Strategy

Epic 5 should treat the regression harness as the specification surface.

### Fixture Groups

Add fixtures under `tests/fixtures/deterministic/secrets/` for:

- `D-7-sensitive-files`
- `D-7-metadata-endpoints`
- `D-8-known-secret-vars`
- `D-8-generic-env-enum`
- `D-9-network-send`
- `D-10-dynamic-exec`
- `D-19-read-send-chain`
- `D-19-read-exec-chain`
- `D-19-metadata-send-chain`

Each major family should include both markdown and code-backed variants where applicable.

### False-Positive Boundaries

Epic 5 needs explicit safe fixtures for:

- `os.getenv("PORT")`
- `process.env.NODE_ENV`
- documentation that mentions `.env` without instructing secret extraction
- legitimate health-check or API usage that does not combine with sensitive reads
- fixed command execution examples that are operationally benign

### Cross-File Coverage

At least one fixture per major chain should distribute the component actions across multiple files in one skill so the chain analyzer is forced to operate at skill scope rather than artifact scope.

### Targeted Unit Tests

Outside the fixture harness, add focused tests for:

- chain synthesis behavior
- built-in versus configured chain definitions
- markdown-only versus code-backed chain severity
- cross-file chain handling
- component finding preservation and `references` integrity

## Acceptance Criteria

Epic 5 should be considered ready for planning when the design supports these outcomes:

- sensitive credential paths are detected with lower noise around neutral documentation
- known secret environment variable references are detected reliably
- generic environment access is only flagged when it appears suspicious
- outbound network-send behavior is detected across markdown and code contexts
- dynamic and shell execution behavior is detected across languages and shell forms
- cloud metadata targets are modeled distinctly through `SSRF_METADATA`
- chain findings can combine evidence across files within the same skill
- markdown-only chains escalate to `HIGH`
- chains involving at least one code or script artifact escalate to `CRITICAL`
- component findings remain visible while chain findings reference them
- the regression harness includes both positive and negative Epic 5 coverage

## Follow-On Planning Notes

When this design transitions into a written implementation plan, the plan should break the work into at least these tracks:

1. rule registration and helper groundwork
2. D-7 and D-8 component rules
3. D-9 and D-10 component rules
4. D-19 chain synthesis
5. fixture corpus and regression coverage
6. docs sync for implementation reality

That plan should preserve the balanced posture approved here and avoid collapsing into a single large implementation step.
