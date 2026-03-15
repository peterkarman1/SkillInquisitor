# Epic 4 Design: Deterministic Encoding, Extraction, and Recursive Re-Scanning

**Date:** 2026-03-14
**Status:** Approved for planning
**Epic:** Epic 4 — Deterministic Checks: Encoding & Obfuscation

## Goal

Build the first recursive content-expansion subsystem for SkillInquisitor so the deterministic scanner can reveal and re-scan hidden payloads instead of only inspecting top-level artifact text.

After Epic 4, the project should have:
- extraction of HTML comment and code fence content into first-class scannable segments
- bounded recursive decoding of suspicious encoded payloads, starting with Base64 and text-like hex payloads
- explicit detection coverage for Base64, ROT13, hex/XOR obfuscation, HTML comments, and code fences
- provenance-aware derived segments that preserve where hidden content came from
- regression fixtures that lock down nested and multi-layer obfuscation behavior

This epic is not just a detector drop. It is the point where SkillInquisitor's `Skill -> Artifact -> Segment` model becomes truly recursive and capable of surfacing concealed payloads for downstream analysis.

## Approved Constraints

- Optimize for full architecture fidelity, not a thin milestone.
- Keep `normalize.py` as the owner of recursive segment expansion.
- Keep rule modules responsible for findings, not traversal orchestration.
- Preserve a flat `artifact.segments` list with nested provenance chains rather than introducing a tree model.
- Add hard bounds for recursion depth, candidate count, decoded size, and total derived segments per artifact.
- Make decoding selective and evidence-driven to control false positives.
- Prefer text-oriented decoded payload handling in Epic 4; binary-aware analysis can come later.
- Ensure derived segments are reusable by later ML and LLM layers without redesign.

## Non-Goals

Epic 4 does not implement:
- LLM analysis of decoded script payloads yet
- behavior-chain analysis across decoded content and sibling files
- final formatter upgrades for rich provenance rendering
- a generalized binary unpacking or archive extraction framework
- every possible obfuscation codec; Epic 4 focuses on the BRD-defined set

Epic 4 should produce a durable recursive expansion architecture, not a universal decoding framework. Extracted and decoded segments should be shaped so later ML and LLM layers can consume them without needing a second extraction design.

## Approach

The approved approach is a **recursive segment-expansion pipeline with rule-owned encoded-content findings**.

`normalize.py` continues to normalize artifact content and now also derives child segments from extraction and decoding operations. Each child segment carries its own `Location` plus a provenance chain showing how it was derived from the original artifact. The rule engine remains simple: it scans every segment in `artifact.segments` uniformly.

This preserves the architecture's intended boundary:
- normalization reveals hidden content
- deterministic rules decide what is suspicious enough to report

The important design consequence is that Epic 4 changes the scanner from "scan one original segment per artifact" to "scan all derived text views that survived bounded extraction/decoding heuristics."

## Deliverables

Epic 4 should produce these deliverables:

- `src/skillinquisitor/models.py`
  - Extend segment and configuration models to support recursive expansion bookkeeping and bounds.
- `src/skillinquisitor/normalize.py`
  - Add extraction, selective decoding, recursive traversal, dedupe, and provenance-aware segment generation.
- `src/skillinquisitor/detectors/rules/encoding.py`
  - Add Epic 4 rule family registration and implementations for D-3, D-4, D-5, D-21, and D-22.
- `src/skillinquisitor/detectors/rules/__init__.py`
  - Register the Epic 4 encoding rules alongside the Epic 3 Unicode rules.
- `src/skillinquisitor/detectors/rules/engine.py`
  - Reuse the current execution model with only the minimal support needed for the new rule family.
- `tests/fixtures/deterministic/encoding/`
  - Add positive, negative, nested, and multi-layer fixtures for Epic 4.
- `tests/test_normalize.py`
  - Add focused coverage for segment extraction, recursion bounds, dedupe, and provenance chains.
- `tests/test_deterministic.py`
  - Add fixture-driven Epic 4 contracts.
- `tests/test_pipeline.py`
  - Prove derived segments flow through the real pipeline and trigger downstream rules.
- `docs/requirements/architecture.md`
  - Update if any Epic 4 implementation details meaningfully refine the current architecture text.
- `README.md`, `CHANGELOG.md`, `TODO.md`
  - Update to reflect Epic 4 behavior once implementation lands.

## Architecture

Epic 4 should add one new subsystem shape while preserving the current pipeline contract:

1. artifact and segment normalization
   - existing Unicode/steganography normalization still runs and becomes reusable at segment scope
2. recursive segment expansion
   - extraction and decoding produce derived segments
3. deterministic rule execution
   - rules scan all segments uniformly
4. deterministic post-processing
   - contextual and multi-layer findings are derived from segments plus primary findings
4. finding reporting
   - findings point to the source artifact location and carry provenance context through the originating segment

### Core Boundary

The approved file-level ownership is:

- `normalize.py`
  - traversal order
  - extraction and decoding orchestration
  - recursion limits
  - segment dedupe
  - provenance construction
- `detectors/rules/encoding.py`
  - detection findings for encoded or hidden content
  - Base64 presence findings
  - ROT13 reference findings
  - hex/XOR pattern findings
  - HTML comment and code-fence findings where appropriate
- `pipeline.py`
  - unchanged high-level control flow; it receives richer normalized artifacts and scans their segments

This split avoids duplicating extraction logic in both normalization and rule evaluators.

### Text View Contract

Epic 4 should make one explicit contract for expansion:

- recursive extraction and decoding operate on raw-text segment content, never on `normalized_content`
- every accepted segment, including derived segments, also gets its own concealment-aware `normalized_content` view computed from its raw `content`
- downstream layers consume segments through a stable pair:
  - raw `content` for provenance-preserving source text
  - `normalized_content` for concealment-aware matching where a layer chooses to use it
- every derived segment's source span maps to the raw parent segment that produced it

This keeps source locations deterministic while still letting hidden Unicode and splitter tricks inside comments, fences, and decoded payloads be normalized consistently. Epic 4 should not attempt to project extracted spans through the normalization rewrites; normalization is an auxiliary analysis view, not the source-mapping view.

### Finding Anchoring Rule

When a detector matches against `normalized_content` rather than raw `content`, the finding should still anchor to the segment's raw source `Location` as the canonical location.

Epic 4 should not attempt offset remapping from normalized text back into raw text. If a rule needs to preserve the normalized excerpt or normalized-match offsets, it should store those in `Finding.details` while keeping the raw source span as the fixture-stable reported location.

This same rule applies to derived segments: `Finding.location` always equals the raw source `Location` carried by the segment being scanned. Relative offsets inside normalized or derived text may be stored in metadata, but they are never the canonical reported location.

## Model Changes

Epic 4 should extend the shared model conservatively so later layers can reuse it.

### `Segment`

The current `Segment` model already carries `content`, `segment_type`, `location`, and `provenance_chain`. That is enough to represent ancestry, but Epic 4 should add lightweight metadata needed for recursive processing and reporting:

- `id: str`
  - stable per-segment identifier for parent linkage, dedupe, and future references
- `normalized_content: str | None = None`
  - concealment-aware normalized view of this segment's raw content
- `depth: int = 0`
  - recursion depth relative to the original segment
- `parent_segment_id: str | None = None`
  - explicit linkage to the parent segment used to derive this segment
- `parent_start_offset: int | None = None`
  - start offset within the parent segment content that produced this segment
- `parent_end_offset: int | None = None`
  - end offset within the parent segment content that produced this segment
- `parent_segment_type: SegmentType | None = None`
  - optional convenience metadata for debugging and formatting
- `details: dict[str, object] = Field(default_factory=dict)`
  - extraction metadata such as decoder kind, source token preview, or fence language

The long-term ancestry source of truth remains `provenance_chain`.

`Segment.id` should be deterministic rather than random. A stable hash of artifact path, parent segment ID, segment type, source offsets, and derived content is sufficient for Epic 4.

### `SegmentType`

Epic 4 should extend `SegmentType` with types for the new expansion paths:

- `HEX_DECODE`
- `ROT13_TRANSFORM`
- `HTML_COMMENT`
- `CODE_FENCE`
- `BASE64_DECODE`

`HTML_COMMENT`, `CODE_FENCE`, and `BASE64_DECODE` already exist in the enum today; Epic 4 should add `HEX_DECODE` and `ROT13_TRANSFORM` rather than overloading existing names.

### `ScanConfig`

Epic 4 needs explicit recursion and decoding bounds in config. The exact schema shape can be nested under deterministic config, but the implementation should support these controls:

- `max_derived_depth`
- `max_derived_segments_per_artifact`
- `max_decode_candidates_per_segment`
- `max_decoded_bytes`
- `base64_min_length`
- `hex_min_length`
- `require_rot13_signal`

Defaults should be conservative and deterministic.

### `Finding`

Epic 4 should add `segment_id: str | None = None` to findings so post-processing and future formatter work can reason about which segment produced which result without reverse-matching on location text alone.

## Recursive Segment Expansion Design

Epic 4 should keep `artifact.segments` as a flat list. The hierarchy is represented through provenance rather than nested child collections.

### Expansion Flow

For each artifact:

1. build the original segment from raw artifact content
2. apply existing normalization transforms and store normalization metadata on the artifact
3. recursively expand derived segments from the original segment
4. compute `normalized_content` for every accepted segment, including derived ones, using the same concealment-aware normalization helper family
5. attach all accepted derived segments to `artifact.segments`
6. scan the full flat segment list through the normal rule engine
7. run a deterministic post-processing pass for contextual and chain findings

The important nuance is that steps 2 and 3 operate on different views:
- step 2 computes `normalized_content` and `normalization_transformations` for artifact-level policy
- step 3 derives child segments only from raw segment text so source-span mapping stays exact
- step 4 computes per-segment normalized views after segment creation so all layers can consume a consistent segment contract

### Expansion Order

The expansion order should be deterministic and depth-first:

1. HTML comment extraction
2. code-fence extraction
3. Base64 decoding
4. hex decoding
5. ROT13 transformed scan path

The extraction-first posture matters because a Base64 payload hidden inside an HTML comment or code fence should be discovered by expanding the comment or fence content first, then recursively scanning that derived text for encoding candidates.

### Normative Traversal and Truncation Rules

Epic 4 should define one deterministic traversal algorithm:

- candidate discovery within a parent segment is always left-to-right by raw source start offset
- extractor priority for equal or competing ranges is:
  1. code fences
  2. HTML comments outside already-selected code-fence spans
  3. Base64 candidates
  4. hex candidates
  5. ROT13 transform trigger
- recursion is depth-first pre-order over accepted child segments in that discovery order
- `max_derived_depth` is checked before child creation; children beyond that depth are not created
- only accepted decode-derived children (`BASE64_DECODE`, `HEX_DECODE`) count toward `max_decode_candidates_per_segment`
- rejected, malformed, or over-byte-limit decode candidates do not consume decode slots
- when `max_decode_candidates_per_segment` is reached, later decode candidates in the same parent are ignored
- all accepted derived children of any type count toward `max_derived_segments_per_artifact`
- when `max_derived_segments_per_artifact` is reached, later candidate children are skipped and never recursed into

This gives bounded scans a fixture-stable left-to-right survival rule.

### Extraction Precedence and Overlap

Extraction from markdown must be non-overlapping and precedence-driven.

Rules:
- identify fenced code spans first on the raw parent segment
- HTML comment extraction on that same parent must exclude comment spans fully contained inside already-identified code-fence spans
- once a code-fence child segment is created, HTML comments inside that fence body are extracted only when recursively processing the fence child

This means the same hidden comment text is extracted exactly once per ancestry path, avoiding duplicate segments and unstable contextual findings.

### Extraction Eligibility Matrix

Epic 4 should apply HTML comment and code-fence extraction only to segments whose root artifact `file_type` is `MARKDOWN`.

Within markdown-rooted artifacts, segments with these `SegmentType` values are eligible for HTML comment and code-fence extraction:
- `ORIGINAL`
- `HTML_COMMENT`
- `CODE_FENCE`
- `BASE64_DECODE`
- `HEX_DECODE`
- `ROT13_TRANSFORM`

Within non-markdown artifacts:
- HTML comment extraction does not run in Epic 4
- code-fence extraction does not run in Epic 4

Malformed or overlapping markdown constructs are resolved by first non-overlapping left-to-right match wins at the current parent segment scope.

This keeps recursive markdown extraction available for hidden markdown-like payloads while avoiding a broad “parse everything as markdown” policy.

### Dedupe

Epic 4 should deduplicate derived segments aggressively enough to prevent explosion while preserving distinct provenance paths.

Recommended dedupe key:
- artifact path
- parent segment ID
- source span offsets in the parent
- derived segment type
- derived content hash

Do not globally dedupe by content alone. The same decoded payload appearing in two different locations should remain independently traceable.

## Normalize-to-Rules Interface

Epic 4 should define a narrow interface between recursive expansion and rule evaluation so `encoding.py` does not need to redo candidate analysis.

`normalize.py` should expose accepted extraction and decoding decisions through derived segment metadata:

- `segment_type`
  - identifies whether the segment came from an HTML comment, code fence, Base64 decode, hex decode, or ROT13 transform
- `details["decoder"]`
  - for decode-derived segments, values such as `base64`, `hex`, or `rot13`
- `details["source_preview"]`
  - short truncated preview of the matched source token for user-facing messages and debugging
- `details["fence_language"]`
  - for code-fence segments when present
- `details["decode_gate"]`
  - structured summary of why the candidate was accepted, such as length, successful decode, and text-likeness checks

Epic 4 should not model rejected candidates as segments. Rejected candidates are simply skipped. This keeps the contract narrow:
- normalization owns candidate discovery, gating, and accepted derived-segment creation
- rules inspect the resulting derived segments and their metadata to emit findings

This means `D-3A` and `D-5A` are findings about accepted suspicious payloads that survived Epic 4 gating, not about every regex-shaped candidate in raw text.

All later layers should receive the same `Segment` contract:
- raw `content`
- optional `normalized_content`
- provenance metadata
- source `Location`

That is the compatibility point that lets Epic 4 satisfy the architecture goal of extracted content being scannable by all applicable layers when those layers exist.

## Extraction Design

### HTML Comments (D-21)

HTML comments in markdown are extraction points, not only findings.

Epic 4 should:
- extract each HTML comment body as a child `Segment`
- preserve the source span of the comment body inside the artifact
- append a provenance step indicating extraction from an HTML comment
- allow all later deterministic rules to scan the extracted body

The derived segment content should be the inner comment body, not the literal `<!-- -->` wrapper.

### Code Fences (D-22)

Code fences are also extraction points.

Epic 4 should:
- extract fenced content from markdown artifacts as child segments
- preserve the source span of the inner fenced body
- capture optional fence-language metadata in segment details
- allow downstream deterministic rules to scan the extracted body

This is important both for hidden prompt content and for script-like payloads placed in markdown examples.

### Contextual Extraction Findings

Epic 4 should not emit findings merely because an HTML comment or code fence exists.

Instead:
- extraction alone is silent
- `D-21A` and `D-22A` are contextual findings emitted only when the extracted segment or one of its descendants produces at least one other non-`INFO` deterministic finding
- those findings exist to explain that suspicious content was hidden inside a comment or fence, not to punish normal markdown structure

This keeps D-21 and D-22 useful without turning ordinary documentation into noise.

## Decoding Design

Epic 4 should make decoding selective, bounded, and text-first.

### Base64 (D-3)

Base64 handling should have two responsibilities:

1. detection
   - report that a suspicious Base64 payload exists
2. expansion
   - decode text-like candidates into child segments for recursive re-scanning

#### Candidate Gating

Base64 candidates should be accepted only when they satisfy enough evidence:

- length above configured minimum
- valid Base64 alphabet and padding shape
- decode succeeds
- decoded bytes fit the configured size limit
- decoded payload is plausibly textual after UTF-8 decode or a similarly narrow text heuristic

This should avoid decoding random hashes, compressed blobs, or arbitrary binary noise during Epic 4.

#### Recursive Re-Scanning

Accepted decoded payloads become `BASE64_DECODE` child segments and are recursively expanded again, allowing patterns like:
- Base64 -> hex -> dangerous text
- HTML comment -> Base64 -> dangerous script

### Hex (D-5 partial)

Epic 4 should support text-like hex payload expansion when the confidence signal is strong enough.

Recommended support:
- long contiguous hex strings over a configured minimum length
- explicit decode constructs like `bytes.fromhex(...)`

When a candidate decodes cleanly into plausible text, it should become a `HEX_DECODE` child segment and enter the same recursive expansion path.

### XOR and Dynamic Obfuscation (D-5 partial)

XOR-style obfuscation should be detector-owned in Epic 4, not normalization-owned.

The scanner should detect constructs such as:
- `chr(ord(c) ^ N)`
- similar looped XOR decode idioms

But it should not attempt symbolic execution or full deobfuscation in Epic 4. The purpose here is strong pattern detection and future extensibility, not building an interpreter.

### ROT13 (D-4)

ROT13 has two behaviors:

1. detect explicit ROT13 usage or references
2. derive a transformed scan view when the file contains a real ROT13 signal

Epic 4 should not ROT13-transform every file by default. That would create noisy derived content and poor explainability.

Instead, Epic 4 should require a clear trigger, such as:
- `rot13`
- `rot_13`
- `codecs.decode(..., 'rot13')`

When that signal exists, Epic 4 should create one `ROT13_TRANSFORM` child from the entire signaled segment content, not just the matched token span:

- if the signal is on the original artifact segment, transform that full segment text
- if the signal is inside an extracted child segment, transform that full child segment text

This preserves the BRD intent of scanning the full text view while keeping recursion scope deterministic and local to the signaled segment.

Additional ROT13 constraints:
- at most one `ROT13_TRANSFORM` child may be created per parent segment
- multiple ROT13 references inside the same parent still collapse to that one deterministic child
- `ROT13_TRANSFORM` segments are not eligible for further ROT13 transforms
- `ROT13_TRANSFORM` segments remain eligible for other extraction and decoding passes if their raw transformed content contains valid candidates

## Provenance Design

Provenance is a primary requirement of Epic 4, not an incidental detail.

Each derived segment should:
- point at the source artifact file path
- carry start and end lines for the source span that produced it
- append a `ProvenanceStep` explaining the transformation

Example provenance chain:
- `ORIGINAL`
- `HTML_COMMENT`
- `BASE64_DECODE`

This is sufficient for future formatter work to explain findings like "dangerous payload decoded from Base64 found inside an HTML comment."

### Location Strategy

Epic 4 should continue the project's current correctness-first posture:

- line numbers are required where feasible
- columns are included when reliable and cheap
- derived segments should map back to the source span that produced them, not to synthetic line numbers within the decoded text alone
- `Finding.location` always reports the scanned segment's raw source span; any normalized-relative or derived-text-relative offsets belong only in `Finding.details`

## Rule Design

Epic 4 should introduce a new rule module, `detectors/rules/encoding.py`, registered through the same engine as existing rules.

The module should expose two rule phases:

1. primary segment and artifact evaluators
   - emit direct findings from raw or normalized segment views
2. post-processing evaluators
   - inspect segments plus primary findings to emit contextual and chain findings such as `D-21A`, `D-22A`, and `D-5C`

The engine or pipeline should invoke this post-processing phase deterministically after the main rule scan and before final finding sorting.

### Rule Family

Recommended built-in rules:

- `D-3A`
  - suspicious Base64 payload detected
- `D-4A`
  - explicit ROT13 reference detected
- `D-4B`
  - ROT13-transformed content revealed suspicious patterns
- `D-5A`
  - suspicious hex payload detected
- `D-5B`
  - XOR decode construct detected
- `D-5C`
  - multi-layer encoding chain detected
- `D-21A`
  - suspicious content originated from an HTML comment
- `D-22A`
  - suspicious content originated from a code fence

This is the fixed Epic 4 built-in rule surface for planning and fixture design.

### Rule Boundaries

Rules should not decode or recurse themselves. They should evaluate:
- raw segment content
- segment normalized content where useful
- artifact metadata
- provenance and segment details

This allows rules to emit findings about:
- the presence of encoded content
- the fact that a derived segment came from a hidden location
- the existence of obfuscation constructs
- the fact that multiple encoding layers were traversed

### Multi-Layer Encoding

Epic 4 should detect multi-layer encoding chains by looking at derived segment provenance and decode lineage, not by inventing a separate traversal system inside the rule module.

Epic 4 should define `is_decode_like(segment_type)` as exactly:
- `BASE64_DECODE`
- `HEX_DECODE`
- `ROT13_TRANSFORM`

If a derived segment's provenance contains multiple decode-like steps, the rule layer can emit a dedicated chain-style obfuscation finding only when:

- the provenance contains two or more `is_decode_like(...)` steps, and
- the leaf segment itself has one or more primary suspicious findings at `MEDIUM` severity or above

This keeps `D-5C` focused on meaningful concealment rather than flagging every benign nested transform.

### Post-Processing Contract

Epic 4 should define a deterministic post-processing pass with these inputs:
- normalized skills and their flat segment lists
- primary deterministic findings with `segment_id`

It should support:
- descendant lookup by `parent_segment_id`
- finding lookup by `segment_id`
- contextual finding emission with `references` pointing to the primary suspicious findings they explain

Post-processing should run once after primary rule execution. Post-processed findings participate in the normal final finding sort and dedupe path.

### Post-Processing Cardinality

Epic 4 should make contextual finding counts deterministic:

- `D-21A`
  - emit at most one finding per HTML-comment segment
  - anchor to the HTML-comment segment's raw source `Location`
  - reference the sorted unique primary suspicious finding IDs found within that comment subtree
- `D-22A`
  - emit at most one finding per code-fence segment
  - anchor to the code-fence segment's raw source `Location`
  - reference the sorted unique primary suspicious finding IDs found within that fence subtree
- `D-5C`
  - emit at most one finding per suspicious leaf segment whose provenance contains two or more decode-like steps
  - anchor to that leaf segment's raw source `Location`
  - reference the sorted unique primary finding IDs that made the leaf suspicious

This one-per-ancestor or one-per-leaf rule should be the basis for deterministic fixture expectations and finding dedupe.

## Error Handling and Safety

Epic 4 should treat malformed candidates as normal scan input, not as exceptional failure paths.

Requirements:
- failed decode attempts do not fail the scan
- over-limit candidates are skipped deterministically
- malformed markdown comments or fences degrade gracefully
- decode failures should not emit noisy findings unless the pattern itself is suspicious enough to deserve one

The scanner should remain exact and stable for the same input.

## Testing Strategy

Epic 4 should be regression-harness-first.

### Fixture Coverage

Add `tests/fixtures/deterministic/encoding/` fixtures covering:

- `D-3-base64`
  - positive Base64 payloads
  - safe long Base64-like text that should not decode into findings
- `D-4-rot13`
  - explicit ROT13 references
  - safe prose containing accidental `rot13`-like text
- `D-5-hex-xor`
  - long hex strings
  - `bytes.fromhex(...)`
  - XOR idioms
  - safe hex-looking identifiers
- `D-21-html-comments`
  - hidden malicious text inside comments
  - benign comments that should not over-fire
- `D-22-code-fences`
  - fenced payloads
  - ordinary code examples that stay safe
- nested and chain fixtures
  - HTML comment -> Base64 -> dangerous text
  - Base64 -> hex -> dangerous text
  - cases that hit recursion limits safely

Each rule family needs positive and negative coverage.

### Focused Tests

Add direct tests for:
- provenance chain construction
- extraction span locations
- recursion-depth enforcement
- candidate-count and decoded-size limits
- dedupe behavior
- ROT13 trigger gating
- deterministic `Segment.id` generation
- post-processing behavior for `D-21A`, `D-22A`, and `D-5C`

### Acceptance Standard

Epic 4 is done when:
- derived text views are created and scanned through the real pipeline
- encoded payloads are recursively re-scanned up to configured depth
- findings from derived content preserve usable provenance
- false-positive controls are covered by explicit safe fixtures
- every segment has a stable raw-plus-normalized contract usable by later ML and LLM layers without redesign

## Risks and Mitigations

- Risk: recursive expansion explodes segment count
  - Mitigation: hard config bounds, deterministic traversal order, and dedupe
- Risk: decoding heuristics over-fire on harmless text
  - Mitigation: strong candidate gating and safe fixture coverage
- Risk: extraction and rules duplicate logic
  - Mitigation: keep decoding/extraction in normalization and findings in the rule module
- Risk: provenance becomes too vague for future reporting
  - Mitigation: require source-span locations and ordered provenance steps for every derived segment
- Risk: ROT13 transformed scanning becomes noisy
  - Mitigation: only derive transformed segments when an explicit ROT13 signal exists
- Risk: hex decoding expands too aggressively
  - Mitigation: restrict Epic 4 hex expansion to high-confidence, text-like candidates and keep XOR as detection-only

## Planning Notes

The implementation plan should likely split Epic 4 into a small number of tightly coupled phases:

1. model and config extensions for recursive segment expansion
2. normalization/extraction infrastructure
3. encoding rule module implementation
4. pipeline integration validation
5. fixture and regression expansion

That sequencing keeps the recursive segment machinery stable before adding the full rule family and large fixture corpus.
