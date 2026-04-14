# ML Prompt-Injection Ensemble -- Archived Documentation

This document preserves the complete design and implementation details of the
ML prompt-injection ensemble (Layer 2) before its removal from the codebase.
The ensemble was the second layer of SkillInquisitor's three-layer detection
pipeline, sitting between deterministic rule matching (Layer 1) and LLM code
analysis (Layer 3).

---

## Overview

The ML ensemble ran three small HuggingFace sequence-classification models
against text segments extracted from skill files. Each model independently
scored how likely a segment contained prompt injection, and a weighted
soft-voting formula combined the scores into a single ensemble decision. The
system was designed to catch prompt-injection attacks that deterministic regex
patterns might miss, while keeping inference fast enough to run on CPU-only
machines.

---

## Three-Model Architecture

| Model ID | Family | Parameters | Default Weight | Malicious Label Strategy |
|---|---|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | DeBERTa v3 | 184M | 0.40 | Label name contains `"injection"` |
| `patronus-studio/wolf-defender-prompt-injection` | ModernBERT | 308M | 0.35 | Label at index 1 (`malicious_label_index=1`) |
| `madhurjindal/Jailbreak-Detector` | DistilBERT | 66M | 0.25 | Label name contains `"jailbreak"` |

Total combined parameter count: approximately 558M.

### Model Catalog

Each model was registered in `MODEL_CATALOG` (in `models.py`) as a
`ModelCatalogEntry` dataclass with fields:

```python
@dataclass(frozen=True)
class ModelCatalogEntry:
    id: str
    family: str
    type: str = "hf_sequence_classifier"
    default_weight: float = 1.0
    malicious_labels: tuple[str, ...] = ()
    malicious_label_index: int | None = None
    gated: bool = False
    summary: str = ""
```

The catalog served two purposes:
1. Providing human-readable summaries for the `models list` CLI command.
2. Defining the malicious-score extraction strategy per model (see below).

### Malicious Score Extraction

Each model outputs a softmax probability distribution over its label set. The
ensemble needed a single "malicious probability" from each model, but different
models used different label names and conventions. The extraction logic in
`HuggingFaceClassifierModel._malicious_score_from_labels()` applied these
strategies in order:

1. **Named label match** -- If the catalog entry had `malicious_labels`
   (e.g., `("injection",)` for deberta, `("jailbreak",)` for the Jailbreak
   Detector), find labels whose lowercased name contains any of those aliases
   and return the highest matching score.

2. **Index-based match** -- If the catalog entry had `malicious_label_index`
   (e.g., `1` for wolf-defender), return the score at that label index
   directly.

3. **Fallback heuristic** -- If no catalog entry existed, scan label names for
   tokens like `"inject"`, `"malicious"`, `"attack"`, `"unsafe"`,
   `"jailbreak"`.

4. **Binary fallback** -- If the model has exactly two labels and nothing else
   matched, return the score of label index 1 (assumed to be the positive /
   malicious class).

5. **Error** -- Raise `ValueError` if none of the above resolved.

---

## Weighted Soft Voting

The ensemble combined per-model scores using a weighted average:

```
ensemble_score = sum(score_i * weight_i) / sum(weight_i)
```

With default weights (0.40 + 0.35 + 0.25 = 1.00), this simplifies to a
weighted mean. If a model failed to load or predict, it was excluded from both
the numerator and denominator, so the ensemble degraded gracefully with fewer
models.

The `AggregateScore` dataclass captured the full result:

```python
@dataclass(frozen=True)
class AggregateScore:
    ensemble_score: float    # weighted average
    confidence: float        # unweighted mean of per-model scores
    uncertainty: float       # min(1.0, pstdev(scores) * 2)
    max_risk: float          # highest individual model score
    threshold: float         # configured decision threshold
    triggered: bool          # ensemble_score >= threshold
    per_model_scores: dict[str, float]
```

- `confidence` was the simple arithmetic mean (via `statistics.fmean`).
- `uncertainty` was twice the population standard deviation, capped at 1.0.
  High uncertainty indicated disagreement between models.
- A finding was created only when `triggered` was `True`.

---

## Long-Text Chunking

Transformer models have a fixed context window (typically 512 tokens). The
ensemble handled long segments by splitting them into chunks before inference.

### Chunking Parameters (from `MLConfig`)

| Parameter | Default | Purpose |
|---|---|---|
| `chunk_max_chars` | 1800 | Maximum characters per chunk |
| `chunk_overlap_lines` | 3 | Number of overlapping lines between consecutive chunks |
| `min_segment_chars` | 12 | Minimum content length; shorter segments are skipped |

### Chunking Algorithm (`_expand_ml_segment`)

1. If the segment content is <= `chunk_max_chars`, return it as-is.
2. Split content into lines.
3. Accumulate lines into a chunk until adding the next line would exceed
   `chunk_max_chars`.
4. Emit the chunk as a new `Segment` with:
   - ID: `{parent_id}:mlchunk:{index}`
   - Location: adjusted `start_line` and `end_line`
   - Details: `ml_chunk_index` and `ml_chunk_overlap_lines`
5. The next chunk starts `overlap_lines` lines before the end of the current
   chunk, ensuring context continuity across boundaries.
6. Repeat until all lines are consumed.

Each chunk was scored independently. If any chunk triggered the ensemble
threshold, a finding was created for that chunk's location.

---

## Configurable Threshold

The ensemble threshold (default `0.5`) controlled the decision boundary:

- `ensemble_score >= threshold` --> finding created
- `ensemble_score < threshold` --> no finding

The threshold was configurable via YAML config:

```yaml
layers:
  ml:
    threshold: 0.5
```

---

## Severity Assignment

Findings were assigned severity based on how far the ensemble score exceeded
the threshold:

```python
severity = (Severity.HIGH
            if aggregate.ensemble_score >= max(0.75, aggregate.threshold + 0.25)
            else Severity.MEDIUM)
```

So with the default threshold of 0.5:
- Score >= 0.75 --> `HIGH`
- Score >= 0.50 but < 0.75 --> `MEDIUM`

---

## Soft Finding Logic

### Borderline Score Soft Marking

Findings with `ensemble_score < 0.85` were automatically marked as soft
findings. This meant they required LLM consensus confirmation (at least 75% of
the active LLM model group) before counting toward the risk score. The rationale
was that borderline ML signals have too high a false-positive rate to convict
on their own.

### Doc-Like Segment Soft Marking

Segments from documentation-like files (`.md`, `.mdx`, `.rst`, `.adoc`, `.txt`,
`.yaml`, `.yml`) or documentation-like segment types (`FRONTMATTER_DESCRIPTION`,
`CODE_FENCE`, `HTML_COMMENT`) were also force-marked soft -- unless the segment
contained an explicit prompt-injection cue pattern. This was the primary defense
against false positives on security documentation that discusses attacks using
attack-like vocabulary.

### Explicit Prompt-Injection Cue Pattern

A compiled regex (`PROMPT_INJECTION_CUE_PATTERN`) checked for 20 patterns
that strongly indicate actual prompt injection rather than documentation about
it:

- "ignore previous instructions"
- "forget all prior instructions"
- "reveal the system prompt"
- "you are now"
- "from now on act as"
- "pretend to be"
- "assume the role of"
- "do not mention" / "don't mention"
- "without telling the user"
- "do not disclose"
- "proceed without confirmation"
- "do not ask for approval"
- "skip confirmation"
- Chat-ML delimiters: `<|system|>`, `<|im_start|>`, `[INST]`, `<<SYS>>`
- "DAN"
- "developer mode"

If a doc-like segment matched any of these cues, the doc-like soft override
was suppressed, allowing a high-confidence finding to remain hard.

### Reference Example Soft Marking

Segments classified as reference examples (e.g., "here is an example of a
prompt injection attack") by the shared `is_reference_example()` context helper
were also force-marked soft regardless of score.

### Soft Finding Representation

Soft findings carried extra detail fields:

```python
details["soft"] = True
details["soft_status"] = "pending"
```

The `"pending"` status indicated the finding awaited LLM consensus. The LLM
layer would later update this to `"confirmed"` or `"rejected"`.

---

## Finding Representation

Every ML ensemble finding used these fixed identifiers:

| Field | Value |
|---|---|
| `rule_id` | `ML-PI` |
| `layer` | `DetectionLayer.ML_ENSEMBLE` |
| `category` | `Category.PROMPT_INJECTION` |
| `message` | `"ML ensemble detected prompt injection."` |

The `details` dict included:

```python
{
    "ensemble_score": 0.823456,     # weighted average, rounded to 6 decimals
    "threshold": 0.5,               # configured threshold
    "uncertainty": 0.134567,        # model disagreement metric
    "max_risk": 0.95,               # highest single-model score
    "per_model_scores": {
        "protectai/deberta-v3-base-prompt-injection-v2": 0.891234,
        "patronus-studio/wolf-defender-prompt-injection": 0.823456,
        "madhurjindal/Jailbreak-Detector": 0.712345,
    },
    "segment_type": "ORIGINAL",     # or "DERIVED", "NORMALIZED", etc.
    "derived": False,               # True if segment_type is not ORIGINAL
    "context": "actionable_instruction",  # from classify_segment_context()
    "reference_example": False,     # from is_reference_example()
    "provenance": ["ORIGINAL"],     # provenance chain segment types
    # If soft:
    "soft": True,
    "soft_status": "pending",
}
```

The `confidence` field on the `Finding` object itself was set to the
unweighted mean of per-model scores (the `AggregateScore.confidence` value).

---

## HuggingFace Model Download and Caching

### Cache Layout

Models were cached in the HuggingFace Hub standard layout under the configured
`model_cache_dir` (default `~/.skillinquisitor/models`):

```
~/.skillinquisitor/models/
  models--protectai--deberta-v3-base-prompt-injection-v2/
  models--patronus-studio--wolf-defender-prompt-injection/
  models--madhurjindal--Jailbreak-Detector/
```

The cache path for a model was computed as:
```python
cache_dir / f"models--{model_id.replace('/', '--')}"
```

### Download Logic (`download.py`)

The `download_configured_models()` function:

1. Expanded and created the cache directory.
2. Checked for ML runtime dependencies (`torch`, `transformers`,
   `huggingface_hub`). If unavailable, returned `"dependency-unavailable"`
   for all models.
3. For each configured model:
   - If already cached, returned `"already-cached"`.
   - Otherwise, called `huggingface_hub.snapshot_download()` with an
     `allow_patterns` filter to download only the files needed for inference:
     - `config.json`
     - `model.safetensors`
     - `tokenizer.json`, `tokenizer_config.json`, `special_tokens_map.json`
     - `vocab.json`, `merges.txt`
     - `sentencepiece.bpe.model`, `*.model`
   - On success: `"downloaded"`. On failure: `"failed:{ExceptionType}"`.

### Status Listing

`list_model_statuses()` returned a list of dicts for the `models list` CLI
command:

```python
{
    "layer": "ml",
    "model_id": "protectai/deberta-v3-base-prompt-injection-v2",
    "type": "hf_sequence_classifier",
    "weight": 0.40,
    "status": "cached" | "missing",
    "gated": False,
    "summary": "High-recall DeBERTa v3 prompt-injection detector (184M params).",
}
```

---

## Runtime Pooling

### `_MLPoolEntry` and `_PooledInjectionModel`

The `ScanRuntime` maintained a pool of loaded ML models to avoid redundant
cold-load cycles across scans in long-lived processes (e.g., the embedded
`ScanService`).

```python
@dataclass
class _MLPoolEntry:
    model: InjectionModel
    lock: threading.Lock = field(default_factory=threading.Lock)
```

Each pool entry held a loaded model and a mutex. The
`_PooledInjectionModel` wrapper replaced the load/unload lifecycle with
no-ops, serializing prediction calls through the entry's lock:

```python
class _PooledInjectionModel:
    def load(self) -> None:
        return None  # already loaded in pool

    def predict_many(self, texts, batch_size):
        with self._entry.lock:
            return self._entry.model.predict_many(texts, batch_size=batch_size)

    def unload(self) -> None:
        return None  # pool owns the lifecycle
```

### Pool Management in `ScanRuntime`

- **`get_ml_models(config)`** -- For each configured model, checked if the
  model ID already existed in `self._ml_pool`. If so, wrapped it as
  `_PooledInjectionModel` (warm reuse). If not, called
  `build_injection_model()`, loaded it immediately, stored it as a new
  `_MLPoolEntry`, and tracked the cold load in telemetry.

- **`ml_section()`** -- An async context manager that acquired one of the
  `ml_global_slots` semaphore permits, bounding concurrency of ML inference
  across concurrent scans.

- **`close()`** -- Drained the pool, calling `unload()` on every pooled model
  and clearing `self._ml_pool`.

### Lifecycle Modes

The `RuntimeConfig.ml_lifecycle` field controlled whether pooling was used:

| Value | Behavior |
|---|---|
| `"command"` | Models are pooled in `ScanRuntime` and reused across scans. The pipeline passed `runtime.get_ml_models(config)` to the ensemble constructor. |
| `"scan"` (default) | Each scan builds and loads its own models. The ensemble constructor received `None` and built models internally with the load-one-run-unload pattern. |

### Telemetry

`RuntimeTelemetry` tracked pool activity:
- `ml_cold_loads` -- Number of models loaded from disk into the pool.
- `ml_warm_reuses` -- Number of times a pooled model was reused without
  reloading.

---

## Sequential Load-One-Run-Unload Cycle

When not using runtime pooling (the default `"scan"` lifecycle), the ensemble
ran models sequentially to minimize peak memory:

```python
@staticmethod
def _predict_with_model(model, texts, batch_size):
    model.load()
    try:
        return model.predict_many(texts, batch_size=batch_size)
    finally:
        model.unload()
```

The `HuggingFaceClassifierModel.unload()` method:

1. Set `self._tokenizer` and `self._model` to `None`.
2. If CUDA was in use, called `torch.cuda.empty_cache()`.
3. Called `gc.collect()` to reclaim memory immediately.

This ensured that at most one model (~308M params for the largest) was resident
at a time, keeping peak memory under ~1.5 GB even on CPU-only machines.

### Concurrency

The `_predict_models()` method supported two modes:

- **Sequential** (default, `max_concurrency <= 1`): Models ran one at a time in
  order.
- **Concurrent** (`max_concurrency > 1`): Models ran in parallel via
  `asyncio.gather()` with a semaphore. Each model ran in its own
  `asyncio.to_thread()` call.

Both modes collected failed models separately so partial results could still
produce findings.

---

## Model Loading and Inference

### `HuggingFaceClassifierModel.load()`

1. Imported `torch` and `transformers` (lazy imports to keep ML deps optional).
2. Resolved the torch device (`cpu`, `cuda`, or `mps`) based on preference and
   availability.
3. Loaded tokenizer via `AutoTokenizer.from_pretrained()`.
4. Loaded model via `AutoModelForSequenceClassification.from_pretrained()`.
5. Moved model to device if GPU/MPS.
6. Set model to eval mode.
7. Extracted label names from model config's `id2label` mapping.

The `local_files_only` flag was set to `not auto_download`, so if auto-download
was disabled, the model had to already be cached.

### `HuggingFaceClassifierModel.predict_many()`

1. Iterated over texts in batches of `batch_size` (default 8).
2. Tokenized each batch with `truncation=True`, `padding=True`,
   `max_length=512`.
3. Moved encoded tensors to device if GPU/MPS.
4. Ran forward pass under `torch.no_grad()`.
5. Applied softmax to logits.
6. For each row, built an `InjectionResult` with:
   - `label`: the label name with the highest probability
   - `label_scores`: full probability distribution
   - `malicious_score`: extracted via the catalog-driven strategy

---

## Segment Collection and Artifact Filtering

### `collect_ml_segments()` (in `pipeline.py`)

For each skill's artifacts:

1. **Artifact filtering** (`_artifact_is_ml_candidate()`):
   - Must be a text artifact with segments.
   - Excluded basenames: `_meta.yaml`, `expected.yaml`, `.gitignore`,
     `license`, `license.txt`.
   - Always included: `SKILL.md`.
   - Excluded: files under `/references/` directories.
   - Included: Markdown and YAML file types.
   - Excluded: code file types (Python, Shell, JS, TS, Ruby, Go, Rust) --
     these went to the LLM layer instead.
   - Included: other text-like extensions (`.txt`, `.rst`, `.adoc`) or files
     under `/docs/`.

2. **Segment expansion**: Each segment was passed through `_expand_ml_segment()`
   for long-text chunking.

3. **Minimum length filter**: Segments shorter than `min_segment_chars` (12)
   after stripping whitespace were dropped.

---

## Decisive Combo Bypass

The pipeline could skip the ML layer entirely when deterministic findings
already formed a decisive malicious combination. This was checked via
`has_decisive_non_llm_combo()` from `adjudication.py` before running the
ensemble.

When skipped, the ML metadata recorded:

```python
{
    "enabled": True,
    "findings": 0,
    "models": [],
    "skipped_reason": "strong_deterministic_combo",
}
```

A secondary bypass (`_should_skip_llm_for_findings()`) could also skip the
LLM layer when ML findings corroborated a strong deterministic pattern. This
checked for fake-prerequisite findings (`D-20H`) co-occurring with ML prompt-
injection findings and actionable remote host findings (`D-15E`) on the same
file paths.

---

## Config Schema

### `MLConfig` (in `models.py`)

```python
class MLConfig(BaseModel):
    enabled: bool = True
    models: list[WeightedModelConfig] = Field(default_factory=_default_ml_models)
    threshold: float = 0.5
    auto_download: bool = True
    max_concurrency: int = 1
    max_batch_size: int = 8
    min_segment_chars: int = 12
    chunk_max_chars: int = 1800
    chunk_overlap_lines: int = 3
```

### `WeightedModelConfig` (in `models.py`)

```python
class WeightedModelConfig(BaseModel):
    id: str
    weight: float = 1.0
    type: str | None = None
```

### `RuntimeConfig` ML fields

```python
class RuntimeConfig(BaseModel):
    ml_global_slots: int = 1        # semaphore permits for concurrent ML sections
    ml_lifecycle: str = "scan"      # "scan" or "command" pooling mode
    ml_resident_model_limit: int = 1
```

### YAML Config Example

```yaml
layers:
  ml:
    enabled: true
    threshold: 0.5
    auto_download: true
    max_concurrency: 1
    max_batch_size: 8
    min_segment_chars: 12
    chunk_max_chars: 1800
    chunk_overlap_lines: 3
    models:
      - id: protectai/deberta-v3-base-prompt-injection-v2
        weight: 0.40
      - id: patronus-studio/wolf-defender-prompt-injection
        weight: 0.35
      - id: madhurjindal/Jailbreak-Detector
        weight: 0.25

runtime:
  ml_global_slots: 1
  ml_lifecycle: scan
```

---

## Role in Adjudication

ML ensemble findings participated in the adjudication system with specific
treatment:

1. **Not independently convicting**: ML findings (`DetectionLayer.ML_ENSEMBLE`)
   were not treated as corroborating evidence by themselves. They required
   non-ML corroboration from deterministic findings on the same file path to
   count as substantive signal in the risk-label decision.

2. **Corroboration check**: `_finding_has_non_ml_corroboration()` verified that
   at least one other finding on the same file path existed that was not from
   the ML layer and was not a reference example.

3. **Soft finding gate**: Soft ML findings (score < 0.85, doc-like segments,
   reference examples) required LLM consensus (75% of active model group)
   before counting toward the legacy risk score. Without LLM confirmation,
   they were dropped with zero score impact.

---

## Graceful Degradation

The ensemble handled missing dependencies and models at multiple levels:

1. **Missing ML dependencies**: If `torch`, `transformers`, or
   `huggingface_hub` were not installed, `has_ml_runtime_dependencies()`
   returned `False` and the ensemble returned zero findings with a warning.

2. **Missing model cache**: If `auto_download` was `False` and models were not
   cached, `AutoTokenizer.from_pretrained()` would raise an error caught by
   the per-model error handling.

3. **Per-model failure**: If any individual model failed to load or predict,
   it was recorded in `failed_models` and the remaining models' scores were
   still combined. The ensemble could produce findings even with only one
   working model.

4. **ML layer disabled**: If `config.layers.ml.enabled` was `False`, the
   ensemble returned immediately with `{"enabled": False}`.

---

## Source Files (Removed)

| File | Purpose |
|---|---|
| `src/skillinquisitor/detectors/ml/__init__.py` | Public API: `MLPromptInjectionEnsemble`, `download_configured_models`, `list_model_statuses` |
| `src/skillinquisitor/detectors/ml/ensemble.py` | Weighted voting aggregator, finding builder, soft-marking logic, chunking cue pattern |
| `src/skillinquisitor/detectors/ml/models.py` | `HuggingFaceClassifierModel`, `InjectionModel` protocol, `MODEL_CATALOG`, device resolution |
| `src/skillinquisitor/detectors/ml/download.py` | HuggingFace snapshot download, cache-path logic, status listing |

Pipeline integration points (modified during removal):

| File | ML-related code |
|---|---|
| `src/skillinquisitor/pipeline.py` | `run_ml_ensemble()`, `collect_ml_segments()`, `_expand_ml_segment()`, `_artifact_is_ml_candidate()`, decisive combo bypass |
| `src/skillinquisitor/runtime.py` | `_MLPoolEntry`, `_PooledInjectionModel`, `get_ml_models()`, `ml_section()`, pool close logic |
| `src/skillinquisitor/models.py` | `MLConfig`, `WeightedModelConfig`, `RuntimeConfig.ml_*` fields, `LayersConfig.ml` |
| `src/skillinquisitor/adjudication.py` | ML signal collection, non-ML corroboration checks, decisive combo logic |
