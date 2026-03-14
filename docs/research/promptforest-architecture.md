# PromptForest Architecture Document

**Repository:** https://github.com/appleroll-research/promptforest
**Author:** Appleroll Research
**License:** Apache 2.0
**Language:** Python (33.6%) + Jupyter Notebooks (66.3%)

---

## 1. Overview

PromptForest is an **ensemble-based prompt injection detection system** designed for production LLM environments. It solves the problem of detecting when a user's input to an LLM contains a malicious prompt injection attack (e.g., jailbreaks, instruction overrides, adversarial prompts).

The key insight is that instead of using a single large detection model, PromptForest combines **three smaller, diverse models** using weighted soft voting. This achieves:

- **Better calibration** (ECE of 0.070 vs 0.096 for the larger Qualifire Sentinel v2) — meaning confidence scores more accurately reflect real probabilities
- **Lower latency** (~141ms vs ~226ms) due to smaller total parameter count (~237M vs ~600M)
- The tradeoff is slightly lower raw accuracy (0.901 vs 0.973)

---

## 2. Codebase Structure

```
promptforest/
├── __init__.py          # Exports PFEnsemble, version "0.1.0"
├── cli.py               # CLI entry point with "serve" and "check" subcommands
├── config.py            # Configuration loading, defaults, YAML merging
├── download.py          # Downloads HuggingFace models to ~/.promptforest/models/
├── lib.py               # Core ensemble logic (the key file)
├── server.py            # HTTP server wrapping the ensemble
├── xgboost/
│   ├── prepare_data.py  # Loads 6 datasets, normalizes labels, generates embeddings
│   ├── train.py         # Trains XGBoost on sentence embeddings
│   ├── inference.py     # Standalone inference script
│   ├── benchmark.py     # XGBoost-specific benchmarking
│   ├── clean.ipynb      # Data cleaning notebook
│   └── xgb_model.pkl    # Pre-trained XGBoost model (shipped with package)
├── benchmark/
│   ├── Makefile             # Convenience targets for running benchmarks
│   ├── _config.yaml         # Accuracy benchmark config
│   ├── _config_latency.yaml # Latency benchmark config
│   ├── accuracy_benchmark.ipynb
│   ├── latency_benchmark.ipynb
│   ├── calibration_graph.png
│   └── latency_distribution.png
└── config.yaml          # Example user configuration
```

---

## 3. The Scanning / Detection Mechanism

### 3.1 Model Initialization (`PFEnsemble.__init__`)

1. Loads config (default or user-provided YAML)
2. Checks if models exist at `~/.promptforest/models/`; if not, triggers automatic download from HuggingFace
3. Instantiates three model wrappers based on config

### 3.2 The Three Detection Models

| Model | Class | Type | Parameters | How It Works |
|-------|-------|------|------------|--------------|
| **Meta Llama Prompt Guard 2** (86M) | `HFModel` | HuggingFace sequence classifier | ~86M | Tokenizes input, runs through transformer, extracts softmax probability for the "malicious" class |
| **Vijil Dome** (ModernBERT-based) | `HFModel` | HuggingFace sequence classifier | ~150M | Same pipeline, uses ModernBERT tokenizer from `answerdotai/ModernBERT-base` |
| **PromptForest-XGB** | `XGBoostModel` | Custom XGBoost | ~1M | Encodes prompt via SentenceTransformer (`all-MiniLM-L6-v2`) into 384-dim embedding, then feeds to XGBoost classifier |

### 3.3 Label Detection (`_determine_label_map`)

Each HuggingFace model may use different label names. The system auto-detects which output index corresponds to "malicious" by scanning the model's `id2label` mapping for keywords: `unsafe`, `malicious`, `injection`, `attack`, `jailbreak`. Falls back to index 1 if none found.

### 3.4 Parallel Inference (`check_prompt`)

All three models run **concurrently** via `ThreadPoolExecutor`. Each returns a float probability [0, 1] of the prompt being malicious.

### 3.5 Ensemble Aggregation

- **Weighted average**: Each model's probability is multiplied by its `accuracy_weight` from config, then averaged. This is compared to a 0.5 threshold for the binary decision.
- **Unweighted average**: Used for the `confidence` and `malicious_score` fields (noted to give 2-3x better results in benchmarks).
- **Uncertainty**: Calculated as `min(std_dev * 2, 1.0)` — the standard deviation of the three model outputs, scaled up. High disagreement among models means high uncertainty.
- **Max risk score**: The highest individual model probability, useful as a conservative signal.

### 3.6 Response Format

```json
{
  "is_malicious": true,
  "confidence": 0.85,
  "uncertainty": 0.12,
  "malicious_score": 0.85,
  "max_risk_score": 0.95,
  "details": {
    "llama_guard": 0.95,
    "vijil": 0.87,
    "xgboost": 0.72
  },
  "latency_ms": 141.2
}
```

---

## 4. Key Components and Interactions

### 4.1 Configuration System (`config.py`)

- Defines model paths (`~/.promptforest/models/`), the packaged `xgb_model.pkl`, and default config
- Supports YAML-based user config that merges with defaults using deep merge
- Users can override model weights, thresholds, and model paths

### 4.2 Model Download System (`download.py`)

- Handles automatic downloading of HuggingFace models on first use
- Stores models locally at `~/.promptforest/models/`
- Checks for existing models before downloading

### 4.3 CLI Interface (`cli.py`)

Two subcommands:
- **`promptforest serve`**: Starts an HTTP server for real-time prompt checking
- **`promptforest check`**: One-shot checking of a single prompt from the command line

### 4.4 HTTP Server (`server.py`)

- Wraps the `PFEnsemble` as an HTTP endpoint
- Accepts POST requests with prompt text
- Returns JSON detection results

### 4.5 XGBoost Training Pipeline (`xgboost/`)

- **`prepare_data.py`**: Loads 6 different prompt injection datasets, normalizes labels to binary (safe/malicious), generates sentence embeddings using `all-MiniLM-L6-v2`
- **`train.py`**: Trains an XGBoost classifier on the sentence embeddings
- **`inference.py`**: Standalone inference for the XGBoost model
- Ships a pre-trained `xgb_model.pkl` so users don't need to retrain

---

## 5. Scanning Pipeline Flow (End-to-End)

```
User Input (prompt text)
         │
         ▼
┌─────────────────────┐
│   PFEnsemble.check_prompt()  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────────────────────────┐
│         ThreadPoolExecutor              │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ LlamaGuard│ │ VijilDome│ │ XGBoost │ │
│  │   (86M)   │ │  (150M)  │ │  (~1M)  │ │
│  └─────┬─────┘ └────┬─────┘ └────┬────┘ │
│        │p=0.95       │p=0.87      │p=0.72│
└────────┼─────────────┼────────────┼──────┘
         │             │            │
         ▼             ▼            ▼
┌──────────────────────────────────────────┐
│         Ensemble Aggregation             │
│  • Weighted avg → is_malicious (bool)    │
│  • Unweighted avg → confidence/score     │
│  • Std dev → uncertainty                 │
│  • Max → max_risk_score                  │
└──────────────────────────────────────────┘
         │
         ▼
    JSON Response
```

---

## 6. Configuration Options

Example `config.yaml`:

```yaml
models:
  - name: llama_guard
    type: huggingface
    model_id: meta-llama/Prompt-Guard-2-86M
    accuracy_weight: 0.40
  - name: vijil
    type: huggingface
    model_id: vijil/dome
    accuracy_weight: 0.35
  - name: xgboost
    type: xgboost
    model_path: xgb_model.pkl
    accuracy_weight: 0.25

threshold: 0.5
```

Users can customize:
- **Model weights**: Adjust how much each model contributes to the final decision
- **Threshold**: Change the decision boundary for is_malicious
- **Model paths**: Point to custom or fine-tuned models
- **Model selection**: Enable/disable specific models

---

## 7. Design Patterns and Technical Decisions

### Ensemble Diversity
The three models represent fundamentally different approaches:
- **Llama Prompt Guard 2**: Large transformer trained specifically for prompt injection by Meta
- **Vijil Dome**: ModernBERT-based classifier from a security-focused company
- **XGBoost on embeddings**: Traditional ML on sentence embeddings — fast, lightweight, different failure modes

This diversity is intentional — models that fail on different inputs provide better ensemble coverage.

### Calibration Over Raw Accuracy
The project explicitly optimizes for **calibration** (ECE) rather than pure accuracy. Well-calibrated confidence scores are more useful in production because they enable:
- Risk-based routing (e.g., high-uncertainty prompts go to human review)
- Threshold tuning per use case
- Meaningful uncertainty quantification

### Parallel Inference
Using `ThreadPoolExecutor` for concurrent model inference minimizes latency. Since the models are I/O-bound (GPU/CPU compute), threading provides real speedup.

### Auto-Download with Local Caching
Models are automatically downloaded from HuggingFace on first use and cached at `~/.promptforest/models/`. This provides a smooth first-run experience while avoiding repeated downloads.

### Pre-trained XGBoost Shipped In-Package
The `xgb_model.pkl` is shipped directly in the package, avoiding the need for users to train the model. The training pipeline is still included for reproducibility and custom training.

---

## 8. Benchmark Results

| Metric | PromptForest | Qualifire Sentinel v2 |
|--------|-------------|----------------------|
| Accuracy | 0.901 | 0.973 |
| ECE (Calibration) | **0.070** | 0.096 |
| Latency (median) | **~141ms** | ~226ms |
| Parameters | ~237M | ~600M |

The project positions itself as the better choice when:
- Calibration matters more than raw accuracy
- Latency is a concern
- Resource-constrained environments need smaller models
- Uncertainty quantification is needed for downstream decision-making
