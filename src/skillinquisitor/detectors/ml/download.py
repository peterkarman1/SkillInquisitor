from __future__ import annotations

from pathlib import Path

from skillinquisitor.detectors.ml.models import MODEL_CATALOG, has_ml_runtime_dependencies
from skillinquisitor.models import ScanConfig


def _expand_cache_dir(config: ScanConfig) -> Path:
    return Path(config.model_cache_dir).expanduser()


def _model_cache_path(cache_dir: Path, model_id: str) -> Path:
    return cache_dir / "hub" / f"models--{model_id.replace('/', '--')}"


def _is_cached(model_id: str, cache_dir: Path) -> bool:
    return _model_cache_path(cache_dir, model_id).exists()


def list_model_statuses(config: ScanConfig) -> list[dict[str, object]]:
    cache_dir = _expand_cache_dir(config)
    statuses: list[dict[str, object]] = []
    for model_config in config.layers.ml.models:
        catalog_entry = MODEL_CATALOG.get(model_config.id.casefold()) or MODEL_CATALOG.get(model_config.id)
        statuses.append(
            {
                "layer": "ml",
                "model_id": model_config.id,
                "type": model_config.type or "hf_sequence_classifier",
                "weight": model_config.weight,
                "status": "cached" if _is_cached(model_config.id, cache_dir) else "missing",
                "gated": bool(catalog_entry.gated) if catalog_entry else False,
                "summary": catalog_entry.summary if catalog_entry else "",
            }
        )
    return statuses


def download_configured_models(config: ScanConfig) -> list[tuple[str, str]]:
    cache_dir = _expand_cache_dir(config)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if not has_ml_runtime_dependencies():
        return [(model.id, "dependency-unavailable") for model in config.layers.ml.models]

    from huggingface_hub import snapshot_download

    results: list[tuple[str, str]] = []
    for model_config in config.layers.ml.models:
        if _is_cached(model_config.id, cache_dir):
            results.append((model_config.id, "already-cached"))
            continue
        try:
            snapshot_download(
                repo_id=model_config.id,
                cache_dir=str(cache_dir),
                allow_patterns=[
                    "config.json",
                    "model.safetensors",
                    "tokenizer.json",
                    "tokenizer_config.json",
                    "special_tokens_map.json",
                    "vocab.json",
                    "merges.txt",
                    "sentencepiece.bpe.model",
                    "*.model",
                ],
            )
        except Exception as exc:  # pragma: no cover - network/runtime variability
            results.append((model_config.id, f"failed:{type(exc).__name__}"))
            continue
        results.append((model_config.id, "downloaded"))
    return results
