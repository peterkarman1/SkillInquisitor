from __future__ import annotations

import shutil
from pathlib import Path

from skillinquisitor.detectors.llm.models import has_llm_runtime_dependencies, resolve_group_models
from skillinquisitor.models import LLMModelConfig, ScanConfig


def _expand_cache_dir(config: ScanConfig) -> Path:
    return Path(config.model_cache_dir).expanduser()


def _model_cache_path(cache_dir: Path, model: LLMModelConfig) -> Path:
    repo_id = model.repo_id or model.id
    filename = model.filename or Path(model.id).name
    return cache_dir / "llm" / repo_id.replace("/", "--") / filename


def _is_cached(model: LLMModelConfig, cache_dir: Path) -> bool:
    if model.repo_id is None and model.filename is None:
        return Path(model.id).expanduser().exists()
    return _model_cache_path(cache_dir, model).exists()


def resolve_model_file(
    model: LLMModelConfig,
    *,
    cache_dir: Path,
    auto_download: bool,
) -> Path:
    if model.filename is None and model.repo_id is None:
        candidate = Path(model.id).expanduser()
        if candidate.exists():
            return candidate
        raise FileNotFoundError(f"Model path does not exist: {candidate}")

    cached = _model_cache_path(cache_dir, model)
    if cached.exists():
        return cached
    if not auto_download:
        raise FileNotFoundError(f"LLM model is not cached locally: {model.id}")

    results = download_llm_models_for_entries(
        [model],
        cache_dir=cache_dir,
        auto_download=auto_download,
    )
    status = results[0][1]
    if status not in {"downloaded", "already-cached"}:
        raise FileNotFoundError(f"Unable to download LLM model {model.id}: {status}")
    return _model_cache_path(cache_dir, model)


def list_llm_model_statuses(config: ScanConfig) -> list[dict[str, object]]:
    cache_dir = _expand_cache_dir(config)
    statuses: list[dict[str, object]] = []
    for group_name, group_models in config.layers.llm.model_groups.items():
        for model in group_models:
            statuses.append(
                {
                    "layer": "llm",
                    "group": group_name,
                    "model_id": model.id,
                    "runtime": model.runtime,
                    "filename": model.filename or "",
                    "weight": model.weight,
                    "status": "cached" if _is_cached(model, cache_dir) else "missing",
                }
            )
    for model in config.layers.llm.models:
        statuses.append(
            {
                "layer": "llm",
                "group": "explicit",
                "model_id": model.id,
                "runtime": model.runtime,
                "filename": model.filename or "",
                "weight": model.weight,
                "status": "cached" if _is_cached(model, cache_dir) else "missing",
            }
        )
    return statuses


def download_llm_models(config: ScanConfig, requested_group: str | None = None) -> list[tuple[str, str]]:
    cache_dir = _expand_cache_dir(config)
    cache_dir.mkdir(parents=True, exist_ok=True)
    _, models = resolve_group_models(config, requested_group=requested_group)
    return download_llm_models_for_entries(models, cache_dir=cache_dir, auto_download=config.layers.llm.auto_download)


def download_llm_models_for_entries(
    models: list[LLMModelConfig],
    *,
    cache_dir: Path,
    auto_download: bool,
) -> list[tuple[str, str]]:
    if not models:
        return []
    if not auto_download:
        return [(model.id, "auto-download-disabled") for model in models]
    if not has_llm_runtime_dependencies():
        return [(model.id, "dependency-unavailable") for model in models]

    from huggingface_hub import hf_hub_download

    results: list[tuple[str, str]] = []
    for model in models:
        if model.repo_id is None or model.filename is None:
            candidate = Path(model.id).expanduser()
            if candidate.exists():
                results.append((model.id, "already-cached"))
            else:
                results.append((model.id, "local-path-missing"))
            continue
        if _is_cached(model, cache_dir):
            results.append((model.id, "already-cached"))
            continue
        target_dir = _model_cache_path(cache_dir, model).parent
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            downloaded_path = hf_hub_download(
                repo_id=model.repo_id,
                filename=model.filename,
                cache_dir=str(cache_dir / "llm" / "hf"),
            )
        except Exception as exc:  # pragma: no cover - network/runtime variability
            results.append((model.id, f"failed:{type(exc).__name__}"))
            continue
        target = _model_cache_path(cache_dir, model)
        src = Path(downloaded_path).resolve()  # Resolve symlinks from HF cache
        shutil.copy2(str(src), str(target))
        results.append((model.id, "downloaded"))
    return results
