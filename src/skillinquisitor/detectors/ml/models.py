from __future__ import annotations

from dataclasses import dataclass
import gc
from pathlib import Path
from typing import Protocol


class MLDependencyError(RuntimeError):
    """Raised when optional ML dependencies are unavailable."""


@dataclass(frozen=True)
class InjectionResult:
    label: str
    label_scores: dict[str, float]
    malicious_score: float


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


MODEL_CATALOG: dict[str, ModelCatalogEntry] = {
    "protectai/deberta-v3-base-prompt-injection-v2": ModelCatalogEntry(
        id="protectai/deberta-v3-base-prompt-injection-v2",
        family="deberta-v3-base",
        default_weight=0.40,
        malicious_labels=("injection",),
        summary="High-recall DeBERTa v3 prompt-injection detector (184M params).",
    ),
    "patronus-studio/wolf-defender-prompt-injection": ModelCatalogEntry(
        id="patronus-studio/wolf-defender-prompt-injection",
        family="modernbert",
        default_weight=0.35,
        malicious_label_index=1,
        summary="ModernBERT prompt-injection classifier with broad coverage (308M params).",
    ),
    "madhurjindal/Jailbreak-Detector": ModelCatalogEntry(
        id="madhurjindal/Jailbreak-Detector",
        family="distilbert",
        default_weight=0.25,
        malicious_labels=("jailbreak",),
        summary="Compact DistilBERT jailbreak detector with low false-positive rate (66M params).",
    ),
}


class InjectionModel(Protocol):
    model_id: str

    def load(self) -> None:
        """Load model state into memory."""

    def predict_many(self, texts: list[str], batch_size: int) -> list[InjectionResult]:
        """Predict prompt-injection risk for many texts."""

    def unload(self) -> None:
        """Release model state from memory."""


def has_ml_runtime_dependencies() -> bool:
    try:
        import huggingface_hub  # noqa: F401
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError:
        return False
    return True


def _resolve_torch_device(device_preference: str) -> str:
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - guarded by caller
        raise MLDependencyError("ML dependencies are not installed. Install with `uv sync --extra ml --group dev`.") from exc

    lowered = device_preference.lower()
    if lowered in {"cpu", "cuda", "mps"}:
        return lowered
    if torch.cuda.is_available():
        return "cuda"
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


class HuggingFaceClassifierModel:
    def __init__(
        self,
        *,
        model_id: str,
        cache_dir: Path,
        device_preference: str,
        auto_download: bool,
    ) -> None:
        self.model_id = model_id
        self.cache_dir = cache_dir
        self.device_preference = device_preference
        self.auto_download = auto_download
        self._tokenizer = None
        self._model = None
        self._torch = None
        self._device = "cpu"
        self._label_names: list[str] = []
        self._catalog_entry = MODEL_CATALOG.get(model_id.casefold()) or MODEL_CATALOG.get(model_id)

    def load(self) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise MLDependencyError("ML dependencies are not installed. Install with `uv sync --extra ml --group dev`.") from exc

        self._torch = torch
        self._device = _resolve_torch_device(self.device_preference)
        self._tokenizer = AutoTokenizer.from_pretrained(
            self.model_id,
            cache_dir=str(self.cache_dir),
            local_files_only=not self.auto_download,
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            self.model_id,
            cache_dir=str(self.cache_dir),
            local_files_only=not self.auto_download,
        )
        if self._device == "cuda":
            self._model.to("cuda")
        elif self._device == "mps":
            self._model.to("mps")
        self._model.eval()

        config = self._model.config
        id2label = getattr(config, "id2label", None) or {}
        num_labels = getattr(config, "num_labels", None) or len(id2label)
        self._label_names = []
        for index in range(num_labels):
            raw_label = id2label.get(index)
            if raw_label is None:
                raw_label = id2label.get(str(index))
            if raw_label is None:
                raw_label = f"LABEL_{index}"
            self._label_names.append(str(raw_label))

    def predict_many(self, texts: list[str], batch_size: int) -> list[InjectionResult]:
        if self._tokenizer is None or self._model is None or self._torch is None:
            raise RuntimeError("Model must be loaded before prediction")

        results: list[InjectionResult] = []
        for start in range(0, len(texts), batch_size):
            chunk = texts[start : start + batch_size]
            encoded = self._tokenizer(
                chunk,
                truncation=True,
                padding=True,
                max_length=512,
                return_tensors="pt",
            )
            if self._device in {"cuda", "mps"}:
                encoded = {key: value.to(self._device) for key, value in encoded.items()}
            with self._torch.no_grad():
                logits = self._model(**encoded).logits
            probabilities = self._torch.softmax(logits, dim=-1).detach().cpu().tolist()
            for row in probabilities:
                label_scores = {
                    self._label_names[index]: float(score)
                    for index, score in enumerate(row)
                }
                results.append(
                    InjectionResult(
                        label=max(label_scores, key=label_scores.get),
                        label_scores=label_scores,
                        malicious_score=self._malicious_score_from_labels(label_scores),
                    )
                )
        return results

    def unload(self) -> None:
        self._tokenizer = None
        self._model = None
        if self._torch is not None and self._device == "cuda" and self._torch.cuda.is_available():
            self._torch.cuda.empty_cache()
        self._torch = None
        gc.collect()

    def _malicious_score_from_labels(self, label_scores: dict[str, float]) -> float:
        catalog_entry = self._catalog_entry or MODEL_CATALOG.get(self.model_id) or MODEL_CATALOG.get(self.model_id.casefold())
        lowered_scores = {label.lower(): score for label, score in label_scores.items()}
        if catalog_entry is not None:
            if catalog_entry.malicious_labels:
                matched_scores = [
                    score
                    for label, score in lowered_scores.items()
                    if any(alias in label for alias in catalog_entry.malicious_labels)
                ]
                if matched_scores:
                    return max(matched_scores)
            if catalog_entry.malicious_label_index is not None:
                label_name = self._label_names[catalog_entry.malicious_label_index]
                return float(label_scores[label_name])

        fallback_hits = [
            score
            for label, score in lowered_scores.items()
            if any(token in label for token in ("inject", "malicious", "attack", "unsafe", "jailbreak"))
        ]
        if fallback_hits:
            return max(fallback_hits)

        if len(self._label_names) == 2:
            return float(label_scores[self._label_names[1]])

        raise ValueError(f"Unable to determine malicious label mapping for model {self.model_id}")


def build_injection_model(
    *,
    model_id: str,
    model_type: str | None,
    cache_dir: Path,
    device_preference: str,
    auto_download: bool,
) -> InjectionModel:
    resolved_type = (model_type or "hf_sequence_classifier").lower()
    if resolved_type != "hf_sequence_classifier":
        raise ValueError(f"Unsupported ML model type: {resolved_type}")
    return HuggingFaceClassifierModel(
        model_id=model_id,
        cache_dir=cache_dir,
        device_preference=device_preference,
        auto_download=auto_download,
    )
