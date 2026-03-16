from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean, pstdev

from skillinquisitor.detectors.ml.models import InjectionModel, build_injection_model, has_ml_runtime_dependencies
from skillinquisitor.models import Category, DetectionLayer, Finding, ScanConfig, Segment, SegmentType, Severity


@dataclass(frozen=True)
class AggregateScore:
    ensemble_score: float
    confidence: float
    uncertainty: float
    max_risk: float
    threshold: float
    triggered: bool
    per_model_scores: dict[str, float]


def aggregate_model_scores(
    *,
    model_results: dict[str, object],
    weights: dict[str, float],
    threshold: float,
) -> AggregateScore:
    if not model_results:
        return AggregateScore(
            ensemble_score=0.0,
            confidence=0.0,
            uncertainty=0.0,
            max_risk=0.0,
            threshold=threshold,
            triggered=False,
            per_model_scores={},
        )

    per_model_scores = {
        model_id: float(result.malicious_score)
        for model_id, result in model_results.items()
    }
    total_weight = sum(weights.get(model_id, 1.0) for model_id in per_model_scores) or 1.0
    ensemble_score = sum(
        score * weights.get(model_id, 1.0)
        for model_id, score in per_model_scores.items()
    ) / total_weight
    confidence = fmean(per_model_scores.values())
    uncertainty = 0.0
    if len(per_model_scores) > 1:
        uncertainty = min(1.0, pstdev(per_model_scores.values()) * 2)
    max_risk = max(per_model_scores.values())
    return AggregateScore(
        ensemble_score=ensemble_score,
        confidence=confidence,
        uncertainty=uncertainty,
        max_risk=max_risk,
        threshold=threshold,
        triggered=ensemble_score >= threshold,
        per_model_scores=per_model_scores,
    )


class MLPromptInjectionEnsemble:
    def __init__(self, models: list[InjectionModel] | None = None) -> None:
        self._models = models

    async def analyze(
        self,
        *,
        segments: list[Segment],
        config: ScanConfig,
    ) -> tuple[list[Finding], dict[str, object]]:
        if not config.layers.ml.enabled:
            return [], {"enabled": False, "findings": 0, "models": []}
        if not segments:
            return [], {
                "enabled": True,
                "findings": 0,
                "models": [],
                "candidate_segments": 0,
            }
        if not has_ml_runtime_dependencies() and self._models is None:
            return [], {
                "enabled": True,
                "findings": 0,
                "models": [],
                "candidate_segments": len(segments),
                "warning": "ML dependencies unavailable",
            }

        models = self._models or self._build_models(config)
        if not models:
            return [], {"enabled": True, "findings": 0, "models": [], "candidate_segments": len(segments)}

        batch_size = max(1, config.layers.ml.max_batch_size)
        model_results, failed_models = await self._predict_models(
            models=models,
            texts=[segment.content for segment in segments],
            batch_size=batch_size,
            max_concurrency=max(1, config.layers.ml.max_concurrency),
        )
        weights = {model.id: model.weight for model in config.layers.ml.models}

        findings: list[Finding] = []
        for index, segment in enumerate(segments):
            per_segment_results = {
                model_id: predictions[index]
                for model_id, predictions in model_results.items()
                if index < len(predictions)
            }
            aggregate = aggregate_model_scores(
                model_results=per_segment_results,
                weights=weights,
                threshold=config.layers.ml.threshold,
            )
            if not aggregate.triggered:
                continue
            findings.append(self._build_finding(segment=segment, aggregate=aggregate))

        metadata = {
            "enabled": True,
            "findings": len(findings),
            "models": list(model_results.keys()),
            "candidate_segments": len(segments),
            "max_concurrency": max(1, config.layers.ml.max_concurrency),
            "failed_models": failed_models,
        }
        return findings, metadata

    async def detect_batch(
        self,
        segments: list[Segment],
        config: ScanConfig,
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        findings, _ = await self.analyze(segments=segments, config=config)
        return findings

    def _build_models(self, config: ScanConfig) -> list[InjectionModel]:
        cache_dir = Path(config.model_cache_dir).expanduser()
        return [
            build_injection_model(
                model_id=model.id,
                model_type=model.type,
                cache_dir=cache_dir,
                device_preference=config.device,
                auto_download=config.layers.ml.auto_download,
            )
            for model in config.layers.ml.models
        ]

    async def _predict_models(
        self,
        *,
        models: list[InjectionModel],
        texts: list[str],
        batch_size: int,
        max_concurrency: int,
    ) -> tuple[dict[str, list[object]], list[dict[str, str]]]:
        if max_concurrency <= 1 or len(models) <= 1:
            results: dict[str, list[object]] = {}
            failed_models: list[dict[str, str]] = []
            for model in models:
                try:
                    results[model.model_id] = await asyncio.to_thread(
                        self._predict_with_model,
                        model,
                        texts,
                        batch_size,
                    )
                except Exception as exc:
                    failed_models.append({"model_id": model.model_id, "error": type(exc).__name__})
            return results, failed_models

        semaphore = asyncio.Semaphore(max_concurrency)

        async def run_model(model: InjectionModel) -> tuple[str, list[object]] | dict[str, str]:
            async with semaphore:
                try:
                    predictions = await asyncio.to_thread(
                        self._predict_with_model,
                        model,
                        texts,
                        batch_size,
                    )
                except Exception as exc:
                    return {"model_id": model.model_id, "error": type(exc).__name__}
                return model.model_id, predictions

        pairs = await asyncio.gather(*(run_model(model) for model in models))
        results: dict[str, list[object]] = {}
        failed_models: list[dict[str, str]] = []
        for item in pairs:
            if isinstance(item, dict):
                failed_models.append(item)
            else:
                model_id, predictions = item
                results[model_id] = predictions
        return results, failed_models

    @staticmethod
    def _predict_with_model(
        model: InjectionModel,
        texts: list[str],
        batch_size: int,
    ) -> list[object]:
        model.load()
        try:
            return model.predict_many(texts, batch_size=batch_size)
        finally:
            model.unload()

    @staticmethod
    def _build_finding(*, segment: Segment, aggregate: AggregateScore) -> Finding:
        severity = Severity.HIGH if aggregate.ensemble_score >= max(0.75, aggregate.threshold + 0.25) else Severity.MEDIUM

        # Borderline ML findings (below high-confidence cutoff) are marked soft
        # so the LLM layer can confirm or reject them. This reduces FPs on
        # security documentation that uses attack-like vocabulary.
        is_soft = aggregate.ensemble_score < 0.85
        soft_details: dict[str, object] = {}
        if is_soft:
            soft_details["soft"] = True
            soft_details["soft_status"] = "pending"

        return Finding(
            rule_id="ML-PI",
            layer=DetectionLayer.ML_ENSEMBLE,
            category=Category.PROMPT_INJECTION,
            severity=severity,
            message="ML ensemble detected prompt injection.",
            location=segment.location,
            segment_id=segment.id,
            confidence=aggregate.confidence,
            details={
                "ensemble_score": round(aggregate.ensemble_score, 6),
                "threshold": aggregate.threshold,
                "uncertainty": round(aggregate.uncertainty, 6),
                "max_risk": round(aggregate.max_risk, 6),
                "per_model_scores": {
                    model_id: round(score, 6)
                    for model_id, score in aggregate.per_model_scores.items()
                },
                "segment_type": segment.segment_type.value,
                "derived": segment.segment_type is not SegmentType.ORIGINAL,
                "provenance": [
                    step.segment_type.value
                    for step in segment.provenance_chain
                ],
                **soft_details,
            },
        )
