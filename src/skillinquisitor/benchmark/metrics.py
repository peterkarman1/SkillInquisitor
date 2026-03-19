"""Benchmark metrics engine for evaluating SkillInquisitor detection quality.

Computes confusion matrices, per-category recall, severity accuracy,
latency statistics, and rule/category coverage from benchmark results.
All math is hand-rolled with no external dependencies.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, Field

from skillinquisitor.models import RiskLabel


# ---------------------------------------------------------------------------
# Severity ordinal mapping (lower = more severe)
# ---------------------------------------------------------------------------

SEVERITY_ORDINAL: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

RISK_LABEL_ORDER: dict[RiskLabel, int] = {
    RiskLabel.LOW: 0,
    RiskLabel.MEDIUM: 1,
    RiskLabel.HIGH: 2,
    RiskLabel.CRITICAL: 3,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class FindingSummary(BaseModel):
    """Lightweight representation of a single finding for benchmark scoring."""

    rule_id: str
    category: str
    severity: str
    confidence: float = 1.0
    message: str = ""


class BenchmarkResult(BaseModel):
    """Result of scanning a single skill during a benchmark run."""

    skill_id: str
    ground_truth_verdict: str  # MALICIOUS | SAFE | AMBIGUOUS
    ground_truth_categories: list[str] = Field(default_factory=list)
    ground_truth_severity: str | None = None
    ground_truth_expected_rules: list[str] = Field(default_factory=list)
    ground_truth_min_categories: list[str] = Field(default_factory=list)
    ground_truth_notes: str = ""
    risk_score: int = 100
    risk_label: RiskLabel | None = None
    binary_label: str = "not_malicious"
    verdict: str = "SAFE"
    findings: list[FindingSummary] = Field(default_factory=list)
    timing: dict[str, float] = Field(default_factory=dict)
    error: str | None = None
    binary_outcome: str = "EXCLUDED"  # TP | FP | TN | FN | EXCLUDED


class ConfusionMatrix(BaseModel):
    """Standard binary confusion matrix with derived metrics."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        denom = p + r
        return 2.0 * p * r / denom if denom > 0.0 else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    @property
    def fnr(self) -> float:
        denom = self.fn + self.tp
        return self.fn / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        t = self.total
        return (self.tp + self.tn) / t if t > 0 else 0.0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


class CategoryRecall(BaseModel):
    """Per-category detection recall across benchmark skills."""

    detected: int = 0
    total: int = 0
    recall: float = 0.0


class CoverageResult(BaseModel):
    """Coverage of expected rules or categories for a single result."""

    hits: list[str] = Field(default_factory=list)
    misses: list[str] = Field(default_factory=list)

    @property
    def coverage_rate(self) -> float:
        total = len(self.hits) + len(self.misses)
        return len(self.hits) / total if total > 0 else 0.0


class SeverityMetrics(BaseModel):
    """Aggregate severity accuracy metrics for true-positive results."""

    mean_absolute_error: float = 0.0
    under_severity_rate: float = 0.0
    over_severity_rate: float = 0.0
    sample_count: int = 0


class LatencyStats(BaseModel):
    """Latency percentiles and throughput from benchmark timing data."""

    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    total_seconds: float = 0.0
    throughput_per_second: float = 0.0
    per_layer: dict[str, dict[str, float]] = Field(default_factory=dict)


class BenchmarkMetrics(BaseModel):
    """Top-level container for all computed benchmark metrics."""

    confusion_matrix: ConfusionMatrix = Field(default_factory=ConfusionMatrix)
    per_category_recall: dict[str, CategoryRecall] = Field(default_factory=dict)
    severity_metrics: SeverityMetrics = Field(default_factory=SeverityMetrics)
    latency: LatencyStats = Field(default_factory=LatencyStats)
    total_skills: int = 0
    error_count: int = 0
    ambiguous_count: int = 0
    threshold: float = 60.0
    binary_cutoff: RiskLabel = RiskLabel.HIGH


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _coerce_risk_label(value: RiskLabel | str | None) -> RiskLabel | None:
    if value is None:
        return None
    if isinstance(value, RiskLabel):
        return value
    try:
        return RiskLabel(value)
    except ValueError:
        try:
            return RiskLabel[value.upper()]
        except KeyError:
            return None


def classify_binary(
    ground_truth_verdict: str,
    risk_score: int | None = None,
    threshold: float = 60.0,
    *,
    risk_label: RiskLabel | str | None = None,
    binary_cutoff: RiskLabel | str = RiskLabel.HIGH,
) -> str:
    """Classify a single result as TP/FP/TN/FN/EXCLUDED.

    Label-based path:
    - AMBIGUOUS -> EXCLUDED
    - MALICIOUS + risk_label >= cutoff -> TP
    - MALICIOUS + risk_label < cutoff -> FN
    - SAFE + risk_label >= cutoff -> FP
    - SAFE + risk_label < cutoff -> TN

    Compatibility path:
    - If no risk label is available, fall back to the historical score threshold.
    """
    verdict_upper = ground_truth_verdict.upper()
    if verdict_upper == "AMBIGUOUS":
        return "EXCLUDED"

    label = _coerce_risk_label(risk_label)
    cutoff = _coerce_risk_label(binary_cutoff) or RiskLabel.HIGH

    if label is not None:
        flagged = RISK_LABEL_ORDER[label] >= RISK_LABEL_ORDER[cutoff]
    else:
        flagged = (risk_score or 0) < threshold

    if verdict_upper == "MALICIOUS":
        return "TP" if flagged else "FN"

    # SAFE
    return "FP" if flagged else "TN"


# ---------------------------------------------------------------------------
# Confusion matrix
# ---------------------------------------------------------------------------


def compute_confusion_matrix(results: list[BenchmarkResult]) -> ConfusionMatrix:
    """Aggregate binary outcomes into a confusion matrix. Skip EXCLUDED."""
    tp = fp = tn = fn = 0
    for r in results:
        outcome = r.binary_outcome
        if outcome == "TP":
            tp += 1
        elif outcome == "FP":
            fp += 1
        elif outcome == "TN":
            tn += 1
        elif outcome == "FN":
            fn += 1
        # EXCLUDED is skipped
    return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)


# ---------------------------------------------------------------------------
# Per-category recall
# ---------------------------------------------------------------------------


def compute_per_category_recall(
    results: list[BenchmarkResult],
) -> dict[str, CategoryRecall]:
    """For each attack category in ground truth, count how many skills
    had at least one finding in that category.

    Only considers MALICIOUS skills (not SAFE or AMBIGUOUS).
    A category is 'detected' if any finding has a matching category value.
    """
    category_totals: dict[str, int] = {}
    category_detected: dict[str, int] = {}

    for r in results:
        if r.ground_truth_verdict.upper() != "MALICIOUS":
            continue

        finding_categories = {f.category for f in r.findings}

        for cat in r.ground_truth_categories:
            category_totals[cat] = category_totals.get(cat, 0) + 1
            if cat in finding_categories:
                category_detected[cat] = category_detected.get(cat, 0) + 1

    result: dict[str, CategoryRecall] = {}
    for cat, total in sorted(category_totals.items()):
        detected = category_detected.get(cat, 0)
        recall = detected / total if total > 0 else 0.0
        result[cat] = CategoryRecall(detected=detected, total=total, recall=recall)
    return result


# ---------------------------------------------------------------------------
# Coverage helpers
# ---------------------------------------------------------------------------


def compute_category_coverage(result: BenchmarkResult) -> CoverageResult:
    """Compare a single result's finding categories against min_category_coverage.

    Minimum coverage: expected categories that have at least one matching finding.
    """
    finding_categories = {f.category for f in result.findings}
    hits: list[str] = []
    misses: list[str] = []
    for cat in result.ground_truth_min_categories:
        if cat in finding_categories:
            hits.append(cat)
        else:
            misses.append(cat)
    return CoverageResult(hits=hits, misses=misses)


def compute_rule_coverage(result: BenchmarkResult) -> CoverageResult:
    """Compare a single result's finding rule_ids against expected_rules.

    Minimum coverage: expected rules that appear in at least one finding.
    """
    finding_rules = {f.rule_id for f in result.findings}
    hits: list[str] = []
    misses: list[str] = []
    for rule in result.ground_truth_expected_rules:
        if rule in finding_rules:
            hits.append(rule)
        else:
            misses.append(rule)
    return CoverageResult(hits=hits, misses=misses)


# ---------------------------------------------------------------------------
# Severity accuracy
# ---------------------------------------------------------------------------


def compute_severity_accuracy(results: list[BenchmarkResult]) -> SeverityMetrics:
    """For TP results only: ordinal distance between ground truth severity
    and the max severity among findings.

    Uses SEVERITY_ORDINAL mapping. Lower ordinal = more severe.
    under_severity_rate: scanner severity is less severe than ground truth.
    over_severity_rate: scanner severity is more severe than ground truth.
    """
    errors: list[int] = []
    under_count = 0
    over_count = 0

    for r in results:
        if r.binary_outcome != "TP":
            continue
        if r.ground_truth_severity is None:
            continue
        gt_ordinal = SEVERITY_ORDINAL.get(r.ground_truth_severity.lower())
        if gt_ordinal is None:
            continue
        if not r.findings:
            continue

        # Find the most severe finding (lowest ordinal)
        scanner_ordinal: int | None = None
        for f in r.findings:
            f_ord = SEVERITY_ORDINAL.get(f.severity.lower())
            if f_ord is not None:
                if scanner_ordinal is None or f_ord < scanner_ordinal:
                    scanner_ordinal = f_ord
        if scanner_ordinal is None:
            continue

        # Ordinal distance: positive means scanner is less severe
        distance = scanner_ordinal - gt_ordinal
        errors.append(abs(distance))
        if distance > 0:
            under_count += 1
        elif distance < 0:
            over_count += 1

    n = len(errors)
    if n == 0:
        return SeverityMetrics()

    mae = sum(errors) / n
    return SeverityMetrics(
        mean_absolute_error=mae,
        under_severity_rate=under_count / n,
        over_severity_rate=over_count / n,
        sample_count=n,
    )


# ---------------------------------------------------------------------------
# Latency statistics
# ---------------------------------------------------------------------------


def _percentile(values: list[float], p: float) -> float:
    """Compute the p-th percentile of a sorted list (nearest-rank method).

    ``p`` is in [0, 100]. Returns 0.0 for an empty list.
    """
    if not values:
        return 0.0
    sorted_values = sorted(values)
    rank = math.ceil(p / 100.0 * len(sorted_values))
    # Clamp to valid index range
    idx = max(0, min(rank - 1, len(sorted_values) - 1))
    return sorted_values[idx]


def compute_latency_stats(results: list[BenchmarkResult]) -> LatencyStats:
    """Compute latency percentiles from timing data.

    Uses 'total_ms' for overall stats.
    Per-layer: compute p50/p95/p99 for each layer key that appears.
    """
    total_times: list[float] = []
    layer_times: dict[str, list[float]] = {}

    for r in results:
        if not r.timing:
            continue
        if "total_ms" in r.timing:
            total_times.append(r.timing["total_ms"])
        for key, val in r.timing.items():
            if key == "total_ms":
                continue
            if key not in layer_times:
                layer_times[key] = []
            layer_times[key].append(val)

    if not total_times:
        return LatencyStats()

    total_seconds = sum(total_times) / 1000.0
    throughput = len(total_times) / total_seconds if total_seconds > 0.0 else 0.0

    per_layer: dict[str, dict[str, float]] = {}
    for layer_key in sorted(layer_times.keys()):
        vals = layer_times[layer_key]
        per_layer[layer_key] = {
            "p50": _percentile(vals, 50),
            "p95": _percentile(vals, 95),
            "p99": _percentile(vals, 99),
        }

    return LatencyStats(
        p50_ms=_percentile(total_times, 50),
        p95_ms=_percentile(total_times, 95),
        p99_ms=_percentile(total_times, 99),
        total_seconds=total_seconds,
        throughput_per_second=throughput,
        per_layer=per_layer,
    )


# ---------------------------------------------------------------------------
# Top-level aggregation
# ---------------------------------------------------------------------------


def compute_all_metrics(
    results: list[BenchmarkResult],
    threshold: float = 60.0,
    *,
    binary_cutoff: RiskLabel | str = RiskLabel.HIGH,
) -> BenchmarkMetrics:
    """Compute all metric groups from benchmark results.

    1. Classify each result binary (updates binary_outcome field)
    2. Compute confusion matrix
    3. Compute per-category recall
    4. Compute severity accuracy
    5. Compute latency stats
    6. Return aggregated BenchmarkMetrics
    """
    cutoff = _coerce_risk_label(binary_cutoff) or RiskLabel.HIGH

    # Step 1: classify each result
    for r in results:
        r.binary_outcome = classify_binary(
            r.ground_truth_verdict,
            r.risk_score,
            threshold,
            risk_label=r.risk_label,
            binary_cutoff=cutoff,
        )

    # Step 2-5: compute each metric group
    cm = compute_confusion_matrix(results)
    per_cat = compute_per_category_recall(results)
    severity = compute_severity_accuracy(results)
    latency = compute_latency_stats(results)

    error_count = sum(1 for r in results if r.error is not None)
    ambiguous_count = sum(
        1 for r in results if r.ground_truth_verdict.upper() == "AMBIGUOUS"
    )

    return BenchmarkMetrics(
        confusion_matrix=cm,
        per_category_recall=per_cat,
        severity_metrics=severity,
        latency=latency,
        total_skills=len(results),
        error_count=error_count,
        ambiguous_count=ambiguous_count,
        threshold=threshold,
        binary_cutoff=cutoff,
    )
