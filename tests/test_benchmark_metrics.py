"""Comprehensive tests for the benchmark metrics engine."""

from __future__ import annotations

import pytest

from skillinquisitor.benchmark.metrics import (
    SEVERITY_ORDINAL,
    BenchmarkMetrics,
    BenchmarkResult,
    CategoryRecall,
    ConfusionMatrix,
    CoverageResult,
    FindingSummary,
    LatencyStats,
    SeverityMetrics,
    _percentile,
    classify_binary,
    compute_all_metrics,
    compute_category_coverage,
    compute_confusion_matrix,
    compute_latency_stats,
    compute_per_category_recall,
    compute_rule_coverage,
    compute_severity_accuracy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    *,
    rule_id: str = "RULE-1",
    category: str = "prompt_injection",
    severity: str = "high",
    confidence: float = 1.0,
    message: str = "",
) -> FindingSummary:
    return FindingSummary(
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=confidence,
        message=message,
    )


def _result(
    *,
    skill_id: str = "skill-1",
    ground_truth_verdict: str = "MALICIOUS",
    ground_truth_categories: list[str] | None = None,
    ground_truth_severity: str | None = None,
    ground_truth_expected_rules: list[str] | None = None,
    ground_truth_min_categories: list[str] | None = None,
    risk_score: int = 100,
    findings: list[FindingSummary] | None = None,
    timing: dict[str, float] | None = None,
    error: str | None = None,
    binary_outcome: str = "EXCLUDED",
) -> BenchmarkResult:
    return BenchmarkResult(
        skill_id=skill_id,
        ground_truth_verdict=ground_truth_verdict,
        ground_truth_categories=ground_truth_categories or [],
        ground_truth_severity=ground_truth_severity,
        ground_truth_expected_rules=ground_truth_expected_rules or [],
        ground_truth_min_categories=ground_truth_min_categories or [],
        risk_score=risk_score,
        findings=findings or [],
        timing=timing or {},
        error=error,
        binary_outcome=binary_outcome,
    )


# ===========================================================================
# 1. ConfusionMatrix properties
# ===========================================================================


class TestConfusionMatrixProperties:
    """Test precision/recall/F1/FPR/FNR/accuracy for known values and
    division-by-zero edge cases."""

    def test_perfect_classifier(self):
        cm = ConfusionMatrix(tp=50, fp=0, tn=50, fn=0)
        assert cm.precision == 1.0
        assert cm.recall == 1.0
        assert cm.f1 == 1.0
        assert cm.fpr == 0.0
        assert cm.fnr == 0.0
        assert cm.accuracy == 1.0
        assert cm.total == 100

    def test_known_values(self):
        cm = ConfusionMatrix(tp=40, fp=10, tn=30, fn=20)
        assert cm.precision == pytest.approx(40 / 50)
        assert cm.recall == pytest.approx(40 / 60)
        assert cm.fpr == pytest.approx(10 / 40)
        assert cm.fnr == pytest.approx(20 / 60)
        assert cm.accuracy == pytest.approx(70 / 100)
        assert cm.total == 100
        # F1 = 2 * p * r / (p + r)
        p = 40 / 50
        r = 40 / 60
        expected_f1 = 2 * p * r / (p + r)
        assert cm.f1 == pytest.approx(expected_f1)

    def test_all_zeros(self):
        cm = ConfusionMatrix()
        assert cm.precision == 0.0
        assert cm.recall == 0.0
        assert cm.f1 == 0.0
        assert cm.fpr == 0.0
        assert cm.fnr == 0.0
        assert cm.accuracy == 0.0
        assert cm.total == 0

    def test_no_positives(self):
        """When there are no actual positives, recall and fnr denominators are 0."""
        cm = ConfusionMatrix(tp=0, fp=5, tn=10, fn=0)
        assert cm.recall == 0.0
        assert cm.fnr == 0.0
        assert cm.precision == 0.0  # 0 / (0+5)
        assert cm.fpr == pytest.approx(5 / 15)

    def test_no_negatives(self):
        """When there are no actual negatives, fpr denominator is 0."""
        cm = ConfusionMatrix(tp=10, fp=0, tn=0, fn=5)
        assert cm.fpr == 0.0
        assert cm.precision == 1.0
        assert cm.recall == pytest.approx(10 / 15)

    def test_only_tp(self):
        cm = ConfusionMatrix(tp=10)
        assert cm.precision == 1.0
        assert cm.recall == 1.0
        assert cm.f1 == 1.0

    def test_only_fp(self):
        cm = ConfusionMatrix(fp=10)
        assert cm.precision == 0.0
        assert cm.recall == 0.0
        assert cm.f1 == 0.0


# ===========================================================================
# 2. classify_binary
# ===========================================================================


class TestClassifyBinary:
    """Test all 5 outcomes at default threshold (60) and a custom threshold (40)."""

    def test_ambiguous_excluded(self):
        assert classify_binary("AMBIGUOUS", 50, 60.0) == "EXCLUDED"
        assert classify_binary("AMBIGUOUS", 70, 60.0) == "EXCLUDED"
        assert classify_binary("ambiguous", 30, 40.0) == "EXCLUDED"

    def test_malicious_tp_default(self):
        # risk_score=30 < threshold=60 -> flagged -> TP
        assert classify_binary("MALICIOUS", 30, 60.0) == "TP"

    def test_malicious_fn_default(self):
        # risk_score=80 >= threshold=60 -> not flagged -> FN
        assert classify_binary("MALICIOUS", 80, 60.0) == "FN"

    def test_malicious_at_threshold(self):
        # risk_score=60 >= threshold=60 -> not flagged -> FN
        assert classify_binary("MALICIOUS", 60, 60.0) == "FN"

    def test_safe_tn_default(self):
        # risk_score=80 >= threshold=60 -> not flagged -> TN
        assert classify_binary("SAFE", 80, 60.0) == "TN"

    def test_safe_fp_default(self):
        # risk_score=30 < threshold=60 -> flagged -> FP
        assert classify_binary("SAFE", 30, 60.0) == "FP"

    def test_safe_at_threshold(self):
        # risk_score=60 >= threshold=60 -> not flagged -> TN
        assert classify_binary("SAFE", 60, 60.0) == "TN"

    def test_custom_threshold_40_tp(self):
        assert classify_binary("MALICIOUS", 20, 40.0) == "TP"

    def test_custom_threshold_40_fn(self):
        assert classify_binary("MALICIOUS", 50, 40.0) == "FN"

    def test_custom_threshold_40_tn(self):
        assert classify_binary("SAFE", 50, 40.0) == "TN"

    def test_custom_threshold_40_fp(self):
        assert classify_binary("SAFE", 20, 40.0) == "FP"

    def test_case_insensitive_verdict(self):
        assert classify_binary("malicious", 30, 60.0) == "TP"
        assert classify_binary("safe", 80, 60.0) == "TN"


# ===========================================================================
# 3. compute_confusion_matrix
# ===========================================================================


class TestComputeConfusionMatrix:
    """Test aggregation of binary outcomes into a confusion matrix."""

    def test_mixed_outcomes(self):
        results = [
            _result(binary_outcome="TP"),
            _result(binary_outcome="TP"),
            _result(binary_outcome="FP"),
            _result(binary_outcome="TN"),
            _result(binary_outcome="TN"),
            _result(binary_outcome="TN"),
            _result(binary_outcome="FN"),
            _result(binary_outcome="EXCLUDED"),
        ]
        cm = compute_confusion_matrix(results)
        assert cm.tp == 2
        assert cm.fp == 1
        assert cm.tn == 3
        assert cm.fn == 1
        assert cm.total == 7  # EXCLUDED is skipped

    def test_empty_results(self):
        cm = compute_confusion_matrix([])
        assert cm.tp == 0
        assert cm.fp == 0
        assert cm.tn == 0
        assert cm.fn == 0

    def test_all_excluded(self):
        results = [
            _result(binary_outcome="EXCLUDED"),
            _result(binary_outcome="EXCLUDED"),
        ]
        cm = compute_confusion_matrix(results)
        assert cm.total == 0


# ===========================================================================
# 4. compute_per_category_recall
# ===========================================================================


class TestComputePerCategoryRecall:
    """Test per-category recall computation."""

    def test_full_detection(self):
        results = [
            _result(
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["prompt_injection"],
                findings=[_finding(category="prompt_injection")],
            ),
            _result(
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["prompt_injection"],
                findings=[_finding(category="prompt_injection")],
            ),
        ]
        cats = compute_per_category_recall(results)
        assert "prompt_injection" in cats
        assert cats["prompt_injection"].detected == 2
        assert cats["prompt_injection"].total == 2
        assert cats["prompt_injection"].recall == 1.0

    def test_partial_detection(self):
        results = [
            _result(
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["obfuscation"],
                findings=[_finding(category="obfuscation")],
            ),
            _result(
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["obfuscation"],
                findings=[_finding(category="prompt_injection")],  # wrong category
            ),
        ]
        cats = compute_per_category_recall(results)
        assert cats["obfuscation"].detected == 1
        assert cats["obfuscation"].total == 2
        assert cats["obfuscation"].recall == pytest.approx(0.5)

    def test_ignores_safe_and_ambiguous(self):
        results = [
            _result(
                ground_truth_verdict="SAFE",
                ground_truth_categories=["prompt_injection"],
                findings=[_finding(category="prompt_injection")],
            ),
            _result(
                ground_truth_verdict="AMBIGUOUS",
                ground_truth_categories=["obfuscation"],
                findings=[_finding(category="obfuscation")],
            ),
        ]
        cats = compute_per_category_recall(results)
        assert len(cats) == 0

    def test_multiple_categories(self):
        results = [
            _result(
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["prompt_injection", "data_exfiltration"],
                findings=[
                    _finding(category="prompt_injection"),
                    _finding(category="data_exfiltration"),
                ],
            ),
        ]
        cats = compute_per_category_recall(results)
        assert cats["prompt_injection"].recall == 1.0
        assert cats["data_exfiltration"].recall == 1.0

    def test_no_findings_zero_recall(self):
        results = [
            _result(
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["credential_theft"],
                findings=[],
            ),
        ]
        cats = compute_per_category_recall(results)
        assert cats["credential_theft"].detected == 0
        assert cats["credential_theft"].total == 1
        assert cats["credential_theft"].recall == 0.0

    def test_empty_results(self):
        cats = compute_per_category_recall([])
        assert len(cats) == 0


# ===========================================================================
# 5. compute_category_coverage
# ===========================================================================


class TestComputeCategoryCoverage:
    """Test hits and misses for min_category_coverage."""

    def test_full_coverage(self):
        r = _result(
            ground_truth_min_categories=["prompt_injection", "obfuscation"],
            findings=[
                _finding(category="prompt_injection"),
                _finding(category="obfuscation"),
            ],
        )
        cov = compute_category_coverage(r)
        assert set(cov.hits) == {"prompt_injection", "obfuscation"}
        assert cov.misses == []
        assert cov.coverage_rate == 1.0

    def test_partial_coverage(self):
        r = _result(
            ground_truth_min_categories=["prompt_injection", "obfuscation", "steganography"],
            findings=[_finding(category="prompt_injection")],
        )
        cov = compute_category_coverage(r)
        assert cov.hits == ["prompt_injection"]
        assert set(cov.misses) == {"obfuscation", "steganography"}
        assert cov.coverage_rate == pytest.approx(1 / 3)

    def test_no_coverage(self):
        r = _result(
            ground_truth_min_categories=["credential_theft"],
            findings=[_finding(category="prompt_injection")],
        )
        cov = compute_category_coverage(r)
        assert cov.hits == []
        assert cov.misses == ["credential_theft"]
        assert cov.coverage_rate == 0.0

    def test_no_expectations(self):
        r = _result(ground_truth_min_categories=[], findings=[_finding()])
        cov = compute_category_coverage(r)
        assert cov.hits == []
        assert cov.misses == []
        assert cov.coverage_rate == 0.0

    def test_no_findings(self):
        r = _result(
            ground_truth_min_categories=["prompt_injection"],
            findings=[],
        )
        cov = compute_category_coverage(r)
        assert cov.hits == []
        assert cov.misses == ["prompt_injection"]
        assert cov.coverage_rate == 0.0


# ===========================================================================
# 6. compute_rule_coverage
# ===========================================================================


class TestComputeRuleCoverage:
    """Test hits and misses for expected_rules."""

    def test_full_coverage(self):
        r = _result(
            ground_truth_expected_rules=["RULE-1", "RULE-2"],
            findings=[
                _finding(rule_id="RULE-1"),
                _finding(rule_id="RULE-2"),
                _finding(rule_id="RULE-3"),  # extra finding
            ],
        )
        cov = compute_rule_coverage(r)
        assert set(cov.hits) == {"RULE-1", "RULE-2"}
        assert cov.misses == []
        assert cov.coverage_rate == 1.0

    def test_partial_coverage(self):
        r = _result(
            ground_truth_expected_rules=["RULE-1", "RULE-2", "RULE-3"],
            findings=[_finding(rule_id="RULE-1")],
        )
        cov = compute_rule_coverage(r)
        assert cov.hits == ["RULE-1"]
        assert set(cov.misses) == {"RULE-2", "RULE-3"}
        assert cov.coverage_rate == pytest.approx(1 / 3)

    def test_no_coverage(self):
        r = _result(
            ground_truth_expected_rules=["RULE-X"],
            findings=[_finding(rule_id="RULE-Y")],
        )
        cov = compute_rule_coverage(r)
        assert cov.hits == []
        assert cov.misses == ["RULE-X"]
        assert cov.coverage_rate == 0.0

    def test_no_expected_rules(self):
        r = _result(
            ground_truth_expected_rules=[],
            findings=[_finding(rule_id="RULE-1")],
        )
        cov = compute_rule_coverage(r)
        assert cov.coverage_rate == 0.0

    def test_no_findings(self):
        r = _result(
            ground_truth_expected_rules=["RULE-1"],
            findings=[],
        )
        cov = compute_rule_coverage(r)
        assert cov.misses == ["RULE-1"]
        assert cov.coverage_rate == 0.0


# ===========================================================================
# 7. compute_severity_accuracy
# ===========================================================================


class TestComputeSeverityAccuracy:
    """Test with matching, under-, and over-severity cases."""

    def test_exact_match(self):
        results = [
            _result(
                ground_truth_severity="high",
                binary_outcome="TP",
                findings=[_finding(severity="high")],
            ),
        ]
        sm = compute_severity_accuracy(results)
        assert sm.mean_absolute_error == 0.0
        assert sm.under_severity_rate == 0.0
        assert sm.over_severity_rate == 0.0
        assert sm.sample_count == 1

    def test_under_severity(self):
        # Ground truth: high (ordinal 1), scanner: medium (ordinal 2)
        # distance = 2 - 1 = 1 (positive => under-severe)
        results = [
            _result(
                ground_truth_severity="high",
                binary_outcome="TP",
                findings=[_finding(severity="medium")],
            ),
        ]
        sm = compute_severity_accuracy(results)
        assert sm.mean_absolute_error == 1.0
        assert sm.under_severity_rate == 1.0
        assert sm.over_severity_rate == 0.0
        assert sm.sample_count == 1

    def test_over_severity(self):
        # Ground truth: medium (ordinal 2), scanner: critical (ordinal 0)
        # distance = 0 - 2 = -2 (negative => over-severe)
        results = [
            _result(
                ground_truth_severity="medium",
                binary_outcome="TP",
                findings=[_finding(severity="critical")],
            ),
        ]
        sm = compute_severity_accuracy(results)
        assert sm.mean_absolute_error == 2.0
        assert sm.under_severity_rate == 0.0
        assert sm.over_severity_rate == 1.0
        assert sm.sample_count == 1

    def test_mixed_severity(self):
        results = [
            _result(
                skill_id="exact",
                ground_truth_severity="high",
                binary_outcome="TP",
                findings=[_finding(severity="high")],
            ),
            _result(
                skill_id="under",
                ground_truth_severity="critical",
                binary_outcome="TP",
                findings=[_finding(severity="medium")],  # ordinal 2 vs 0 => distance 2
            ),
            _result(
                skill_id="over",
                ground_truth_severity="low",
                binary_outcome="TP",
                findings=[_finding(severity="high")],  # ordinal 1 vs 3 => distance -2
            ),
        ]
        sm = compute_severity_accuracy(results)
        assert sm.sample_count == 3
        # MAE = (0 + 2 + 2) / 3
        assert sm.mean_absolute_error == pytest.approx(4 / 3)
        assert sm.under_severity_rate == pytest.approx(1 / 3)
        assert sm.over_severity_rate == pytest.approx(1 / 3)

    def test_skips_non_tp(self):
        results = [
            _result(
                ground_truth_severity="high",
                binary_outcome="FP",
                findings=[_finding(severity="high")],
            ),
            _result(
                ground_truth_severity="high",
                binary_outcome="FN",
                findings=[],
            ),
        ]
        sm = compute_severity_accuracy(results)
        assert sm.sample_count == 0
        assert sm.mean_absolute_error == 0.0

    def test_no_ground_truth_severity(self):
        results = [
            _result(
                ground_truth_severity=None,
                binary_outcome="TP",
                findings=[_finding(severity="high")],
            ),
        ]
        sm = compute_severity_accuracy(results)
        assert sm.sample_count == 0

    def test_picks_most_severe_finding(self):
        # Multiple findings: should pick the most severe (lowest ordinal)
        results = [
            _result(
                ground_truth_severity="high",
                binary_outcome="TP",
                findings=[
                    _finding(severity="low"),      # ordinal 3
                    _finding(severity="critical"),  # ordinal 0
                    _finding(severity="medium"),    # ordinal 2
                ],
            ),
        ]
        sm = compute_severity_accuracy(results)
        # Scanner picks critical (0) vs high (1) => over by 1
        assert sm.mean_absolute_error == 1.0
        assert sm.over_severity_rate == 1.0

    def test_empty_results(self):
        sm = compute_severity_accuracy([])
        assert sm.sample_count == 0
        assert sm.mean_absolute_error == 0.0


# ===========================================================================
# 8. compute_latency_stats / _percentile
# ===========================================================================


class TestPercentile:
    """Test the hand-rolled percentile helper."""

    def test_empty_list(self):
        assert _percentile([], 50) == 0.0

    def test_single_value(self):
        assert _percentile([42.0], 50) == 42.0
        assert _percentile([42.0], 99) == 42.0

    def test_known_percentiles(self):
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        assert _percentile(values, 50) == 30.0
        assert _percentile(values, 100) == 50.0

    def test_unsorted_input(self):
        values = [50.0, 10.0, 30.0, 20.0, 40.0]
        assert _percentile(values, 50) == 30.0

    def test_p0(self):
        values = [10.0, 20.0, 30.0]
        # ceil(0/100 * 3) = 0, clamped to index 0
        assert _percentile(values, 0) == 10.0


class TestComputeLatencyStats:
    """Test latency stats computation with timing data."""

    def test_basic_latency(self):
        results = [
            _result(timing={"total_ms": 100.0, "deterministic_ms": 50.0, "ml_ms": 50.0}),
            _result(timing={"total_ms": 200.0, "deterministic_ms": 80.0, "ml_ms": 120.0}),
            _result(timing={"total_ms": 300.0, "deterministic_ms": 100.0, "ml_ms": 200.0}),
        ]
        stats = compute_latency_stats(results)
        assert stats.p50_ms == 200.0
        assert stats.total_seconds == pytest.approx(0.6)
        assert stats.throughput_per_second == pytest.approx(3 / 0.6)
        assert "deterministic_ms" in stats.per_layer
        assert "ml_ms" in stats.per_layer
        assert stats.per_layer["deterministic_ms"]["p50"] == 80.0

    def test_empty_results(self):
        stats = compute_latency_stats([])
        assert stats.p50_ms == 0.0
        assert stats.total_seconds == 0.0
        assert stats.throughput_per_second == 0.0

    def test_no_timing_data(self):
        results = [_result(timing={}), _result(timing={})]
        stats = compute_latency_stats(results)
        assert stats.p50_ms == 0.0
        assert stats.total_seconds == 0.0

    def test_partial_timing(self):
        """Some results have timing, some don't."""
        results = [
            _result(timing={"total_ms": 100.0}),
            _result(timing={}),
            _result(timing={"total_ms": 300.0}),
        ]
        stats = compute_latency_stats(results)
        assert stats.p50_ms == 100.0  # nearest-rank p50 of [100, 300]
        assert stats.total_seconds == pytest.approx(0.4)

    def test_single_result(self):
        results = [_result(timing={"total_ms": 500.0, "llm_ms": 400.0})]
        stats = compute_latency_stats(results)
        assert stats.p50_ms == 500.0
        assert stats.p95_ms == 500.0
        assert stats.p99_ms == 500.0
        assert stats.per_layer["llm_ms"]["p50"] == 400.0


# ===========================================================================
# 9. compute_all_metrics (end-to-end)
# ===========================================================================


class TestComputeAllMetrics:
    """Test end-to-end aggregation."""

    def test_basic_aggregation(self):
        results = [
            # MALICIOUS, risk_score=30 < 60 => TP
            _result(
                skill_id="mal-1",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["prompt_injection"],
                ground_truth_severity="high",
                risk_score=30,
                findings=[_finding(category="prompt_injection", severity="high")],
                timing={"total_ms": 100.0},
            ),
            # MALICIOUS, risk_score=80 >= 60 => FN
            _result(
                skill_id="mal-2",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["obfuscation"],
                risk_score=80,
                findings=[],
                timing={"total_ms": 200.0},
            ),
            # SAFE, risk_score=90 >= 60 => TN
            _result(
                skill_id="safe-1",
                ground_truth_verdict="SAFE",
                risk_score=90,
                findings=[],
                timing={"total_ms": 50.0},
            ),
            # SAFE, risk_score=20 < 60 => FP
            _result(
                skill_id="safe-2",
                ground_truth_verdict="SAFE",
                risk_score=20,
                findings=[_finding(category="prompt_injection")],
                timing={"total_ms": 150.0},
            ),
            # AMBIGUOUS => EXCLUDED
            _result(
                skill_id="ambig-1",
                ground_truth_verdict="AMBIGUOUS",
                risk_score=50,
                findings=[],
            ),
        ]

        metrics = compute_all_metrics(results, threshold=60.0)

        # Check binary outcomes were set
        assert results[0].binary_outcome == "TP"
        assert results[1].binary_outcome == "FN"
        assert results[2].binary_outcome == "TN"
        assert results[3].binary_outcome == "FP"
        assert results[4].binary_outcome == "EXCLUDED"

        # Confusion matrix
        assert metrics.confusion_matrix.tp == 1
        assert metrics.confusion_matrix.fp == 1
        assert metrics.confusion_matrix.tn == 1
        assert metrics.confusion_matrix.fn == 1

        # Counts
        assert metrics.total_skills == 5
        assert metrics.ambiguous_count == 1
        assert metrics.error_count == 0
        assert metrics.threshold == 60.0

        # Per-category recall
        assert "prompt_injection" in metrics.per_category_recall
        assert metrics.per_category_recall["prompt_injection"].recall == 1.0
        assert "obfuscation" in metrics.per_category_recall
        assert metrics.per_category_recall["obfuscation"].recall == 0.0

        # Latency (4 results with timing data)
        assert metrics.latency.total_seconds > 0.0

    def test_custom_threshold(self):
        results = [
            _result(
                ground_truth_verdict="MALICIOUS",
                risk_score=35,
            ),
        ]
        metrics = compute_all_metrics(results, threshold=40.0)
        assert metrics.threshold == 40.0
        assert results[0].binary_outcome == "TP"
        assert metrics.confusion_matrix.tp == 1

    def test_error_counting(self):
        results = [
            _result(error="scan failed"),
            _result(error="timeout"),
            _result(error=None),
        ]
        metrics = compute_all_metrics(results)
        assert metrics.error_count == 2


# ===========================================================================
# 10. Edge cases
# ===========================================================================


class TestEdgeCases:
    """Test with empty results, all errors, all ambiguous."""

    def test_empty_results(self):
        metrics = compute_all_metrics([])
        assert metrics.total_skills == 0
        assert metrics.confusion_matrix.total == 0
        assert metrics.error_count == 0
        assert metrics.ambiguous_count == 0
        assert len(metrics.per_category_recall) == 0
        assert metrics.severity_metrics.sample_count == 0
        assert metrics.latency.p50_ms == 0.0

    def test_all_ambiguous(self):
        results = [
            _result(ground_truth_verdict="AMBIGUOUS", risk_score=40),
            _result(ground_truth_verdict="AMBIGUOUS", risk_score=70),
        ]
        metrics = compute_all_metrics(results)
        assert metrics.ambiguous_count == 2
        assert metrics.confusion_matrix.total == 0
        for r in results:
            assert r.binary_outcome == "EXCLUDED"

    def test_all_errors(self):
        results = [
            _result(error="err1", ground_truth_verdict="MALICIOUS", risk_score=80),
            _result(error="err2", ground_truth_verdict="SAFE", risk_score=90),
        ]
        metrics = compute_all_metrics(results)
        assert metrics.error_count == 2
        assert metrics.total_skills == 2
        # Still classified: FN and TN
        assert results[0].binary_outcome == "FN"
        assert results[1].binary_outcome == "TN"

    def test_coverage_result_property_empty(self):
        cr = CoverageResult()
        assert cr.coverage_rate == 0.0

    def test_severity_ordinal_completeness(self):
        """Ensure SEVERITY_ORDINAL covers all expected levels."""
        expected = {"critical", "high", "medium", "low", "info"}
        assert set(SEVERITY_ORDINAL.keys()) == expected
        # Ordinals should be strictly increasing
        prev = -1
        for key in ["critical", "high", "medium", "low", "info"]:
            assert SEVERITY_ORDINAL[key] > prev
            prev = SEVERITY_ORDINAL[key]

    def test_benchmark_metrics_defaults(self):
        """BenchmarkMetrics can be constructed with all defaults."""
        bm = BenchmarkMetrics()
        assert bm.total_skills == 0
        assert bm.threshold == 60.0
        assert bm.confusion_matrix.total == 0

    def test_finding_summary_defaults(self):
        fs = FindingSummary(rule_id="R1", category="cat", severity="high")
        assert fs.confidence == 1.0
        assert fs.message == ""

    def test_benchmark_result_defaults(self):
        br = BenchmarkResult(skill_id="s1", ground_truth_verdict="SAFE")
        assert br.risk_score == 100
        assert br.verdict == "SAFE"
        assert br.binary_outcome == "EXCLUDED"
        assert br.findings == []
        assert br.timing == {}
        assert br.error is None

    def test_binary_outcome_mutable(self):
        """binary_outcome must be mutable for compute_all_metrics to work."""
        br = BenchmarkResult(skill_id="s1", ground_truth_verdict="MALICIOUS")
        br.binary_outcome = "TP"
        assert br.binary_outcome == "TP"
