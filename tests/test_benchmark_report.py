"""Comprehensive tests for the benchmark report generator."""

from __future__ import annotations

import pytest

from skillinquisitor.benchmark.metrics import (
    BenchmarkMetrics,
    BenchmarkResult,
    CategoryRecall,
    ConfusionMatrix,
    FindingSummary,
    LatencyStats,
    SeverityMetrics,
)
from skillinquisitor.benchmark.report import (
    _bar,
    _fmt_duration,
    _fmt_pct,
    generate_report,
)


# ---------------------------------------------------------------------------
# Helpers — tiny builder functions
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
    ground_truth_notes: str = "",
    risk_score: int = 100,
    verdict: str = "SAFE",
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
        ground_truth_notes=ground_truth_notes,
        risk_score=risk_score,
        verdict=verdict,
        findings=findings or [],
        timing=timing or {},
        error=error,
        binary_outcome=binary_outcome,
    )


def _metrics(
    *,
    tp: int = 8,
    fp: int = 2,
    tn: int = 10,
    fn: int = 3,
    categories: dict[str, tuple[int, int, float]] | None = None,
    error_count: int = 0,
    ambiguous_count: int = 0,
    threshold: float = 60.0,
    total_skills: int = 23,
    p50_ms: float = 120.0,
    p95_ms: float = 400.0,
    p99_ms: float = 800.0,
    total_seconds: float = 12.5,
    throughput: float = 1.84,
    per_layer: dict[str, dict[str, float]] | None = None,
) -> BenchmarkMetrics:
    cm = ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)
    cat_recall: dict[str, CategoryRecall] = {}
    if categories:
        for name, (det, tot, rec) in categories.items():
            cat_recall[name] = CategoryRecall(detected=det, total=tot, recall=rec)
    return BenchmarkMetrics(
        confusion_matrix=cm,
        per_category_recall=cat_recall,
        severity_metrics=SeverityMetrics(),
        latency=LatencyStats(
            p50_ms=p50_ms,
            p95_ms=p95_ms,
            p99_ms=p99_ms,
            total_seconds=total_seconds,
            throughput_per_second=throughput,
            per_layer=per_layer or {},
        ),
        total_skills=total_skills,
        error_count=error_count,
        ambiguous_count=ambiguous_count,
        threshold=threshold,
    )


def _default_report(**overrides) -> str:  # noqa: ANN003
    """Generate a report with sensible defaults; override any keyword."""
    kwargs: dict = dict(
        run_id="run-001",
        git_sha="abc1234",
        dirty=False,
        timestamp="2026-03-15T10:00:00Z",
        dataset_version="1.0.0",
        wall_clock_seconds=154.3,
        tier="full",
        layers=["deterministic", "ml"],
        threshold=60.0,
        results=[],
        metrics=_metrics(),
    )
    kwargs.update(overrides)
    return generate_report(**kwargs)


# ===========================================================================
# 1. Section headers present
# ===========================================================================


class TestSectionHeaders:
    """All expected section headers appear in a fully-populated report."""

    def test_all_section_headers_present(self):
        results = [
            _result(
                skill_id="mal-1",
                binary_outcome="TP",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["prompt_injection"],
                ground_truth_severity="high",
                risk_score=30,
                verdict="MALICIOUS",
                findings=[_finding()],
                timing={"total_ms": 100.0},
            ),
            _result(
                skill_id="mal-2",
                binary_outcome="FN",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["obfuscation"],
                ground_truth_severity="medium",
                ground_truth_notes="sneaky base64",
                risk_score=80,
                verdict="SAFE",
                findings=[],
                timing={"total_ms": 200.0},
            ),
            _result(
                skill_id="safe-fp",
                binary_outcome="FP",
                ground_truth_verdict="SAFE",
                risk_score=20,
                verdict="MALICIOUS",
                findings=[_finding(rule_id="RULE-FP")],
                timing={"total_ms": 150.0},
            ),
            _result(
                skill_id="safe-1",
                binary_outcome="TN",
                ground_truth_verdict="SAFE",
                risk_score=90,
                verdict="SAFE",
                findings=[],
                timing={"total_ms": 50.0},
            ),
        ]
        metrics = _metrics(
            tp=1,
            fp=1,
            tn=1,
            fn=1,
            total_skills=4,
            categories={
                "prompt_injection": (1, 1, 1.0),
                "obfuscation": (0, 1, 0.0),
            },
        )
        report = _default_report(results=results, metrics=metrics)

        assert "# SkillInquisitor Benchmark Report" in report
        assert "## Run Metadata" in report
        assert "## Executive Summary" in report
        assert "## Confusion Matrix" in report
        assert "## Per-Category Detection Rates" in report
        assert "## Performance" in report
        assert "## Error Analysis" in report

    def test_runtime_metadata_present_when_provided(self):
        report = _default_report(
            runtime={
                "scan_workers": 4,
                "ml_lifecycle": "command",
                "llm_lifecycle": "command",
            }
        )
        assert "Runtime scan_workers" in report
        assert "command" in report

    def test_regression_header_absent_without_baseline(self):
        report = _default_report()
        assert "## Regression Delta" not in report

    def test_regression_header_present_with_baseline(self):
        report = _default_report(
            baseline_metrics={"confusion_matrix": {"precision": 0.7, "recall": 0.8, "f1": 0.74, "fpr": 0.1}},
            baseline_results=[],
        )
        assert "## Regression Delta" in report


# ===========================================================================
# 2. Confusion matrix values
# ===========================================================================


class TestConfusionMatrixOutput:
    """Confusion matrix cell values and derived metrics appear in the output."""

    def test_values_in_output(self):
        metrics = _metrics(tp=40, fp=5, tn=30, fn=10)
        report = _default_report(metrics=metrics)

        assert "40" in report
        assert "5" in report
        assert "30" in report
        assert "10" in report

    def test_derived_metrics_in_output(self):
        metrics = _metrics(tp=40, fp=10, tn=30, fn=20)
        report = _default_report(metrics=metrics)
        # Precision = 40/50 = 80.0%
        assert "80.0%" in report
        # Recall = 40/60 = 66.7%
        assert "66.7%" in report

    def test_ambiguous_distribution_shown(self):
        results = [
            _result(
                skill_id="ambig-1",
                ground_truth_verdict="AMBIGUOUS",
                binary_outcome="EXCLUDED",
                verdict="SAFE",
            ),
            _result(
                skill_id="ambig-2",
                ground_truth_verdict="AMBIGUOUS",
                binary_outcome="EXCLUDED",
                verdict="MALICIOUS",
            ),
        ]
        metrics = _metrics(ambiguous_count=2)
        report = _default_report(results=results, metrics=metrics)
        assert "### Ambiguous Distribution" in report
        assert "SAFE" in report
        assert "MALICIOUS" in report


# ===========================================================================
# 3. Per-category table
# ===========================================================================


class TestPerCategoryTable:
    """Per-category detection table includes all categories from metrics."""

    def test_all_categories_present(self):
        cats = {
            "prompt_injection": (5, 5, 1.0),
            "obfuscation": (2, 4, 0.5),
            "credential_theft": (0, 3, 0.0),
        }
        metrics = _metrics(categories=cats)
        report = _default_report(metrics=metrics)

        assert "prompt_injection" in report
        assert "obfuscation" in report
        assert "credential_theft" in report

    def test_sorted_by_recall_ascending(self):
        cats = {
            "prompt_injection": (5, 5, 1.0),
            "obfuscation": (2, 4, 0.5),
            "credential_theft": (0, 3, 0.0),
        }
        metrics = _metrics(categories=cats)
        report = _default_report(metrics=metrics)

        # credential_theft (0%) should come before obfuscation (50%)
        # which should come before prompt_injection (100%)
        pos_cred = report.index("credential_theft")
        pos_obf = report.index("obfuscation")
        pos_pi = report.index("prompt_injection")
        assert pos_cred < pos_obf < pos_pi

    def test_worst_categories_callout(self):
        cats = {
            "prompt_injection": (5, 5, 1.0),
            "obfuscation": (2, 4, 0.5),
            "credential_theft": (0, 3, 0.0),
        }
        metrics = _metrics(categories=cats)
        report = _default_report(metrics=metrics)
        assert "Worst categories" in report
        assert "credential_theft" in report

    def test_no_categories_message(self):
        metrics = _metrics(categories={})
        report = _default_report(metrics=metrics)
        assert "No category data available" in report

    def test_bar_in_table(self):
        cats = {"prompt_injection": (5, 5, 1.0)}
        metrics = _metrics(categories=cats)
        report = _default_report(metrics=metrics)
        # Full bar for 100% recall
        assert "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588" in report


# ===========================================================================
# 4. Error analysis with FN/FP
# ===========================================================================


class TestErrorAnalysis:
    """Error analysis section appears when there are FN or FP results."""

    def test_fn_section_appears(self):
        results = [
            _result(
                skill_id="missed-1",
                binary_outcome="FN",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["obfuscation"],
                ground_truth_notes="Uses base64 encoding trick",
            ),
        ]
        report = _default_report(results=results)
        assert "### False Negatives" in report
        assert "obfuscation" in report
        assert "missed-1" in report
        assert "Uses base64 encoding trick" in report

    def test_fp_section_appears(self):
        results = [
            _result(
                skill_id="falsely-flagged",
                binary_outcome="FP",
                ground_truth_verdict="SAFE",
                findings=[_finding(rule_id="RULE-FP-1")],
            ),
        ]
        report = _default_report(results=results)
        assert "### False Positives" in report
        assert "RULE-FP-1" in report
        assert "falsely-flagged" in report

    def test_no_error_analysis_when_perfect(self):
        results = [
            _result(skill_id="tp-1", binary_outcome="TP"),
            _result(skill_id="tn-1", binary_outcome="TN"),
        ]
        report = _default_report(results=results)
        assert "## Error Analysis" not in report

    def test_top_10_concerning_failures(self):
        results = [
            _result(
                skill_id=f"fn-{i}",
                binary_outcome="FN",
                ground_truth_verdict="MALICIOUS",
                ground_truth_severity="critical",
                ground_truth_categories=["prompt_injection"],
                risk_score=90,
            )
            for i in range(12)
        ]
        report = _default_report(results=results)
        assert "### Top 10 Most Concerning Failures" in report
        # Should only list 10
        table_section = report.split("### Top 10 Most Concerning Failures")[1]
        # Count data rows (lines starting with |, excluding header)
        table_lines = [
            line
            for line in table_section.split("\n")
            if line.startswith("| fn-")
        ]
        assert len(table_lines) == 10

    def test_fn_groups_by_category(self):
        results = [
            _result(
                skill_id="fn-cat-a-1",
                binary_outcome="FN",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["cat_a"],
            ),
            _result(
                skill_id="fn-cat-a-2",
                binary_outcome="FN",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["cat_a"],
            ),
            _result(
                skill_id="fn-cat-b-1",
                binary_outcome="FN",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["cat_b"],
            ),
        ]
        report = _default_report(results=results)
        assert "**cat_a** (2 missed)" in report
        assert "**cat_b** (1 missed)" in report

    def test_fn_limits_examples_to_3(self):
        results = [
            _result(
                skill_id=f"fn-{i}",
                binary_outcome="FN",
                ground_truth_verdict="MALICIOUS",
                ground_truth_categories=["overloaded"],
            )
            for i in range(5)
        ]
        report = _default_report(results=results)
        assert "**overloaded** (5 missed)" in report
        assert "... and 2 more" in report


# ===========================================================================
# 5. Errors section
# ===========================================================================


class TestErrorsSection:
    """Errors section appears when there are errored results."""

    def test_errors_listed(self):
        results = [
            _result(skill_id="err-1", error="scan timed out"),
            _result(skill_id="err-2", error="model unavailable"),
        ]
        metrics = _metrics(error_count=2)
        report = _default_report(results=results, metrics=metrics)
        assert "## Errors" in report
        assert "err-1" in report
        assert "scan timed out" in report
        assert "err-2" in report
        assert "model unavailable" in report

    def test_no_errors_section_when_clean(self):
        results = [_result(skill_id="ok-1", error=None)]
        report = _default_report(results=results)
        assert "## Errors" not in report


# ===========================================================================
# 6. Regression delta
# ===========================================================================


class TestRegressionDelta:
    """Regression delta section appears with correct content."""

    def test_metric_deltas_shown(self):
        baseline_metrics = {
            "confusion_matrix": {
                "precision": 0.8,
                "recall": 0.7,
                "f1": 0.746,
                "fpr": 0.15,
            },
        }
        metrics = _metrics(tp=9, fp=1, tn=10, fn=3)  # precision=90%, recall=75%
        report = _default_report(
            metrics=metrics,
            baseline_metrics=baseline_metrics,
            baseline_results=[],
        )
        assert "## Regression Delta" in report
        assert "Precision" in report
        assert "Recall" in report
        assert "Baseline" in report
        assert "Current" in report
        assert "Delta" in report

    def test_new_failures_listed(self):
        baseline_results = [
            {"skill_id": "regressed", "binary_outcome": "TP"},
            {"skill_id": "still-good", "binary_outcome": "TN"},
        ]
        results = [
            _result(skill_id="regressed", binary_outcome="FN"),
            _result(skill_id="still-good", binary_outcome="TN"),
        ]
        report = _default_report(
            results=results,
            baseline_metrics={"confusion_matrix": {"precision": 0.9, "recall": 0.9, "f1": 0.9, "fpr": 0.05}},
            baseline_results=baseline_results,
        )
        assert "### New Failures" in report
        assert "regressed" in report

    def test_new_fixes_listed(self):
        baseline_results = [
            {"skill_id": "fixed", "binary_outcome": "FP"},
        ]
        results = [
            _result(skill_id="fixed", binary_outcome="TN"),
        ]
        report = _default_report(
            results=results,
            baseline_metrics={"confusion_matrix": {"precision": 0.9, "recall": 0.9, "f1": 0.9, "fpr": 0.05}},
            baseline_results=baseline_results,
        )
        assert "### New Fixes" in report
        assert "fixed" in report

    def test_executive_summary_shows_regression_counts(self):
        baseline_results = [
            {"skill_id": "regressed", "binary_outcome": "TP"},
            {"skill_id": "fixed", "binary_outcome": "FN"},
        ]
        results = [
            _result(skill_id="regressed", binary_outcome="FN"),
            _result(skill_id="fixed", binary_outcome="TP"),
        ]
        report = _default_report(
            results=results,
            baseline_metrics={"confusion_matrix": {"precision": 0.9, "recall": 0.9, "f1": 0.9, "fpr": 0.05}},
            baseline_results=baseline_results,
        )
        assert "1 regressions, 1 fixes since baseline" in report


# ===========================================================================
# 7. Empty results (no crashes)
# ===========================================================================


class TestEmptyResults:
    """Report generation with empty or minimal inputs does not crash."""

    def test_empty_results_no_crash(self):
        metrics = _metrics(
            tp=0, fp=0, tn=0, fn=0,
            total_skills=0,
            categories={},
        )
        report = _default_report(results=[], metrics=metrics)
        assert "# SkillInquisitor Benchmark Report" in report
        assert "## Run Metadata" in report
        assert "## Executive Summary" in report
        assert "## Confusion Matrix" in report

    def test_all_defaults_no_crash(self):
        report = generate_report(
            run_id="empty",
            git_sha="0000000",
            dirty=True,
            timestamp="2026-01-01T00:00:00Z",
            dataset_version="0.0.0",
            wall_clock_seconds=0.0,
            tier="smoke",
            layers=[],
            threshold=60.0,
            results=[],
            metrics=BenchmarkMetrics(),
        )
        assert "# SkillInquisitor Benchmark Report" in report
        assert "0000000-dirty" in report
        assert "none" in report  # empty layers

    def test_only_excluded_results(self):
        results = [
            _result(
                skill_id="ambig",
                ground_truth_verdict="AMBIGUOUS",
                binary_outcome="EXCLUDED",
            ),
        ]
        metrics = _metrics(tp=0, fp=0, tn=0, fn=0, ambiguous_count=1, total_skills=1)
        report = _default_report(results=results, metrics=metrics)
        assert "# SkillInquisitor Benchmark Report" in report
        # No error analysis because no FN/FP
        assert "## Error Analysis" not in report


# ===========================================================================
# 8. _bar() helper
# ===========================================================================


class TestBarHelper:
    """Test the Unicode bar helper function."""

    def test_full_bar(self):
        result = _bar(1.0)
        assert result == "\u2588" * 10

    def test_empty_bar(self):
        result = _bar(0.0)
        assert result == "\u2591" * 10

    def test_half_bar(self):
        result = _bar(0.5)
        assert result == "\u2588" * 5 + "\u2591" * 5

    def test_custom_width(self):
        result = _bar(0.5, width=20)
        assert result == "\u2588" * 10 + "\u2591" * 10
        assert len(result) == 20

    def test_clamp_above_one(self):
        result = _bar(1.5)
        assert result == "\u2588" * 10

    def test_clamp_below_zero(self):
        result = _bar(-0.5)
        assert result == "\u2591" * 10

    def test_length_always_equals_width(self):
        for frac in [0.0, 0.1, 0.33, 0.5, 0.7, 0.99, 1.0]:
            assert len(_bar(frac, width=10)) == 10
            assert len(_bar(frac, width=5)) == 5


# ===========================================================================
# 9. _fmt_pct() and _fmt_duration()
# ===========================================================================


class TestFmtPct:
    """Test percentage formatting."""

    def test_zero(self):
        assert _fmt_pct(0.0) == "0.0%"

    def test_one(self):
        assert _fmt_pct(1.0) == "100.0%"

    def test_fraction(self):
        assert _fmt_pct(0.942) == "94.2%"

    def test_small_fraction(self):
        assert _fmt_pct(0.001) == "0.1%"

    def test_rounding(self):
        assert _fmt_pct(0.9999) == "100.0%"

    def test_negative(self):
        assert _fmt_pct(-0.05) == "-5.0%"


class TestFmtDuration:
    """Test duration formatting."""

    def test_seconds_only(self):
        assert _fmt_duration(0.3) == "0.3s"

    def test_under_minute(self):
        assert _fmt_duration(45.2) == "45.2s"

    def test_minutes_and_seconds(self):
        assert _fmt_duration(154.0) == "2m 34s"

    def test_exact_minute(self):
        assert _fmt_duration(60.0) == "1m 0s"

    def test_zero(self):
        assert _fmt_duration(0.0) == "0.0s"

    def test_large_duration(self):
        result = _fmt_duration(3661.0)
        assert result == "61m 1s"


# ===========================================================================
# 10. Metadata fields
# ===========================================================================


class TestMetadataFields:
    """Verify run metadata values appear in the report."""

    def test_run_id(self):
        report = _default_report(run_id="run-xyz-123")
        assert "run-xyz-123" in report

    def test_git_sha_clean(self):
        report = _default_report(git_sha="deadbeef", dirty=False)
        assert "deadbeef" in report
        assert "deadbeef-dirty" not in report

    def test_git_sha_dirty(self):
        report = _default_report(git_sha="deadbeef", dirty=True)
        assert "deadbeef-dirty" in report

    def test_timestamp(self):
        report = _default_report(timestamp="2026-03-15T10:00:00Z")
        assert "2026-03-15T10:00:00Z" in report

    def test_dataset_version(self):
        report = _default_report(dataset_version="2.1.0")
        assert "2.1.0" in report

    def test_layers(self):
        report = _default_report(layers=["deterministic", "ml", "llm"])
        assert "deterministic, ml, llm" in report

    def test_tier(self):
        report = _default_report(tier="smoke")
        assert "smoke" in report

    def test_threshold(self):
        report = _default_report(threshold=42.0)
        assert "42.0" in report

    def test_wall_clock(self):
        report = _default_report(wall_clock_seconds=154.3)
        assert "2m 34s" in report


# ===========================================================================
# 11. Performance section
# ===========================================================================


class TestPerformanceSection:
    """Verify performance data appears in the report."""

    def test_latency_values(self):
        metrics = _metrics(p50_ms=120.0, p95_ms=400.0, p99_ms=800.0)
        report = _default_report(metrics=metrics)
        assert "120.0 ms" in report
        assert "400.0 ms" in report
        assert "800.0 ms" in report

    def test_per_layer_breakdown(self):
        per_layer = {
            "deterministic_ms": {"p50": 10.0, "p95": 20.0, "p99": 30.0},
            "ml_ms": {"p50": 80.0, "p95": 200.0, "p99": 500.0},
        }
        metrics = _metrics(per_layer=per_layer)
        report = _default_report(metrics=metrics)
        assert "### Per-Layer Latency" in report
        assert "deterministic_ms" in report
        assert "ml_ms" in report

    def test_top_5_slowest_skills(self):
        results = [
            _result(skill_id=f"skill-{i}", timing={"total_ms": float(i * 100)})
            for i in range(1, 8)
        ]
        report = _default_report(results=results)
        assert "### Top 5 Slowest Skills" in report
        assert "skill-7" in report  # slowest at 700ms
        assert "skill-6" in report
        assert "skill-5" in report

    def test_throughput_shown(self):
        metrics = _metrics(throughput=3.5)
        report = _default_report(metrics=metrics)
        assert "3.50 skills/sec" in report
