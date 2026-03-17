"""Markdown report generator for benchmark runs.

Produces a human-readable Markdown document summarising detection quality,
regression deltas, per-category recall, latency, and error analysis.
"""

from __future__ import annotations

from collections import defaultdict

from skillinquisitor.benchmark.metrics import (
    SEVERITY_ORDINAL,
    BenchmarkMetrics,
    BenchmarkResult,
)

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

_FULL_BLOCK = "\u2588"
_LIGHT_SHADE = "\u2591"


def _bar(fraction: float, width: int = 10) -> str:
    """Return a Unicode bar like ``████░░░░░░`` proportional to *fraction*.

    *fraction* is clamped to [0, 1].
    """
    fraction = max(0.0, min(1.0, fraction))
    filled = round(fraction * width)
    empty = width - filled
    return _FULL_BLOCK * filled + _LIGHT_SHADE * empty


def _fmt_pct(value: float) -> str:
    """Format a 0-1 fraction as ``94.2%``."""
    return f"{value * 100:.1f}%"


def _fmt_duration(seconds: float) -> str:
    """Format seconds as ``2m 34s`` or ``0.3s``."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    remaining = seconds - minutes * 60
    return f"{minutes}m {remaining:.0f}s"


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _section_metadata(
    run_id: str,
    git_sha: str,
    dirty: bool,
    timestamp: str,
    dataset_version: str,
    layers: list[str],
    tier: str,
    threshold: float,
    wall_clock_seconds: float,
    total_skills: int,
    runtime: dict[str, object] | None = None,
) -> str:
    sha_display = git_sha + ("-dirty" if dirty else "")
    rows = [
        ("Run ID", run_id),
        ("Git SHA", sha_display),
        ("Timestamp", timestamp),
        ("Dataset version", dataset_version),
        ("Layers", ", ".join(layers) if layers else "none"),
        ("Tier", tier),
        ("Threshold", str(threshold)),
        ("Wall clock", _fmt_duration(wall_clock_seconds)),
        ("Total skills", str(total_skills)),
    ]
    if runtime:
        rows.extend(
            [
                ("Runtime scan_workers", str(runtime.get("scan_workers", ""))),
                ("Runtime ml_lifecycle", str(runtime.get("ml_lifecycle", ""))),
                ("Runtime llm_lifecycle", str(runtime.get("llm_lifecycle", ""))),
            ]
        )
    lines = ["## Run Metadata", "", "| Field | Value |", "|---|---|"]
    for field, value in rows:
        lines.append(f"| {field} | {value} |")
    return "\n".join(lines)


def _section_executive_summary(
    metrics: BenchmarkMetrics,
    regressions: int | None = None,
    fixes: int | None = None,
) -> str:
    cm = metrics.confusion_matrix
    lines = [
        "## Executive Summary",
        "",
        f"- **Precision**: {_fmt_pct(cm.precision)}",
        f"- **Recall**: {_fmt_pct(cm.recall)}",
        f"- **F1 Score**: {_fmt_pct(cm.f1)}",
        f"- **TP**: {cm.tp}  **FP**: {cm.fp}  **TN**: {cm.tn}  **FN**: {cm.fn}",
    ]
    if metrics.error_count > 0:
        lines.append(f"- **Errors**: {metrics.error_count}")
    lines.append(f"- **Ambiguous (excluded)**: {metrics.ambiguous_count}")

    if regressions is not None and fixes is not None:
        lines.append(
            f"- **{regressions} regressions, {fixes} fixes since baseline**"
        )

    # Weakest category
    cats = metrics.per_category_recall
    if cats:
        weakest_name = min(cats, key=lambda c: cats[c].recall)
        weakest = cats[weakest_name]
        lines.append(
            f"- **Weakest category**: {weakest_name} "
            f"({_fmt_pct(weakest.recall)} recall, {weakest.detected}/{weakest.total})"
        )

    return "\n".join(lines)


def _section_regression_delta(
    metrics: BenchmarkMetrics,
    baseline_metrics: dict,
    results: list[BenchmarkResult],
    baseline_results: list[dict],
) -> str:
    lines = ["## Regression Delta", ""]

    # --- metric delta table ---
    cm = metrics.confusion_matrix
    b_cm = baseline_metrics.get("confusion_matrix", {})
    delta_rows: list[tuple[str, str, str, str]] = []

    metric_pairs: list[tuple[str, float, float]] = [
        ("Precision", cm.precision, b_cm.get("precision", 0.0)),
        ("Recall", cm.recall, b_cm.get("recall", 0.0)),
        ("F1", cm.f1, b_cm.get("f1", 0.0)),
        ("FPR", cm.fpr, b_cm.get("fpr", 0.0)),
    ]
    for name, current, baseline in metric_pairs:
        delta = current - baseline
        sign = "+" if delta >= 0 else ""
        delta_rows.append(
            (name, _fmt_pct(baseline), _fmt_pct(current), f"{sign}{_fmt_pct(delta)}")
        )

    lines.append("| Metric | Baseline | Current | Delta |")
    lines.append("|---|---:|---:|---:|")
    for name, base_val, cur_val, delta_val in delta_rows:
        lines.append(f"| {name} | {base_val} | {cur_val} | {delta_val} |")
    lines.append("")

    # --- new failures and new fixes ---
    current_outcomes: dict[str, str] = {
        r.skill_id: r.binary_outcome for r in results
    }
    baseline_outcomes: dict[str, str] = {}
    for br in baseline_results:
        sid = br.get("skill_id", "")
        outcome = br.get("binary_outcome", "EXCLUDED")
        if sid:
            baseline_outcomes[sid] = outcome

    good = {"TP", "TN"}
    bad = {"FP", "FN"}

    new_failures: list[str] = []
    new_fixes: list[str] = []
    for sid in sorted(set(current_outcomes) | set(baseline_outcomes)):
        cur = current_outcomes.get(sid)
        base = baseline_outcomes.get(sid)
        if base in good and cur in bad:
            new_failures.append(sid)
        elif base in bad and cur in good:
            new_fixes.append(sid)

    if new_failures:
        lines.append("### New Failures")
        lines.append("")
        for sid in new_failures:
            lines.append(
                f"- `{sid}`: was {baseline_outcomes.get(sid)} -> now {current_outcomes.get(sid)}"
            )
        lines.append("")

    if new_fixes:
        lines.append("### New Fixes")
        lines.append("")
        for sid in new_fixes:
            lines.append(
                f"- `{sid}`: was {baseline_outcomes.get(sid)} -> now {current_outcomes.get(sid)}"
            )
        lines.append("")

    if not new_failures and not new_fixes:
        lines.append("No regressions or fixes detected.")
        lines.append("")

    return "\n".join(lines)


def _section_confusion_matrix(metrics: BenchmarkMetrics, results: list[BenchmarkResult]) -> str:
    cm = metrics.confusion_matrix
    lines = [
        "## Confusion Matrix",
        "",
        "|                  | Predicted Positive | Predicted Negative |",
        "|------------------|-------------------:|-------------------:|",
        f"| Actually Positive| {cm.tp:>18} | {cm.fn:>18} |",
        f"| Actually Negative| {cm.fp:>18} | {cm.tn:>18} |",
        "",
        f"- Precision: {_fmt_pct(cm.precision)}",
        f"- Recall: {_fmt_pct(cm.recall)}",
        f"- F1: {_fmt_pct(cm.f1)}",
        f"- FPR: {_fmt_pct(cm.fpr)}",
    ]

    if metrics.ambiguous_count > 0:
        lines.append("")
        lines.append("### Ambiguous Distribution")
        lines.append("")
        verdict_counts: dict[str, int] = defaultdict(int)
        for r in results:
            if r.ground_truth_verdict.upper() == "AMBIGUOUS":
                verdict_counts[r.verdict] += 1
        lines.append("| Verdict | Count |")
        lines.append("|---|---:|")
        for verdict in sorted(verdict_counts):
            lines.append(f"| {verdict} | {verdict_counts[verdict]} |")

    return "\n".join(lines)


def _section_per_category(metrics: BenchmarkMetrics) -> str:
    cats = metrics.per_category_recall
    if not cats:
        return "## Per-Category Detection Rates\n\nNo category data available."

    sorted_cats = sorted(cats.items(), key=lambda kv: kv[1].recall)

    lines = [
        "## Per-Category Detection Rates",
        "",
        "| Category | Detected | Total | Recall | Bar |",
        "|---|---:|---:|---:|---|",
    ]
    for name, cr in sorted_cats:
        lines.append(
            f"| {name} | {cr.detected} | {cr.total} | {_fmt_pct(cr.recall)} | {_bar(cr.recall)} |"
        )

    # Worst categories callout
    worst = sorted_cats[:3]
    if worst:
        lines.append("")
        lines.append(
            "**Worst categories**: "
            + ", ".join(f"{name} ({_fmt_pct(cr.recall)})" for name, cr in worst)
        )

    return "\n".join(lines)


def _section_performance(metrics: BenchmarkMetrics, results: list[BenchmarkResult]) -> str:
    lat = metrics.latency
    lines = [
        "## Performance",
        "",
        "### Overall Latency",
        "",
        f"- p50: {lat.p50_ms:.1f} ms",
        f"- p95: {lat.p95_ms:.1f} ms",
        f"- p99: {lat.p99_ms:.1f} ms",
        f"- Throughput: {lat.throughput_per_second:.2f} skills/sec",
    ]

    # Per-layer breakdown
    if lat.per_layer:
        lines.append("")
        lines.append("### Per-Layer Latency")
        lines.append("")
        lines.append("| Layer | p50 (ms) | p95 (ms) | p99 (ms) |")
        lines.append("|---|---:|---:|---:|")
        for layer_name, stats in sorted(lat.per_layer.items()):
            lines.append(
                f"| {layer_name} | {stats.get('p50', 0.0):.1f} "
                f"| {stats.get('p95', 0.0):.1f} "
                f"| {stats.get('p99', 0.0):.1f} |"
            )

    # Top 5 slowest skills
    timed = [(r.skill_id, r.timing.get("total_ms", 0.0)) for r in results if r.timing]
    timed.sort(key=lambda x: x[1], reverse=True)
    slowest = timed[:5]
    if slowest:
        lines.append("")
        lines.append("### Top 5 Slowest Skills")
        lines.append("")
        lines.append("| Skill | Total (ms) |")
        lines.append("|---|---:|")
        for sid, ms in slowest:
            lines.append(f"| {sid} | {ms:.1f} |")

    return "\n".join(lines)


def _section_error_analysis(results: list[BenchmarkResult]) -> str:
    fn_results = [r for r in results if r.binary_outcome == "FN"]
    fp_results = [r for r in results if r.binary_outcome == "FP"]

    if not fn_results and not fp_results:
        return ""

    lines = ["## Error Analysis", ""]

    # --- False Negatives ---
    if fn_results:
        lines.append("### False Negatives")
        lines.append("")
        fn_by_cat: dict[str, list[BenchmarkResult]] = defaultdict(list)
        for r in fn_results:
            cats = r.ground_truth_categories or ["uncategorised"]
            for cat in cats:
                fn_by_cat[cat].append(r)

        for cat in sorted(fn_by_cat):
            group = fn_by_cat[cat]
            lines.append(f"**{cat}** ({len(group)} missed)")
            lines.append("")
            for r in group[:3]:
                notes_part = f" — {r.ground_truth_notes}" if r.ground_truth_notes else ""
                lines.append(f"- `{r.skill_id}`{notes_part}")
            if len(group) > 3:
                lines.append(f"- ... and {len(group) - 3} more")
            lines.append("")

    # --- False Positives ---
    if fp_results:
        lines.append("### False Positives")
        lines.append("")
        fp_by_rule: dict[str, list[BenchmarkResult]] = defaultdict(list)
        for r in fp_results:
            trigger = r.findings[0].rule_id if r.findings else "unknown"
            fp_by_rule[trigger].append(r)

        for rule in sorted(fp_by_rule):
            group = fp_by_rule[rule]
            lines.append(f"**{rule}** ({len(group)} false triggers)")
            lines.append("")
            for r in group[:3]:
                lines.append(f"- `{r.skill_id}`")
            if len(group) > 3:
                lines.append(f"- ... and {len(group) - 3} more")
            lines.append("")

    # --- Top 10 Most Concerning Failures ---
    failures = [r for r in results if r.binary_outcome in ("FN", "FP")]
    if failures:
        # Rank by severity_ordinal * (1 - risk_score/100), higher is worse
        def _concern_score(r: BenchmarkResult) -> float:
            sev = r.ground_truth_severity or "info"
            ordinal = SEVERITY_ORDINAL.get(sev.lower(), 4)
            # Invert ordinal so critical(0) is most concerning
            inv_ordinal = max(SEVERITY_ORDINAL.values()) - ordinal + 1
            return inv_ordinal * (1 - r.risk_score / 100.0)

        failures.sort(key=_concern_score, reverse=True)
        top = failures[:10]

        lines.append("### Top 10 Most Concerning Failures")
        lines.append("")
        lines.append("| Skill | Ground Truth | Risk Score | Verdict |")
        lines.append("|---|---|---:|---|")
        for r in top:
            gt = r.ground_truth_verdict
            lines.append(f"| {r.skill_id} | {gt} | {r.risk_score} | {r.verdict} |")
        lines.append("")

    return "\n".join(lines)


def _section_errors(results: list[BenchmarkResult]) -> str:
    errored = [r for r in results if r.error is not None]
    if not errored:
        return ""

    lines = ["## Errors", ""]
    for r in errored:
        lines.append(f"- `{r.skill_id}`: {r.error}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_report(
    run_id: str,
    git_sha: str,
    dirty: bool,
    timestamp: str,
    dataset_version: str,
    wall_clock_seconds: float,
    tier: str,
    layers: list[str],
    threshold: float,
    results: list[BenchmarkResult],
    metrics: BenchmarkMetrics,
    baseline_metrics: dict | None = None,
    baseline_results: list[dict] | None = None,
    runtime: dict[str, object] | None = None,
) -> str:
    """Generate a Markdown benchmark report from a completed run.

    Parameters
    ----------
    run_id:
        Unique identifier for this run.
    git_sha:
        Short Git SHA of the code under test.
    dirty:
        Whether the working tree had uncommitted changes.
    timestamp:
        ISO-8601 timestamp of the run start.
    dataset_version:
        Version string for the benchmark dataset.
    wall_clock_seconds:
        Total wall-clock time for the run.
    tier:
        Benchmark tier (e.g. ``smoke``, ``full``).
    layers:
        Detection layers that were active (e.g. ``["deterministic", "ml"]``).
    threshold:
        Risk-score threshold used for binary classification.
    results:
        Per-skill benchmark results.
    metrics:
        Aggregated metrics computed from *results*.
    baseline_metrics:
        Previous run's metrics as a plain dict (for delta comparison).
    baseline_results:
        Previous run's per-skill results as a list of dicts.

    Returns
    -------
    str
        The complete Markdown report.
    """
    sections: list[str] = []

    # 1. Title
    sections.append("# SkillInquisitor Benchmark Report")

    # 2. Run metadata
    sections.append(
        _section_metadata(
            run_id=run_id,
            git_sha=git_sha,
            dirty=dirty,
            timestamp=timestamp,
            dataset_version=dataset_version,
            layers=layers,
            tier=tier,
            threshold=threshold,
            wall_clock_seconds=wall_clock_seconds,
            total_skills=metrics.total_skills,
            runtime=runtime,
        )
    )

    # 3. Executive summary
    regressions: int | None = None
    fixes: int | None = None
    if baseline_metrics is not None and baseline_results is not None:
        current_outcomes = {r.skill_id: r.binary_outcome for r in results}
        baseline_outcomes: dict[str, str] = {}
        for br in baseline_results:
            sid = br.get("skill_id", "")
            outcome = br.get("binary_outcome", "EXCLUDED")
            if sid:
                baseline_outcomes[sid] = outcome
        good = {"TP", "TN"}
        bad = {"FP", "FN"}
        regressions = sum(
            1
            for sid in set(current_outcomes) | set(baseline_outcomes)
            if baseline_outcomes.get(sid) in good and current_outcomes.get(sid) in bad
        )
        fixes = sum(
            1
            for sid in set(current_outcomes) | set(baseline_outcomes)
            if baseline_outcomes.get(sid) in bad and current_outcomes.get(sid) in good
        )

    sections.append(
        _section_executive_summary(metrics, regressions=regressions, fixes=fixes)
    )

    # 4. Regression delta (conditional)
    if baseline_metrics is not None and baseline_results is not None:
        sections.append(
            _section_regression_delta(metrics, baseline_metrics, results, baseline_results)
        )

    # 5. Confusion matrix
    sections.append(_section_confusion_matrix(metrics, results))

    # 6. Per-category detection rates
    sections.append(_section_per_category(metrics))

    # 7. Performance
    sections.append(_section_performance(metrics, results))

    # 8. Error analysis (FN/FP)
    error_analysis = _section_error_analysis(results)
    if error_analysis:
        sections.append(error_analysis)

    # 9. Errors
    errors = _section_errors(results)
    if errors:
        sections.append(errors)

    return "\n\n".join(sections) + "\n"
