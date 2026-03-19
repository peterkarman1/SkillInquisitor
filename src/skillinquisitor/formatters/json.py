from __future__ import annotations

import json
from collections import Counter

from skillinquisitor.models import ScanResult, Severity


def format_json(result: ScanResult) -> str:
    """Format scan results as findings-focused JSON.

    Excludes raw file content, artifacts, and segments for security.
    Includes a summary with counts by severity, layer, and category.
    """
    # Build skills list with only path and name
    skills = [{"path": s.path, "name": s.name} for s in result.skills]

    # Serialize findings using model_dump to get enum values as strings
    findings = [f.model_dump(mode="json") for f in result.findings]

    # Build summary counters
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    layer_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    for f in result.findings:
        severity_counts[f.severity.value] += 1
        layer_counts[f.layer.value] += 1
        category_counts[f.category.value] += 1

    output = {
        "version": "1.0",
        "risk_label": result.risk_label.value,
        "binary_label": result.binary_label,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "adjudication": result.adjudication,
        "skills": skills,
        "findings": findings,
        "summary": {
            "by_severity": severity_counts,
            "by_layer": dict(layer_counts),
            "by_category": dict(category_counts),
        },
        "layer_metadata": result.layer_metadata,
        "total_timing": result.total_timing,
    }

    return json.dumps(output, indent=2, default=str)
