from __future__ import annotations

from skillinquisitor.models import ScanResult


def format_console(result: ScanResult) -> str:
    lines = [
        f"Verdict: {result.verdict}",
        f"Risk score: {result.risk_score}",
        f"{len(result.findings)} findings",
    ]
    for finding in result.findings:
        location = f"{finding.location.file_path}:{finding.location.start_line or 1}"
        lines.append(
            f"- [{finding.rule_id}] {finding.severity.value} {finding.category.value} {location} {finding.message}"
        )
    return "\n".join(lines) + "\n"
