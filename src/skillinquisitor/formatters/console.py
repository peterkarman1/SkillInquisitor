from __future__ import annotations

from skillinquisitor.models import ScanResult


def format_console(result: ScanResult) -> str:
    return (
        f"Verdict: {result.verdict}\n"
        f"Risk score: {result.risk_score}\n"
        f"0 findings\n"
    )
