from __future__ import annotations

from collections import Counter
from collections import defaultdict

from skillinquisitor.models import Finding, ScanResult, Severity

# Severity ordering for sorting (lower index = higher priority)
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def format_console(result: ScanResult, *, verbose: bool = False) -> str:
    lines: list[str] = []

    # --- Header ---
    skill_names = [skill.name or skill.path for skill in result.skills]
    file_count = sum(len(skill.artifacts) for skill in result.skills)

    lines.append(f"Risk label: {result.risk_label.value}")
    lines.append(f"Binary label: {result.binary_label}")
    lines.append(f"Legacy verdict: {result.verdict}")
    lines.append(f"Legacy risk score: {result.risk_score}/100")
    if skill_names:
        lines.append(f"Skills: {', '.join(skill_names)}")
    lines.append(f"Files scanned: {file_count}")
    lines.append(f"{len(result.findings)} findings")
    if result.adjudication:
        summary = result.adjudication.get("summary")
        if summary:
            lines.append(f"Decision summary: {summary}")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    # Build lookup: finding id -> finding, for cross-references
    id_to_finding: dict[str, Finding] = {f.id: f for f in result.findings}

    # Build set of absorbed finding ids (ids referenced by other findings)
    absorbed_ids: set[str] = set()
    # Map absorbed id -> list of chain rule_ids that absorb it
    absorbed_by: dict[str, list[str]] = defaultdict(list)
    for finding in result.findings:
        for ref_id in finding.references:
            absorbed_ids.add(ref_id)
            absorbed_by[ref_id].append(finding.rule_id)

    # --- Group findings by file path ---
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        file_path = finding.location.file_path or "(unknown)"
        by_file[file_path].append(finding)

    # Sort file paths alphabetically
    for file_path in sorted(by_file.keys()):
        findings = by_file[file_path]

        # Sort within file: severity (CRITICAL first), then line number
        findings.sort(
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity, 99),
                f.location.start_line or 0,
            )
        )

        lines.append(f"── {file_path}")

        for finding in findings:
            line_num = finding.location.start_line or 1
            severity_label = finding.severity.value.upper()
            absorbed_annotation = ""
            if finding.id in absorbed_ids:
                chain_rules = absorbed_by[finding.id]
                absorbed_annotation = f"  -> Absorbed by chain {', '.join(chain_rules)}"

            suppression_annotation = ""
            if "SUPPRESSION_PRESENT" in finding.action_flags:
                suppression_annotation = "  ! Suppression amplifier active"

            lines.append(
                f"   {severity_label}  {finding.rule_id}  {finding.category.value}"
                f"  {finding.message}  :{line_num}"
                f"{absorbed_annotation}"
                f"{suppression_annotation}"
            )

            # Show chain cross-references
            if finding.references:
                for i, ref_id in enumerate(finding.references):
                    is_last = i == len(finding.references) - 1
                    connector = "└─" if is_last else "├─"
                    ref_finding = id_to_finding.get(ref_id)
                    if ref_finding:
                        ref_line = ref_finding.location.start_line or 1
                        lines.append(
                            f"      {connector} {ref_finding.rule_id}"
                            f"  {ref_finding.severity.value.upper()}"
                            f"  {ref_finding.message}  :{ref_line}"
                        )
                    else:
                        lines.append(f"      {connector} (ref {ref_id})")

        lines.append("")

    # --- Summary footer ---
    lines.append("── Summary")

    # Counts by severity
    severity_counts: Counter[str] = Counter()
    for finding in result.findings:
        severity_counts[finding.severity.value.upper()] += 1

    severity_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            severity_parts.append(f"{sev}: {count}")
    lines.append(f"   By severity: {', '.join(severity_parts)}")

    # Counts by layer
    layer_counts: Counter[str] = Counter()
    for finding in result.findings:
        layer_counts[finding.layer.value] += 1
    layer_parts = [f"{layer}: {count}" for layer, count in sorted(layer_counts.items())]
    lines.append(f"   By layer: {', '.join(layer_parts)}")

    # Counts by category
    category_counts: Counter[str] = Counter()
    for finding in result.findings:
        category_counts[finding.category.value] += 1
    category_parts = [f"{cat}: {count}" for cat, count in sorted(category_counts.items())]
    lines.append(f"   By category: {', '.join(category_parts)}")

    lines.append("")

    # --- Verbose scoring details ---
    if verbose:
        scoring = result.layer_metadata.get("scoring", {})
        if scoring:
            lines.append("── Scoring Details")
            for key, value in scoring.items():
                lines.append(f"   {key}: {value}")
            lines.append("")

    return "\n".join(lines)
