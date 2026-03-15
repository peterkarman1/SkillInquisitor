"""SARIF 2.1.0 formatter for SkillInquisitor scan results."""

from __future__ import annotations

import json
from typing import Any

from skillinquisitor.models import Finding, ScanResult, Severity

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

INFORMATION_URI = "https://github.com/skillinquisitor/skillinquisitor"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _build_region(finding: Finding) -> dict[str, int]:
    """Build a SARIF region dict, omitting fields that are None."""
    region: dict[str, int] = {}
    if finding.location.start_line is not None:
        region["startLine"] = finding.location.start_line
    if finding.location.end_line is not None:
        region["endLine"] = finding.location.end_line
    if finding.location.start_col is not None:
        region["startColumn"] = finding.location.start_col
    if finding.location.end_col is not None:
        region["endColumn"] = finding.location.end_col
    return region


def _build_physical_location(finding: Finding) -> dict[str, Any]:
    """Build a SARIF physicalLocation from a Finding."""
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": finding.location.file_path or ""},
    }
    region = _build_region(finding)
    if region:
        physical["region"] = region
    return physical


def _build_result(finding: Finding, findings_by_id: dict[str, Finding]) -> dict[str, Any]:
    """Convert a Finding into a SARIF result object."""
    level = _SEVERITY_TO_LEVEL[finding.severity]

    sarif_result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.message},
        "locations": [
            {"physicalLocation": _build_physical_location(finding)},
        ],
    }

    # confidence -> rank
    if finding.confidence is not None:
        sarif_result["rank"] = finding.confidence * 100

    # Chain findings: add relatedLocations for referenced findings
    if finding.references:
        related: list[dict[str, Any]] = []
        for idx, ref_id in enumerate(finding.references):
            ref_finding = findings_by_id.get(ref_id)
            if ref_finding is not None:
                related_loc: dict[str, Any] = {
                    "id": idx,
                    "physicalLocation": _build_physical_location(ref_finding),
                }
                related.append(related_loc)
        if related:
            sarif_result["relatedLocations"] = related

    # Custom properties
    props: dict[str, Any] = {
        "severity": finding.severity.value,
        "category": finding.category.value,
        "layer": finding.layer.value,
    }
    if finding.action_flags:
        props["action_flags"] = list(finding.action_flags)
    if finding.details:
        props["details"] = dict(finding.details)

    sarif_result["properties"] = {"skillinquisitor": props}

    return sarif_result


def _build_rule(finding: Finding) -> dict[str, Any]:
    """Build a SARIF rule definition from the first Finding with a given rule_id."""
    level = _SEVERITY_TO_LEVEL[finding.severity]
    return {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.message},
        "defaultConfiguration": {"level": level},
        "properties": {
            "skillinquisitor": {
                "category": finding.category.value,
                "severity": finding.severity.value,
            }
        },
    }


def format_sarif(result: ScanResult) -> str:
    """Format a ScanResult as SARIF 2.1.0 JSON.

    Returns a JSON string conforming to the SARIF 2.1.0 specification.
    """
    findings_by_id: dict[str, Finding] = {f.id: f for f in result.findings}

    # Build unique rules from findings (first occurrence of each rule_id wins)
    rules: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()
    for finding in result.findings:
        if finding.rule_id not in seen_rule_ids:
            seen_rule_ids.add(finding.rule_id)
            rules.append(_build_rule(finding))

    # Build results
    results = [_build_result(f, findings_by_id) for f in result.findings]

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillInquisitor",
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "skillinquisitor": {
                                "verdict": result.verdict,
                                "risk_score": result.risk_score,
                            }
                        },
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2)
