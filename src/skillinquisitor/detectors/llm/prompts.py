from __future__ import annotations

from skillinquisitor.models import Finding


JSON_CONTRACT = """Return JSON only with keys:
- "disposition": one of confirm, dispute, escalate, informational
- "severity": one of critical, high, medium, low, info
- "category": one of prompt_injection, steganography, obfuscation, credential_theft, data_exfiltration, persistence, supply_chain, jailbreak, structural, behavioral, suppression, cross_agent, custom
- "message": concise user-facing assessment
- "confidence": float from 0 to 1
- "behaviors": list of short behavior labels
- "evidence": list of exact code snippets or symbols"""


def build_general_prompt(target) -> str:
    return (
        f"Review the following skill code file for malicious or suspicious behavior.\n"
        f"Skill: {target.skill_name or target.skill_path}\n"
        f"File: {target.relative_path}\n"
        f"Language: {target.file_type.value}\n\n"
        "Focus on data exfiltration, credential theft, persistence, cross-agent tampering, "
        "downloader behavior, dynamic execution, stealth, and delayed activation.\n"
        f"{JSON_CONTRACT}\n\n"
        "Return JSON only.\n\n"
        "Code:\n"
        "```text\n"
        f"{target.normalized_content or target.content}\n"
        "```"
    )


def build_targeted_prompt(*, target, finding: Finding) -> str:
    action_flags = ", ".join(finding.action_flags) if finding.action_flags else "none"
    return (
        f"Deterministic finding to verify:\n"
        f"- rule_id: {finding.rule_id}\n"
        f"- severity: {finding.severity.value}\n"
        f"- message: {finding.message}\n"
        f"- file: {finding.location.file_path}\n"
        f"- line: {finding.location.start_line}\n"
        f"- action_flags: {action_flags}\n"
        f"- details: {finding.details}\n\n"
        "Decide whether the deterministic signal is truly malicious, benign, or ambiguous in context.\n"
        f"{JSON_CONTRACT}\n\n"
        "Return JSON only.\n\n"
        f"Target file: {target.relative_path}\n"
        "Code:\n"
        "```text\n"
        f"{target.normalized_content or target.content}\n"
        "```"
    )


def build_repo_prompt(*, skill_name: str, packed_content: str, related_findings: list[Finding]) -> str:
    finding_lines = [
        f"- {finding.rule_id}: {finding.message} ({finding.location.file_path}:{finding.location.start_line or 1})"
        for finding in related_findings
    ]
    findings_block = "\n".join(finding_lines) if finding_lines else "- none"
    return (
        f"Review the whole packed skill context for {skill_name}.\n"
        "This bundle may contain multiple files, so look for cross-file data flow and staged behavior.\n"
        f"Prior deterministic findings:\n{findings_block}\n\n"
        f"{JSON_CONTRACT}\n\n"
        "Return JSON only.\n\n"
        "Packed skill:\n"
        "```text\n"
        f"{packed_content}\n"
        "```"
    )
