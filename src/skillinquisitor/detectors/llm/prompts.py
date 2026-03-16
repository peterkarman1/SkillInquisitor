from __future__ import annotations

from skillinquisitor.models import Finding


JSON_CONTRACT = """RESPONSE FORMAT: Return ONLY a valid JSON object. No markdown fences, no text before or after.

Required JSON keys:
- "disposition": "confirm" (malicious), "dispute" (benign/safe), "escalate" (needs review), or "informational"
- "severity": "critical", "high", "medium", "low", or "info"
- "category": "prompt_injection", "steganography", "obfuscation", "credential_theft", "data_exfiltration", "persistence", "supply_chain", "jailbreak", "structural", "behavioral", "suppression", "cross_agent", or "custom"
- "message": 1-2 sentence explanation
- "confidence": float 0.0 to 1.0
- "behaviors": list of short behavior labels (e.g. ["credential_read", "network_send"])
- "evidence": list of exact suspicious code snippets from the file"""


def build_general_prompt(target) -> str:
    return (
        "You are auditing an AI agent skill file for security threats.\n\n"
        f"Skill: {target.skill_name or target.skill_path}\n"
        f"File: {target.relative_path}\n"
        f"Language: {target.file_type.value}\n\n"
        "INSTRUCTIONS:\n"
        "1. Read the code carefully line by line\n"
        "2. Look for these specific threats:\n"
        "   - Reading sensitive files (~/.ssh, ~/.aws, .env, /etc/passwd)\n"
        "   - Sending data to external URLs (curl, requests.post, fetch, urllib)\n"
        "   - Dynamic code execution (eval, exec, subprocess with user input)\n"
        "   - Persistence mechanisms (writing to crontab, .bashrc, git hooks)\n"
        "   - Credential harvesting (reading API keys, tokens, passwords from env)\n"
        "   - Obfuscated code (base64 decode + exec, ROT13, hex encoding)\n"
        "   - Reverse shells or command-and-control callbacks\n"
        "3. If the code does NONE of these, disposition should be 'dispute' (safe)\n"
        "4. If the code does ANY of these, disposition should be 'confirm' (malicious)\n\n"
        "IMPORTANT: Legitimate uses exist for subprocess, network requests, and file reads.\n"
        "- Running pytest/black/linters via subprocess = SAFE\n"
        "- Health check GET requests to localhost = SAFE\n"
        "- Reading PORT/LOG_LEVEL env vars = SAFE\n"
        "- Reading ~/.aws/credentials + sending externally = MALICIOUS\n"
        "- eval() on user-controlled input = MALICIOUS\n\n"
        f"{JSON_CONTRACT}\n\n"
        "Code to analyze:\n"
        "```\n"
        f"{target.normalized_content or target.content}\n"
        "```"
    )


def build_targeted_prompt(*, target, finding: Finding) -> str:
    action_flags = ", ".join(finding.action_flags) if finding.action_flags else "none"

    # Build a more detailed context for the specific finding
    rule_explanations = {
        "D-10A": "Dynamic or shell execution was detected (eval, exec, subprocess, os.system). This is malicious if it executes untrusted/external input. It is SAFE if it runs known tools like pytest, black, or linters.",
        "D-14C": "An unexpected file was found in the skill directory. This is suspicious if the file is a binary, executable, or hidden file. It is SAFE if it's a normal config file, README, or license.",
        "D-15E": "An external URL was detected. This is suspicious if it points to an unknown host for downloading payloads. It is SAFE if it's documentation linking to well-known sites.",
        "D-15G": "A non-HTTPS URL was detected. This is suspicious if data is being transmitted over HTTP. It may be SAFE if it's in documentation or a localhost reference.",
        "D-18C": "The skill has an overly broad description that could match too many triggers. This is suspicious if the skill seems designed to intercept all requests. It is SAFE if it's just a general-purpose tool with a broad but honest description.",
        "D-22A": "Content from a code fence was flagged. This is suspicious if the code fence contains executable malicious code. It is SAFE if it's a documentation example.",
        "D-5A": "A hex-encoded payload was detected. This is suspicious if the hex decodes to executable commands. It is SAFE if it's a hash value, Docker image ID, or color code.",
        "D-2A": "Mixed-script characters (e.g., Cyrillic in Latin text) were detected. This is suspicious if characters are being used to disguise malicious names. It is SAFE in multilingual documentation.",
        "D-12C": "A directive to skip user confirmation was detected. This is suspicious if it's trying to bypass safety checks. It is SAFE in CI/CD automation contexts.",
        "D-7A": "A reference to a sensitive file path was detected. Malicious if the code READS the file. SAFE if it's just mentioned in documentation.",
        "D-9A": "An outbound network request was detected. Malicious if sending stolen data. SAFE for legitimate API calls or health checks.",
        "D-19A": "A data exfiltration chain was detected: reading sensitive data + sending it externally.",
        "D-19B": "A credential theft chain was detected: reading sensitive data + executing it dynamically.",
        "D-11A": "Prompt injection detected: instructions attempting to override the AI's behavior.",
    }

    rule_context = rule_explanations.get(finding.rule_id, f"Rule {finding.rule_id} flagged potentially suspicious behavior.")

    return (
        "You are verifying a specific security finding in an AI agent skill file.\n\n"
        "A deterministic scanner flagged this code. Your job is to determine if the finding is a "
        "TRUE POSITIVE (real threat) or a FALSE POSITIVE (benign behavior).\n\n"
        "FINDING DETAILS:\n"
        f"- Rule: {finding.rule_id}\n"
        f"- Severity: {finding.severity.value}\n"
        f"- Message: {finding.message}\n"
        f"- File: {finding.location.file_path}\n"
        f"- Line: {finding.location.start_line}\n"
        f"- Action flags: {action_flags}\n\n"
        f"RULE EXPLANATION:\n{rule_context}\n\n"
        "YOUR TASK:\n"
        "- If the flagged behavior is genuinely malicious → disposition: 'confirm'\n"
        "- If the flagged behavior is benign/legitimate → disposition: 'dispute'\n"
        "- If you are unsure → disposition: 'escalate'\n\n"
        f"{JSON_CONTRACT}\n\n"
        f"File: {target.relative_path}\n"
        "Code:\n"
        "```\n"
        f"{target.normalized_content or target.content}\n"
        "```"
    )


def build_repo_prompt(*, skill_name: str, packed_content: str, related_findings: list[Finding]) -> str:
    finding_lines = [
        f"- {finding.rule_id} ({finding.severity.value}): {finding.message} at {finding.location.file_path}:{finding.location.start_line or 1}"
        for finding in related_findings
    ]
    findings_block = "\n".join(finding_lines) if finding_lines else "- none"
    return (
        "You are reviewing a complete AI agent skill for security threats.\n\n"
        f"Skill name: {skill_name}\n\n"
        "This bundle contains all files in the skill. Look for:\n"
        "1. Cross-file data flow (one file reads secrets, another sends them)\n"
        "2. Staged behavior (setup script plants persistence, main script triggers later)\n"
        "3. Social engineering (fake prerequisites asking users to run commands)\n"
        "4. Hidden payloads in seemingly innocent files\n\n"
        f"Prior deterministic findings:\n{findings_block}\n\n"
        "If you find malicious cross-file patterns, disposition: 'confirm'\n"
        "If the skill appears safe, disposition: 'dispute'\n\n"
        f"{JSON_CONTRACT}\n\n"
        "Complete skill contents:\n"
        "```\n"
        f"{packed_content}\n"
        "```"
    )
