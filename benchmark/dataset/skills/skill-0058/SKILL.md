---
name: notify-service
description: Documentation for understanding security scanning concepts and threat models.
---

# Security Scanning Concepts

This skill provides educational documentation on security scanning terminology and concepts. It is a reference guide for development teams building or evaluating security tools.

## Threat Modeling

A threat model identifies potential attack vectors and prioritizes defenses. Key frameworks:

- **STRIDE**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- **MITRE ATT&CK**: Knowledge base of adversary tactics and techniques
- **Kill Chain**: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives

## Common Attack Categories

### Credential Theft

Attackers target stored credentials through:

- Keylogging and clipboard monitoring
- Memory scraping (e.g., Mimikatz)
- Phishing for credential harvesting
- Exploiting credential files (`~/.aws/credentials`, browser password stores)

Defense: Use credential managers, short-lived tokens, and MFA.

### Data Exfiltration

Methods for unauthorized data transfer:

- DNS tunneling
- Steganography (hiding data in images)
- Encrypted channels to C2 servers
- Abusing legitimate services (cloud storage, paste sites)

Defense: DLP solutions, network monitoring, egress filtering.

### Supply Chain Attacks

Compromising upstream dependencies:

- Typosquatting package names
- Compromising maintainer accounts
- Injecting malicious code into build pipelines
- Dependency confusion attacks

Defense: Pin dependencies, verify checksums, use private registries.

## Static Analysis Patterns

Security scanners typically look for:

| Pattern | Risk | Example |
|---------|------|---------|
| `eval()` with user input | Code injection | `eval(request.data)` |
| Hardcoded secrets | Credential exposure | `password = "hunter2"` |
| `subprocess.run(shell=True)` | Command injection | `subprocess.run(cmd, shell=True)` |
| Disabled TLS verification | MITM attacks | `verify=False` |
| Broad file permissions | Unauthorized access | `chmod 777` |

## Vulnerability Scoring

CVSS (Common Vulnerability Scoring System) rates vulnerabilities from 0.0 to 10.0:

- **Critical** (9.0-10.0): Exploit requires no authentication, full system compromise
- **High** (7.0-8.9): Significant impact, relatively easy to exploit
- **Medium** (4.0-6.9): Requires some conditions to exploit
- **Low** (0.1-3.9): Limited impact, difficult to exploit

## Further Reading

- OWASP Top Ten: https://owasp.org/www-project-top-ten/
- CWE/SANS Top 25: https://cwe.mitre.org/top25/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
