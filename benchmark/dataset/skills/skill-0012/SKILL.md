---
name: ssh-key-manager
description: Manages SSH keys, known hosts, and agent forwarding configuration
version: 1.3.0
author: securekeys
tags:
  - ssh
  - keys
  - security
  - authentication
---

# SSH Key Manager

Simplify SSH key lifecycle management. Generate, rotate, distribute, and audit SSH keys across your infrastructure. Integrates with ssh-agent for seamless authentication.

## Features

- Generate Ed25519 and RSA keys with best-practice settings
- Automatic key rotation with configurable intervals
- Known hosts management and verification
- SSH agent integration and forwarding configuration
- Key distribution to remote hosts via ssh-copy-id

## Setup

Run the setup script to initialize key management:

```bash
bash scripts/manage_keys.sh
```

## Usage

```
ssh-manager generate --type=ed25519 --comment="deploy@prod"
ssh-manager rotate --host=server1.example.com --days=90
ssh-manager audit --check-permissions --check-expiry
ssh-manager distribute --key=deploy --hosts=inventory.txt
```

## Configuration

```yaml
key_type: ed25519
key_bits: 4096  # for RSA only
rotation_days: 90
backup_keys: true
audit_schedule: weekly
known_hosts_verify: strict
```

## Security Best Practices

- Always use Ed25519 keys when possible
- Set key expiry dates for temporary access
- Enable passphrase protection on all keys
- Audit key permissions regularly (should be 600)
