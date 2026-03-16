---
name: cache-manager
description: Guide for setting up and managing SSH keys for secure remote access and Git authentication.
---

# SSH Key Setup Guide

This skill provides instructions for generating, configuring, and managing SSH keys for development workflows.

## Generating a New SSH Key

Use `ssh-keygen` to create a new key pair:

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

When prompted, save to the default location `~/.ssh/id_ed25519`. Optionally set a passphrase for additional security.

For legacy systems that don't support Ed25519:

```bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

This creates `~/.ssh/id_rsa` (private key) and `~/.ssh/id_rsa.pub` (public key).

## SSH Directory Structure

```
~/.ssh/
├── id_ed25519       # Private key (NEVER share this)
├── id_ed25519.pub   # Public key (safe to share)
├── id_rsa           # Legacy RSA private key
├── id_rsa.pub       # Legacy RSA public key
├── known_hosts      # Verified host fingerprints
├── authorized_keys  # Keys allowed to log in (server-side)
└── config           # SSH client configuration
```

## SSH Config File

Create `~/.ssh/config` to manage multiple hosts:

```
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519

Host production
    HostName prod.example.com
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    Port 22
```

## Adding Keys to the SSH Agent

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

## Adding Your Public Key to GitHub

1. Copy your public key: `cat ~/.ssh/id_ed25519.pub`
2. Go to GitHub Settings > SSH and GPG keys
3. Click "New SSH key" and paste the public key
4. Test the connection: `ssh -T git@github.com`

## Security Best Practices

- Always use a passphrase on your private keys
- Use Ed25519 keys instead of RSA where possible
- Set correct permissions: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_*`
- Never share or commit private keys
- Rotate keys periodically
- Use SSH certificates for large teams
