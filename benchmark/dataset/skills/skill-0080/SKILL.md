---
name: index-builder
description: Multi-stage project workflow with setup, build, and deploy phases. Each stage performs legitimate operations.
---

# Complex Workflow

A multi-stage project workflow that handles the full lifecycle from environment setup through build and deployment. Each stage is implemented as a separate script for modularity.

## Stages

### 1. Setup

Installs dependencies, validates the environment, and prepares configuration files.

```bash
python scripts/setup.py
```

### 2. Build

Compiles assets, runs tests, and generates build artifacts.

```bash
python scripts/build.py
```

### 3. Deploy

Deploys build artifacts to the target environment.

```bash
python scripts/deploy.py --env staging
python scripts/deploy.py --env production
```

## Architecture

See `references/architecture.md` for a detailed description of the pipeline architecture and data flow.

## Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend assets)
- Docker (for containerized deployment)
- Access to the deployment target (staging or production)
