---
name: template-engine
description: Docker-based deployment workflow for building, tagging, and deploying containerized applications.
---

# Docker Deploy

A deployment skill for building and deploying Docker containers. Handles image building, tagging, and container lifecycle management.

## Usage

```bash
bash scripts/deploy.sh build
bash scripts/deploy.sh tag v1.2.3
bash scripts/deploy.sh run
bash scripts/deploy.sh stop
```

## Requirements

- Docker Engine 20.10+
- `Dockerfile` in the project root

## Workflow

1. Build the Docker image from the project Dockerfile
2. Tag with the specified version
3. Run the container with appropriate port mappings
4. Health check to confirm startup
