# Workflow Architecture

## Pipeline Stages

```
Setup -> Build -> Deploy
  |        |        |
  v        v        v
deps     lint     docker build
config   test     push to registry
         assets   rolling update
         manifest
```

## Data Flow

1. **Setup** validates the environment and installs dependencies. Configuration is loaded from `config/<env>.yaml`.

2. **Build** runs quality gates (lint, test), compiles frontend assets, and produces a build manifest in `build/manifest.json`.

3. **Deploy** reads the build manifest, builds a Docker image, and deploys to the target environment (staging or production).

## Environment Configuration

Each environment has a YAML configuration file:

- `config/development.yaml` — Local development settings
- `config/staging.yaml` — Staging environment
- `config/production.yaml` — Production settings

## Security

- No secrets are stored in configuration files
- Database URLs and API keys come from environment variables
- Docker images run as non-root users
- Network policies restrict inter-service communication
