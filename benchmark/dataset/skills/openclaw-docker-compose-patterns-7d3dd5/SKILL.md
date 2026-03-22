---
name: docker-compose-patterns
description: Write correct and production-ready Docker Compose files. Use when configuring multi-container applications, setting up healthchecks and dependency ordering, managing volumes and networks, handling environment variables, writing dev/prod overrides, or configuring resource limits and service profiles.
---

# Docker Compose Patterns

## Healthchecks and Dependency Ordering

### Healthcheck Syntax

```yaml
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 3s
      retries: 5
      start_period: 10s
```

Use `CMD-SHELL` when you need shell features (`||`, pipes). Use `CMD` for direct exec. The `start_period` is a grace period during which failures do not count toward retries -- set it long enough for initialization.

### depends_on with Conditions

Plain `depends_on` only waits for the container to start, not for the service to be ready:

```yaml
services:
  app:
    build: .
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
      migrations:
        condition: service_completed_successfully
```

Conditions: `service_started` (default), `service_healthy` (healthcheck passing), `service_completed_successfully` (exited 0 -- useful for migrations).

Common mistake: `depends_on: [db]` (short form) only waits for the container to exist, not for the service to accept connections. Always use `condition: service_healthy` for databases.

## Volumes

### Named Volumes vs Bind Mounts

```yaml
services:
  app:
    volumes:
      - app-data:/var/lib/app/data             # Named volume (Docker-managed)
      - ./src:/app/src                          # Bind mount (host directory)
      - ./config/nginx.conf:/etc/nginx/nginx.conf:ro  # Read-only bind
      - type: tmpfs                             # In-memory, never hits disk
        target: /tmp
volumes:
  app-data:                                     # Must declare named volumes here
```

Named volumes are Docker-managed, portable, and pre-populated from the image. Bind mounts map host paths directly and host content wins over image content. Prefer named volumes for database data in production -- bind mounts risk accidental deletion by host cleanup.

## Networks

```yaml
services:
  app:
    networks:
      frontend:
      backend:
        aliases:
          - api-service
  db:
    networks:
      backend:

networks:
  frontend:
  backend:
    internal: true    # No external access
```

Compose creates a default `{project}_default` network that all services join. Custom networks are only needed for isolation. Services on different networks cannot communicate. The `internal: true` flag blocks internet access from that network. Network aliases let services be reached by names other than the service name.

## Environment Variables

Precedence (highest first): shell/CLI > `environment` in compose > `env_file`.

```yaml
services:
  app:
    env_file: [.env, .env.local]     # .env.local overrides .env
    environment:
      DB_HOST: postgres              # Overrides env_file
      API_KEY:                       # Pass-through from host (no value = inherit)
```

### Variable Substitution

Substitution happens at compose parse time using the **host** environment, not inside the container:

```yaml
services:
  app:
    image: myapp:${TAG:-latest}
    environment:
      DB_HOST: ${DB_HOST:?DB_HOST must be set}
      LOG_LEVEL: ${LOG_LEVEL:-info}
```

| Syntax | Meaning |
|--------|---------|
| `${VAR:-default}` | Value of VAR, or `default` if unset/empty |
| `${VAR:?error}` | Value of VAR, or exit with error if unset/empty |

Common mistake with `.env` files: `PASSWORD="secret"` includes the literal quotes. Write `PASSWORD=secret`.

## Build Configuration

### Build Context, Args, and Multi-Stage Targets

```yaml
services:
  app:
    build:
      context: .
      dockerfile: docker/Dockerfile.prod
      args:
        NODE_VERSION: "20"
      target: production        # Stops at the named stage
      cache_from:
        - myapp:latest
```

Multi-stage Dockerfile pattern -- keep build tools out of the final image:

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS production
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
CMD ["node", "dist/index.js"]
```

Common mistake: forgetting `docker compose up --build` after Dockerfile changes. Plain `docker compose up` reuses the cached image.

### Dockerfile Cache Invalidation

Copy dependency files first, install, then copy source. This way code changes do not invalidate the install layer:

```dockerfile
COPY package*.json ./
RUN npm ci
COPY . .             # Only this layer rebuilds on source changes
```

## Profiles

Profiles define optional services that only start when activated:

```yaml
services:
  app:
    build: .
    # No profile -- always starts
  debug-tools:
    image: busybox
    profiles: [debug]
  monitoring:
    image: prometheus
    profiles: [monitoring, production]
```

```bash
docker compose up                          # Only non-profiled services
docker compose --profile debug up          # Default + debug
docker compose --profile debug --profile monitoring up
```

Common mistake: adding a profile to a service that non-profiled services depend on. If `app` depends on `db` and `db` has a profile, `app` fails unless that profile is activated.

## Extending Services

### YAML Anchors and Aliases

YAML anchors reduce duplication within a single file. Use the `x-` prefix for extension fields (Compose ignores them):

```yaml
x-common: &common
  restart: unless-stopped
  logging:
    driver: json-file
    options:
      max-size: "10m"
      max-file: "3"

services:
  app:
    <<: *common
    build: .
  worker:
    <<: *common
    build: .
    command: ["node", "worker.js"]
```

Without the `x-` prefix, Compose tries to parse extension fields as service definitions and fails.

### The `extends` Keyword

For sharing across files, a service can `extends` from another file: `extends: { file: common.yaml, service: base }`. Limitations: does not inherit `depends_on`, `networks`, or `volumes`, and no chaining (extended service cannot itself use `extends`).

## Dev vs Production Overrides

Compose auto-merges `docker-compose.override.yml` on top of `docker-compose.yml`. Use this for dev settings (bind mounts, debug ports). For production, use explicit files:

```bash
docker compose up                                    # Loads base + override
docker compose -f docker-compose.yml -f prod.yml up  # Explicit (skips override)
```

Merge rules: scalars are replaced, lists (like `ports`) are appended.

## Resource Limits

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 512M
        reservations:
          cpus: "0.5"
          memory: 256M
```

`deploy.resources` works with `docker compose up` (no Swarm needed). Other `deploy` fields like `replicas` are ignored outside Swarm.

## Init Containers Pattern

Use `service_completed_successfully` for one-shot setup tasks:

```yaml
services:
  migrate:
    build: .
    command: ["python", "manage.py", "migrate"]
    depends_on:
      db: { condition: service_healthy }
  app:
    build: .
    depends_on:
      migrate: { condition: service_completed_successfully }
      db: { condition: service_healthy }
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 3s
      retries: 5
      start_period: 10s
```

## Common Mistakes

1. **`depends_on` without `condition`**: Short form `depends_on: [db]` only ensures start order, not readiness. Use `condition: service_healthy`.

2. **Forgetting `--build`**: `docker compose up` reuses cached images. Use `--build` after Dockerfile changes.

3. **Quoted `.env` values**: `PASSWORD="secret"` includes the literal quotes. Write `PASSWORD=secret`.

4. **Mixed tabs/spaces in YAML**: Causes parse errors. Use spaces only.

5. **Missing volume declarations**: Named volumes must be declared in the top-level `volumes` key.

6. **Profiled dependencies**: A non-profiled service depending on a profiled service fails unless the profile is active.

7. **Host vs container variable substitution**: `${VAR:-default}` resolves at compose parse time from the host environment, not at container runtime.

8. **Dockerfile layer ordering**: Copy lock files and install deps before copying source, or every code change triggers a full reinstall.
