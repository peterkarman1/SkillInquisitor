---
name: nginx-config
description: Configure nginx correctly -- covering location matching precedence, proxy_pass behavior, upstream blocks, SSL/TLS, rate limiting, caching, WebSocket proxying, and common pitfalls.
---

# Nginx Configuration

## Location Block Matching Precedence

Nginx evaluates location blocks in a specific order that does not depend on the order they appear in the config file (except for regex matches). The matching algorithm:

1. **Exact match `= /path`** -- checked first. If matched, processing stops immediately.
2. **Preferential prefix `^~ /path`** -- longest match wins. If matched, no regex locations are checked.
3. **Regex `~ /pattern` or `~* /pattern`** -- checked in config file order. First match wins. `~` is case-sensitive, `~*` is case-insensitive.
4. **Plain prefix `/path`** -- longest match wins. Only used if no regex matched.

### Example

```nginx
location = /api {
    # Only matches exactly /api, not /api/ or /api/users
    return 200 "exact";
}

location ^~ /static/ {
    # Matches /static/anything -- regex locations are skipped
    root /var/www;
}

location ~ \.php$ {
    # Matches any URI ending in .php
    fastcgi_pass 127.0.0.1:9000;
}

location / {
    # Default fallback -- matches everything
    proxy_pass http://backend;
}
```

### Critical Details

- `= /api` does NOT match `/api/` (trailing slash matters for exact matches).
- `^~` is not regex -- it means "if this prefix matches, skip regex locations."
- Regex locations are checked in config file order. Put specific patterns before general ones.
- Plain prefix locations: longest match wins regardless of config order.

## proxy_pass Trailing Slash Behavior

This is the single most confusing aspect of nginx configuration. Whether proxy_pass has a URI component (anything after the host:port, including just a `/`) completely changes how the request is forwarded.

### Rule: URI vs No URI

- **No URI** (`proxy_pass http://backend;`) -- the original request URI is passed through unchanged.
- **With URI** (`proxy_pass http://backend/;` or `proxy_pass http://backend/api/;`) -- the matching location prefix is stripped and replaced with the URI.

### Reference Table

| location      | proxy_pass                    | Request          | Upstream receives  |
|---------------|-------------------------------|------------------|--------------------|
| `/webapp/`    | `http://backend/api/`         | `/webapp/foo`    | `/api/foo`         |
| `/webapp/`    | `http://backend/api`          | `/webapp/foo`    | `/apifoo`          |
| `/webapp`     | `http://backend/api/`         | `/webapp/foo`    | `/api//foo`        |
| `/webapp`     | `http://backend/api`          | `/webapp/foo`    | `/api/foo`         |
| `/webapp/`    | `http://backend`              | `/webapp/foo`    | `/webapp/foo`      |

The safe pattern: match trailing slashes on both sides.

```nginx
# CORRECT -- slashes match
location /webapp/ {
    proxy_pass http://backend/api/;
}

# WRONG -- missing trailing slash on proxy_pass causes /apifoo
location /webapp/ {
    proxy_pass http://backend/api;
}
```

### proxy_pass with Variables

When you use variables in proxy_pass, nginx does NOT perform URI replacement at all. You must construct the full URI yourself:

```nginx
location ~ ^/webapp/(.*)$ {
    set $upstream http://backend;
    proxy_pass $upstream/api/$1$is_args$args;
}
```

This is useful when you want nginx to start even if the upstream is temporarily down (nginx resolves hostnames at startup and fails if they are unreachable, but variables defer resolution). However, variable-based proxy_pass requires a `resolver` directive:

```nginx
resolver 8.8.8.8 valid=30s;
```

## Upstream Block Configuration

```nginx
upstream backend {
    server 10.0.0.1:8080 weight=3 max_fails=3 fail_timeout=30s;
    server 10.0.0.2:8080 weight=1;
    server 10.0.0.3:8080 backup;
    keepalive 32;   # Idle keepalive connections per worker
}

server {
    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;      # Required for keepalive
        proxy_set_header Connection "";
    }
}
```

- `weight=N` -- relative weight for round-robin (default 1). Other methods: `least_conn`, `ip_hash`.
- `max_fails` / `fail_timeout` -- marks server unavailable after N failures within the timeout (default: 1 fail / 10s). `fail_timeout` also controls how long the server stays unavailable.
- `keepalive N` -- must be paired with `proxy_http_version 1.1` and clearing Connection.

## Common Proxy Headers

```nginx
proxy_set_header Host $host;                              # Original hostname
proxy_set_header X-Real-IP $remote_addr;                  # Client IP
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # IP chain
proxy_set_header X-Forwarded-Proto $scheme;               # HTTP or HTTPS
```

**Pitfall:** Without `Host $host`, the upstream receives the proxy_pass hostname (e.g., `backend`) instead of what the client used (e.g., `example.com`). This breaks virtual hosting and absolute URL generation.

## SSL/TLS Configuration

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers off;

    # HSTS (31536000 = 1 year)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/ssl/certs/chain.pem;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
}

# Redirect HTTP to HTTPS (use return, not rewrite)
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

## Rate Limiting

Nginx uses a leaky bucket algorithm. Define the zone in the `http` block, apply it in `location`:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    server {
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            limit_req_status 429;
            proxy_pass http://backend;
        }
    }
}
```

- `rate=10r/s` means 1 request per 100ms. Without `burst`, the second request within 100ms gets rejected.
- `burst=20` without `nodelay`: excess requests are queued and forwarded at the rate limit. The 20th waits 2 seconds.
- `burst=20 nodelay`: excess requests are forwarded immediately, but burst slots refill at the rate limit. This is usually what you want.
- `limit_req_status 429` returns 429 instead of the default 503.
- Two-stage limiting (nginx 1.15.7+): `burst=12 delay=8` handles the first 8 immediately, delays 9--12, rejects beyond 12.

## Caching

```nginx
http {
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m
                     max_size=1g inactive=60m use_temp_path=off;
    server {
        location /api/ {
            proxy_cache my_cache;
            proxy_cache_valid 200 302 10m;
            proxy_cache_valid 404 1m;
            add_header X-Cache-Status $upstream_cache_status;
            proxy_cache_key "$scheme$request_method$host$request_uri";
            proxy_pass http://backend;
        }
    }
}
```

- `keys_zone=name:size` -- shared memory for keys/metadata (1MB holds ~8,000 keys).
- `inactive=60m` -- items not accessed within this period are deleted regardless of freshness.
- `use_temp_path=off` -- writes directly to cache directory (avoids extra file copies).

## try_files for SPA Routing

SPAs need all routes to serve `index.html` so the client-side router can handle them:

```nginx
root /var/www/app;

location /api/ {
    proxy_pass http://backend;  # API routes handled separately
}

location / {
    try_files $uri $uri/ /index.html;
}
```

`try_files` checks arguments in order: try the exact file, try as directory, then fall back to `/index.html`. The `/api/` location takes precedence (longest prefix match) so API requests are not caught by the SPA fallback.

## WebSocket Proxying

Nginx does not pass `Upgrade` and `Connection` hop-by-hop headers by default. You must set them explicitly:

```nginx
# For dedicated WebSocket endpoints:
location /ws/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 86400s;   # WebSockets are long-lived
    proxy_send_timeout 86400s;
}
```

For mixed HTTP/WebSocket endpoints, use a `map` to set Connection conditionally:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

## root vs alias

`root` appends the location path; `alias` replaces it:

```nginx
location /static/ { root /var/www; }
# /static/img/logo.png -> /var/www/static/img/logo.png

location /static/ { alias /var/www/assets/; }
# /static/img/logo.png -> /var/www/assets/img/logo.png
```

Common mistakes: (1) Using `root /var/www/assets/` when you mean `alias` -- nginx looks for `/var/www/assets/static/...`. (2) Missing trailing slash on alias -- `alias /var/www/assets` produces `/var/www/assetsimg/...`. (3) With regex locations, alias requires a capture: `location ~ ^/static/(.*)$ { alias /var/www/assets/$1; }`.

## Common Mistakes

1. **Missing semicolons.** Every directive ends with `;`. Missing one produces a cryptic error pointing to the wrong line.
2. **Resolver for variables in proxy_pass.** Variables defer DNS resolution, but require a `resolver` directive or lookups silently fail.
3. **`if` is evil (mostly).** `if` in location blocks creates a separate internal request context. Use `map` and `try_files` instead.
4. **proxy_pass URI in named/regex locations.** You cannot include a URI in proxy_pass inside `@name` locations, regex locations, or `if` blocks.
5. **HTTPS upstream without verification.** `proxy_pass https://...` does NOT verify the upstream certificate. Set `proxy_ssl_verify on`.
6. **Buffer and body limits.** Large cookies/tokens need `proxy_buffer_size 16k;`. File uploads need `client_max_body_size 100m;` (default is 1MB).
7. **Always test before reload.** Run `nginx -t` before `nginx -s reload`.

