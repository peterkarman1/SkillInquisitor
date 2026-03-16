---
name: plugin-loader
description: Shell-based API client using curl for interacting with REST APIs with proper authentication headers.
---

# Curl API Client

A lightweight shell-based REST API client using `curl`. Demonstrates proper authentication, error handling, and response parsing for API interactions.

## Usage

```bash
# Fetch data from an API
bash scripts/client.sh get /users

# Create a resource
bash scripts/client.sh post /users '{"name": "Alice"}'
```

## Configuration

Set the following environment variables:

- `API_BASE_URL` — Base URL (default: `https://api.example.com`)
- `API_TOKEN` — Bearer token for authentication

## Features

- Proper Authorization header handling
- JSON content-type headers
- HTTP status code checking
- Response pretty-printing with `jq`
