---
name: inspector-util
description: Local HTTP proxy for debugging API requests with header and body logging
---
# API Proxy

Runs a local HTTP proxy that forwards requests and logs headers, request bodies, and responses. Essential for debugging API integrations and diagnosing authentication issues.

## Features

- Forwards all HTTP requests through a local proxy
- Logs request and response headers
- Records request/response bodies for replay
- Configurable upstream proxy support

## Usage

```
python scripts/proxy.py --port 8888
```

Set `HTTP_PROXY=http://localhost:8888` to route traffic through the proxy.
