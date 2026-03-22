---
name: curl-advanced
description: Advanced curl patterns for API interactions -- OAuth2 flows, multipart uploads, cookie handling, retries, SSL/TLS, timing metrics, parallel requests, and common mistakes.
---

# curl Advanced Usage

## POST Data Variants

Understanding the differences between `-d`, `--data-raw`, `--data-binary`, `--data-urlencode`, and `--json` is critical. Getting these wrong is one of the most common curl mistakes.

```bash
# -d / --data: sends application/x-www-form-urlencoded by default
# STRIPS newlines from file content when using @file
curl -d "key=value&other=123" https://api.example.com/form

# --data-raw: like -d but does NOT treat @ as a file reference
# Use this when your data literally starts with @
curl --data-raw '@not-a-file' https://api.example.com/endpoint

# --data-binary: sends data exactly as-is, preserving newlines and binary content
# Required for file uploads via POST body
curl --data-binary @payload.bin -H "Content-Type: application/octet-stream" \
  https://api.example.com/upload

# --data-urlencode: URL-encodes the value (but NOT the key)
curl --data-urlencode "query=hello world & goodbye" https://api.example.com/search
# Sends: query=hello%20world%20%26%20goodbye

# --json (curl 7.82+): shorthand that sets Content-Type AND Accept to application/json
# Equivalent to: -d '...' -H "Content-Type: application/json" -H "Accept: application/json"
curl --json '{"name":"alice","age":30}' https://api.example.com/users

# GOTCHA: -d sets Content-Type to application/x-www-form-urlencoded
# For JSON APIs, you MUST either use --json or add -H "Content-Type: application/json"
# Forgetting this is the #1 cause of "415 Unsupported Media Type" errors
```

## Shell Quoting Pitfalls

```bash
# WRONG: double quotes allow shell expansion
curl -d "{"name": "$USER"}" https://api.example.com/  # broken JSON

# RIGHT: single quotes prevent shell expansion
curl -d '{"name": "alice"}' https://api.example.com/

# Shell variables inside JSON -- use jq to build safely
curl --json "$(jq -n --arg name "$USERNAME" '{name: $name}')" \
  https://api.example.com/
```

## OAuth2 Flows

### Client Credentials Grant

```bash
# Step 1: Get access token
TOKEN_RESPONSE=$(curl -s -X POST https://auth.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=read write")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

# Step 2: Use the token
curl -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  https://api.example.com/resources
```

### Authorization Code Exchange (with PKCE)

```bash
# Generate PKCE verifier and challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=/+' | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')

# Exchange authorization code for tokens
curl -s -X POST https://auth.example.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=${AUTH_CODE}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "client_id=${CLIENT_ID}" \
  -d "code_verifier=${CODE_VERIFIER}"
```

### Refresh Token Flow

```bash
curl -s -X POST https://auth.example.com/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=${REFRESH_TOKEN}" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}"

# GOTCHA: some providers invalidate the old refresh token after use (rotation)
# Always store the new refresh_token from the response if present
```

## Multipart Form Uploads

```bash
# -F / --form sends multipart/form-data (NOT the same as -d)
# Use -F for file uploads and mixed form data

# Upload a file
curl -F "file=@/path/to/document.pdf" https://api.example.com/upload

# Upload with explicit content type
curl -F "file=@photo.png;type=image/png" https://api.example.com/upload

# Upload with custom filename (overrides local filename)
curl -F "file=@localfile.txt;filename=report.csv" https://api.example.com/upload

# Mix files and form fields
curl -F "title=Monthly Report" \
     -F "category=finance" \
     -F "attachment=@report.pdf" \
     -F "thumbnail=@preview.jpg;type=image/jpeg" \
     https://api.example.com/documents

# Upload from stdin
echo "inline content" | curl -F "file=@-;filename=data.txt" https://api.example.com/upload

# GOTCHA: -d and -F are mutually exclusive. Do NOT mix them.
# -d sends application/x-www-form-urlencoded
# -F sends multipart/form-data
# Using both in the same command produces unexpected behavior
```

## Cookie Handling

```bash
# Send a cookie (from string)
curl -b "session=abc123; lang=en" https://example.com/dashboard

# Save cookies to a file (cookie jar) after request
curl -c cookies.txt https://example.com/login -d "user=alice&pass=secret"

# Send cookies from a file in subsequent requests
curl -b cookies.txt https://example.com/dashboard

# Combined: load cookies from file AND save new/updated cookies back
curl -b cookies.txt -c cookies.txt https://example.com/dashboard

# GOTCHA: -b with a filename activates the cookie engine AND sends cookies
# -b with a raw string just sends the string as a Cookie header
# To activate the cookie engine with an empty jar, use: -b ""

# Cookie file format (Netscape format, tab-separated):
# domain  flag  path  secure  expiration  name  value
# .example.com  TRUE  /  TRUE  1735689600  session  abc123

# Start a new session (ignore session cookies from jar)
curl -b cookies.txt -c cookies.txt --junk-session-cookies https://example.com/
```

## Retry Semantics

```bash
# --retry N: retry up to N times on transient errors
# By default, retries only on: connection timeouts, HTTP 408, 429, 500, 502, 503, 504
curl --retry 3 https://api.example.com/data

# --retry-delay: fixed delay between retries (seconds)
curl --retry 5 --retry-delay 2 https://api.example.com/data

# --retry-max-time: total time limit for all retries (seconds)
curl --retry 10 --retry-max-time 60 https://api.example.com/data

# --retry-all-errors (curl 7.71+): retry on ANY error, not just transient ones
curl --retry 3 --retry-all-errors https://api.example.com/data

# GOTCHA: HTTP 4xx/5xx are NOT transfer errors by default
# curl only sees them as errors with --fail (-f)
# Without --fail, a 500 response is a "successful" transfer (curl exit code 0)
curl --fail --retry 3 https://api.example.com/data

# GOTCHA: --retry without --retry-all-errors does NOT retry connection refused,
# DNS failures, or most other network errors. Only specific HTTP codes and timeouts.
# Use --retry-all-errors for robust retry behavior.

# Respect Retry-After header (curl 7.66+)
curl --retry 3 --retry-delay 0 https://api.example.com/data
# When --retry-delay is 0, curl respects the server's Retry-After header
```

## SSL/TLS Options

```bash
# Skip certificate verification (DANGEROUS -- development only)
curl -k https://self-signed.example.com/

# Specify CA certificate bundle
curl --cacert /path/to/ca-bundle.crt https://api.example.com/

# Client certificate authentication (mutual TLS / mTLS)
curl --cert /path/to/client.crt --key /path/to/client.key https://api.example.com/

# Force specific TLS version
curl --tlsv1.2 https://api.example.com/      # minimum TLS 1.2
curl --tlsv1.3 https://api.example.com/      # minimum TLS 1.3

# GOTCHA: -k disables ALL certificate checks, including hostname verification
# Never use in production. For self-signed certs, add them to --cacert instead.
```

## HTTP/2 and HTTP/3

```bash
# HTTP/2 (most modern curl builds support this)
curl --http2 https://api.example.com/          # prefer HTTP/2, fall back to 1.1
curl --http2-prior-knowledge https://api.example.com/  # assume h2, skip upgrade

# HTTP/3 (requires curl built with HTTP/3 support -- nghttp3/ngtcp2 or quiche)
curl --http3 https://api.example.com/          # prefer HTTP/3 with fallback
curl --http3-only https://api.example.com/     # HTTP/3 only, no fallback

# Check if your curl supports HTTP/2 or HTTP/3
curl --version | grep -oE 'HTTP/[23]'
```

## Timing Metrics with --write-out

```bash
# Detailed timing breakdown
curl -o /dev/null -s -w "\
DNS Lookup:    %{time_namelookup}s\n\
TCP Connect:   %{time_connect}s\n\
TLS Handshake: %{time_appconnect}s\n\
TTFB:          %{time_starttransfer}s\n\
Total:         %{time_total}s\n\
Download Size: %{size_download} bytes\n\
HTTP Code:     %{response_code}\n" \
  https://api.example.com/

# All timing as JSON (curl 7.72+)
curl -o /dev/null -s -w '%{json}' https://api.example.com/ | jq .

# Get just the HTTP status code
HTTP_CODE=$(curl -o /dev/null -s -w "%{response_code}" https://api.example.com/)

# GOTCHA: -w output goes to stdout, same as response body
# Always use -o /dev/null to separate body from metrics
# Or use %{stderr} to redirect write-out to stderr:
curl -s -w "%{stderr}Code: %{response_code}\n" https://api.example.com/ > body.txt
```

## Parallel Requests (curl 7.66+)

```bash
# --parallel (-Z) runs multiple URLs concurrently
curl --parallel --parallel-max 10 \
  -o out1.json https://api.example.com/1 \
  -o out2.json https://api.example.com/2 \
  -o out3.json https://api.example.com/3

# With URL globbing
curl --parallel -o "page_#1.html" "https://example.com/page/[1-20]"

# GOTCHA: --parallel-max defaults to 50. For rate-limited APIs, set it lower.
```

## Following Redirects

```bash
# -L follows redirects (curl does NOT follow by default)
curl -L https://short.url/abc123

# Limit number of redirects (default is 50 with -L)
curl -L --max-redirs 5 https://example.com/

# Show redirect chain
curl -L -v https://short.url/abc123 2>&1 | grep -E "^(< HTTP|< [Ll]ocation)"

# GOTCHA: POST requests get converted to GET on 301/302 redirects (per HTTP spec)
# Use --post301 / --post302 / --post303 to preserve POST method
curl -L --post301 --post302 -d '{"data":1}' https://api.example.com/endpoint

# Or use 307/308 status codes server-side (they preserve the method by spec)
```

## Proxy Settings

```bash
# HTTP proxy
curl -x http://proxy.example.com:8080 https://api.example.com/

# SOCKS5 proxy (e.g., through SSH tunnel)
curl -x socks5://localhost:1080 https://api.example.com/
curl -x socks5h://localhost:1080 https://api.example.com/  # proxy does DNS resolution

# Proxy with authentication
curl -x http://proxy:8080 --proxy-user "user:password" https://api.example.com/

# Environment variables (curl respects these automatically)
export http_proxy=http://proxy:8080
export https_proxy=http://proxy:8080
export no_proxy=localhost,127.0.0.1,.internal.example.com

# GOTCHA: socks5:// vs socks5h:// -- the 'h' means DNS is resolved by the proxy
# Without 'h', DNS resolves locally, which defeats the purpose of some proxy setups
```

## Useful Patterns

```bash
# Health check: get just the status code
curl -o /dev/null -s -w "%{response_code}" --max-time 10 https://api.example.com/

# Download with resume support (-C - auto-detects offset)
curl -L -C - -o large-file.zip https://example.com/large-file.zip

# Save response body and headers separately
curl -s -D headers.txt -o body.json https://api.example.com/data
```

## Common Mistakes

1. **Forgetting `-H "Content-Type: application/json"` with `-d`.** The `-d` flag defaults to `application/x-www-form-urlencoded`. Use `--json` (curl 7.82+) or add the header explicitly.

2. **Using `-d` with `@file` when binary content matters.** `-d @file` strips newlines. Use `--data-binary @file` for faithful file content.

3. **Not using `--fail` with `--retry`.** Without `--fail`, HTTP error responses (4xx/5xx) are treated as successful transfers. curl will not retry them.

4. **Confusing `-F` and `-d`.** They use different Content-Types and encodings. `-F` is for file uploads (multipart/form-data). `-d` is for form fields or raw body data. Never mix them.

5. **Using `-k` in production.** This disables all certificate validation. Add your CA cert to `--cacert` instead.

6. **Quoting issues with shell variables in JSON.** Use `jq -n` to build JSON safely, or use `--json` with careful quoting.

7. **Expecting redirects to be followed automatically.** curl does NOT follow redirects unless you pass `-L`. This surprises people coming from browsers or libraries like Python requests.

8. **Not separating `-w` output from response body.** Use `-o /dev/null` or `-o file` to prevent the response body from mixing with `--write-out` output on stdout.
