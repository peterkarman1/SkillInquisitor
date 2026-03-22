---
name: openssl-operations
description: Perform certificate and key operations with OpenSSL. Use when generating keys, creating CSRs, making self-signed certs, converting between PEM/DER/PKCS12, verifying certificate chains, inspecting certificates, testing TLS connections, or performing S/MIME signing and encryption.
---

# OpenSSL Operations

## Key Generation

### RSA Keys

Use `genpkey` (not the deprecated `genrsa`). The `genrsa` command outputs PKCS#1 format and defaults may be insecure. The `genpkey` command outputs PKCS#8 format and is the modern replacement.

```bash
# Correct: modern genpkey (PKCS#8 output)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key

# With passphrase protection
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -aes-256-cbc -out server.key

# Deprecated: avoid genrsa (PKCS#1 output, older defaults)
# openssl genrsa -out server.key 2048
```

Minimum 2048 bits for RSA. Use 4096 if longevity matters.

### ECDSA Keys

ECDSA keys use named curves, not arbitrary sizes. Two curves are widely supported for TLS:

```bash
# P-256 (recommended -- good security, best performance)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key

# P-384 (stronger but slower)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out server.key
```

Avoid the older `ecparam -genkey` approach -- it outputs SEC1 format with embedded parameters.

### Ed25519 Keys

Ed25519 does not use `-pkeyopt` -- the algorithm implies the curve and key size:

```bash
openssl genpkey -algorithm ed25519 -out server.key
```

### Extract Public Key

```bash
openssl pkey -in server.key -pubout -out server-public.key
```

Warning: forgetting `-pubout` silently outputs the private key instead.

## Certificate Signing Requests (CSR)

### Basic CSR

```bash
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Example Inc/CN=example.com"
```

### CSR with Subject Alternative Names (SAN)

Modern browsers require SAN -- the Common Name (CN) alone is not enough. Since OpenSSL 1.1.1, use `-addext` on the command line:

```bash
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=California/O=Example Inc/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com,IP:10.0.0.1"
```

For older OpenSSL or complex configs, use a config file:

```ini
# san.cnf
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
IP.1 = 10.0.0.1
```

```bash
openssl req -new -key server.key -out server.csr -config san.cnf
```

Inspect a CSR with `openssl req -in server.csr -text -noout -verify`. Always verify SANs appear in the output.

## Self-Signed Certificates

### One-Liner with SAN (OpenSSL 1.1.1+)

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -sha256 -days 365 -nodes \
  -subj "/C=US/O=Dev/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

The `-nodes` flag means "no DES" (no passphrase on the key). Without it, you will be prompted for a passphrase.

When using `-config` with `openssl req -x509`, you must also pass `-extensions v3_req` (or your section name) to apply SANs. This is a frequent source of "SAN missing" bugs:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout server.key -out server.crt -sha256 -days 365 -nodes \
  -config san.cnf -extensions v3_req
```

## Certificate Formats and Conversions

### Format Reference

| Format | Extension | Encoding | Contains | Notes |
|--------|-----------|----------|----------|-------|
| PEM | .pem, .crt, .cer, .key | Base64 (ASCII) | Cert, key, or both | Most common on Linux |
| DER | .der, .cer | Binary | Single cert or key | Common on Windows/Java |
| PKCS#12 | .p12, .pfx | Binary | Cert + key + chain | Import/export bundles |

PEM files start with `-----BEGIN CERTIFICATE-----` or `-----BEGIN PRIVATE KEY-----`. DER files are raw binary -- if you see readable headers, it is PEM.

### Conversions

```bash
# PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkey -in key.pem -outform DER -out key.der

# DER to PEM
openssl x509 -in cert.der -inform DER -outform PEM -out cert.pem

# PEM to PKCS#12 (cert + key + optional chain)
openssl pkcs12 -export -out bundle.p12 \
  -inkey server.key -in server.crt -certfile chain.pem

# PKCS#12 to PEM (extract parts separately)
openssl pkcs12 -in bundle.p12 -clcerts -nokeys -out cert.pem
openssl pkcs12 -in bundle.p12 -nocerts -nodes -out key.pem
openssl pkcs12 -in bundle.p12 -cacerts -nokeys -out chain.pem
```

OpenSSL 3.x changed the default cipher for PKCS#12 export. Older tools (Java keytool, Windows) may reject the file. Use `-legacy` if needed:

```bash
openssl pkcs12 -export -legacy -out bundle.p12 \
  -inkey server.key -in server.crt
```

## Inspecting Certificates

### View Certificate Details

```bash
openssl x509 -in server.crt -text -noout
```

Key fields to check:
- **Validity**: Not Before / Not After
- **Subject**: CN and other fields
- **Subject Alternative Name**: DNS names and IPs
- **Issuer**: who signed it
- **Key Usage / Extended Key Usage**: what operations are permitted

### View Specific Fields

```bash
openssl x509 -in server.crt -noout -dates              # Expiration
openssl x509 -in server.crt -noout -subject -issuer    # Subject/Issuer
openssl x509 -in server.crt -noout -fingerprint -sha256  # Fingerprint
```

### Check Key/Certificate Match

Compare the modulus (RSA) or public key hash to verify a private key matches a certificate:

```bash
# For RSA keys -- modulus must match
openssl x509 -in server.crt -noout -modulus | openssl sha256
openssl rsa -in server.key -noout -modulus | openssl sha256
openssl req -in server.csr -noout -modulus | openssl sha256
```

If the SHA-256 hashes are identical, the key, cert, and CSR all match. For ECDSA/Ed25519, compare the public key directly:

```bash
openssl x509 -in server.crt -pubkey -noout | openssl sha256
openssl pkey -in server.key -pubout | openssl sha256
```

## Certificate Chain Verification

```bash
# Simple verification against a CA bundle
openssl verify -CAfile ca-bundle.crt server.crt

# With intermediates: use -untrusted (NOT -CAfile) for intermediate certs
openssl verify -CAfile root-ca.crt -untrusted intermediate.crt server.crt
```

Common pitfall: putting intermediates in `-CAfile` masks chain-building problems. The `-untrusted` flag means "use for chain building but do not trust as a root" -- this matches what real TLS clients do.

## TLS Connection Testing

```bash
# Basic connection test (Ctrl+C to exit -- it waits for input)
openssl s_client -connect example.com:443

# With SNI (required for virtual hosts -- without it you get the default cert)
openssl s_client -connect example.com:443 -servername example.com

# Show full chain, force TLS version, verify against specific CA
openssl s_client -connect example.com:443 -showcerts
openssl s_client -connect example.com:443 -tls1_3
openssl s_client -connect example.com:443 -CAfile /path/to/ca-bundle.crt

# STARTTLS for mail servers
openssl s_client -connect mail.example.com:587 -starttls smtp
```

### Extract or Inspect Remote Certificate

```bash
# Download server cert to file
openssl s_client -connect example.com:443 -servername example.com \
  </dev/null 2>/dev/null | openssl x509 -outform PEM -out server.crt

# Check remote cert expiration
openssl s_client -connect example.com:443 -servername example.com \
  </dev/null 2>/dev/null | openssl x509 -noout -dates
```

The `</dev/null` prevents s_client from waiting for input. `2>/dev/null` suppresses connection info.

## S/MIME Operations

```bash
# Sign (use -text for MIME headers)
openssl smime -sign -in message.txt -out message.eml \
  -signer cert.pem -inkey key.pem -text

# Encrypt (recipient cert at end, not with -signer)
openssl smime -encrypt -aes-256-cbc -in message.txt \
  -out encrypted.eml -text recipient.crt

# Decrypt
openssl smime -decrypt -in encrypted.eml -out decrypted.txt \
  -recip recipient.crt -inkey recipient.key

# Verify
openssl smime -verify -in message.eml -CAfile ca-bundle.crt -out original.txt
```

Note: `openssl cms` is the newer replacement for `openssl smime` and supports CMS/PKCS#7 v3 features. Prefer `cms` for new work.

## Common Mistakes

1. **Using `genrsa` instead of `genpkey`**: `genrsa` is deprecated in OpenSSL 3.x and outputs PKCS#1 format. Use `genpkey` for PKCS#8 output and support for all key types.

2. **Missing SAN in certificates**: Modern browsers ignore CN for hostname validation. Always include subjectAltName.

3. **Wrong format assumptions**: A `.crt` file could be PEM or DER. Check with `file cert.crt` or try `openssl x509 -in cert.crt -text -noout` -- if it fails, add `-inform DER`.

4. **Putting intermediates in `-CAfile`**: This masks chain-building problems. Use `-untrusted` for intermediates, `-CAfile` for the root only.

5. **Forgetting `-nodes` in scripts**: Without it, OpenSSL prompts for a passphrase, hanging automated pipelines.

6. **PKCS#12 compatibility with OpenSSL 3.x**: The default cipher changed. Use `-legacy` when the consuming tool (Java keytool, older Windows) rejects the file.

7. **Forgetting `-servername` with s_client**: Without SNI, you get the server's default certificate, which may not match the domain you intended to test.

8. **Forgetting `-extensions` when using `-config`**: The config file defines extension sections, but `openssl req -x509 -config san.cnf` will not apply them unless you also pass `-extensions v3_req` (or whatever section name you used).
