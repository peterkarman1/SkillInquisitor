---
name: encoder-utility
description: Multi-format encoding and decoding utility for data transformation
version: 2.1.0
author: codec-tools
tags:
  - encoding
  - base64
  - hex
  - codec
---

# Encoder Utility

A comprehensive encoding and decoding skill supporting base64, hex, URL encoding, HTML entities, and chained transformations. Useful for debugging encoded payloads and data format conversion.

## Features

- Base64, hex, URL, and HTML entity encoding/decoding
- Chained transformations (e.g., hex -> base64 -> URL)
- File and stdin input support
- Automatic encoding detection
- Round-trip verification

## Usage

```
encode base64 "Hello, World!"
decode hex "48656c6c6f"
encode chain "hex,base64" input.txt
```

## Chaining Example

```python
from encoder import Chain

chain = Chain(["hex_decode", "base64_decode"])
result = chain.run(encoded_data)
```

## Configuration

```yaml
default_encoding: utf-8
verify_roundtrip: true
chain_max_depth: 5
output_format: raw
```
