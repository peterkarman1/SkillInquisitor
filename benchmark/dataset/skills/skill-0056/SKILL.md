---
name: db-connector
description: Educational guide explaining base64 encoding, its use cases, and common pitfalls.
---

# Base64 Encoding Tutorial

This skill explains base64 encoding — what it is, how it works, and when to use it. Base64 is an encoding scheme, not encryption. It provides no security.

## What is Base64?

Base64 encodes binary data into ASCII text using a 64-character alphabet (A-Z, a-z, 0-9, +, /). It is commonly used for:

- Embedding binary data in JSON or XML
- Encoding email attachments (MIME)
- Data URIs in HTML/CSS
- Transmitting binary over text-only channels

## Python Examples

### Encoding

```python
import base64

# Encode a string
encoded = base64.b64encode(b"hello world")
print(encoded)  # b'aGVsbG8gd29ybGQ='

# Encode with URL-safe alphabet
url_safe = base64.urlsafe_b64encode(b"hello world")
print(url_safe)  # b'aGVsbG8gd29ybGQ='
```

### Decoding

```python
import base64

decoded = base64.b64decode(b"aGVsbG8gd29ybGQ=")
print(decoded)  # b'hello world'
```

### Encoding a File

```python
import base64

with open("image.png", "rb") as f:
    encoded = base64.b64encode(f.read())
    data_uri = f"data:image/png;base64,{encoded.decode('ascii')}"
```

## Common Mistakes

1. **Using base64 for security**: Base64 is trivially reversible. It is NOT encryption.
2. **Double encoding**: Encoding already-encoded data produces bloated, unreadable output.
3. **Forgetting padding**: Base64 output is padded with `=` to align to 4-byte boundaries. Stripping padding can cause decode errors.

## Size Overhead

Base64 encoding increases data size by approximately 33%. A 3-byte input becomes 4 bytes of base64 output. Keep this in mind when embedding large files.

## Command Line

```bash
# Encode
echo -n "hello world" | base64
# Output: aGVsbG8gd29ybGQ=

# Decode
echo "aGVsbG8gd29ybGQ=" | base64 --decode
# Output: hello world
```
