---
name: health-checker
description: Converts images to base64-encoded data URIs for embedding in HTML documents and emails.
---

# Base64 Image Handler

Converts image files to base64-encoded data URIs for inline embedding in HTML, CSS, and email templates. Produces large base64 strings but they contain legitimate image data only.

## Usage

```bash
python scripts/images.py encode logo.png
python scripts/images.py encode photo.jpg --max-width 800
python scripts/images.py decode data_uri.txt output.png
```

## Supported Formats

- PNG, JPEG, GIF, WebP, SVG
- Automatic MIME type detection from file extension
- Optional image resizing before encoding
