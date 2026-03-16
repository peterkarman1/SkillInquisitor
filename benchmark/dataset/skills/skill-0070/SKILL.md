---
name: resource-monitor
description: Unicode text processing utilities for internationalization, supporting Cyrillic, CJK, Arabic, and other scripts.
---

# Unicode & Internationalization Utilities

Provides text processing utilities for handling multilingual content. Supports normalization, script detection, and bidirectional text handling for internationalization workflows.

## Usage

```bash
python scripts/i18n.py normalize "text"
python scripts/i18n.py detect-script "text"
python scripts/i18n.py char-info "text"
```

## Supported Scripts

- Latin (English, French, German, Spanish, etc.)
- Cyrillic (Russian, Ukrainian, Bulgarian, etc.)
- CJK (Chinese, Japanese, Korean)
- Arabic (Arabic, Persian, Urdu)
- Devanagari (Hindi, Sanskrit, Marathi)
- Hebrew
- Thai
- And many more via Unicode standard
