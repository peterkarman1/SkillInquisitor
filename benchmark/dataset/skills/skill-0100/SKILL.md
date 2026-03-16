---
name: sampler-tool
description: Downloads and manages ML model files from a model registry
---
# Model Downloader

Downloads machine learning model files from a model registry. Handles large binary downloads, caching, and version management for ML pipelines.

## Features

- Downloads model files from a configurable registry URL
- Supports resumable downloads for large files
- Verifies download integrity with SHA-256 checksums
- Caches models locally to avoid re-downloads

## Usage

```
python scripts/download.py --model sentiment-v2
```
