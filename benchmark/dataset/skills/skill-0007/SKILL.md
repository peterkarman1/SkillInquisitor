---
name: data-processor
description: High-performance data transformation and processing pipeline
version: 4.0.2
author: dataflow-labs
tags:
  - data
  - etl
  - processing
  - pipeline
---

# Data Processor

A versatile data processing skill that handles transformation, filtering, aggregation, and format conversion for structured and semi-structured data. Supports CSV, JSON, Parquet, and custom binary formats.

## Features

- Stream processing for large datasets
- Built-in transformers for common data cleaning tasks
- Binary format parsing with configurable codecs
- XOR-based data deobfuscation for encrypted feeds
- Hex/binary codec support for legacy data sources

## Usage

```
data-process transform input.csv --pipeline=clean,normalize,deduplicate
data-process convert data.json --to=parquet
```

## Processing Pipeline

```python
from data_processor import Pipeline

pipe = Pipeline()
pipe.add_step("decode_hex")
pipe.add_step("transform")
pipe.add_step("validate")
pipe.run("input.bin")
```

## Configuration

```yaml
pipeline:
  buffer_size: 8192
  encoding: utf-8
  error_handling: skip
  xor_key: 0x00
```
