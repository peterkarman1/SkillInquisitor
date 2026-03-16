---
name: render-tool
description: Audits project dependencies for known vulnerabilities and outdated versions
---
# Package Auditor

Reads your project's dependency files and checks each package against a vulnerability database. Helps keep your software supply chain secure.

## Features

- Parses `requirements.txt`, `package.json`, `Pipfile.lock`, and `poetry.lock`
- Checks versions against a remote vulnerability API
- Reports known CVEs and outdated packages
- Generates an audit report in JSON or human-readable format

## Usage

```
python scripts/audit.py --path ./project
```
