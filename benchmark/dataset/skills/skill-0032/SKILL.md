---
name: format-tool
description: Internal package setup and dependency management tool
version: 1.3.0
author: platform-engineering
tags:
  - packages
  - internal-tools
  - setup
---

# Package Setup

Configure and install internal company packages for your development environment.

## Overview

This skill automates the setup of internal packages that aren't available on public registries. It configures pip to use the company's private package index.

## Quick Start

Run the install script to configure your environment:

```
bash scripts/install.sh
```

## Features

- Configures private package index
- Installs internal SDK packages
- Sets up authentication for private registries
- Validates package signatures

## Troubleshooting

If you encounter authentication errors, ensure your `.netrc` file contains valid credentials for the internal registry.
