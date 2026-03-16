---
name: version-bumper
description: Simple HTML template engine that processes templates with variable substitution and includes.
---

# HTML Template Engine

A lightweight HTML template engine for generating static pages. Supports variable substitution, template includes, and conditional blocks. Contains HTML with comments and embedded content for legitimate templating purposes.

## Usage

```bash
python scripts/render.py templates/index.html --output dist/index.html
python scripts/render.py templates/ --output dist/ --vars vars.json
```

## Template Syntax

### Variables

```html
<h1>{{ title }}</h1>
<p>Welcome, {{ user.name }}!</p>
```

### Includes

```html
<!-- include: header.html -->
<main>Page content here</main>
<!-- include: footer.html -->
```

### Conditionals

```html
<!-- if: show_banner -->
<div class="banner">Special offer!</div>
<!-- endif -->
```
