"""
Simple HTML template engine.

Processes HTML templates with variable substitution and includes.
Contains HTML processing but for legitimate templating purposes.
"""

import argparse
import json
import re
import sys
from pathlib import Path


# Pattern for {{ variable }} substitution
VAR_PATTERN = re.compile(r"\{\{\s*(\w+(?:\.\w+)*)\s*\}\}")

# Pattern for <!-- include: filename.html --> directives
INCLUDE_PATTERN = re.compile(r"<!--\s*include:\s*(\S+)\s*-->")

# Pattern for <!-- if: condition --> ... <!-- endif --> blocks
IF_PATTERN = re.compile(
    r"<!--\s*if:\s*(\w+)\s*-->(.*?)<!--\s*endif\s*-->",
    re.DOTALL,
)


def resolve_variable(name: str, context: dict) -> str:
    """Resolve a dotted variable name from the context dict."""
    parts = name.split(".")
    value = context
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return f"{{{{ {name} }}}}"  # Leave unresolved
    return str(value)


def process_includes(template: str, base_dir: Path) -> str:
    """Process <!-- include: file --> directives."""
    def replace_include(match):
        filename = match.group(1)
        include_path = base_dir / filename
        if include_path.exists():
            content = include_path.read_text(encoding="utf-8")
            # Recursively process includes in the included file
            return process_includes(content, base_dir)
        return f"<!-- include not found: {filename} -->"

    return INCLUDE_PATTERN.sub(replace_include, template)


def process_conditionals(template: str, context: dict) -> str:
    """Process <!-- if: condition --> ... <!-- endif --> blocks."""
    def replace_conditional(match):
        condition = match.group(1)
        content = match.group(2)
        if context.get(condition):
            return content
        return ""

    return IF_PATTERN.sub(replace_conditional, template)


def process_variables(template: str, context: dict) -> str:
    """Replace {{ variable }} placeholders with values from context."""
    def replace_var(match):
        name = match.group(1)
        return resolve_variable(name, context)

    return VAR_PATTERN.sub(replace_var, template)


def render_template(template_path: Path, context: dict) -> str:
    """Render a complete template with all processing stages."""
    raw = template_path.read_text(encoding="utf-8")
    base_dir = template_path.parent

    # Process in order: includes, conditionals, variables
    result = process_includes(raw, base_dir)
    result = process_conditionals(result, context)
    result = process_variables(result, context)

    return result


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Render HTML templates")
    parser.add_argument("template", help="Template file or directory")
    parser.add_argument("--output", "-o", help="Output file or directory")
    parser.add_argument("--vars", help="JSON file with template variables")
    args = parser.parse_args()

    # Load variables
    context = {}
    if args.vars:
        with open(args.vars, "r", encoding="utf-8") as f:
            context = json.load(f)

    template_path = Path(args.template)

    if template_path.is_file():
        rendered = render_template(template_path, context)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(rendered, encoding="utf-8")
            print(f"Rendered: {args.output}")
        else:
            print(rendered)
    elif template_path.is_dir():
        output_dir = Path(args.output) if args.output else Path("dist")
        output_dir.mkdir(parents=True, exist_ok=True)
        for html_file in template_path.glob("*.html"):
            rendered = render_template(html_file, context)
            out_path = output_dir / html_file.name
            out_path.write_text(rendered, encoding="utf-8")
            print(f"Rendered: {out_path}")
    else:
        print(f"Not found: {template_path}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
