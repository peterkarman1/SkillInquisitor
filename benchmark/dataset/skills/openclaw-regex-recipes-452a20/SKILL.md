---
name: regex-recipes
description: Write correct, efficient regular expressions -- covering lookaheads/lookbehinds, named groups, non-greedy quantifiers, catastrophic backtracking, and practical patterns for validation and parsing.
---

# Regex Recipes

## Lookahead and Lookbehind

Lookaheads and lookbehinds assert that a pattern exists (or does not exist) at a position without consuming characters. They do not advance the match pointer.

### Positive Lookahead `(?=...)`

Match `foo` only if followed by `bar`:

```regex
foo(?=bar)
```

Matches `foo` in `foobar`, but not in `foobaz`. The matched text is only `foo` -- `bar` is not consumed.

### Negative Lookahead `(?!...)`

Match `foo` only if NOT followed by `bar`:

```regex
foo(?!bar)
```

Matches `foo` in `foobaz`, but not in `foobar`.

### Positive Lookbehind `(?<=...)`

Match `bar` only if preceded by `foo`:

```regex
(?<=foo)bar
```

### Negative Lookbehind `(?<!...)`

Match `bar` only if NOT preceded by `foo`:

```regex
(?<!foo)bar
```

### Lookbehind Length Restrictions

Python's `re` module requires lookbehinds to be fixed-width. Variable-length lookbehinds like `(?<=a+)b` will raise an error. Use the `regex` third-party module for variable-length lookbehinds, or restructure the pattern.

JavaScript has supported variable-length lookbehinds since ES2018, but older environments do not.

## Named Capturing Groups

Named groups improve readability and maintainability over numbered groups.

### Syntax Varies by Language

| Language   | Named Group             | Backreference         |
|-----------|------------------------|-----------------------|
| Python    | `(?P<name>...)`        | `(?P=name)` or `\g<name>` in replacement |
| JavaScript| `(?<name>...)`         | `\k<name>`            |
| Go (RE2)  | `(?P<name>...)`        | No backreferences     |
| Java      | `(?<name>...)`         | `\k<name>`            |
| .NET      | `(?<name>...)` or `(?'name'...)` | `\k<name>` |
| Perl/PCRE | `(?P<name>...)` or `(?<name>...)` | `\k<name>` or `(?P=name)` |

### Python Example

```python
import re

pattern = r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})'
m = re.match(pattern, '2025-03-15')
print(m.group('year'))   # '2025'
print(m.group('month'))  # '03'
```

### JavaScript Example

```javascript
const pattern = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/;
const m = '2025-03-15'.match(pattern);
console.log(m.groups.year);  // '2025'
console.log(m.groups.month); // '03'
```

### Pitfall: Mixing Named and Numbered Groups

Avoid mixing named and unnamed groups. In .NET, unnamed groups are numbered first (left to right), then named groups get subsequent numbers. In Python, both are numbered left to right together. This inconsistency makes cross-language regex harder to port. Use `(?:...)` for groups you do not need to capture.

## Non-Greedy (Lazy) Quantifiers

By default, `*`, `+`, and `?` are greedy -- they match as much as possible. Appending `?` makes them lazy -- they match as little as possible.

| Greedy | Lazy  | Meaning                        |
|--------|-------|--------------------------------|
| `*`    | `*?`  | Zero or more, prefer fewer     |
| `+`    | `+?`  | One or more, prefer fewer      |
| `?`    | `??`  | Zero or one, prefer zero       |
| `{n,m}`| `{n,m}?` | Between n and m, prefer fewer |

### When Lazy Is Wrong

A common mistake is using `.*?` to match "anything between delimiters":

```regex
".*?"
```

This works for simple cases but fails on strings with escaped quotes: `"hello \"world\""`. A better pattern uses a negated class or accounts for escapes:

```regex
"([^"\\]|\\.)*"
```

This matches either a non-quote/non-backslash character OR a backslash followed by anything. It handles escaped quotes correctly and is also more efficient because it cannot backtrack catastrophically.

## Catastrophic Backtracking

This is the single most dangerous regex problem. It occurs when nested quantifiers allow exponentially many ways to match the same input.

### The Classic Pathological Pattern

```regex
(a+)+b
```

Against the input `aaaaaaaaaaaaaac` (no `b`), the engine tries every possible way to partition the `a`s among the inner and outer groups before concluding there is no match. With n `a`s, this takes O(2^n) steps.

### Real-World Example: CSV Field Matching

```regex
^(.*?,){11}P
```

This tries to match 11 comma-delimited fields before checking for `P`. The problem is that `.*?` can match commas too, so the engine tries exponentially many ways to distribute commas among the 11 groups when the match fails.

The fix is to be specific about what a field contains:

```regex
^([^,\r\n]*,){11}P
```

Now each field is `[^,\r\n]*` -- it cannot match commas, so there is exactly one way to partition the input. Backtracking is linear.

### How to Prevent It

1. **Make alternatives mutually exclusive.** If tokens in nested repetitions cannot overlap, backtracking is linear. `(a+b+|c+d+)+` is safe because `a`, `b`, `c`, `d` do not overlap.

2. **Use negated character classes instead of `.`** when you know the delimiter. `[^,]*` instead of `.*?` for CSV fields. `[^"]*` instead of `.*?` between quotes.

3. **Atomic groups `(?>...)`** lock in a match and discard backtracking positions. Supported in Perl, PCRE, Java, .NET, Ruby. Not in Python `re` or JavaScript.

4. **Possessive quantifiers `*+`, `++`** are shorthand for atomic groups around a single quantifier. `a++` is equivalent to `(?>a+)`. Supported in Java, Perl, PCRE, PHP. Not in Python `re` or JavaScript.

5. **Set a timeout** in production code. Python: use `regex` module with `timeout` parameter. .NET: pass `TimeSpan` to `Regex` constructor. Java: interrupt the thread.

### Red Flags to Watch For

- Nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`
- Overlapping alternatives inside repetition: `(a|a)+`
- Lazy dot with multiple repetitions: `(.*?X){n}` where the separator X could also be matched by `.`

## Multiline vs DOTALL (Single-Line)

These flags are frequently confused because of unfortunate naming.

| Flag | Python | JavaScript | Effect |
|------|--------|-----------|--------|
| Multiline | `re.MULTILINE` or `(?m)` | `/m` | `^` and `$` match at line boundaries, not just string start/end |
| DOTALL | `re.DOTALL` or `(?s)` | `/s` | `.` matches newlines too (normally it does not) |

These are independent flags. You can use both, either, or neither.

```python
import re

text = "line1\nline2\nline3"

# Without MULTILINE: ^ matches only start of string
re.findall(r'^line\d', text)                      # ['line1']

# With MULTILINE: ^ matches start of each line
re.findall(r'^line\d', text, re.MULTILINE)        # ['line1', 'line2', 'line3']

# Without DOTALL: . does not match newline
re.findall(r'line1.line2', text)                   # []

# With DOTALL: . matches newline
re.findall(r'line1.line2', text, re.DOTALL)        # ['line1\nline2']
```

## Word Boundaries `\b`

`\b` matches the position between a word character (`\w` = `[a-zA-Z0-9_]`) and a non-word character.

### Common Pitfalls

1. **`\b` does not match a character** -- it matches a position. `\bfoo\b` in `foo bar` matches `foo`, but `\b` itself is zero-width.

2. **Hyphens are not word characters.** `\bwell-known\b` matches because `-` is a non-word character, so there is a word boundary between `l` and `-`, and between `-` and `k`. The pattern matches `well-known` as expected, but `\bwell-known\b` will also match `well-known` inside `well-knownly`.

3. **Non-ASCII / Unicode.** In Python `re` without the `re.UNICODE` flag (Python 2) or in JavaScript without the `/u` flag, `\b` only considers ASCII letters as word characters. Accented characters like `e` are treated as non-word characters, so `\bcafe\b` matches `cafe` inside `cafeteria` in some engines. In Python 3, `\w` is Unicode-aware by default.

## Verbose Mode (`re.VERBOSE` / `x` flag)

Use verbose mode for complex patterns. Whitespace is ignored (use `\ ` or `[ ]` for literal spaces) and `#` starts a comment.

```python
import re

pattern = re.compile(r"""
    (?P<protocol>https?://)        # Protocol
    (?P<domain>[^/\s]+)            # Domain name
    (?P<path>/[^\s?]*)?            # Optional path
    (?:\?(?P<query>[^\s]*))?       # Optional query string
""", re.VERBOSE)
```

## Practical Recipes

### Semantic Version

```regex
^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$
```

Key points: major/minor/patch must not have leading zeros (except `0` itself). Pre-release and build metadata are optional.

### IPv4 Address

```regex
^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$
```

Common mistake: using `\d{1,3}` which matches `999.999.999.999`. Each octet must be 0--255.

### URL (Basic)

Do not try to write a single regex that validates all URLs per the RFC. For practical extraction:

```regex
https?://[^\s<>"']+
```

For structured parsing, use `urllib.parse` (Python) or `new URL()` (JavaScript).

### Email (Practical)

Full RFC 5322 compliance requires a regex that is hundreds of characters long and still does not cover all edge cases (quoted local parts, IP literals, comments). For practical validation:

```regex
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
```

This rejects some technically valid addresses (e.g., `"user name"@example.com`) but covers 99.9% of real-world email addresses. For true validation, send a confirmation email.

## Common LLM and Developer Mistakes

1. **Forgetting to escape dots.** `example.com` matches `exampleXcom`. Use `example\.com`.

2. **Wrong anchoring.** `\d{3}-\d{4}` matches `555-1234` but also matches inside `1555-12345`. Use `^\d{3}-\d{4}$` or `\b\d{3}-\d{4}\b` for exact matching.

3. **Backslash handling in strings.** In Python, always use raw strings (`r"..."`) for regex patterns. Without raw strings, `\b` is the backspace character, not a word boundary. `"\bword\b"` is `<backspace>word<backspace>`.

4. **Assuming `.` matches newlines.** By default it does not. Use `re.DOTALL` or `[\s\S]` as a cross-language alternative.

5. **Using `re.match` when `re.search` is needed.** `re.match` only matches at the start of the string. `re.search` finds a match anywhere. This is a Python-specific trap.

6. **Greedy matching across delimiters.** `<.*>` on `<a>foo</a>` matches the entire string, not just `<a>`. Use `<[^>]*>` or `<.*?>`.

7. **Character class misunderstandings.** Inside `[...]`, most special characters lose their meaning. `[.]` matches a literal dot, not any character. But `^` at the start negates, `-` between characters is a range, and `\` still escapes.

