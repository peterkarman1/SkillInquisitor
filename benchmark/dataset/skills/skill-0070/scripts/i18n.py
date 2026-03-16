"""
Unicode and internationalization utilities.

Handles multilingual text processing including normalization,
script detection, and character analysis. Uses legitimate mixed
scripts for i18n purposes.
"""

import sys
import unicodedata


# Example strings for testing different scripts
SAMPLE_TEXTS = {
    "english": "Hello, world!",
    "russian": "\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440!",
    "chinese": "\u4f60\u597d\u4e16\u754c\uff01",
    "japanese": "\u3053\u3093\u306b\u3061\u306f\u4e16\u754c\uff01",
    "korean": "\uc548\ub155\ud558\uc138\uc694 \uc138\uacc4!",
    "arabic": "\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645!",
    "hindi": "\u0928\u092e\u0938\u094d\u0924\u0947 \u0926\u0941\u0928\u093f\u092f\u093e!",
    "thai": "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e0a\u0e32\u0e27\u0e42\u0e25\u0e01!",
    "hebrew": "\u05e9\u05dc\u05d5\u05dd \u05e2\u05d5\u05dc\u05dd!",
}


def normalize_text(text: str, form: str = "NFC") -> str:
    """
    Normalize Unicode text to the specified form.

    Forms:
      NFC  - Canonical Decomposition, followed by Canonical Composition
      NFD  - Canonical Decomposition
      NFKC - Compatibility Decomposition, followed by Canonical Composition
      NFKD - Compatibility Decomposition
    """
    if form not in ("NFC", "NFD", "NFKC", "NFKD"):
        raise ValueError(f"Unknown normalization form: {form}")
    return unicodedata.normalize(form, text)


def detect_scripts(text: str) -> dict[str, int]:
    """Detect which Unicode scripts are present in the text."""
    scripts: dict[str, int] = {}
    for char in text:
        if char.isspace() or unicodedata.category(char).startswith("P"):
            continue
        try:
            script = unicodedata.name(char).split()[0]
        except ValueError:
            script = "UNKNOWN"
        scripts[script] = scripts.get(script, 0) + 1
    return scripts


def char_info(text: str) -> list[dict]:
    """Get detailed Unicode information for each character."""
    result = []
    for char in text:
        try:
            name = unicodedata.name(char)
        except ValueError:
            name = "<unnamed>"
        result.append({
            "char": char,
            "codepoint": f"U+{ord(char):04X}",
            "name": name,
            "category": unicodedata.category(char),
            "bidirectional": unicodedata.bidirectional(char),
        })
    return result


def is_mixed_script(text: str) -> bool:
    """Check if text contains characters from multiple scripts."""
    scripts = detect_scripts(text)
    return len(scripts) > 1


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 3:
        print("Usage: i18n.py <normalize|detect-script|char-info> <text>")
        return 1

    command = sys.argv[1]
    text = sys.argv[2]

    if command == "normalize":
        form = sys.argv[3] if len(sys.argv) > 3 else "NFC"
        normalized = normalize_text(text, form)
        print(f"Input:      {text!r}")
        print(f"Normalized: {normalized!r} ({form})")
        print(f"Changed:    {text != normalized}")

    elif command == "detect-script":
        scripts = detect_scripts(text)
        print(f"Text: {text}")
        print("Scripts detected:")
        for script, count in sorted(scripts.items(), key=lambda x: -x[1]):
            print(f"  {script}: {count} character(s)")
        if is_mixed_script(text):
            print("Note: Text contains mixed scripts.")

    elif command == "char-info":
        info = char_info(text)
        for entry in info:
            print(
                f"  {entry['char']}  {entry['codepoint']:>8s}  "
                f"{entry['category']}  {entry['name']}"
            )

    else:
        print(f"Unknown command: {command}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
