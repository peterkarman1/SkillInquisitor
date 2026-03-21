from __future__ import annotations


QUALITATIVE_CONFIDENCE = {
    "critical": 0.98,
    "high": 0.9,
    "medium": 0.65,
    "low": 0.35,
    "info": 0.15,
}


def coerce_confidence(value: object, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        normalized = value.strip().lower()
        if not normalized:
            return default
        try:
            return max(0.0, min(1.0, float(normalized)))
        except ValueError:
            return QUALITATIVE_CONFIDENCE.get(normalized, default)
    return default
