from __future__ import annotations

import json

from skillinquisitor.models import ScanResult


def format_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
