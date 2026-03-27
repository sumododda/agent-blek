from __future__ import annotations

import os


def resolve_api_key(value: str) -> str | None:
    if not value:
        return None
    if value.startswith("${") and value.endswith("}"):
        return os.environ.get(value[2:-1])
    return value
