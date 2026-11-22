#!/usr/bin/env python3
"""Strict JSON loader for PALACO design-time contracts (not an authority engine)."""
import json
from pathlib import Path


def _unique_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ValueError(f"non-finite JSON number: {value}")


def load_strict_json(path):
    """Reject duplicate keys and non-standard numeric constants at all depths."""
    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object_pairs,
        parse_constant=_reject_nonfinite,
    )
