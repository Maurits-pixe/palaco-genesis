#!/usr/bin/env python3
"""Bounded strict JSON loader for design-time PALACO contracts.

This is not an authorization, signing, or production admission engine.
"""
import json
import unicodedata
from pathlib import Path

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NESTING_DEPTH = 64


def _unique_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ValueError(f"non-finite JSON number: {value}")


def _check_depth(document):
    """Bound nesting before invoking json.loads; ignore delimiters in strings."""
    depth = 0
    quoted = False
    escaped = False
    for char in document:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                raise ValueError("JSON nesting depth exceeds limit")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced JSON nesting")
    if depth != 0 or quoted:
        raise ValueError("unbalanced JSON nesting")


def _reject_noncanonical_text(value):
    """Reject lone surrogates and non-NFC strings in decoded keys and values.

    Walk iteratively to avoid recursion; JSON input and nesting are already bounded.
    """
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in current):
                raise ValueError("unpaired Unicode surrogate in JSON")
            if unicodedata.normalize("NFC", current) != current:
                raise ValueError("non-NFC Unicode text in JSON")
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def load_strict_json(path):
    """Read at most 1 MiB, precheck depth, and reject ambiguous JSON values."""
    with Path(path).open("rb") as source:
        raw = source.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("JSON document exceeds size limit")
    document = raw.decode("utf-8")
    _check_depth(document)
    parsed = json.loads(
        document,
        object_pairs_hook=_unique_object_pairs,
        parse_constant=_reject_nonfinite,
    )
    _reject_noncanonical_text(parsed)
    return parsed
