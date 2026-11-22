#!/usr/bin/env python3
"""Deterministic, review-only digest for PALACO design-time JSON contracts.

PALACO-CJSON-v0 is a local convention, NOT RFC 8785 / JCS, and not a signature.
It intentionally refuses floating-point numbers and non-NFC strings rather than
silently choosing a potentially incompatible representation.
"""
import hashlib
import json
import unicodedata

try:
    from tools.strict_contract_json import load_strict_json
except ModuleNotFoundError:
    from strict_contract_json import load_strict_json

DOMAIN = b"PALACO-CJSON-v0\x00"
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_NESTING_DEPTH = 64


def canonical_bytes(value):
    """Return sorted, compact UTF-8 JSON bytes for a restricted value set."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if item is None or item is True or item is False:
            continue
        if type(item) is int:
            if abs(item) > MAX_SAFE_INTEGER:
                raise ValueError("integer outside interoperable safe range")
            continue
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise ValueError("non-NFC Unicode text")
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                raise ValueError("unpaired Unicode surrogate")
        elif isinstance(item, list):
            if depth >= MAX_NESTING_DEPTH:
                raise ValueError("JSON nesting depth exceeds limit")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            if depth >= MAX_NESTING_DEPTH:
                raise ValueError("JSON nesting depth exceeds limit")
            if any(not isinstance(key, str) for key in item):
                raise ValueError("object keys must be strings")
            stack.extend((key, depth + 1) for key in item.keys())
            stack.extend((child, depth + 1) for child in item.values())
        else:
            raise ValueError("unsupported canonical JSON value type")
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False,
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")


def digest_contract(value):
    """Domain-separated SHA-256 digest; integrity only, never authorization."""
    payload = canonical_bytes(value)
    return hashlib.sha256(
        DOMAIN + len(payload).to_bytes(8, "big") + payload
    ).hexdigest()


def digest_contract_file(path):
    """Use the bounded strict reader before canonicalization."""
    return digest_contract(load_strict_json(path))
