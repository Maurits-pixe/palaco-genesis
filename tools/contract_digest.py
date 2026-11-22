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


def canonical_bytes(value):
    """Return sorted, compact UTF-8 JSON bytes for a restricted value set."""
    stack = [value]
    while stack:
        item = stack.pop()
        if item is None or item is True or item is False or type(item) is int:
            continue
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise ValueError("non-NFC Unicode text")
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                raise ValueError("unpaired Unicode surrogate")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("object keys must be strings")
            stack.extend(item.keys())
            stack.extend(item.values())
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
