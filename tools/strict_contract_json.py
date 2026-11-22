#!/usr/bin/env python3
"""Bounded strict JSON loader for design-time PALACO contracts.

This is not an authorization, signing, or production admission engine.
"""
import json
import math
import unicodedata
from pathlib import Path

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NESTING_DEPTH = 64
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_NUMBER_TOKEN_CHARS = 1024


def _unique_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_safe_integer(token):
    """Reject overlong/unsafe integers before constructing Python big ints."""
    if len(token) > MAX_NUMBER_TOKEN_CHARS:
        raise ValueError("JSON numeric token exceeds length limit")
    digits = token[1:] if token.startswith("-") else token
    bound = str(MAX_SAFE_INTEGER)
    if len(digits) > len(bound) or (
        len(digits) == len(bound) and digits > bound
    ):
        raise ValueError("JSON integer outside interoperable safe range")
    return int(token)


def _parse_finite_float(token):
    """Bound numeric work; reject overflow and nonzero-to-zero underflow."""
    if len(token) > MAX_NUMBER_TOKEN_CHARS:
        raise ValueError("JSON numeric token exceeds length limit")
    number = float(token)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number from exponent overflow")
    if number == 0.0:
        # Inspect only the significand: a genuine all-zero literal (including
        # signed zero and zero with any exponent) remains valid. A nonzero
        # significand converting to zero would silently lose its entire value.
        significand = token.split("e", 1)[0].split("E", 1)[0]
        if any("1" <= char <= "9" for char in significand):
            raise ValueError("JSON decimal underflow to zero")
    return number


def _check_depth(document):
    """Bound and pair delimiters before json.loads, ignoring quoted content.

    This structural guard is not a replacement for JSON grammar validation.
    """
    openings = []
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
            openings.append(char)
            if len(openings) > MAX_NESTING_DEPTH:
                raise ValueError("JSON nesting depth exceeds limit")
        elif char in "]}":
            expected = "[" if char == "]" else "{"
            if not openings or openings.pop() != expected:
                raise ValueError("mismatched JSON delimiters")
    if openings or quoted:
        raise ValueError("unbalanced JSON nesting or unterminated string")


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
    # Do not accept encoding markers that change interpretation between
    # independently implemented contract readers.
    if raw.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        raise ValueError("JSON byte-order mark is not permitted")
    document = raw.decode("utf-8")
    _check_depth(document)
    parsed = json.loads(
        document,
        object_pairs_hook=_unique_object_pairs,
        parse_constant=_reject_nonfinite,
        parse_float=_parse_finite_float,
        parse_int=_parse_safe_integer,
    )
    _reject_noncanonical_text(parsed)
    return parsed
