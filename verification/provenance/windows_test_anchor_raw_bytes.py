"""WNRA-05D test-only strict raw-byte parser for a simulated anchor request.

These byte rules are a LOCAL NEGATIVE FIXTURE PROFILE, not protocol canon.
They neither authenticate an actor nor authorize issuance or production.
"""
from __future__ import annotations

from dataclasses import fields
import json

from windows_test_anchor_adapter import AnchorRequest, make_simulated_response

MAX_SAFE_INTEGER = 2**53 - 1
REQUEST_FIELDS = frozenset(field.name for field in fields(AnchorRequest))


class FixtureByteRejected(ValueError):
    pass


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureByteRejected("DUPLICATE_KEY")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if token == "-0":
        raise FixtureByteRejected("NEGATIVE_ZERO")
    value = int(token)
    if abs(value) > MAX_SAFE_INTEGER:
        raise FixtureByteRejected("UNSAFE_INTEGER")
    return value


def _fraction(token: str) -> object:
    raise FixtureByteRejected("FRACTION_OR_EXPONENT")


def _constant(token: str) -> object:
    raise FixtureByteRejected("NON_FINITE_VALUE")


def parse_simulated_request_bytes(raw: bytes) -> AnchorRequest:
    if not isinstance(raw, bytes):
        raise FixtureByteRejected("NOT_BYTES")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FixtureByteRejected("INVALID_UTF8") from exc
    if decoded.startswith("\ufeff"):
        raise FixtureByteRejected("UTF8_BOM")
    try:
        obj = json.loads(
            decoded,
            object_pairs_hook=_unique_pairs,
            parse_int=_integer,
            parse_float=_fraction,
            parse_constant=_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise FixtureByteRejected("INVALID_JSON") from exc
    if not isinstance(obj, dict) or set(obj) != REQUEST_FIELDS:
        raise FixtureByteRejected("SCHEMA_MISMATCH")
    if type(obj.get("sequence")) is not int:
        raise FixtureByteRejected("INVALID_SEQUENCE_TYPE")
    try:
        canonical = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, UnicodeError) as exc:
        raise FixtureByteRejected("INVALID_VALUE") from exc
    if canonical != raw:
        raise FixtureByteRejected("NONCANONICAL_TEST_BYTES")
    try:
        request = AnchorRequest(**obj)
        make_simulated_response(request)
    except (TypeError, ValueError) as exc:
        raise FixtureByteRejected("INVALID_REQUEST") from exc
    return request
