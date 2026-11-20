"""Pure, offline-only candidate event staging for PALACO module integration.

No data transfer, identity assertion, signature verification, persistence,
authorization, merge decision or execution occurs here. Caller-supplied
checkpoints are NOT independently trusted.
"""
import hashlib
import json
import re

from integration_contract import MODULES

SCHEMA = "palaco-offline-stage/v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
GENESIS = hashlib.sha256(b"PALACO-OFFLINE-STAGE-v1:GENESIS").hexdigest()
MAX_EVENTS = 10000


class StageError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _check_event(event):
    if type(event) is not dict or set(event) != {
        "schema", "module", "event_id", "sequence", "previous",
        "payload_sha256",
    }:
        raise StageError("INVALID_EVENT_SHAPE")
    if event["schema"] != SCHEMA or type(event["module"]) is not str or event["module"] not in MODULES:
        raise StageError("INVALID_MODULE")
    if type(event["event_id"]) is not str or not ID.fullmatch(event["event_id"]):
        raise StageError("INVALID_EVENT_ID")
    if type(event["sequence"]) is not int or event["sequence"] < 1:
        raise StageError("INVALID_SEQUENCE")
    for key in ("previous", "payload_sha256"):
        if type(event[key]) is not str or not HEX.fullmatch(event[key]):
            raise StageError("INVALID_DIGEST")


def _digest(event):
    return hashlib.sha256(b"PALACO-OFFLINE-STAGE-v1:EVENT\x00" +
                          _canonical(event)).hexdigest()


def replay(events):
    """Validate and replay a sequence of *metadata-only* events.

    Returns the untrusted calculated head. No external checkpoint is verified.
    """
    if type(events) not in (tuple, list) or len(events) > MAX_EVENTS:
        raise StageError("INVALID_HISTORY")
    head, ids = GENESIS, set()
    for count, event in enumerate(events, 1):
        _check_event(event)
        if event["sequence"] != count or event["previous"] != head:
            raise StageError("BROKEN_CHAIN")
        if event["event_id"] in ids:
            raise StageError("DUPLICATE_EVENT_ID")
        ids.add(event["event_id"])
        head = _digest(event)
    return head


def stage(events, event, *, expected_head):
    """Append a candidate event with exact checkpoint and monotonic sequence.

    An exact duplicate event returns unchanged history; changed event IDs or
    changed bytes are rejected. expected_head protects against *accidental*
    stale updates only; it cannot defeat malicious history replacement.
    """
    head = replay(events)
    if type(expected_head) is not str or expected_head != head:
        raise StageError("STALE_CHECKPOINT")
    _check_event(event)
    prior = next((old for old in events if old["event_id"] == event["event_id"]), None)
    if prior is not None:
        if _canonical(prior) != _canonical(event):
            raise StageError("IDEMPOTENCY_CONFLICT")
        return tuple(events), head, True
    if len(events) >= MAX_EVENTS:
        raise StageError("HISTORY_LIMIT")
    if event["sequence"] != len(events) + 1 or event["previous"] != head:
        raise StageError("BROKEN_CHAIN")
    frozen = json.loads(_canonical(event))
    return tuple(events) + (frozen,), _digest(frozen), False


def make_candidate(module, event_id, sequence, previous, payload_bytes):
    """Create metadata for a synthetic/public test payload, not an identity."""
    if type(payload_bytes) is not bytes:
        raise StageError("INVALID_PAYLOAD")
    event = {
        "schema": SCHEMA, "module": module, "event_id": event_id,
        "sequence": sequence, "previous": previous,
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
    }
    _check_event(event)
    return event
