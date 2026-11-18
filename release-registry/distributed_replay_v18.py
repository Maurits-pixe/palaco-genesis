"""PALACO v18 offline-first distributed replay reconciliation CONTRACT.

Local candidates NEVER constitute globally accepted claims. Only an external
atomic coordinator can select first use, issue authenticated decisions and
provide monotonic anti-rollback state. This pure module does NOT do so.
"""
import hashlib
import json
import re

from offline_stage import _canonical

SCHEMA = "palaco-distributed-replay/v18"
RECEIPT_SCHEMA = "palaco-distributed-replay-receipt/v18"
DOMAIN = b"PALACO-DISTRIBUTED-REPLAY-v18:RECEIPT\x00"
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_CLAIMS = 10000


class CoordinationError(ValueError):
    pass


def _id(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise CoordinationError("INVALID_IDENTIFIER")


def _hex(value):
    if type(value) is not str or not HEX.fullmatch(value):
        raise CoordinationError("INVALID_DIGEST")


def candidate(sender_id, recipient_id, message_id, package_sha256, device_id):
    """Immutable-format metadata candidate, not a receive authorization."""
    for value in (sender_id, recipient_id, message_id, device_id):
        _id(value)
    _hex(package_sha256)
    return {"schema": SCHEMA, "sender_id": sender_id,
            "recipient_id": recipient_id, "message_id": message_id,
            "package_sha256": package_sha256, "device_id": device_id}


def _claim(value):
    if type(value) is not dict or set(value) != {
        "schema", "sender_id", "recipient_id", "message_id",
        "package_sha256", "device_id"
    } or value["schema"] != SCHEMA:
        raise CoordinationError("INVALID_CANDIDATE")
    for field in ("sender_id", "recipient_id", "message_id", "device_id"):
        _id(value[field])
    _hex(value["package_sha256"])


def _tuple(value):
    return (value["sender_id"], value["recipient_id"], value["message_id"])


def prepare_batch(claims):
    """Export canonical offline queue; do not discard conflicting candidates."""
    if type(claims) not in (tuple, list) or len(claims) > MAX_CLAIMS:
        raise CoordinationError("INVALID_BATCH")
    unique = set()
    result = []
    for item in claims:
        _claim(item)
        packed = _canonical(item)
        if packed in unique:
            raise CoordinationError("DUPLICATE_CANDIDATE")
        unique.add(packed)
        result.append(json.loads(packed))
    return _canonical({"schema": SCHEMA, "claims": result})


def read_batch(payload):
    if type(payload) is not bytes or len(payload) > 4_000_000:
        raise CoordinationError("INVALID_BATCH")
    try:
        parsed = json.loads(payload.decode("ascii"))
        if type(parsed) is not dict or set(parsed) != {"schema", "claims"} or (
                parsed["schema"] != SCHEMA or type(parsed["claims"]) is not list or
                _canonical(parsed) != payload):
            raise CoordinationError("INVALID_BATCH")
        if prepare_batch(parsed["claims"]) != payload:
            raise CoordinationError("INVALID_BATCH")
        return tuple(parsed["claims"])
    except CoordinationError:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise CoordinationError("INVALID_BATCH") from exc


def receipt_statement(claim, *, authority_sequence, decision):
    """Domain-separated bytes that a remote coordinator MUST authenticate."""
    _claim(claim)
    if type(authority_sequence) is not int or authority_sequence < 1:
        raise CoordinationError("INVALID_AUTHORITY_SEQUENCE")
    if type(decision) is not str or decision not in ("first-claim", "duplicate", "conflict"):
        raise CoordinationError("INVALID_DECISION")
    return DOMAIN + _canonical({
        "schema": RECEIPT_SCHEMA, "claim": claim,
        "authority_sequence": authority_sequence, "decision": decision})


def inspect_decisions(claims, receipts, *, verify_authority=None,
                      get_trusted_watermark=None):
    """Inspect offline reconciliation without granting any execution authority.

    verify_authority(statement, opaque_receipt) MUST authenticate the trusted
    coordinator and its current key policy. get_trusted_watermark() MUST give a
    separately authenticated monotonically stored minimum authority sequence.
    These callbacks MUST NOT derive trust from the submitted batch/receipts.

    Even verified 'first-claim' is diagnostic only, not permission for v16
    receive_exchange or release. A real coordinator must atomically register
    globally unique tuples, and provide a durable monotonic proof of ordering.
    """
    if not callable(verify_authority) or not callable(get_trusted_watermark):
        raise CoordinationError("EXTERNAL_AUTHORITY_REQUIRED")
    if type(claims) not in (list, tuple) or type(receipts) not in (list, tuple):
        raise CoordinationError("INVALID_INPUT")
    if len(claims) != len(receipts) or not claims or len(claims) > MAX_CLAIMS:
        raise CoordinationError("INVALID_INPUT")
    for item in claims:
        _claim(item)
    try:
        watermark = get_trusted_watermark()
    except Exception as exc:
        raise CoordinationError("WATERMARK_UNAVAILABLE") from exc
    if type(watermark) is not int or watermark < 1:
        raise CoordinationError("INVALID_WATERMARK")
    seen_receipts = set()
    outcomes = []
    tuple_digests = {}
    for claim, receipt in zip(claims, receipts):
        if type(receipt) is not dict or set(receipt) != {
            "schema", "authority_sequence", "decision", "proof"
        } or receipt["schema"] != RECEIPT_SCHEMA:
            raise CoordinationError("INVALID_RECEIPT")
        sequence = receipt["authority_sequence"]
        statement = receipt_statement(
            claim, authority_sequence=sequence, decision=receipt["decision"])
        proof = receipt["proof"]
        if type(proof) is not str or not 1 <= len(proof) <= 8192:
            raise CoordinationError("INVALID_PROOF")
        if sequence > watermark:
            raise CoordinationError("UNANCHORED_DECISION")
        if sequence in seen_receipts:
            raise CoordinationError("DUPLICATE_AUTHORITY_SEQUENCE")
        seen_receipts.add(sequence)
        try:
            verified = verify_authority(statement, proof)
        except Exception as exc:
            raise CoordinationError("AUTHORITY_UNAVAILABLE") from exc
        if verified is not True:
            raise CoordinationError("AUTHORITY_UNVERIFIED")
        key = _tuple(claim)
        if key in tuple_digests and (
                receipt["decision"] == "first-claim" or
                tuple_digests[key] != claim["package_sha256"]):
            # A globally duplicated candidate can be reported, but NEVER
            # treated as another first claim or silently reconciled as equal.
            if receipt["decision"] == "first-claim":
                raise CoordinationError("MULTIPLE_FIRST_CLAIMS")
        tuple_digests.setdefault(key, claim["package_sha256"])
        outcomes.append({"message_id": claim["message_id"],
                         "device_id": claim["device_id"],
                         "decision": receipt["decision"],
                         "authority_sequence": sequence})
    return {
        "schema": "palaco-distributed-replay-inspection/v18",
        "inspected": len(outcomes), "outcomes": outcomes,
        "authority_watermark_checked": True,
        "authorization": "DENY", "release": "HOLD",
        "production_release_enabled": False
    }
