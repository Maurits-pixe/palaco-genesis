#!/usr/bin/env python3
"""Verify signed reviewer registry snapshots; advisory HOLD only.

This module never issues credentials or authorization. The issuer trust roots
and evaluation time are caller supplied and must be independently authenticated.
"""
import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEX64 = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
REVIEWER_FIELDS = {"reviewer_id", "key_fingerprint", "valid_from", "valid_until", "revoked"}
SNAPSHOT_FIELDS = {"schema_version", "revision", "reviewers"}
ENVELOPE_FIELDS = {"snapshot", "issuer_key_id", "issuer_signature_b64"}
MAX_REVIEWERS = 1024


def canonical(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != SNAPSHOT_FIELDS:
        raise ValueError("invalid-snapshot")
    if snapshot["schema_version"] != "0.1.0" or type(snapshot["revision"]) is not int or snapshot["revision"] < 1:
        raise ValueError("invalid-revision")
    reviewers = snapshot["reviewers"]
    if not isinstance(reviewers, list) or len(reviewers) > MAX_REVIEWERS:
        raise ValueError("invalid-reviewers")
    ids, keys = set(), set()
    for reviewer in reviewers:
        if not isinstance(reviewer, dict) or set(reviewer) != REVIEWER_FIELDS:
            raise ValueError("invalid-reviewer")
        rid, fingerprint = reviewer["reviewer_id"], reviewer["key_fingerprint"]
        if not isinstance(rid, str) or not IDENT.fullmatch(rid):
            raise ValueError("invalid-reviewer-id")
        if not isinstance(fingerprint, str) or not HEX64.fullmatch(fingerprint):
            raise ValueError("invalid-key-fingerprint")
        if rid in ids or fingerprint in keys:
            raise ValueError("duplicate-reviewer-or-key")
        ids.add(rid)
        keys.add(fingerprint)
        if type(reviewer["revoked"]) is not bool:
            raise ValueError("invalid-revocation-status")
        start = parse_time(reviewer["valid_from"])
        end = parse_time(reviewer["valid_until"])
        if start >= end:
            raise ValueError("invalid-validity-window")
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def parse_time(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp-must-be-utc")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("invalid-timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("invalid-timestamp")
    return parsed


def evaluate(envelope, issuer_roots, reviewer_id, reviewer_key_fingerprint, at_utc,
             minimum_revision=1):
    """Signed snapshot + reviewer status; returns no authority, even on PASS.

    No rollback detection beyond a *trusted external* minimum_revision. The
    caller must authenticate roots, chosen time, and minimum revision.
    """
    output = {"release_gate": "HOLD", "authorization_granted": False,
              "reviewer_eligible_for_manual_review": False, "state": "quarantined"}
    def deny(reason):
        return {**output, "reason": reason}
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        return deny("invalid-envelope")
    if not isinstance(issuer_roots, dict):
        return deny("missing-issuer-roots")
    if type(minimum_revision) is not int or minimum_revision < 1:
        return deny("invalid-minimum-revision")
    if not isinstance(reviewer_id, str) or not IDENT.fullmatch(reviewer_id):
        return deny("invalid-reviewer-id")
    if not isinstance(reviewer_key_fingerprint, str) or not HEX64.fullmatch(reviewer_key_fingerprint):
        return deny("invalid-reviewer-key")
    try:
        now = parse_time(at_utc)
        payload = canonical(envelope["snapshot"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    if envelope["snapshot"]["revision"] < minimum_revision:
        return deny("stale-registry-revision")
    key_id = envelope["issuer_key_id"]
    if not isinstance(key_id, str) or not HEX64.fullmatch(key_id):
        return deny("invalid-issuer-key-id")
    key = issuer_roots.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32 or hashlib.sha256(key).hexdigest() != key_id:
        return deny("untrusted-issuer")
    encoded = envelope["issuer_signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-issuer-signature")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-issuer-signature")
    if len(signature) != 64:
        return deny("invalid-issuer-signature")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, b"PALACO-REVIEWER-REGISTRY-V1\x00" + payload)
    except (InvalidSignature, ValueError):
        return deny("invalid-issuer-signature")
    matches = [r for r in envelope["snapshot"]["reviewers"] if r["reviewer_id"] == reviewer_id]
    if not matches:
        return deny("unknown-reviewer")
    reviewer = matches[0]
    if reviewer["key_fingerprint"] != reviewer_key_fingerprint:
        return deny("reviewer-key-mismatch")
    if reviewer["revoked"]:
        return deny("reviewer-revoked")
    if not (parse_time(reviewer["valid_from"]) <= now < parse_time(reviewer["valid_until"])):
        return deny("reviewer-outside-validity")
    return {**output, "state": "pending-review", "reason": "issuer-signed-reviewer-eligible-authority-unverified",
            "reviewer_eligible_for_manual_review": True}
