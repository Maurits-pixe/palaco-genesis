"""Offline signed reviewer-policy loader with externally pinned root and revision.

The root public key, trusted revision and clock must come from an independently
protected native authority. This module neither enrolls roots nor persists
revision state. A valid signature is NOT recovery authorization.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ed25519_review_verifier import (
    Ed25519ReviewVerifier, ReviewerPublicKey,
)
from protocol import TransferError

DOMAIN = b"PALACO:BT:REVIEWER-POLICY:V1\0"
PROTOCOL = "PALACO-BT-REVIEWER-POLICY-V1"
MAX_POLICY_BYTES = 65536
MAX_REVIEWERS = 128


@dataclass(frozen=True)
class SignedReviewerPolicy:
    """Canonical signed policy JSON and Ed25519 signature, both untrusted."""

    canonical_json: str
    signature: bytes


def canonical_policy(revision: int, reviewers: dict) -> str:
    """Construct an unsigned candidate policy; signing is an external action."""
    if type(revision) is not int or not 1 <= revision < 2**63:
        raise TransferError("invalid reviewer policy revision")
    if type(reviewers) is not dict or not 1 <= len(reviewers) <= MAX_REVIEWERS:
        raise TransferError("invalid reviewer policy roster")
    parsed = {}
    for key_id, entry in reviewers.items():
        if (type(key_id) is not str or not 1 <= len(key_id) <= 128 or
                not all(c.isascii() and (c.isalnum() or c in "-_.") for c in key_id)):
            raise TransferError("invalid reviewer key ID")
        if type(entry) is not ReviewerPublicKey:
            raise TransferError("invalid reviewer entry")
        parsed[key_id] = {
            "public_key": entry.public_key_raw.hex(),
            "role": entry.role,
            "revoked": entry.revoked,
            "valid_from": entry.valid_from,
            "valid_until": entry.valid_until,
        }
    raw = json.dumps({
        "protocol": PROTOCOL, "revision": revision,
        "reviewers": parsed,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(raw.encode("ascii")) > MAX_POLICY_BYTES:
        raise TransferError("policy too large")
    return raw


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise TransferError("duplicate policy field")
        value[key] = item
    return value


def load_signed_policy(
    bundle: SignedReviewerPolicy,
    pinned_root_public_key: bytes,
    expected_revision: int,
    trusted_clock: Callable[[], int],
) -> Ed25519ReviewVerifier:
    """Verify root signature and exact externally anchored version; fail closed."""
    if type(bundle) is not SignedReviewerPolicy:
        raise TransferError("signed reviewer policy required")
    if (type(pinned_root_public_key) is not bytes or
            len(pinned_root_public_key) != 32 or
            type(bundle.signature) is not bytes or len(bundle.signature) != 64 or
            type(expected_revision) is not int or
            not 1 <= expected_revision < 2**63 or
            not callable(trusted_clock)):
        raise TransferError("trusted root, revision and clock required")
    raw = bundle.canonical_json
    if type(raw) is not str or len(raw) > MAX_POLICY_BYTES or not raw.isascii():
        raise TransferError("policy encoding or size invalid")
    try:
        doc = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (ValueError, TypeError) as exc:
        raise TransferError("invalid policy JSON") from exc
    if type(doc) is not dict or set(doc) != {"protocol", "revision", "reviewers"}:
        raise TransferError("unexpected policy fields")
    if doc["protocol"] != PROTOCOL or doc["revision"] != expected_revision:
        raise TransferError("untrusted or rolled-back policy revision")
    keys = doc["reviewers"]
    if type(keys) is not dict or not 1 <= len(keys) <= MAX_REVIEWERS:
        raise TransferError("invalid reviewer roster")
    entries = {}
    for key_id, item in keys.items():
        if type(item) is not dict or set(item) != {
            "public_key", "role", "revoked", "valid_from", "valid_until"
        }:
            raise TransferError("invalid reviewer record")
        public_hex = item["public_key"]
        if (type(public_hex) is not str or len(public_hex) != 64 or
                any(c not in "0123456789abcdef" for c in public_hex)):
            raise TransferError("invalid public-key encoding")
        entries[key_id] = ReviewerPublicKey(
            bytes.fromhex(public_hex), item["role"], item["revoked"],
            item["valid_from"], item["valid_until"],
        )
    if canonical_policy(expected_revision, entries) != raw:
        raise TransferError("noncanonical policy")
    try:
        Ed25519PublicKey.from_public_bytes(pinned_root_public_key).verify(
            bundle.signature, DOMAIN + raw.encode("ascii"),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise TransferError("reviewer policy signature rejected") from exc
    return Ed25519ReviewVerifier(entries, trusted_clock)
