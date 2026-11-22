#!/usr/bin/env python3
"""Offline, deterministic handoff of an independently signed history witness.

No network publishing, file writes, authentication of recipient, or authority.
A bundle hash is an integrity identifier, not proof of delivery or receipt.
"""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "palaco_offline_handoff_anchor", Path(__file__).with_name("signed_review_history_anchor.py"))
anchor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(anchor)

BUNDLE_FIELDS = {"schema_version", "purpose", "recipient_id", "signed_anchor", "anchor_sha256"}
PACKAGE_FIELDS = {"bundle", "bundle_sha256"}
PURPOSE = "offline-history-witness-verification"
RECIPIENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DOMAIN = b"PALACO-OFFLINE-WITNESS-HANDOFF-V1\x00"
MAX_BUNDLE_BYTES = 16384


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(domain, value):
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _valid_bundle(bundle):
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS:
        return False
    if bundle["schema_version"] != "0.1.0" or bundle["purpose"] != PURPOSE:
        return False
    if not isinstance(bundle["recipient_id"], str) or not RECIPIENT.fullmatch(bundle["recipient_id"]):
        return False
    if not isinstance(bundle["anchor_sha256"], str) or not anchor.HEX.fullmatch(bundle["anchor_sha256"]):
        return False
    witness = bundle["signed_anchor"]
    if not isinstance(witness, dict) or set(witness) != anchor.ENVELOPE_FIELDS:
        return False
    try:
        if len(_canonical(bundle)) > MAX_BUNDLE_BYTES:
            return False
        return _digest(b"PALACO-DETACHED-ANCHOR-ENVELOPE-V1\x00", witness) == bundle["anchor_sha256"]
    except (TypeError, ValueError, OverflowError):
        return False


def prepare(history_db, signed_anchor, recipient_id, witness_roots,
            revoked_witnesses, minimum_entries):
    """Return a copy-safe offline package *only* for a verified local anchor.

    Does not deliver or save the package. The caller must independently verify
    the recipient identity, deliver through a secure channel, and retain an
    independently authenticated minimum entry count on the receiving side.
    """
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "package_prepared": False}
    if not isinstance(recipient_id, str) or not RECIPIENT.fullmatch(recipient_id):
        return {**base, "reason": "invalid-recipient-id"}
    checked = anchor.verify(history_db, signed_anchor, witness_roots,
                            revoked_witnesses, minimum_entries)
    if not checked["anchor_valid"]:
        return {**base, "reason": checked["reason"]}
    # Round-trip JSON to detach returned structure from caller-controlled input.
    try:
        detached = json.loads(_canonical(signed_anchor))
        bundle = {"schema_version": "0.1.0", "purpose": PURPOSE,
                  "recipient_id": recipient_id, "signed_anchor": detached,
                  "anchor_sha256": _digest(b"PALACO-DETACHED-ANCHOR-ENVELOPE-V1\x00", detached)}
    except (TypeError, ValueError, OverflowError):
        return {**base, "reason": "unserializable-anchor"}
    if not _valid_bundle(bundle):
        return {**base, "reason": "oversized-or-invalid-bundle"}
    return {**base, "package_prepared": True,
            "reason": "offline-package-only-not-transmitted",
            "package": {"bundle": bundle, "bundle_sha256": _digest(DOMAIN, bundle)}}


def verify_package(history_db, package, expected_recipient, witness_roots,
                   revoked_witnesses, minimum_entries, expected_bundle_sha256):
    """Receive-side read-only validation with externally obtained package hash."""
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "package_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(expected_recipient, str) or not RECIPIENT.fullmatch(expected_recipient):
        return deny("missing-expected-recipient")
    if not isinstance(expected_bundle_sha256, str) or not anchor.HEX.fullmatch(expected_bundle_sha256):
        return deny("missing-external-package-digest")
    if not isinstance(package, dict) or set(package) != PACKAGE_FIELDS:
        return deny("invalid-package-schema")
    bundle = package["bundle"]
    if not _valid_bundle(bundle):
        return deny("invalid-bundle")
    if bundle["recipient_id"] != expected_recipient:
        return deny("recipient-mismatch")
    try:
        actual = _digest(DOMAIN, bundle)
    except (TypeError, ValueError, OverflowError):
        return deny("invalid-bundle")
    if package["bundle_sha256"] != actual or actual != expected_bundle_sha256:
        return deny("bundle-digest-mismatch")
    checked = anchor.verify(history_db, bundle["signed_anchor"], witness_roots,
                            revoked_witnesses, minimum_entries)
    if not checked["anchor_valid"]:
        return deny(checked["reason"])
    return {**base, "package_valid": True, "state": "pending-review",
            "reason": "offline-handoff-verified-not-publication-or-authorization",
            "bundle_sha256": actual, "entries": checked["entries"]}
