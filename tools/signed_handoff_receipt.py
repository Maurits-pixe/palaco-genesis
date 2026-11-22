#!/usr/bin/env python3
"""Validate and locally index detached custodian-signed offline handoff receipts.

Caller supplies independently authenticated custodian keys and a separately
pinned package digest. No signing, sending, approval, trust bootstrap or restore.
"""
import base64
import hashlib
import importlib.util
import re
import sqlite3
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_receipt_handoff", Path(__file__).with_name("offline_review_anchor_handoff.py"))
handoff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(handoff)

DOMAIN = b"PALACO-OFFLINE-HANDOFF-RECEIPT-V1\x00"
BODY_FIELDS = {"schema_version", "recipient_id", "bundle_sha256", "receipt_id", "disposition"}
ENVELOPE_FIELDS = {"receipt", "custodian_key_id", "signature_b64"}
RECEIPT_ID = re.compile(r"^[0-9a-f]{32}$")
DISPOSITION = "received-for-independent-review"


def canonical_receipt(receipt):
    if not isinstance(receipt, dict) or set(receipt) != BODY_FIELDS:
        raise ValueError("invalid-receipt-schema")
    if receipt["schema_version"] != "0.1.0" or receipt["disposition"] != DISPOSITION:
        raise ValueError("invalid-receipt-purpose")
    if not isinstance(receipt["recipient_id"], str) or not handoff.RECIPIENT.fullmatch(receipt["recipient_id"]):
        raise ValueError("invalid-receipt-recipient")
    if not isinstance(receipt["bundle_sha256"], str) or not handoff.anchor.HEX.fullmatch(receipt["bundle_sha256"]):
        raise ValueError("invalid-receipt-digest")
    if not isinstance(receipt["receipt_id"], str) or not RECEIPT_ID.fullmatch(receipt["receipt_id"]):
        raise ValueError("invalid-receipt-id")
    return handoff._canonical(receipt)


def verify_receipt(history_db, package, receipt_envelope, expected_recipient,
                   expected_bundle_sha256, custodian_keys, revoked_custodians,
                   witness_roots, revoked_witnesses, minimum_entries):
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "receipt_valid": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(receipt_envelope, dict) or set(receipt_envelope) != ENVELOPE_FIELDS:
        return deny("invalid-receipt-envelope")
    if not isinstance(custodian_keys, dict) or not isinstance(revoked_custodians, (set, frozenset)):
        return deny("missing-custodian-policy")
    if any(not isinstance(x, str) or not handoff.anchor.HEX.fullmatch(x) for x in revoked_custodians):
        return deny("invalid-custodian-revocations")
    try:
        canonical = canonical_receipt(receipt_envelope["receipt"])
    except (TypeError, ValueError, OverflowError) as exc:
        return deny(str(exc))
    receipt = receipt_envelope["receipt"]
    if receipt["recipient_id"] != expected_recipient:
        return deny("receipt-recipient-mismatch")
    if receipt["bundle_sha256"] != expected_bundle_sha256:
        return deny("receipt-package-mismatch")
    key_id = receipt_envelope["custodian_key_id"]
    if not isinstance(key_id, str) or not handoff.anchor.HEX.fullmatch(key_id):
        return deny("invalid-custodian-key-id")
    if key_id in revoked_custodians:
        return deny("custodian-revoked")
    key = custodian_keys.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32 or hashlib.sha256(key).hexdigest() != key_id:
        return deny("untrusted-custodian-key")
    encoded = receipt_envelope["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-receipt-signature-format")
    try:
        sig = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-receipt-signature-format")
    if len(sig) != 64:
        return deny("invalid-receipt-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, DOMAIN + canonical)
    except (InvalidSignature, ValueError):
        return deny("invalid-receipt-signature")
    checked = handoff.verify_package(history_db, package, expected_recipient,
                                     witness_roots, revoked_witnesses,
                                     minimum_entries, expected_bundle_sha256)
    if not checked["package_valid"]:
        return deny(checked["reason"])
    return {**base, "receipt_valid": True, "state": "pending-review",
            "reason": "signed-receipt-valid-no-verified-delivery-or-authority",
            "receipt_id": receipt["receipt_id"], "custodian_key_id": key_id,
            "bundle_sha256": receipt["bundle_sha256"]}


def index_receipt(receipt_db, history_db, package, receipt_envelope, expected_recipient,
                  expected_bundle_sha256, custodian_keys, revoked_custodians,
                  witness_roots, revoked_witnesses, minimum_entries):
    """Uniqueness in one local SQLite file; a successful record stays HOLD."""
    base = {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "receipt_recorded": False, "state": "quarantined"}
    def deny(reason):
        return {**base, "reason": reason}
    if not isinstance(receipt_db, (str, Path)) or str(receipt_db) == ":memory:":
        raise ValueError("persistent receipt register required")
    if Path(receipt_db).resolve() == Path(history_db).resolve():
        raise ValueError("receipt register must be separate from history database")
    verdict = verify_receipt(history_db, package, receipt_envelope, expected_recipient,
                             expected_bundle_sha256, custodian_keys, revoked_custodians,
                             witness_roots, revoked_witnesses, minimum_entries)
    if not verdict["receipt_valid"]:
        return deny(verdict["reason"])
    body = receipt_envelope["receipt"]
    key_id = receipt_envelope["custodian_key_id"]
    digest = hashlib.sha256(DOMAIN + canonical_receipt(body)).hexdigest()
    conn = sqlite3.connect(str(receipt_db), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS observed_handoff_receipts(
                receipt_id TEXT PRIMARY KEY NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                custodian_key_id TEXT NOT NULL,
                receipt_digest TEXT NOT NULL UNIQUE,
                UNIQUE(bundle_sha256,recipient_id,custodian_key_id)
            )
        """)
        prior = conn.execute("SELECT receipt_digest FROM observed_handoff_receipts WHERE receipt_id=?",
                             (body["receipt_id"],)).fetchone()
        if prior:
            conn.rollback()
            return deny("duplicate-receipt" if prior[0] == digest else "receipt-id-equivocation")
        try:
            conn.execute("""INSERT INTO observed_handoff_receipts
                (receipt_id,bundle_sha256,recipient_id,custodian_key_id,receipt_digest)
                VALUES(?,?,?,?,?)""",
                (body["receipt_id"], body["bundle_sha256"], body["recipient_id"], key_id, digest))
        except sqlite3.IntegrityError:
            conn.rollback()
            return deny("duplicate-bundle-acknowledgement")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {**base, "receipt_recorded": True, "state": "pending-review",
            "reason": "locally-observed-custodian-receipt-no-authority"}
