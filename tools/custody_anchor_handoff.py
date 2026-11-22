#!/usr/bin/env python3
"""Offline transport and receipt of a signed custody-ledger checkpoint.

No network, signing, trusted time, external immutable store or release authority.
The detached expected package digest and public-key policies MUST be obtained
over separately authenticated channels.
"""
import base64
import hashlib
import importlib.util
import json
import re
import sqlite3
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec = importlib.util.spec_from_file_location(
    "palaco_custody_handoff_anchor", Path(__file__).with_name("signed_custody_ledger_anchor.py"))
anchor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(anchor)

HEX = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
DOMAIN = b"PALACO-CUSTODY-LEDGER-HANDOFF-V1\x00"
ACK_DOMAIN = b"PALACO-CUSTODY-LEDGER-ACKNOWLEDGEMENT-V1\x00"
PACKAGE_FIELDS = {"schema_version", "recipient_id", "signed_anchor"}
ACK_FIELDS = {"schema_version", "recipient_id", "package_sha256", "receipt_id", "disposition"}
ACK_ENVELOPE = {"acknowledgement", "custodian_key_id", "signature_b64"}
DISPOSITION = "received-for-independent-review"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def package_digest(package):
    return hashlib.sha256(DOMAIN + _canonical(package)).hexdigest()


def _valid_package(package):
    if not isinstance(package, dict) or set(package) != PACKAGE_FIELDS:
        return False
    if package["schema_version"] != "0.1.0" or not isinstance(package["recipient_id"], str):
        return False
    if not IDENT.fullmatch(package["recipient_id"]):
        return False
    if not isinstance(package["signed_anchor"], dict) or set(package["signed_anchor"]) != anchor.ENVELOPE_FIELDS:
        return False
    try:
        return len(_canonical(package)) <= 8192
    except (TypeError, ValueError, OverflowError):
        return False


def _base(**extra):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "automatic_restore": False, "recovery_approved": False,
            "state": "quarantined", **extra}


def prepare(ledger_db, signed_anchor, recipient_id, witness_roots, revoked, minimum):
    if not isinstance(recipient_id, str) or not IDENT.fullmatch(recipient_id):
        return _base(package_prepared=False, reason="invalid-recipient-id")
    result = anchor.verify(ledger_db, signed_anchor, witness_roots, revoked, minimum)
    if not result["anchor_valid"]:
        return _base(package_prepared=False, reason=result["reason"])
    try:
        package = {"schema_version": "0.1.0", "recipient_id": recipient_id,
                   "signed_anchor": json.loads(_canonical(signed_anchor))}
        if not _valid_package(package):
            raise ValueError("invalid-package")
        digest = package_digest(package)
    except (TypeError, ValueError, OverflowError):
        return _base(package_prepared=False, reason="invalid-package")
    return _base(package_prepared=True, state="pending-review",
                 reason="offline-package-prepared-not-delivered",
                 package=package, package_sha256=digest)


def canonical_ack(body):
    if not isinstance(body, dict) or set(body) != ACK_FIELDS:
        raise ValueError("invalid-acknowledgement-schema")
    if body["schema_version"] != "0.1.0" or body["disposition"] != DISPOSITION:
        raise ValueError("invalid-acknowledgement-disposition")
    if not isinstance(body["recipient_id"], str) or not IDENT.fullmatch(body["recipient_id"]):
        raise ValueError("invalid-acknowledgement-recipient")
    if not isinstance(body["package_sha256"], str) or not HEX.fullmatch(body["package_sha256"]):
        raise ValueError("invalid-acknowledgement-digest")
    if not isinstance(body["receipt_id"], str) or not NONCE.fullmatch(body["receipt_id"]):
        raise ValueError("invalid-acknowledgement-receipt-id")
    return _canonical(body)


def verify_ack(ledger_db, package, ack, expected_recipient, expected_package_sha256,
               witness_roots, revoked_witnesses, minimum_entries,
               custodian_roots, revoked_custodians, allowed_custodian_keys):
    def deny(reason):
        return _base(ack_valid=False, reason=reason)
    if not isinstance(expected_recipient, str) or not IDENT.fullmatch(expected_recipient):
        return deny("missing-expected-recipient")
    if not isinstance(expected_package_sha256, str) or not HEX.fullmatch(expected_package_sha256):
        return deny("missing-external-package-hash")
    if not _valid_package(package):
        return deny("invalid-handoff-package")
    if package["recipient_id"] != expected_recipient:
        return deny("recipient-mismatch")
    if package_digest(package) != expected_package_sha256:
        return deny("package-hash-mismatch")
    if not isinstance(ack, dict) or set(ack) != ACK_ENVELOPE:
        return deny("invalid-acknowledgement-envelope")
    try:
        body = canonical_ack(ack["acknowledgement"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    data = ack["acknowledgement"]
    if data["recipient_id"] != expected_recipient or data["package_sha256"] != expected_package_sha256:
        return deny("acknowledgement-binding-mismatch")
    if (not isinstance(custodian_roots, dict)
        or not isinstance(revoked_custodians, (set, frozenset))
        or not isinstance(allowed_custodian_keys, (set, frozenset))):
        return deny("missing-independent-custodian-policy")
    if any(not isinstance(x, str) or not HEX.fullmatch(x) for x in revoked_custodians):
        return deny("invalid-custodian-revocation")
    key_id = ack["custodian_key_id"]
    if not isinstance(key_id, str) or not HEX.fullmatch(key_id):
        return deny("invalid-custodian-key-id")
    if key_id in revoked_custodians:
        return deny("custodian-revoked")
    if key_id not in allowed_custodian_keys:
        return deny("custodian-not-allowed")
    if key_id == package["signed_anchor"].get("witness_key_id"):
        return deny("witness-custodian-role-collision")
    public = custodian_roots.get(key_id)
    if not isinstance(public, bytes) or len(public) != 32 or hashlib.sha256(public).hexdigest() != key_id:
        return deny("untrusted-custodian")
    encoded = ack["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-ack-signature-format")
    try:
        sig = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-ack-signature-format")
    if len(sig) != 64:
        return deny("invalid-ack-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, ACK_DOMAIN + body)
    except (InvalidSignature, ValueError):
        return deny("invalid-ack-signature")
    confirmed = anchor.verify(ledger_db, package["signed_anchor"], witness_roots,
                              revoked_witnesses, minimum_entries)
    if not confirmed["anchor_valid"]:
        return deny(confirmed["reason"])
    return _base(ack_valid=True, state="pending-review",
                 reason="authenticated-acknowledgement-claim-not-proof-of-custody",
                 receipt_id=data["receipt_id"], custodian_key_id=key_id,
                 package_sha256=expected_package_sha256)


def register_ack(register_db, ledger_db, package, ack, expected_recipient,
                 expected_package_sha256, witness_roots, revoked_witnesses,
                 minimum_entries, custodian_roots, revoked_custodians,
                 allowed_custodian_keys):
    if (not isinstance(register_db, (str, Path)) or str(register_db) == ":memory:"
        or not isinstance(ledger_db, (str, Path))
        or Path(register_db).resolve() == Path(ledger_db).resolve()):
        raise ValueError("distinct persistent receipt register required")
    checked = verify_ack(ledger_db, package, ack, expected_recipient, expected_package_sha256,
                         witness_roots, revoked_witnesses, minimum_entries,
                         custodian_roots, revoked_custodians, allowed_custodian_keys)
    if not checked["ack_valid"]:
        return _base(recorded=False, reason=checked["reason"])
    ident, key_id = checked["receipt_id"], checked["custodian_key_id"]
    digest = hashlib.sha256(ACK_DOMAIN + canonical_ack(ack["acknowledgement"])).hexdigest()
    conn = sqlite3.connect(str(register_db), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS custody_anchor_acknowledgements (
            receipt_id TEXT PRIMARY KEY,
            custodian_key_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            package_sha256 TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            UNIQUE(custodian_key_id, recipient_id, package_sha256)
        )""")
        existing = conn.execute("SELECT receipt_sha256 FROM custody_anchor_acknowledgements WHERE receipt_id=?",
                                (ident,)).fetchone()
        if existing is not None:
            conn.rollback()
            return _base(recorded=False, reason="acknowledgement-replay" if existing[0] == digest
                         else "acknowledgement-id-conflict")
        try:
            conn.execute("""INSERT INTO custody_anchor_acknowledgements VALUES(?,?,?,?,?)""",
                         (ident, key_id, expected_recipient, expected_package_sha256, digest))
        except sqlite3.IntegrityError:
            conn.rollback()
            return _base(recorded=False, reason="duplicate-package-acknowledgement")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return _base(recorded=True, state="pending-review",
                 reason="local-acknowledgement-indexed-no-authority")
