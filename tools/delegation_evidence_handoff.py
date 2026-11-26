#!/usr/bin/env python3
"""Offline handoff and signed receipt of witnessed delegation-history evidence.

Verifies all upstream delegation/witness signatures before packaging. No
network, filesystem export, signing, trusted clock or release authority.
Persistent replay register is separate from the evidence source.
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
    "palaco_delegation_handoff_quorum",
    Path(__file__).with_name("delegation_history_witness_checkpoint.py"))
witness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(witness)
_audit_spec = importlib.util.spec_from_file_location(
    "palaco_delegation_receipt_audit",
    Path(__file__).with_name("delegation_receipt_audit_chain.py"))
audit = importlib.util.module_from_spec(_audit_spec)
_audit_spec.loader.exec_module(audit)

DOMAIN = b"PALACO-DELEGATION-EVIDENCE-HANDOFF-V1\x00"
RECEIPT_DOMAIN = b"PALACO-DELEGATION-EVIDENCE-RECEIPT-V1\x00"
PACKAGE_FIELDS = {"schema_version", "recipient_id", "checkpoint", "witnesses"}
RECEIPT_FIELDS = {"schema_version", "recipient_id", "package_sha256",
                  "receipt_id", "disposition"}
ENVELOPE_FIELDS = {"receipt", "recipient_key_id", "signature_b64"}
DISPOSITION = "received-for-independent-review"
IDENT = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
HEX = witness.history.HEX
MAX_BYTES = 32768


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _result(**kw):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "state": "quarantined", **kw}


def valid_package(package):
    if not isinstance(package, dict) or set(package) != PACKAGE_FIELDS:
        return False
    if package["schema_version"] != "0.1.0":
        return False
    if not isinstance(package["recipient_id"], str) or not IDENT.fullmatch(package["recipient_id"]):
        return False
    if not isinstance(package["checkpoint"], dict) or set(package["checkpoint"]) != witness.BODY_FIELDS:
        return False
    envelopes = package["witnesses"]
    if not isinstance(envelopes, list) or not 2 <= len(envelopes) <= witness.MAX_WITNESSES:
        return False
    if any(not isinstance(env, dict) or set(env) != witness.ENVELOPE_FIELDS
           for env in envelopes):
        return False
    try:
        return len(canonical(package)) <= MAX_BYTES
    except (ValueError, TypeError, OverflowError):
        return False


def package_hash(package):
    return hashlib.sha256(DOMAIN + canonical(package)).hexdigest()


def _matching_witnesses(package, received):
    """Reject missing or reordered signatures without modifying input."""
    if len(received) != len(package["witnesses"]):
        return False
    try:
        # The package commits to the witness envelopes exactly, in given order.
        return canonical(received) == canonical(package["witnesses"])
    except (ValueError, TypeError, OverflowError):
        return False


def prepare(history_inputs, status_records, witnesses, witness_roots,
            witness_organizations, revoked_witnesses, minimum_organizations,
            recipient_id):
    def deny(reason):
        return _result(package_prepared=False, reason=reason)
    if not isinstance(recipient_id, str) or not IDENT.fullmatch(recipient_id):
        return deny("invalid-recipient")
    checked = witness.verify(history_inputs, status_records, witnesses, witness_roots,
                             witness_organizations, revoked_witnesses, minimum_organizations)
    if not checked["checkpoint_quorum_valid"]:
        return deny(checked["reason"])
    try:
        # Explicitly use the verified first checkpoint; all others matched it.
        package = {"schema_version": "0.1.0", "recipient_id": recipient_id,
                   "checkpoint": json.loads(canonical(witnesses[0]["checkpoint"])),
                   "witnesses": json.loads(canonical(witnesses))}
        if not valid_package(package):
            return deny("invalid-handoff-package")
        digest = package_hash(package)
    except (ValueError, TypeError, OverflowError):
        return deny("invalid-handoff-package")
    return _result(package_prepared=True, state="pending-review",
                   reason="offline-package-prepared-not-delivered",
                   package=package, package_sha256=digest)


def canonical_receipt(body):
    if not isinstance(body, dict) or set(body) != RECEIPT_FIELDS:
        raise ValueError("invalid-receipt-schema")
    if body["schema_version"] != "0.1.0" or body["disposition"] != DISPOSITION:
        raise ValueError("invalid-receipt-disposition")
    if not isinstance(body["recipient_id"], str) or not IDENT.fullmatch(body["recipient_id"]):
        raise ValueError("invalid-receipt-recipient")
    if not isinstance(body["package_sha256"], str) or not HEX.fullmatch(body["package_sha256"]):
        raise ValueError("invalid-receipt-package-hash")
    if not isinstance(body["receipt_id"], str) or not NONCE.fullmatch(body["receipt_id"]):
        raise ValueError("invalid-receipt-id")
    return canonical(body)


def verify_receipt(history_inputs, status_records, package, receipt,
                   expected_recipient, expected_package_hash, witness_roots,
                   witness_organizations, revoked_witnesses, minimum_organizations,
                   recipient_roots, revoked_recipients, allowed_recipients):
    def deny(reason):
        return _result(receipt_valid=False, reason=reason)
    if (not isinstance(expected_recipient, str) or not IDENT.fullmatch(expected_recipient)
        or not isinstance(expected_package_hash, str) or not HEX.fullmatch(expected_package_hash)):
        return deny("missing-independent-package-binding")
    if not valid_package(package):
        return deny("invalid-handoff-package")
    if package["recipient_id"] != expected_recipient:
        return deny("recipient-mismatch")
    if package_hash(package) != expected_package_hash:
        return deny("package-hash-mismatch")
    if (not isinstance(receipt, dict) or set(receipt) != ENVELOPE_FIELDS):
        return deny("invalid-receipt-envelope")
    try:
        raw = canonical_receipt(receipt["receipt"])
    except (ValueError, TypeError, OverflowError) as exc:
        return deny(str(exc))
    body = receipt["receipt"]
    if (body["recipient_id"] != expected_recipient
        or body["package_sha256"] != expected_package_hash):
        return deny("receipt-binding-mismatch")
    if (not isinstance(recipient_roots, dict)
        or not isinstance(revoked_recipients, (set, frozenset))
        or not isinstance(allowed_recipients, (set, frozenset))
        or any(not isinstance(k, str) or not HEX.fullmatch(k)
               for k in revoked_recipients | allowed_recipients)):
        return deny("missing-independent-recipient-policy")
    key = receipt["recipient_key_id"]
    if not isinstance(key, str) or not HEX.fullmatch(key):
        return deny("invalid-recipient-key")
    if key in revoked_recipients:
        return deny("recipient-key-revoked")
    if key not in allowed_recipients:
        return deny("recipient-key-not-allowed")
    if (key in set(witness_organizations) if isinstance(witness_organizations, dict) else False):
        return deny("recipient-witness-role-collision")
    pub = recipient_roots.get(key)
    if not isinstance(pub, bytes) or len(pub) != 32 or hashlib.sha256(pub).hexdigest() != key:
        return deny("untrusted-recipient-key")
    encoded = receipt["signature_b64"]
    if not isinstance(encoded, str) or len(encoded) > 96:
        return deny("invalid-receipt-signature-format")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return deny("invalid-receipt-signature-format")
    if len(signature) != 64:
        return deny("invalid-receipt-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, RECEIPT_DOMAIN + raw)
    except (InvalidSignature, ValueError):
        return deny("invalid-receipt-signature")
    verified = witness.verify(history_inputs, status_records, package["witnesses"],
                              witness_roots, witness_organizations, revoked_witnesses,
                              minimum_organizations)
    if not verified["checkpoint_quorum_valid"]:
        return deny(verified["reason"])
    if not _matching_witnesses(package, package["witnesses"]):
        return deny("package-witness-mismatch")
    if package["checkpoint"] != package["witnesses"][0]["checkpoint"]:
        return deny("package-checkpoint-mismatch")
    return _result(receipt_valid=True, state="pending-review",
                   reason="authenticated-receipt-claim-not-proof-of-storage",
                   receipt_id=body["receipt_id"], recipient_key_id=key,
                   package_sha256=expected_package_hash)


def register_receipt(db, history_inputs, status_records, package, receipt,
                     expected_recipient, expected_package_hash, witness_roots,
                     witness_organizations, revoked_witnesses, minimum_organizations,
                     recipient_roots, revoked_recipients, allowed_recipients):
    checked = verify_receipt(
        history_inputs, status_records, package, receipt, expected_recipient,
        expected_package_hash, witness_roots, witness_organizations,
        revoked_witnesses, minimum_organizations, recipient_roots,
        revoked_recipients, allowed_recipients)
    if not checked["receipt_valid"]:
        return _result(recorded=False, reason=checked["reason"])
    if not isinstance(db, (str, Path)) or str(db) == ":memory:":
        return _result(recorded=False, reason="persistent-receipt-register-required")
    if Path(db).exists() and not Path(db).is_file():
        return _result(recorded=False, reason="invalid-register-target")
    rid, key = checked["receipt_id"], checked["recipient_key_id"]
    stamp = hashlib.sha256(RECEIPT_DOMAIN + canonical_receipt(receipt["receipt"])).hexdigest()
    with sqlite3.connect(str(db), timeout=5) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS delegation_handoff_receipts(
            receipt_id TEXT PRIMARY KEY, recipient_key_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL, package_sha256 TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            UNIQUE(recipient_key_id,recipient_id,package_sha256))""")
        existing = conn.execute("SELECT receipt_sha256 FROM delegation_handoff_receipts WHERE receipt_id=?",
                                (rid,)).fetchone()
        if existing is not None:
            conn.rollback()
            return _result(recorded=False, reason="receipt-replay" if existing[0] == stamp
                           else "receipt-id-conflict")
        try:
            event = audit.append(conn, rid, key, expected_recipient,
                                 expected_package_hash, stamp)
            conn.execute("INSERT INTO delegation_handoff_receipts VALUES(?,?,?,?,?)",
                         (rid, key, expected_recipient, expected_package_hash, stamp))
        except sqlite3.IntegrityError:
            conn.rollback()
            return _result(recorded=False, reason="duplicate-package-receipt")
    return _result(recorded=True, state="pending-review",
                   reason="local-receipt-indexed-no-authority",
                   entries=event["entries"], head_hash=event["head_hash"])
