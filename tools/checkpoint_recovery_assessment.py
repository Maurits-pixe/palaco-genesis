#!/usr/bin/env python3
"""Read-only local checkpoint recovery assessment: never repairs or authorizes.

Requires an independently obtained signed checkpoint, issuer trust roots,
revocation policy and trusted minimum sequence. No external witness service.
"""
import importlib.util
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checkpoint = _load("palaco_recovery_checkpoint", "signed_audit_checkpoint.py")
registry = _load("palaco_recovery_registry", "local_checkpoint_registry.py")


def _db_integrity(path):
    if not isinstance(path, (str, Path)) or not Path(path).is_file():
        return "missing-database"
    conn = None
    try:
        conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        check = conn.execute("PRAGMA integrity_check").fetchone()
        if check != ("ok",):
            return "sqlite-integrity-failed"
    except (sqlite3.Error, OSError, ValueError):
        return "unreadable-database"
    finally:
        if conn is not None:
            conn.close()
    return None


def assess(evidence_db, checkpoint_db, witness, issuer_roots,
           revoked_issuers, minimum_sequence):
    """Fail closed: identical trusted checkpoint must match both local stores.

    Read-only, no creation/migration; snapshots can race with concurrent
    writers. A valid local assessment never means it is safe to restore.
    """
    base = {"schema_version": "0.1.0", "release_gate": "HOLD",
            "authorization_granted": False, "automatic_restore": False,
            "recovery_approved": False, "state": "quarantined"}
    def reject(reason):
        return {**base, "reason": reason}
    if not isinstance(issuer_roots, dict) or not isinstance(revoked_issuers, (set, frozenset)):
        return reject("missing-trust-policy")
    if any(not isinstance(x, str) or not checkpoint.HEX.fullmatch(x) for x in revoked_issuers):
        return reject("invalid-revocation-policy")
    if not isinstance(witness, dict) or set(witness) != checkpoint.ENVELOPE:
        return reject("invalid-witness")
    issuer = witness.get("issuer_key_id")
    if not isinstance(issuer, str) or not checkpoint.HEX.fullmatch(issuer):
        return reject("invalid-witness-issuer")
    if issuer in revoked_issuers:
        return reject("witness-issuer-revoked")
    if type(minimum_sequence) is not int or not 1 <= minimum_sequence <= checkpoint.audit.MAX_EVENTS:
        return reject("missing-trusted-minimum")
    # Check both databases without performing migrations or writes.
    for name, path in (("evidence", evidence_db), ("checkpoint", checkpoint_db)):
        issue = _db_integrity(path)
        if issue:
            return reject(name + "-" + issue)
    checked = checkpoint.verify_checkpoint(evidence_db, witness, issuer_roots, minimum_sequence)
    if not checked["checkpoint_valid"]:
        return reject(checked["reason"])
    local = registry.read_floor(checkpoint_db, issuer)
    if local is None:
        return reject("checkpoint-floor-missing-or-unreadable")
    seq, head = local.get("sequence"), local.get("head_hash")
    witnessed_seq, witnessed_hash = checked["sequence"], checked["head_hash"]
    if type(seq) is not int or seq < witnessed_seq:
        return reject("checkpoint-store-rollback")
    if seq > witnessed_seq:
        return reject("witness-older-than-checkpoint-store")
    if head != witnessed_hash:
        return reject("checkpoint-store-equivocation")
    return {**base, "state": "pending-review", "reason": "local-consistency-only-external-trust-unverified",
            "witness_sequence": witnessed_seq, "witness_head": witnessed_hash}
