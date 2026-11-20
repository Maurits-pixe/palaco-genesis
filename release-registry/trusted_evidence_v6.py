"""PALACO v6 independently anchored evidence inspection contract (draft).

The caller must supply independently implemented signature/policy verification,
revocation knowledge and an external monotonic checkpoint. This code never
issues an authorization or verifies a real signature by itself.
"""
import hashlib
import hmac
import re

from offline_stage import _canonical
from trusted_recovery import RecoveryError, verify_backup, checkpoint_statement

SCHEMA = "palaco-trusted-evidence/v6"
HEX = re.compile(r"[0-9a-f]{64}\Z")
KEY_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
DOMAIN = b"PALACO-TRUSTED-EVIDENCE-v6:ATTESTATION\x00"


class EvidenceError(ValueError):
    pass


def attestation_bytes(*, scope, checkpoint, backup_sha256, key_id):
    """Unambiguous bytes for an external signature verification provider."""
    if type(backup_sha256) is not str or not HEX.fullmatch(backup_sha256):
        raise EvidenceError("INVALID_BACKUP_DIGEST")
    if type(key_id) is not str or not KEY_ID.fullmatch(key_id):
        raise EvidenceError("INVALID_KEY_ID")
    try:
        statement = checkpoint_statement(
            scope=scope, sequence=checkpoint["sequence"], head=checkpoint["head"])
    except (RecoveryError, KeyError, TypeError) as exc:
        raise EvidenceError("INVALID_CHECKPOINT") from exc
    return DOMAIN + _canonical({
        "checkpoint_sha256": hashlib.sha256(statement).hexdigest(),
        "backup_sha256": backup_sha256, "key_id": key_id,
        "schema": SCHEMA, "scope": scope,
    })


def inspect_evidence(backup_bytes, checkpoint, attestation, *, scope,
                     verify_checkpoint=None, verify_attestation=None,
                     get_trusted_anchor=None):
    """Inspect an immutable candidate without granting any permission.

    The three external callbacks are REQUIRED and independent of backup data.
    get_trusted_anchor(scope) must return an externally pinned (sequence, head)
    from a trustworthy monotonic registry, never from the submitted files.
    Callbacks returning non-boolean truthy values are denied.
    """
    if type(attestation) is not dict or set(attestation) != {
        "schema", "scope", "key_id", "signature"
    }:
        raise EvidenceError("INVALID_ATTESTATION")
    if attestation["schema"] != SCHEMA or attestation["scope"] != scope:
        raise EvidenceError("SCOPE_MISMATCH")
    key_id, signature = attestation["key_id"], attestation["signature"]
    if type(signature) is not str or not 1 <= len(signature) <= 8192:
        raise EvidenceError("INVALID_SIGNATURE_ENCODING")
    if not callable(verify_checkpoint) or not callable(verify_attestation) or not callable(get_trusted_anchor):
        raise EvidenceError("EXTERNAL_TRUST_REQUIRED")
    try:
        anchor = get_trusted_anchor(scope)
    except Exception as exc:
        raise EvidenceError("ANCHOR_UNAVAILABLE") from exc
    if (type(anchor) is not tuple or len(anchor) != 2 or
            type(anchor[0]) is not int or type(anchor[1]) is not str or
            not HEX.fullmatch(anchor[1]) or
            type(checkpoint) is not dict or
            anchor != (checkpoint.get("sequence"), checkpoint.get("head"))):
        raise EvidenceError("ANCHOR_MISMATCH")
    try:
        events, head = verify_backup(
            backup_bytes, checkpoint, scope=scope, verify=verify_checkpoint)
    except (RecoveryError, ValueError, TypeError) as exc:
        raise EvidenceError("BACKUP_NOT_VERIFIED") from exc
    statement = attestation_bytes(
        scope=scope, checkpoint=checkpoint,
        backup_sha256=hashlib.sha256(backup_bytes).hexdigest(), key_id=key_id)
    try:
        valid = verify_attestation(statement, signature, key_id)
    except Exception as exc:
        raise EvidenceError("ATTESTATION_NOT_VERIFIED") from exc
    if valid is not True:
        raise EvidenceError("ATTESTATION_NOT_VERIFIED")
    # No receipt, event bodies, keys or signatures in this report.
    return {
        "schema": "palaco-evidence-inspection/v6",
        "scope": scope, "sequence": len(events),
        "head": head, "backup_sha256": hashlib.sha256(backup_bytes).hexdigest(),
        "key_id": key_id, "evidence_verification": "EXTERNAL_CALLBACK_ACCEPTED",
        "authorization": "DENY", "release": "HOLD",
        "production_release_enabled": False,
    }
