"""Fail-closed, read-only recovery checkpoint boundary for offline journals.

An independently trusted verifier MUST be injected by the caller. The library
does not provide that verifier, keys, signatures, trusted time, or authorization.
Never use an always-true verifier outside isolated tests.
"""
import hashlib
import hmac
import json
import re

from offline_stage import GENESIS, _canonical, replay, StageError, MAX_EVENTS
from offline_journal import JournalError

SCHEMA = "palaco-trusted-recovery/v2"
HEX = re.compile(r"[0-9a-f]{64}\Z")
SCOPE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
DOMAIN = b"PALACO-TRUSTED-RECOVERY-v2:CHECKPOINT\x00"


class RecoveryError(ValueError):
    pass


def checkpoint_statement(*, scope, sequence, head):
    """Canonical bytes for an external signer or verifier.

    No signatures, secrets or credentials are created by this function.
    """
    if type(scope) is not str or not SCOPE.fullmatch(scope):
        raise RecoveryError("INVALID_SCOPE")
    if type(sequence) is not int or not 0 <= sequence <= MAX_EVENTS:
        raise RecoveryError("INVALID_SEQUENCE")
    if type(head) is not str or not HEX.fullmatch(head):
        raise RecoveryError("INVALID_HEAD")
    if sequence == 0 and head != GENESIS:
        raise RecoveryError("INVALID_GENESIS")
    return DOMAIN + _canonical({"schema": SCHEMA, "scope": scope,
                                 "sequence": sequence, "head": head})


def _verified(checkpoint, *, scope, verify):
    if type(checkpoint) is not dict or set(checkpoint) != {
        "schema", "scope", "sequence", "head", "receipt"
    }:
        raise RecoveryError("INVALID_CHECKPOINT")
    if checkpoint["schema"] != SCHEMA or checkpoint["scope"] != scope:
        raise RecoveryError("SCOPE_MISMATCH")
    # Receipt is opaque. A real integration must enforce signer identity,
    # authorization, revocation, freshness and a monotonic external anchor.
    receipt = checkpoint["receipt"]
    if type(receipt) is not str or not 1 <= len(receipt) <= 4096:
        raise RecoveryError("INVALID_RECEIPT")
    statement = checkpoint_statement(
        scope=checkpoint["scope"], sequence=checkpoint["sequence"],
        head=checkpoint["head"])
    if not callable(verify):
        raise RecoveryError("TRUST_VERIFIER_REQUIRED")
    try:
        result = verify(statement, receipt)
    except Exception as exc:
        raise RecoveryError("TRUST_VERIFICATION_FAILED") from exc
    if result is not True:
        raise RecoveryError("TRUST_VERIFICATION_FAILED")
    return statement


def verify_recovery(journal, checkpoint, *, scope, verify=None):
    """Return metadata only after replay and external checkpoint verification.

    This read does not install a checkpoint or restore the database.
    The caller's verify function is the *only* external trust boundary.
    """
    _verified(checkpoint, scope=scope, verify=verify)
    try:
        events, head = journal.read(expected_head=checkpoint["head"])
    except (JournalError, OSError, ValueError) as exc:
        raise RecoveryError("JOURNAL_VERIFICATION_FAILED") from exc
    if len(events) != checkpoint["sequence"] or not hmac.compare_digest(
        head, checkpoint["head"]
    ):
        raise RecoveryError("RECOVERY_STATE_MISMATCH")
    return events, head


def prepare_backup(journal, checkpoint, *, scope, verify=None):
    """Generate a deterministic metadata-only backup, without writing to disk."""
    events, head = verify_recovery(journal, checkpoint, scope=scope, verify=verify)
    data = {"schema": SCHEMA, "scope": scope, "sequence": len(events),
            "head": head, "events": list(events)}
    return _canonical(data)


def verify_backup(backup_bytes, checkpoint, *, scope, verify=None):
    """Inspect backup bytes without executing code or replacing journal state."""
    _verified(checkpoint, scope=scope, verify=verify)
    if type(backup_bytes) is not bytes or len(backup_bytes) > 8_388_608:
        raise RecoveryError("INVALID_BACKUP")
    try:
        data = json.loads(backup_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise RecoveryError("INVALID_BACKUP_JSON") from exc
    if type(data) is not dict or set(data) != {
        "schema", "scope", "sequence", "head", "events"
    } or data["schema"] != SCHEMA or data["scope"] != scope:
        raise RecoveryError("INVALID_BACKUP_SCHEMA")
    if _canonical(data) != backup_bytes or type(data["events"]) is not list:
        raise RecoveryError("NONCANONICAL_BACKUP")
    try:
        head = replay(data["events"])
    except StageError as exc:
        raise RecoveryError("INVALID_BACKUP_CHAIN") from exc
    if (type(data["sequence"]) is not int or
            data["sequence"] != len(data["events"]) or
            not hmac.compare_digest(head, checkpoint["head"]) or
            data["sequence"] != checkpoint["sequence"] or
            data["head"] != head):
        raise RecoveryError("BACKUP_CHECKPOINT_MISMATCH")
    return tuple(data["events"]), head
