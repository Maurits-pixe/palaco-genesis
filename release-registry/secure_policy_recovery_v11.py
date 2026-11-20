"""PALACO v11 new-file-only recovery of a v9 policy ledger (candidate).

Inputs are UNTRUSTED. Independent monotonic anchor, current policy and human
approval must be provided by verified external integrations. No overwrite,
production permission, signing or active-key issuance is performed.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from durable_policy_journal_v10 import DurablePolicyJournal
from offline_stage import _canonical
from policy_ledger_v9 import LedgerError, replay_ledger, verify_anchored_ledger

SCHEMA = "palaco-policy-backup/v11"
DOMAIN = b"PALACO-POLICY-RECOVERY-v11:APPROVAL\x00"
MAX_BACKUP = 8_388_608


class RestoreError(ValueError):
    pass


def inspect_backup(data, *, get_trusted_anchor=None, verify_policy=None):
    """Return frozen metadata events and a DENY-only report.

    A hash-matching self-supplied anchor is NOT trusted; callback providers
    must be independent of backup files and possess current revocation state.
    """
    if type(data) is not bytes or len(data) > MAX_BACKUP:
        raise RestoreError("INVALID_BACKUP_SIZE")
    try:
        document = json.loads(data.decode("ascii"))
        if type(document) is not dict or set(document) != {"schema", "events"}:
            raise RestoreError("INVALID_BACKUP_SCHEMA")
        if document["schema"] != SCHEMA or type(document["events"]) is not list:
            raise RestoreError("INVALID_BACKUP_SCHEMA")
        if _canonical(document) != data:
            raise RestoreError("NONCANONICAL_BACKUP")
        events = document["events"]
        report = verify_anchored_ledger(
            events, get_trusted_anchor=get_trusted_anchor,
            verify_policy=verify_policy)
    except (UnicodeError, ValueError, TypeError, OverflowError, LedgerError) as exc:
        if isinstance(exc, RestoreError):
            raise
        raise RestoreError("BACKUP_NOT_TRUSTED") from exc
    return tuple(events), report


def approval_bytes(*, data, destination_name, sequence, head):
    """Domain-separated approval for exact backup, target basename and head."""
    if (type(destination_name) is not str or not destination_name or
            destination_name in (".", "..") or
            destination_name.startswith(".") or "/" in destination_name or
            "\\" in destination_name or ":" in destination_name):
        raise RestoreError("INVALID_DESTINATION")
    return DOMAIN + _canonical({
        "schema": SCHEMA, "destination_name": destination_name,
        "backup_sha256": hashlib.sha256(data).hexdigest(),
        "sequence": sequence, "head": head})


def restore_new_journal(data, destination, *, get_trusted_anchor=None,
                        verify_policy=None, approve=None):
    """One isolated local restore; publishes by no-overwrite hard link.

    The independent approve(statement) callback must implement actual human
    consent/authority. Test-fixture callbacks are NEVER production consent.
    """
    events, report = inspect_backup(
        data, get_trusted_anchor=get_trusted_anchor,
        verify_policy=verify_policy)
    target = Path(destination)
    if not target.is_absolute() or target.is_symlink() or target.exists():
        raise RestoreError("DESTINATION_OCCUPIED_OR_INVALID")
    parent = target.parent
    if not parent.is_dir() or parent.is_symlink():
        raise RestoreError("INVALID_DESTINATION_PARENT")
    statement = approval_bytes(
        data=data, destination_name=target.name,
        sequence=report["sequence"], head=report["head"])
    if not callable(approve):
        raise RestoreError("APPROVAL_REQUIRED")
    try:
        approved = approve(statement)
    except Exception as exc:
        raise RestoreError("APPROVAL_UNAVAILABLE") from exc
    if approved is not True:
        raise RestoreError("APPROVAL_DENIED")

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                dir=parent, prefix=".palaco-policy-restore-",
                suffix=".sqlite", delete=False) as handle:
            temporary = Path(handle.name)
        journal = DurablePolicyJournal(temporary)
        with sqlite3.connect(temporary, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            try:
                db.executemany(
                    "INSERT INTO policy_events(sequence,body) VALUES(?,?)",
                    [(event["sequence"], _canonical(event)) for event in events])
                db.commit()
            except BaseException:
                db.rollback()
                raise
        restored, head, _ = journal.read(expected_head=report["head"])
        if restored != events or head != report["head"]:
            raise RestoreError("REPLAY_MISMATCH")
        with open(temporary, "rb") as handle:
            os.fsync(handle.fileno())
        # Atomic no-replace publication on filesystems supporting hard links.
        os.link(temporary, target)
        return {"schema": "palaco-policy-restore-report/v11",
                "sequence": len(events), "head": head,
                "destination": str(target), "release": "HOLD",
                "authorization": "DENY", "production_release_enabled": False}
    except FileExistsError as exc:
        raise RestoreError("DESTINATION_OCCUPIED") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def make_backup(events):
    """Create canonical bytes for isolated test fixtures; NOT an attestation."""
    replay_ledger(events)
    return _canonical({"schema": SCHEMA, "events": list(events)})
