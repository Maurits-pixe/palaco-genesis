"""Non-overwriting candidate restore into a *new* SQLite file.

Only metadata events. Caller must supply a trusted recovery verifier and
independent approval callback. Neither callback is implemented here.
Not a production backup or identity system.
"""
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile

from offline_journal import OfflineJournal
from offline_stage import GENESIS, _canonical
from trusted_recovery import RecoveryError, verify_backup

APPROVAL_DOMAIN = b"PALACO-SECURE-RESTORE-v3:APPROVAL\x00"


def approval_statement(*, scope, checkpoint, backup_bytes, destination):
    """Bind approval to exact bytes, checkpoint, scope and destination name."""
    if type(destination) is not str or not destination or "/" in destination or "\\" in destination:
        raise RecoveryError("INVALID_DESTINATION_NAME")
    if destination in (".", "..") or destination.startswith("."):
        raise RecoveryError("INVALID_DESTINATION_NAME")
    if type(backup_bytes) is not bytes:
        raise RecoveryError("INVALID_BACKUP")
    return APPROVAL_DOMAIN + _canonical({
        "scope": scope, "sequence": checkpoint["sequence"],
        "head": checkpoint["head"],
        "destination": destination,
        "backup_sha256": hashlib.sha256(backup_bytes).hexdigest(),
    })


def restore_to_new_file(backup_bytes, checkpoint, *, scope, verify=None,
                        approve=None, destination):
    """Restore *only* to a never-existing path; no replacement is possible.

    Approve receives canonical binding bytes and MUST independently check
    human consent and policy. A true-only callback is a test fixture, NOT
    actual authorization. A transaction writes the temporary journal.
    The hard-link publishes it without replacing an existing destination.
    """
    events, head = verify_backup(backup_bytes, checkpoint, scope=scope, verify=verify)
    target = Path(destination)
    name = target.name
    if not target.is_absolute() or target.is_symlink() or target.exists():
        raise RecoveryError("INVALID_OR_OCCUPIED_DESTINATION")
    parent = target.parent
    if not parent.is_dir() or parent.is_symlink():
        raise RecoveryError("INVALID_PARENT")
    # Reject traversal or aliases before touching disk.
    if target != parent / name or name in ("", ".", "..") or name.startswith("."):
        raise RecoveryError("INVALID_DESTINATION_NAME")
    statement = approval_statement(
        scope=scope, checkpoint=checkpoint,
        backup_bytes=backup_bytes, destination=name)
    if not callable(approve):
        raise RecoveryError("APPROVAL_REQUIRED")
    try:
        approved = approve(statement)
    except Exception as exc:
        raise RecoveryError("APPROVAL_FAILED") from exc
    if approved is not True:
        raise RecoveryError("APPROVAL_FAILED")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=parent, prefix=".palaco-restore-",
                                         suffix=".sqlite", delete=False) as f:
            temporary = Path(f.name)
        journal = OfflineJournal(temporary)
        with sqlite3.connect(temporary, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            try:
                db.executemany(
                    "INSERT INTO events(sequence,event_id,event_json) VALUES (?,?,?)",
                    [(e["sequence"], e["event_id"], _canonical(e)) for e in events])
                db.commit()
            except BaseException:
                db.rollback()
                raise
        restored, restored_head = journal.read(expected_head=head)
        if restored != events or restored_head != head:
            raise RecoveryError("RESTORE_REPLAY_MISMATCH")
        with open(temporary, "rb") as f:
            os.fsync(f.fileno())
        # A hard link fails atomically if target already exists; never overwrite.
        os.link(temporary, target)
        # Persist directory entry where supported.
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Directory fsync is unavailable on some operating systems.
            # This candidate does not claim crash durability on those OSes.
            pass
        return str(target), restored_head, len(restored)
    except FileExistsError as exc:
        raise RecoveryError("DESTINATION_ALREADY_EXISTS") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
