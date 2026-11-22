"""Read-only recovery inspection for a PALACO Bluetooth receipt checkpoint.

This inspector NEVER repairs, inserts, initializes or advances checkpoints.
A matching report is diagnostic only: it is NOT permission to import records,
release a deployment, or treat a test anchor as a real secure element.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import sqlite3

from protocol import TransferError
from receipt_integrity import _check_anchor_state, receipt_commitment


class RecoveryStatus(Enum):
    MATCH = "match"
    DATABASE_AHEAD = "database_ahead"
    ANCHOR_AHEAD = "anchor_ahead"
    CONTENT_MISMATCH = "content_mismatch"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class RecoveryReport:
    status: RecoveryStatus
    database_count: int | None
    anchor_count: int | None
    database_root: str | None
    anchor_root: str | None

    @property
    def requires_hold(self) -> bool:
        """All nonmatches require manual investigation, never auto-recovery."""
        return self.status is not RecoveryStatus.MATCH


def inspect_checkpoint(database_path, anchor) -> RecoveryReport:
    """Read-only classification, with no schema creation or state mutation."""
    unavailable = RecoveryReport(RecoveryStatus.UNAVAILABLE, None, None, None, None)
    try:
        path = Path(database_path)
        if (not path.is_absolute() or path.is_symlink() or
                not path.is_file() or not path.parent.is_dir()):
            return unavailable
        if not callable(getattr(anchor, "read", None)):
            return unavailable
        trusted = _check_anchor_state(anchor.read())
        # SQLite URI mode=ro is deliberate: no creating absent databases.
        uri = path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            db.execute("PRAGMA query_only=ON")
            rows = db.execute(
                "SELECT transfer_id, payload_sha256 "
                "FROM completed_transfers ORDER BY transfer_id"
            ).fetchall()
        actual = (len(rows), receipt_commitment(rows))
    except (OSError, sqlite3.Error, TransferError, TypeError, ValueError):
        return unavailable
    if actual[0] > trusted[0]:
        status = RecoveryStatus.DATABASE_AHEAD
    elif actual[0] < trusted[0]:
        status = RecoveryStatus.ANCHOR_AHEAD
    elif actual[1] != trusted[1]:
        status = RecoveryStatus.CONTENT_MISMATCH
    else:
        status = RecoveryStatus.MATCH
    return RecoveryReport(status, actual[0], trusted[0], actual[1], trusted[1])
