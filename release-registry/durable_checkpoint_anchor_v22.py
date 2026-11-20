"""PALACO v22 durable checkpoint anchor candidate (local SQLite only).

This separately managed journal records verified, contiguous v21 checkpoints.
Local consistency cannot provide independent trust against privileged rollback.
The caller MUST independently authenticate decision receipts and the anchor
publisher. All reports remain DENY/HOLD; nothing is activated.
"""
from contextlib import closing
from pathlib import Path
import sqlite3

from monotonic_authority_checkpoints_v21 import (
    GENESIS, MAX_DECISIONS, CheckpointError, _walk,
)


class AnchorError(ValueError):
    pass


class DurableCheckpointAnchor:
    def __init__(self, path, *, timeout=5.0):
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise AnchorError("INVALID_DATABASE_PATH")
        self.path, self.timeout = str(target), timeout
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS anchored_checkpoints (
                    sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                    previous TEXT NOT NULL,
                    head TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS anchor_no_update
                  BEFORE UPDATE ON anchored_checkpoints
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS anchor_no_delete
                  BEFORE DELETE ON anchored_checkpoints
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @staticmethod
    def _load(db):
        rows = db.execute(
            "SELECT sequence,previous,head FROM anchored_checkpoints "
            "ORDER BY sequence").fetchall()
        previous = GENESIS
        for n, (sequence, stored_prev, head) in enumerate(rows, 1):
            if (type(sequence) is not int or sequence != n or
                    type(stored_prev) is not str or stored_prev != previous or
                    type(head) is not str or len(head) != 64 or
                    any(c not in "0123456789abcdef" for c in head)):
                raise AnchorError("CORRUPT_CHECKPOINT_CHAIN")
            previous = head
        return len(rows), previous

    def current(self):
        """Local checkpoint tuple, NEVER an independently trusted anchor."""
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                return self._load(db)
            finally:
                db.rollback()

    def advance(self, claims, receipts, *, expected_sequence, expected_head,
                verify_receipt, authorize_publish):
        """Append exactly one checkpoint with a serialized CAS transaction.

        Authorize callback MUST consult an independent authenticated publisher
        policy. Receipt verifier MUST check pinned Ed25519 keys and revocation.
        Both callbacks are external. None authenticates this DB to another host.
        """
        if (type(expected_sequence) is not int or expected_sequence < 0 or
                type(expected_head) is not str or
                not callable(verify_receipt) or not callable(authorize_publish)):
            raise AnchorError("EXTERNAL_POLICY_REQUIRED")
        if (type(claims) not in (tuple, list) or
                type(receipts) not in (tuple, list) or
                len(claims) != len(receipts) or
                len(claims) != expected_sequence + 1 or
                len(claims) > MAX_DECISIONS):
            raise AnchorError("NONCONTIGUOUS_ADVANCE")
        try:
            next_head, _ = _walk(claims, receipts, verify_receipt=verify_receipt)
            prefix_head, _ = _walk(claims[:-1], receipts[:-1],
                                   verify_receipt=verify_receipt)
        except (CheckpointError, ValueError, TypeError) as exc:
            raise AnchorError("UNVERIFIED_HISTORY") from exc
        if prefix_head != expected_head:
            raise AnchorError("HISTORY_PREFIX_MISMATCH")
        try:
            permitted = authorize_publish(expected_sequence + 1, next_head)
        except Exception as exc:
            raise AnchorError("PUBLISH_POLICY_UNAVAILABLE") from exc
        if permitted is not True:
            raise AnchorError("PUBLISH_DENIED")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                sequence, head = self._load(db)
                if sequence != expected_sequence or head != expected_head:
                    raise AnchorError("STALE_CHECKPOINT")
                db.execute(
                    "INSERT INTO anchored_checkpoints(sequence,previous,head) "
                    "VALUES(?,?,?)", (sequence + 1, head, next_head))
                db.commit()
                return {"schema": "palaco-checkpoint-publication/v22",
                        "sequence": sequence + 1, "head": next_head,
                        "authorization": "DENY", "release": "HOLD",
                        "production_release_enabled": False}
            except BaseException:
                db.rollback()
                raise

    def inspect(self, *, independently_verify_anchor):
        """Require external attestation before offering v21-compatible anchor.

        independently_verify_anchor(seq, head) MUST verify a separate secured
        monotonic record, not echo these locally read arguments.
        """
        if not callable(independently_verify_anchor):
            raise AnchorError("EXTERNAL_ANCHOR_REQUIRED")
        sequence, head = self.current()
        if sequence < 1:
            raise AnchorError("EMPTY_ANCHOR_NOT_TRUSTED")
        try:
            trusted = independently_verify_anchor(sequence, head)
        except Exception as exc:
            raise AnchorError("EXTERNAL_ANCHOR_UNAVAILABLE") from exc
        if trusted is not True:
            raise AnchorError("UNTRUSTED_ANCHOR")
        return (sequence, head)
