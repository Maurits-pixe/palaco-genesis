"""PALACO v23 checkpoint publication recovery, local durable intent journal.

A v19 authority commit and a v22 anchor commit cannot be atomic together.
This module stages an immutable publication intent and reconciles it after
interruptions. NO network, external trust source or release is provided.
"""
from contextlib import closing
from pathlib import Path
import sqlite3

from monotonic_authority_checkpoints_v21 import GENESIS, checkpoint_candidate, CheckpointError
from durable_checkpoint_anchor_v22 import AnchorError


class PublicationError(ValueError):
    pass


class CheckpointPublicationRecovery:
    """Single-writer logical queue. Append-only intent and completion tables.

    External publisher, signature verifier and independent attestation MUST be
    real, current, separated services. They are never derived from this DB.
    """
    def __init__(self, path, *, authority, anchor, timeout=5.0):
        if not hasattr(authority, "read_decisions") or not hasattr(anchor, "advance") or not hasattr(anchor, "current"):
            raise PublicationError("INVALID_DEPENDENCIES")
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise PublicationError("INVALID_PATH")
        self.path, self.timeout = str(target), timeout
        self.authority, self.anchor = authority, anchor
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS publication_intents (
                    sequence INTEGER PRIMARY KEY CHECK(sequence>0),
                    previous_head TEXT NOT NULL,
                    head TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS publication_completions (
                    sequence INTEGER PRIMARY KEY CHECK(sequence>0),
                    head TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS intents_no_update BEFORE UPDATE ON publication_intents
                    BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS intents_no_delete BEFORE DELETE ON publication_intents
                    BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS completions_no_update BEFORE UPDATE ON publication_completions
                    BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS completions_no_delete BEFORE DELETE ON publication_completions
                    BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @staticmethod
    def _load(db):
        intents = db.execute(
            "SELECT sequence,previous_head,head FROM publication_intents ORDER BY sequence"
        ).fetchall()
        completions = db.execute(
            "SELECT sequence,head FROM publication_completions ORDER BY sequence"
        ).fetchall()
        prev = GENESIS
        for i, (seq, before, after) in enumerate(intents, 1):
            if (seq != i or before != prev or type(after) is not str or
                    len(after) != 64 or any(x not in '0123456789abcdef' for x in after)):
                raise PublicationError("CORRUPT_INTENT_CHAIN")
            prev = after
        for i, (seq, head) in enumerate(completions, 1):
            if i > len(intents) or seq != i or head != intents[i-1][2]:
                raise PublicationError("CORRUPT_COMPLETION_CHAIN")
        if len(intents) > len(completions) + 1:
            raise PublicationError("MULTIPLE_UNFINISHED_INTENTS")
        return intents, completions

    def inspect_local(self):
        """Untrusted local diagnostics only, never an authentication signal."""
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                intents, completions = self._load(db)
                return {"intent_count": len(intents),
                        "completion_count": len(completions),
                        "pending": len(intents) > len(completions),
                        "authorization": "DENY", "release": "HOLD",
                        "production_release_enabled": False}
            finally:
                db.rollback()

    def stage_next(self):
        """Stage next uncommitted authority decision, without publishing it.

        Stage cannot infer remote/global authority from v19 local history.
        """
        claims, receipts = self.authority.read_decisions()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                intents, completions = self._load(db)
                if len(intents) != len(completions):
                    raise PublicationError("PENDING_INTENT_EXISTS")
                local_seq, local_head = self.anchor.current()
                if (local_seq != len(intents) or
                        local_head != (GENESIS if not intents else intents[-1][2])):
                    raise PublicationError("ANCHOR_AND_OUTBOX_DIVERGED")
                next_seq = local_seq + 1
                if len(claims) < next_seq or len(receipts) < next_seq:
                    raise PublicationError("NO_UNPUBLISHED_DECISION")
                prefix = checkpoint_candidate(claims[:next_seq], receipts[:next_seq])
                previous = checkpoint_candidate(claims[:local_seq], receipts[:local_seq])
                if previous["head"] != local_head:
                    raise PublicationError("AUTHORITY_HISTORY_DIVERGED")
                db.execute(
                    "INSERT INTO publication_intents(sequence,previous_head,head) VALUES(?,?,?)",
                    (next_seq, local_head, prefix["head"]))
                db.commit()
                return {"sequence": next_seq, "head": prefix["head"],
                        "state": "PENDING", "authorization": "DENY", "release": "HOLD"}
            except BaseException:
                db.rollback()
                raise

    def reconcile(self, *, verify_receipt, authorize_publish, independently_verify_anchor):
        """Recover lost acknowledgement; no double append or trust fallback.

        If v22 already has target checkpoint, verify external anchor then
        finalize. If still at predecessor, publish once then verify externally.
        Any divergence/unavailability fails closed and retains pending intent.
        """
        if not all(callable(fn) for fn in (
                verify_receipt, authorize_publish, independently_verify_anchor)):
            raise PublicationError("EXTERNAL_TRUST_REQUIRED")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                intents, completions = self._load(db)
                if len(intents) == len(completions):
                    raise PublicationError("NO_PENDING_INTENT")
                seq, prior, head = intents[-1]
                claims, receipts = self.authority.read_decisions()
                if len(claims) < seq or len(receipts) < seq:
                    raise PublicationError("MISSING_AUTHORITY_HISTORY")
                preview = checkpoint_candidate(claims[:seq], receipts[:seq])
                predecessor = checkpoint_candidate(claims[:seq-1], receipts[:seq-1])
                if preview["head"] != head or predecessor["head"] != prior:
                    raise PublicationError("AUTHORITY_HISTORY_DIVERGED")
                current = self.anchor.current()
                if current == (seq-1, prior):
                    try:
                        self.anchor.advance(
                            claims[:seq], receipts[:seq], expected_sequence=seq-1,
                            expected_head=prior, verify_receipt=verify_receipt,
                            authorize_publish=authorize_publish)
                    except AnchorError as exc:
                        # A concurrent publisher may have succeeded. Reinspect.
                        if self.anchor.current() != (seq, head):
                            raise PublicationError("ANCHOR_PUBLISH_FAILED") from exc
                elif current != (seq, head):
                    raise PublicationError("ANCHOR_AND_OUTBOX_DIVERGED")
                # Never trust a local checkpoint alone.
                if self.anchor.current() != (seq, head):
                    raise PublicationError("ANCHOR_AND_OUTBOX_DIVERGED")
                try:
                    trusted = independently_verify_anchor(seq, head)
                except Exception as exc:
                    raise PublicationError("EXTERNAL_ANCHOR_UNAVAILABLE") from exc
                if trusted is not True:
                    raise PublicationError("EXTERNAL_ANCHOR_UNVERIFIED")
                db.execute(
                    "INSERT INTO publication_completions(sequence,head) VALUES(?,?)",
                    (seq, head))
                db.commit()
                return {"sequence": seq, "head": head, "state": "LOCALLY_RECONCILED",
                        "authorization": "DENY", "release": "HOLD",
                        "production_release_enabled": False}
            except BaseException:
                db.rollback()
                raise
