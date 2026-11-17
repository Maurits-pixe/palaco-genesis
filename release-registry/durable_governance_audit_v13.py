"""PALACO v13 governance audit journal candidate.

Durable local review evidence is not independently authenticated evidence.
All external role and monotonic-anchor checks are delegated to v12. No release,
restore action, key issuance or account authorization is exposed.
"""
from contextlib import closing
import json
from pathlib import Path
import sqlite3

from offline_stage import _canonical
from recovery_governance_v12 import (
    GENESIS, GovernanceError, record_review, replay_reviews, inspect_governance,
)


class AuditJournalError(GovernanceError):
    pass


class DurableGovernanceAudit:
    """One permanently bound recovery proposal per SQLite database.

    All read/write paths validate the immutable proposal and complete review
    chain. Caller-supplied expected_head only provides local concurrency safety,
    NOT resistance to malicious database replacement/rollback.
    """

    def __init__(self, path, *, timeout=5.0):
        self.path = str(Path(path))
        self.timeout = timeout
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS audit_proposal (
                    slot INTEGER PRIMARY KEY CHECK(slot = 1),
                    body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_reviews (
                    review_index INTEGER PRIMARY KEY CHECK(review_index > 0),
                    actor_id TEXT NOT NULL UNIQUE,
                    body BLOB NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS proposal_no_update
                    BEFORE UPDATE ON audit_proposal
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS proposal_no_delete
                    BEFORE DELETE ON audit_proposal
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS reviews_no_update
                    BEFORE UPDATE ON audit_reviews
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS reviews_no_delete
                    BEFORE DELETE ON audit_reviews
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA synchronous = FULL")
        db.execute("PRAGMA busy_timeout = 5000")
        return db

    @staticmethod
    def _frozen(value):
        try:
            return json.loads(_canonical(value))
        except (ValueError, TypeError, OverflowError) as exc:
            raise AuditJournalError("INVALID_INPUT") from exc

    @classmethod
    def _load(cls, db):
        row = db.execute("SELECT body FROM audit_proposal WHERE slot=1").fetchone()
        if row is None:
            if db.execute("SELECT 1 FROM audit_reviews LIMIT 1").fetchone():
                raise AuditJournalError("ORPHAN_REVIEWS")
            raise AuditJournalError("PROPOSAL_NOT_BOUND")
        raw_plan = row[0]
        if type(raw_plan) is not bytes:
            raise AuditJournalError("CORRUPT_PROPOSAL")
        try:
            plan = json.loads(raw_plan.decode("ascii"))
            if _canonical(plan) != raw_plan:
                raise AuditJournalError("CORRUPT_PROPOSAL")
            # v12 validates the exact plan shape even with zero reviews.
            replay_reviews((), plan=plan)
        except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
            raise AuditJournalError("CORRUPT_PROPOSAL") from exc

        reviews = []
        for index, actor, raw in db.execute(
                "SELECT review_index,actor_id,body FROM audit_reviews ORDER BY review_index"):
            if type(raw) is not bytes:
                raise AuditJournalError("CORRUPT_REVIEW")
            try:
                review = json.loads(raw.decode("ascii"))
                if (_canonical(review) != raw or type(review) is not dict or
                        type(review.get("index")) is not int or
                        review["index"] != index or review.get("actor_id") != actor):
                    raise AuditJournalError("CORRUPT_REVIEW")
            except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
                raise AuditJournalError("CORRUPT_REVIEW") from exc
            reviews.append(review)
        try:
            head = replay_reviews(reviews, plan=plan)
        except (GovernanceError, ValueError, TypeError, OverflowError) as exc:
            raise AuditJournalError("CORRUPT_AUDIT_CHAIN") from exc
        return plan, tuple(reviews), head

    def bind(self, plan):
        """Initial bind only. Never replace an existing plan."""
        frozen = self._frozen(plan)
        replay_reviews((), plan=frozen)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT 1 FROM audit_proposal LIMIT 1").fetchone():
                    raise AuditJournalError("PROPOSAL_ALREADY_BOUND")
                if db.execute("SELECT 1 FROM audit_reviews LIMIT 1").fetchone():
                    raise AuditJournalError("ORPHAN_REVIEWS")
                db.execute("INSERT INTO audit_proposal(slot,body) VALUES(1,?)",
                           (_canonical(frozen),))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return GENESIS

    def read(self, *, expected_head):
        """Replay in a consistent read transaction; does NOT assert trust."""
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                plan, reviews, head = self._load(db)
                if type(expected_head) is not str or expected_head != head:
                    raise AuditJournalError("STALE_AUDIT_HEAD")
                return plan, reviews, head
            finally:
                db.rollback()

    def append(self, *, expected_head, actor_id, role, verdict, receipt):
        """Atomic review append with unique reviewer and chain consistency."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                plan, reviews, head = self._load(db)
                if type(expected_head) is not str or expected_head != head:
                    raise AuditJournalError("STALE_AUDIT_HEAD")
                event, next_head = record_review(
                    reviews, plan=plan, expected_head=head,
                    actor_id=actor_id, role=role, verdict=verdict, receipt=receipt)
                db.execute(
                    "INSERT INTO audit_reviews(review_index,actor_id,body) VALUES(?,?,?)",
                    (event["index"], event["actor_id"], _canonical(event)))
                db.commit()
                return event, next_head
            except BaseException:
                db.rollback()
                raise

    def inspect(self, *, verify_role, get_trusted_audit_anchor):
        """Independent external review verification; diagnostic HOLD only."""
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                plan, reviews, _ = self._load(db)
                return inspect_governance(
                    reviews, plan=plan, verify_role=verify_role,
                    get_trusted_audit_anchor=get_trusted_audit_anchor)
            finally:
                db.rollback()
