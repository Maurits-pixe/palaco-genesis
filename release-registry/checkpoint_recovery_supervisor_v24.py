"""PALACO v24 checkpoint recovery supervisor (isolated development candidate).

Single explicit attempt per call. No scheduler, sleep, background automation,
production permissions, approval, or actual trusted anchor implementation.
Only temporary external anchor outages are eligible for bounded retry.
"""
from contextlib import closing
from pathlib import Path
import re
import sqlite3

from checkpoint_publication_recovery_v23 import PublicationError

HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_ATTEMPTS = 3
RETRYABLE = frozenset(("EXTERNAL_ANCHOR_UNAVAILABLE",))
TERMINAL = frozenset(("SUCCEEDED", "BLOCKED", "EXHAUSTED"))


class SupervisorError(ValueError):
    pass


def _classification(code):
    if code in RETRYABLE:
        return "RETRYABLE"
    return "BLOCKED"


def _code(exc):
    """Whitelist stable v23 error codes; never persist raw exception details."""
    if type(exc) is PublicationError and len(exc.args) == 1 and (
            type(exc.args[0]) is str):
        return exc.args[0] if exc.args[0] in {
            "EXTERNAL_ANCHOR_UNAVAILABLE", "EXTERNAL_ANCHOR_UNVERIFIED",
            "ANCHOR_PUBLISH_FAILED", "ANCHOR_AND_OUTBOX_DIVERGED",
            "AUTHORITY_HISTORY_DIVERGED", "MISSING_AUTHORITY_HISTORY",
            "EXTERNAL_TRUST_REQUIRED", "NO_PENDING_INTENT",
        } else "UNRECOGNIZED_PUBLICATION_FAILURE"
    return "UNEXPECTED_FAILURE"


class CheckpointRecoverySupervisor:
    """Persist bounded attempt records separate from the immutable v23 outbox.

    Concurrent invocations are serialized by SQLite BEGIN IMMEDIATE. Caller
    must explicitly invoke run_once; a failed external trust provider never
    triggers implicit acceptance, unbounded retry or production activation.
    """

    def __init__(self, path, *, queue, max_attempts=MAX_ATTEMPTS, timeout=5.0):
        if not callable(getattr(queue, "inspect_local", None)) or not callable(
                getattr(queue, "reconcile", None)):
            raise SupervisorError("INVALID_QUEUE")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 10:
            raise SupervisorError("INVALID_RETRY_LIMIT")
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise SupervisorError("INVALID_PATH")
        self.path, self.timeout = str(target), timeout
        self.queue, self.max_attempts = queue, max_attempts
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS supervisor_attempts(
                    attempt INTEGER PRIMARY KEY CHECK(attempt > 0),
                    target_sequence INTEGER NOT NULL CHECK(target_sequence > 0),
                    result TEXT NOT NULL CHECK(
                        result IN ('RETRYABLE','BLOCKED','EXHAUSTED','SUCCEEDED')),
                    error_code TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS supervisor_no_update
                    BEFORE UPDATE ON supervisor_attempts
                    BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS supervisor_no_delete
                    BEFORE DELETE ON supervisor_attempts
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
            "SELECT attempt,target_sequence,result,error_code "
            "FROM supervisor_attempts ORDER BY attempt").fetchall()
        previous_seq = None
        for number, (attempt, seq, result, code) in enumerate(rows, 1):
            if (attempt != number or type(seq) is not int or seq < 1 or
                    type(code) is not str or
                    (result == "SUCCEEDED" and code != "NONE") or
                    (result != "SUCCEEDED" and not code) or
                    (previous_seq is not None and seq < previous_seq)):
                raise SupervisorError("CORRUPT_ATTEMPT_HISTORY")
            if number > 1 and seq == previous_seq and rows[number-2][2] in TERMINAL:
                raise SupervisorError("ATTEMPT_AFTER_TERMINAL")
            previous_seq = seq
        return rows

    def inspect(self):
        """Local diagnostics only; no trust is derived from this SQLite file."""
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                history = self._load(db)
                state = self.queue.inspect_local()
                if (type(state) is not dict or
                        type(state.get("pending")) is not bool or
                        type(state.get("intent_count")) is not int or
                        type(state.get("completion_count")) is not int):
                    raise SupervisorError("INVALID_QUEUE_STATUS")
                pending = state["pending"]
                seq = state["intent_count"]
                attempts = [x for x in history if x[1] == seq]
                last = attempts[-1][2] if attempts else None
                if pending and last == "SUCCEEDED":
                    raise SupervisorError("OUTBOX_AND_SUPERVISOR_DIVERGED")
                status = ("NO_PENDING" if not pending else
                          last if last in TERMINAL else
                          "EXHAUSTED" if len(attempts) >= self.max_attempts else
                          "RETRYABLE" if last == "RETRYABLE" else "READY")
                return {"schema": "palaco-recovery-supervisor-inspection/v24",
                        "target_sequence": seq if pending else None,
                        "pending": pending, "attempts": len(attempts),
                        "max_attempts": self.max_attempts, "state": status,
                        "last_error": attempts[-1][3] if attempts else None,
                        "authorization": "DENY", "release": "HOLD",
                        "production_release_enabled": False}
            finally:
                db.rollback()

    def run_once(self, *, verify_receipt, authorize_publish,
                 independently_verify_anchor):
        """Make at most one explicit reconciliation attempt, never a retry loop."""
        if not all(callable(x) for x in (
                verify_receipt, authorize_publish, independently_verify_anchor)):
            raise SupervisorError("EXTERNAL_TRUST_REQUIRED")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                history = self._load(db)
                state = self.queue.inspect_local()
                if type(state.get("pending")) is not bool or type(
                        state.get("intent_count")) is not int:
                    raise SupervisorError("INVALID_QUEUE_STATUS")
                if not state["pending"]:
                    raise SupervisorError("NO_PENDING_INTENT")
                target = state["intent_count"]
                if any(row[1] > target for row in history):
                    raise SupervisorError("QUEUE_ROLLBACK_SUSPECTED")
                attempts = [row for row in history if row[1] == target]
                if attempts and attempts[-1][2] in TERMINAL:
                    raise SupervisorError("TERMINAL_ATTEMPT")
                if len(attempts) >= self.max_attempts:
                    raise SupervisorError("RETRY_LIMIT_REACHED")
                try:
                    result = self.queue.reconcile(
                        verify_receipt=verify_receipt,
                        authorize_publish=authorize_publish,
                        independently_verify_anchor=independently_verify_anchor)
                    if (type(result) is not dict or
                            result.get("state") != "LOCALLY_RECONCILED" or
                            result.get("sequence") != target or
                            result.get("authorization") != "DENY" or
                            result.get("release") != "HOLD" or
                            result.get("production_release_enabled") is not False):
                        raise SupervisorError("UNEXPECTED_RECONCILIATION_RESULT")
                    status, error = "SUCCEEDED", "NONE"
                except PublicationError as exc:
                    error = _code(exc)
                    status = _classification(error)
                    if status == "RETRYABLE" and len(attempts) + 1 >= self.max_attempts:
                        status = "EXHAUSTED"
                db.execute(
                    "INSERT INTO supervisor_attempts(attempt,target_sequence,result,error_code) "
                    "VALUES(?,?,?,?)",
                    (len(history) + 1, target, status, error))
                db.commit()
                return {"schema": "palaco-recovery-supervisor-attempt/v24",
                        "target_sequence": target, "attempt": len(attempts) + 1,
                        "state": status, "error_code": error,
                        "authorization": "DENY", "release": "HOLD",
                        "production_release_enabled": False}
            except BaseException:
                db.rollback()
                raise
