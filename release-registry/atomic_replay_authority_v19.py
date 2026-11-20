"""PALACO v19 single-database atomic replay coordinator (draft only).

A coordinator MUST have a genuine authenticated intake policy, an independent
signer and a durable external monotonic anchor before production deployment.
This local SQLite prototype cannot provide distributed fault tolerance.
"""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3

from distributed_replay_v18 import (
    CoordinationError, _claim, _tuple, receipt_statement, RECEIPT_SCHEMA,
)
from offline_stage import _canonical


class AuthorityError(ValueError):
    pass


class AtomicReplayAuthority:
    """Serialized claim decisions with unique first-winner and audit history.

    authorize_candidate(claim) MUST authenticate and authorize the device,
    sender/recipient scope and current key policy. sign_receipt(statement)
    MUST return an independently verifiable opaque receipt string. Neither
    callback is implemented here; synthetic fixtures never establish trust.
    """

    def __init__(self, path, *, authorize_candidate, sign_receipt, timeout=5.0):
        if not callable(authorize_candidate) or not callable(sign_receipt):
            raise AuthorityError("EXTERNAL_AUTHORITY_REQUIRED")
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise AuthorityError("INVALID_DATABASE_PATH")
        self.path = str(target)
        self.authorize_candidate = authorize_candidate
        self.sign_receipt = sign_receipt
        self.timeout = timeout
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS authority_first_claims (
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    package_sha256 TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    decision_sequence INTEGER NOT NULL UNIQUE,
                    PRIMARY KEY(sender_id,recipient_id,message_id)
                );
                CREATE TABLE IF NOT EXISTS authority_decisions (
                    sequence INTEGER PRIMARY KEY CHECK(sequence>0),
                    claim_body BLOB NOT NULL,
                    decision TEXT NOT NULL CHECK(
                        decision IN ('first-claim','duplicate','conflict')),
                    proof TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS authority_first_no_update
                  BEFORE UPDATE ON authority_first_claims
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS authority_first_no_delete
                  BEFORE DELETE ON authority_first_claims
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS authority_decisions_no_update
                  BEFORE UPDATE ON authority_decisions
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS authority_decisions_no_delete
                  BEFORE DELETE ON authority_decisions
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=self.timeout)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def decide(self, claim):
        """Atomically append ONE decision and its receipt to local SQLite.

        A callback error rolls back the database transaction; a cryptographic
        signer might nevertheless have produced an orphan signature, which
        is harmless only if verifiers require committed anchored decisions.
        """
        _claim(claim)
        frozen = __import__("json").loads(_canonical(claim))
        try:
            allowed = self.authorize_candidate(frozen)
        except Exception as exc:
            raise AuthorityError("INTAKE_POLICY_UNAVAILABLE") from exc
        if allowed is not True:
            raise AuthorityError("INTAKE_NOT_AUTHORIZED")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                # Reject gaps/deletions of decision history; this is local
                # consistency only, NOT independent rollback protection.
                row = db.execute(
                    "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM authority_decisions"
                ).fetchone()
                if row[0] != row[1]:
                    raise AuthorityError("CORRUPT_DECISION_SEQUENCE")
                sequence = row[1] + 1
                prior = db.execute(
                    "SELECT package_sha256 FROM authority_first_claims "
                    "WHERE sender_id=? AND recipient_id=? AND message_id=?",
                    _tuple(frozen)).fetchone()
                if prior is None:
                    decision = "first-claim"
                elif prior[0] == frozen["package_sha256"]:
                    decision = "duplicate"
                else:
                    decision = "conflict"
                statement = receipt_statement(
                    frozen, authority_sequence=sequence, decision=decision)
                try:
                    proof = self.sign_receipt(statement)
                except Exception as exc:
                    raise AuthorityError("SIGNING_UNAVAILABLE") from exc
                if type(proof) is not str or not 1 <= len(proof) <= 8192:
                    raise AuthorityError("INVALID_RECEIPT_PROOF")
                if decision == "first-claim":
                    db.execute(
                        "INSERT INTO authority_first_claims("
                        "sender_id,recipient_id,message_id,package_sha256,"
                        "device_id,decision_sequence) VALUES(?,?,?,?,?,?)",
                        (*_tuple(frozen), frozen["package_sha256"],
                         frozen["device_id"], sequence))
                db.execute(
                    "INSERT INTO authority_decisions(sequence,claim_body,decision,proof) "
                    "VALUES(?,?,?,?)",
                    (sequence, _canonical(frozen), decision, proof))
                db.commit()
                return {"schema": RECEIPT_SCHEMA, "authority_sequence": sequence,
                        "decision": decision, "proof": proof}
            except BaseException:
                db.rollback()
                raise

    def read_decisions(self):
        """Export a locally consistent diagnostic, not certified receipts."""
        import json
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                rows = db.execute(
                    "SELECT sequence,claim_body,decision,proof "
                    "FROM authority_decisions ORDER BY sequence").fetchall()
                claims, receipts = [], []
                for expected, (seq, body, decision, proof) in enumerate(rows, 1):
                    if type(body) is not bytes or seq != expected:
                        raise AuthorityError("CORRUPT_DECISION_SEQUENCE")
                    try:
                        obj = json.loads(body.decode("ascii"))
                        _claim(obj)
                        if _canonical(obj) != body:
                            raise AuthorityError("CORRUPT_CLAIM")
                        receipt_statement(
                            obj, authority_sequence=seq, decision=decision)
                    except (ValueError, TypeError, UnicodeError, CoordinationError) as exc:
                        raise AuthorityError("CORRUPT_CLAIM") from exc
                    if type(proof) is not str or not 1 <= len(proof) <= 8192:
                        raise AuthorityError("CORRUPT_RECEIPT")
                    claims.append(obj)
                    receipts.append({"schema": RECEIPT_SCHEMA,
                                     "authority_sequence": seq,
                                     "decision": decision, "proof": proof})
                firsts = db.execute(
                    "SELECT sender_id,recipient_id,message_id,package_sha256,"
                    "device_id,decision_sequence FROM authority_first_claims"
                ).fetchall()
                expected_firsts = {
                    (*_tuple(c), c["package_sha256"], c["device_id"], r["authority_sequence"])
                    for c, r in zip(claims, receipts) if r["decision"] == "first-claim"
                }
                if set(firsts) != expected_firsts or len(firsts) != len(expected_firsts):
                    raise AuthorityError("FIRST_CLAIM_INDEX_MISMATCH")
                seen = {}
                for c, r in zip(claims, receipts):
                    key = _tuple(c)
                    prev = seen.get(key)
                    expected_decision = ("first-claim" if prev is None else
                                         "duplicate" if prev == c["package_sha256"] else "conflict")
                    if r["decision"] != expected_decision:
                        raise AuthorityError("CORRUPT_DECISION")
                    seen.setdefault(key, c["package_sha256"])
                return tuple(claims), tuple(receipts)
            finally:
                db.rollback()
