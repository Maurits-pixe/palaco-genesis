"""PALACO v30 identity signing-key rotation protocol (DRAFT / GO-13 HOLD).

Append-only local transition journal; external independent key enrollment,
revocation and monotonic anchoring are REQUIRED. No private-key operations,
no live identity changes, and no production authority are implemented.
"""
from contextlib import closing
import hashlib
from pathlib import Path
import re
import sqlite3

from offline_stage import _canonical
from identity_session_lifecycle_v29 import _id

GENESIS = hashlib.sha256(b"PALACO-KEY-ROTATION-v30:GENESIS").hexdigest()
DOMAIN = b"PALACO-KEY-ROTATION-v30:EVENT\x00"
HEX = re.compile(r"[0-9a-f]{64}\Z")
EVENTS = ("PREPARE", "COMMIT")
SCHEMA = "palaco-key-rotation-event/v30"


class RotationError(ValueError):
    pass


def _fingerprint(key_bytes):
    if type(key_bytes) is not bytes or len(key_bytes) != 32:
        raise RotationError("INVALID_PUBLIC_KEY")
    return hashlib.sha256(key_bytes).hexdigest()


def _step(prev, sequence, kind, generation, old_key, new_key, fingerprint):
    return hashlib.sha256(DOMAIN + _canonical({
        "schema": SCHEMA, "previous": prev, "sequence": sequence,
        "event": kind, "generation": generation,
        "old_key": old_key, "new_key": new_key,
        "fingerprint": fingerprint,
    })).hexdigest()


class IdentityKeyRotation:
    """Serialize PREPARE/COMMIT transitions, one pending transition maximum.

    No implicit key trust: external verify_predecessor must authenticate an
    independently stored, monotonic exact sequence/head; check_policy must
    authenticate current key lifecycle, issuance scope and publisher.
    """

    def __init__(self, path):
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise RotationError("INVALID_DATABASE_PATH")
        self.path = str(target)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS key_rotation_events(
                    sequence INTEGER PRIMARY KEY CHECK(sequence>0),
                    event TEXT NOT NULL CHECK(event IN ('PREPARE','COMMIT')),
                    generation INTEGER NOT NULL CHECK(generation>0),
                    old_key TEXT NOT NULL,
                    new_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    previous TEXT NOT NULL,
                    head TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS rotation_no_update
                  BEFORE UPDATE ON key_rotation_events
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS rotation_no_delete
                  BEFORE DELETE ON key_rotation_events
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @staticmethod
    def _load(db):
        rows = db.execute(
            "SELECT sequence,event,generation,old_key,new_key,"
            "fingerprint,previous,head FROM key_rotation_events "
            "ORDER BY sequence").fetchall()
        prev, generation, active, pending = GENESIS, 0, None, None
        retired = set()
        for expected, (seq, kind, epoch, old, new, fp, before, head) in enumerate(rows, 1):
            if (seq != expected or type(epoch) is not int or
                    type(kind) is not str or kind not in EVENTS or
                    type(fp) is not str or not HEX.fullmatch(fp) or
                    before != prev):
                raise RotationError("CORRUPT_ROTATION_CHAIN")
            _id(old)
            _id(new)
            if old == new or new in retired or new == active:
                raise RotationError("INVALID_KEY_TRANSITION")
            if head != _step(prev, seq, kind, epoch, old, new, fp):
                raise RotationError("CORRUPT_ROTATION_CHAIN")
            if kind == "PREPARE":
                if pending is not None or epoch != generation + 1 or (
                        generation > 0 and old != active):
                    raise RotationError("INVALID_KEY_TRANSITION")
                pending = (epoch, old, new, fp)
            else:
                if pending != (epoch, old, new, fp):
                    raise RotationError("INVALID_KEY_TRANSITION")
                if generation > 0:
                    retired.add(old)
                generation, active, pending = epoch, new, None
            prev = head
        return len(rows), prev, generation, active, pending, frozenset(retired)

    def inspect_local(self):
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                seq, head, generation, active, pending, retired = self._load(db)
                return {"sequence": seq, "head": head, "generation": generation,
                        "active_key": active, "pending": pending is not None,
                        "retired_count": len(retired), "authorization": "DENY",
                        "release": "HOLD", "production_release_enabled": False}
            finally:
                db.rollback()

    def _append(self, *, event, old_key, new_key, public_key, expected_sequence,
                expected_head, verify_predecessor, check_policy):
        for key in (old_key, new_key):
            _id(key)
        fp = _fingerprint(public_key)
        if (type(expected_sequence) is not int or expected_sequence < 0 or
                type(expected_head) is not str or not HEX.fullmatch(expected_head) or
                not callable(verify_predecessor) or not callable(check_policy)):
            raise RotationError("EXTERNAL_TRUST_REQUIRED")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                seq, head, generation, active, pending, retired = self._load(db)
                if (seq, head) != (expected_sequence, expected_head):
                    raise RotationError("STALE_TRANSITION")
                if event == "PREPARE":
                    if pending is not None or new_key in retired or (
                            generation > 0 and old_key != active) or old_key == new_key:
                        raise RotationError("INVALID_KEY_TRANSITION")
                    epoch = generation + 1
                else:
                    if pending is None or pending[1:] != (old_key, new_key, fp):
                        raise RotationError("NO_MATCHING_PREPARE")
                    epoch = pending[0]
                try:
                    anchored = verify_predecessor(seq, head)
                except Exception as exc:
                    raise RotationError("ANCHOR_UNAVAILABLE") from exc
                if anchored is not True:
                    raise RotationError("UNTRUSTED_PREDECESSOR")
                try:
                    policy = check_policy(event, epoch, old_key, new_key, fp)
                except Exception as exc:
                    raise RotationError("POLICY_UNAVAILABLE") from exc
                if policy is not True:
                    raise RotationError("ROTATION_NOT_AUTHORIZED")
                next_head = _step(head, seq + 1, event, epoch,
                                  old_key, new_key, fp)
                db.execute(
                    "INSERT INTO key_rotation_events(sequence,event,generation,"
                    "old_key,new_key,fingerprint,previous,head)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (seq + 1, event, epoch, old_key, new_key, fp, head, next_head))
                db.commit()
                return {"schema": "palaco-key-rotation-result/v30",
                        "sequence": seq + 1, "head": next_head,
                        "generation": epoch, "state": (
                            "PENDING" if event == "PREPARE" else "LOCALLY_COMMITTED"),
                        "authorization": "DENY", "release": "HOLD",
                        "production_release_enabled": False}
            except BaseException:
                db.rollback()
                raise

    def prepare(self, *, old_key, new_key, public_key, expected_sequence,
                expected_head, verify_predecessor, check_policy):
        return self._append(
            event="PREPARE", old_key=old_key, new_key=new_key,
            public_key=public_key, expected_sequence=expected_sequence,
            expected_head=expected_head, verify_predecessor=verify_predecessor,
            check_policy=check_policy)

    def commit(self, *, old_key, new_key, public_key, expected_sequence,
               expected_head, verify_predecessor, check_policy):
        return self._append(
            event="COMMIT", old_key=old_key, new_key=new_key,
            public_key=public_key, expected_sequence=expected_sequence,
            expected_head=expected_head, verify_predecessor=verify_predecessor,
            check_policy=check_policy)

    def trust_key(self, key_id, claims, *, verify_current_head,
                  check_external_key, expected_fingerprint):
        """Strict optional v28 trust_key policy; denies during pending rotations.

        Caller must independently authenticate current key enrollment and role
        policy. No key is accepted until an external root proves *this* head.
        """
        try:
            _id(key_id)
            if type(claims) is not dict or not callable(verify_current_head) or (
                    not callable(check_external_key)):
                return False
            if type(expected_fingerprint) is not str or not HEX.fullmatch(
                    expected_fingerprint):
                return False
            with closing(self._connect()) as db:
                db.execute("BEGIN")
                try:
                    seq, head, generation, active, pending, retired = self._load(db)
                finally:
                    db.rollback()
            if generation < 1 or pending is not None or key_id != active or (
                    key_id in retired):
                return False
            with closing(self._connect()) as db:
                row = db.execute(
                    "SELECT fingerprint FROM key_rotation_events WHERE "
                    "event='COMMIT' AND generation=?", (generation,)).fetchone()
            if row is None or row[0] != expected_fingerprint:
                return False
            return (verify_current_head(seq, head) is True and
                    check_external_key(key_id, claims, expected_fingerprint) is True)
        except Exception:
            return False
