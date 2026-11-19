"""PALACO v29 session/key/device/owner revocation lifecycle candidate.

Append-only local event journal + externally attested monotonic root.
NOT a real PALACO One provider, distributed revocation oracle, key store,
authenticated publisher or production authorization system. GO-13 HOLD.
"""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3

from offline_stage import _canonical
from recovery_operations_cockpit_v25 import ID

SCHEMA = "palaco-identity-lifecycle-event/v29"
DOMAIN = b"PALACO-IDENTITY-LIFECYCLE-v29:EVENT\x00"
GENESIS = hashlib.sha256(b"PALACO-IDENTITY-LIFECYCLE-v29:GENESIS").hexdigest()
KINDS = frozenset(("REVOKE_SESSION", "REVOKE_DEVICE",
                   "REVOKE_OWNER", "REVOKE_SIGNING_KEY"))


class LifecycleError(ValueError):
    pass


def _id(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise LifecycleError("INVALID_IDENTIFIER")


def _step(previous, sequence, kind, target):
    return hashlib.sha256(DOMAIN + _canonical({
        "schema": SCHEMA, "previous": previous, "sequence": sequence,
        "kind": kind, "target": target,
    })).hexdigest()


class IdentityLifecycleRegistry:
    """A local, sticky-revocation record with an independent trust boundary.

    Authoritative publication, signing-key enrollment/rotation and role
    membership remain external. Revocations cannot be undone via this API.
    """

    def __init__(self, path):
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise LifecycleError("INVALID_DATABASE_PATH")
        self.path = str(target)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS lifecycle_events(
                    sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                    kind TEXT NOT NULL CHECK(kind IN (
                        'REVOKE_SESSION','REVOKE_DEVICE','REVOKE_OWNER',
                        'REVOKE_SIGNING_KEY')),
                    target TEXT NOT NULL,
                    previous TEXT NOT NULL,
                    head TEXT NOT NULL UNIQUE,
                    UNIQUE(kind,target)
                );
                CREATE TRIGGER IF NOT EXISTS lifecycle_no_update
                  BEFORE UPDATE ON lifecycle_events
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS lifecycle_no_delete
                  BEFORE DELETE ON lifecycle_events
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @staticmethod
    def _load(db):
        records = db.execute(
            "SELECT sequence,kind,target,previous,head "
            "FROM lifecycle_events ORDER BY sequence").fetchall()
        previous = GENESIS
        revoked = set()
        for i, (sequence, kind, target, prior, head) in enumerate(records, 1):
            if type(sequence) is not int or sequence != i or kind not in KINDS:
                raise LifecycleError("CORRUPT_LIFECYCLE_SEQUENCE")
            _id(target)
            if (kind, target) in revoked or prior != previous or (
                    type(head) is not str or head != _step(previous, i, kind, target)):
                raise LifecycleError("CORRUPT_LIFECYCLE_CHAIN")
            revoked.add((kind, target))
            previous = head
        return len(records), previous, revoked

    def current_local(self):
        """Diagnostic only. Never treat local root as independent trust."""
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                sequence, head, _ = self._load(db)
                return (sequence, head)
            finally:
                db.rollback()

    def revoke(self, kind, target, *, verify_publisher,
               verify_external_predecessor):
        """Explicit append; independent checks are required before mutation.

        verify_publisher(kind,target,sequence,head) and
        verify_external_predecessor(sequence,head) MUST use current external
        authenticated root/policy. Both require literal True.
        """
        if type(kind) is not str or kind not in KINDS:
            raise LifecycleError("INVALID_EVENT_KIND")
        _id(target)
        if not callable(verify_publisher) or not callable(
                verify_external_predecessor):
            raise LifecycleError("EXTERNAL_TRUST_REQUIRED")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                sequence, head, revoked = self._load(db)
                if (kind, target) in revoked:
                    raise LifecycleError("ALREADY_REVOKED")
                try:
                    anchored = verify_external_predecessor(sequence, head)
                    if anchored is not True:
                        raise LifecycleError("UNTRUSTED_REVOCATION")
                    authorized = verify_publisher(kind, target, sequence + 1, head)
                except LifecycleError:
                    raise
                except Exception as exc:
                    raise LifecycleError("EXTERNAL_POLICY_UNAVAILABLE") from exc
                if anchored is not True or authorized is not True:
                    raise LifecycleError("UNTRUSTED_REVOCATION")
                next_seq = sequence + 1
                new_head = _step(head, next_seq, kind, target)
                db.execute(
                    "INSERT INTO lifecycle_events(sequence,kind,target,previous,head) "
                    "VALUES(?,?,?,?,?)",
                    (next_seq, kind, target, head, new_head))
                db.commit()
                return {"schema": "palaco-identity-lifecycle-write/v29",
                        "sequence": next_seq, "head": new_head,
                        "authorization": "DENY", "release": "HOLD",
                        "production_release_enabled": False}
            except BaseException:
                db.rollback()
                raise

    def verified_snapshot(self, *, verify_external_head):
        """Read entire journal and require external attestation of exact root.

        This check is necessary but not sufficient for live revocation:
        an independent issuer/role source must also confirm active identity,
        current key validity, and current session/device state.
        """
        if not callable(verify_external_head):
            raise LifecycleError("EXTERNAL_ANCHOR_REQUIRED")
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                sequence, head, revoked = self._load(db)
            finally:
                db.rollback()
        try:
            trusted = verify_external_head(sequence, head)
        except Exception as exc:
            raise LifecycleError("EXTERNAL_ANCHOR_UNAVAILABLE") from exc
        if trusted is not True:
            raise LifecycleError("UNTRUSTED_LIFECYCLE")
        return frozenset(revoked)

    def policy_callbacks(self, *, verify_external_head,
                         check_active_key, check_active_owner):
        """Create v28 trust_key + check_current_owner callbacks.

        External callbacks MUST check current key enrollment, role and
        revocation beyond this local journal; never use permanent True in
        live systems. Failed lookups deny by returning literal False.
        """
        if not all(callable(x) for x in (
                verify_external_head, check_active_key, check_active_owner)):
            raise LifecycleError("EXTERNAL_POLICY_REQUIRED")

        def trust_key(key_id, claims):
            try:
                _id(key_id)
                if type(claims) is not dict:
                    return False
                revoked = self.verified_snapshot(
                    verify_external_head=verify_external_head)
                if ("REVOKE_SIGNING_KEY", key_id) in revoked:
                    return False
                return check_active_key(key_id, claims) is True
            except Exception:
                return False

        def check_owner(subject, session_id, device_id, action, day):
            try:
                for value in (subject, session_id, device_id):
                    _id(value)
                if type(action) is not str or action != "OWNER_REVIEW":
                    return False
                if type(day) is not str:
                    return False
                revoked = self.verified_snapshot(
                    verify_external_head=verify_external_head)
                if any(item in revoked for item in (
                        ("REVOKE_OWNER", subject),
                        ("REVOKE_SESSION", session_id),
                        ("REVOKE_DEVICE", device_id))):
                    return False
                return check_active_owner(
                    subject, session_id, device_id, action, day) is True
            except Exception:
                return False

        return trust_key, check_owner
