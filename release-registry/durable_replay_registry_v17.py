"""PALACO v17 durable one-use replay registry for v16 receive_exchange.

Local SQLite candidate, never an identity or production authorization service.
No TTL or pruning: a claimed (sender, recipient, message) remains burned forever
within this database. Entire database replacement still defeats local replay.
"""
from contextlib import closing
from pathlib import Path
import re
import sqlite3

from authenticated_exchange_v16 import _id

HEX = re.compile(r"[0-9a-f]{64}\Z")


class ReplayRegistryError(ValueError):
    pass


class DurableReplayRegistry:
    """Callable v16 claim_replay adapter, serialized with BEGIN IMMEDIATE.

    The file MUST be restricted to a trusted local application directory.
    Do not share this database with untrusted processes or use it as a
    cross-device single-use service. No private keys or plaintext are stored.
    """
    def __init__(self, path, *, timeout=5.0):
        target = Path(path)
        if target.exists() and (target.is_symlink() or not target.is_file()):
            raise ReplayRegistryError("INVALID_DATABASE_PATH")
        if not target.parent.is_dir() or target.parent.is_symlink():
            raise ReplayRegistryError("INVALID_DATABASE_PARENT")
        self.path = str(target)
        self.timeout = timeout
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS replay_claims (
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    package_sha256 TEXT NOT NULL,
                    PRIMARY KEY(sender_id, recipient_id, message_id)
                );
                CREATE TRIGGER IF NOT EXISTS replay_no_update
                    BEFORE UPDATE ON replay_claims
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS replay_no_delete
                    BEFORE DELETE ON replay_claims
                    BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        db.execute("PRAGMA synchronous = FULL")
        db.execute("PRAGMA busy_timeout = 5000")
        return db

    @staticmethod
    def _check(sender_id, recipient_id, message_id, package_sha256):
        try:
            _id(sender_id)
            _id(recipient_id)
            _id(message_id)
        except (ValueError, TypeError) as exc:
            raise ReplayRegistryError("INVALID_MESSAGE_IDENTITY") from exc
        if type(package_sha256) is not str or not HEX.fullmatch(package_sha256):
            raise ReplayRegistryError("INVALID_PACKAGE_DIGEST")

    def __call__(self, sender_id, recipient_id, message_id, package_sha256):
        """Return literal True once, False for all later claims of same tuple.

        The digest is retained for diagnosis, but must NEVER be used to allow
        the same message identifier with different ciphertext.
        """
        self._check(sender_id, recipient_id, message_id, package_sha256)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                prior = db.execute(
                    "SELECT 1 FROM replay_claims WHERE sender_id=? "
                    "AND recipient_id=? AND message_id=?",
                    (sender_id, recipient_id, message_id),
                ).fetchone()
                if prior is not None:
                    db.rollback()
                    return False
                db.execute(
                    "INSERT INTO replay_claims(sender_id,recipient_id,"
                    "message_id,package_sha256) VALUES(?,?,?,?)",
                    (sender_id, recipient_id, message_id, package_sha256))
                db.commit()
                return True
            except BaseException:
                db.rollback()
                raise

    def inspect(self, sender_id, recipient_id, message_id):
        """Read-only local diagnostic; no release/authorization information."""
        self._check(sender_id, recipient_id, message_id, "0" * 64)
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT package_sha256 FROM replay_claims "
                "WHERE sender_id=? AND recipient_id=? AND message_id=?",
                (sender_id, recipient_id, message_id),
            ).fetchone()
        return None if row is None else row[0]
