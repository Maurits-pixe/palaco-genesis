"""PALACO v32 secure trust synchronization protocol candidate (GO-13 HOLD).

A staged bundle is not an installed key. Acknowledgment requires independently
authenticated device proof, fresh challenge, current v31 root verification and
local monotonic CAS. Never grants signing/owner/production permissions.
"""
from contextlib import closing
import hashlib
from pathlib import Path
import re
import secrets
import sqlite3

from key_rotation_distribution_v31 import inspect_candidate, BUNDLE_KEYS
from offline_stage import _canonical

ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA = "palaco-trust-sync-receipt/v32"
DOMAIN = b"PALACO-TRUST-SYNC-v32:RECEIPT\x00"


class SyncError(ValueError):
    pass


def _id(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise SyncError("INVALID_MODULE")


def _bundle(bundle):
    if type(bundle) is not dict or set(bundle) != BUNDLE_KEYS:
        raise SyncError("INVALID_BUNDLE")
    if type(bundle.get("bundle_sha256")) is not str or not HEX.fullmatch(
            bundle["bundle_sha256"]):
        raise SyncError("INVALID_BUNDLE")
    for k in ("generation", "sequence", "lifecycle_sequence"):
        if type(bundle[k]) is not int:
            raise SyncError("INVALID_BUNDLE")
    if bundle.get("authorization") != "DENY" or bundle.get("release") != "HOLD" or (
            bundle.get("production_release_enabled") is not False):
        raise SyncError("UNSAFE_BUNDLE")


class TrustSyncRegistry:
    """Per-module monotonic acknowledgment ledger, NOT a trusted key store.

    verify_device(module, statement, proof) must independently verify a
    registered device signature, key lifecycle, scope and current revocation.
    verify_sync_head(module, seq, digest) must authenticate a remote monotonic
    receipt root, never just echo the local SQLite state.
    """

    def __init__(self, path):
        target = Path(path)
        if (not target.parent.is_dir() or target.parent.is_symlink() or
                (target.exists() and (target.is_symlink() or not target.is_file()))):
            raise SyncError("INVALID_DATABASE_PATH")
        self.path = str(target)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sync_receipts (
                    module TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK(generation>0),
                    rotation_sequence INTEGER NOT NULL CHECK(rotation_sequence>0),
                    rotation_head TEXT NOT NULL,
                    lifecycle_sequence INTEGER NOT NULL CHECK(lifecycle_sequence>=0),
                    lifecycle_head TEXT NOT NULL,
                    bundle_hash TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    PRIMARY KEY(module,generation)
                );
                CREATE TABLE IF NOT EXISTS sync_challenges (
                    token_hash TEXT PRIMARY KEY,
                    module TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    bundle_hash TEXT NOT NULL,
                    prior_generation INTEGER NOT NULL,
                    prior_receipt_hash TEXT NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
                );
                CREATE TRIGGER IF NOT EXISTS sync_receipts_no_update
                  BEFORE UPDATE ON sync_receipts
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS sync_receipts_no_delete
                  BEFORE DELETE ON sync_receipts
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS challenges_no_delete
                  BEFORE DELETE ON sync_challenges
                  BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
                CREATE TRIGGER IF NOT EXISTS challenges_no_change
                  BEFORE UPDATE ON sync_challenges
                  WHEN NOT (OLD.consumed=0 AND NEW.consumed=1 AND
                    NEW.token_hash=OLD.token_hash AND NEW.module=OLD.module AND
                    NEW.generation=OLD.generation AND
                    NEW.bundle_hash=OLD.bundle_hash AND
                    NEW.prior_generation=OLD.prior_generation AND
                    NEW.prior_receipt_hash=OLD.prior_receipt_hash)
                  BEGIN SELECT RAISE(ABORT,'IMMUTABLE_CHALLENGE'); END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @staticmethod
    def _latest(db, module):
        rows = db.execute(
            "SELECT generation,rotation_sequence,rotation_head,lifecycle_sequence,"
            "lifecycle_head,bundle_hash,receipt_hash FROM sync_receipts "
            "WHERE module=? ORDER BY generation", (module,)).fetchall()
        prev_gen, prev_hash, rotation_seq, lifecycle_seq = 0, "GENESIS", 0, 0
        for gen, rot_seq, rot_head, life_seq, life_head, bh, rh in rows:
            if (type(gen) is not int or gen != prev_gen + 1 or
                    type(rot_seq) is not int or rot_seq <= rotation_seq or
                    type(life_seq) is not int or life_seq < lifecycle_seq or
                    any(type(v) is not str or not HEX.fullmatch(v) for v in (
                        rot_head, life_head, bh, rh))):
                raise SyncError("CORRUPT_RECEIPT_CHAIN")
            expected = hashlib.sha256(DOMAIN + _canonical({
                "module": module, "generation": gen,
                "rotation_sequence": rot_seq, "rotation_head": rot_head,
                "lifecycle_sequence": life_seq, "lifecycle_head": life_head,
                "bundle_sha256": bh, "previous": prev_hash,
            })).hexdigest()
            if rh != expected:
                raise SyncError("CORRUPT_RECEIPT_CHAIN")
            prev_gen, prev_hash = gen, rh
            rotation_seq, lifecycle_seq = rot_seq, life_seq
        return prev_gen, prev_hash, rotation_seq, lifecycle_seq

    def inspect_local(self, module):
        _id(module)
        with closing(self._connect()) as db:
            db.execute("BEGIN")
            try:
                gen, digest, _, _ = self._latest(db, module)
                return {"schema": "palaco-trust-sync-inspection/v32",
                        "module": module, "generation": gen,
                        "receipt_hash": digest, "authorization": "DENY",
                        "release": "HOLD", "production_release_enabled": False}
            finally:
                db.rollback()

    def stage(self, module, bundle, *, verify_sync_head,
              verify_rotation_head, verify_lifecycle_head, check_active_key):
        """Stage an unprivileged challenge, not key installation."""
        _id(module)
        _bundle(bundle)
        if not all(callable(fn) for fn in (
                verify_sync_head, verify_rotation_head,
                verify_lifecycle_head, check_active_key)):
            raise SyncError("EXTERNAL_TRUST_REQUIRED")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                gen, digest, _, _ = self._latest(db, module)
                if bundle["generation"] != gen + 1:
                    raise SyncError("DOWNGRADE_OR_GENERATION_GAP")
                try:
                    anchored = verify_sync_head(module, gen, digest)
                    valid = inspect_candidate(
                        bundle, verify_rotation_head=verify_rotation_head,
                        verify_lifecycle_head=verify_lifecycle_head,
                        check_active_key=check_active_key)
                except Exception as exc:
                    raise SyncError("TRUST_UNAVAILABLE") from exc
                if anchored is not True or valid is not True:
                    raise SyncError("UNTRUSTED_BUNDLE")
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
                db.execute(
                    "INSERT INTO sync_challenges(token_hash,module,generation,"
                    "bundle_hash,prior_generation,prior_receipt_hash) "
                    "VALUES(?,?,?,?,?,?)",
                    (token_hash, module, bundle["generation"],
                     bundle["bundle_sha256"], gen, digest))
                db.commit()
                return {"schema": "palaco-trust-sync-challenge/v32",
                        "challenge": token, "module": module,
                        "generation": bundle["generation"],
                        "authorization": "DENY", "release": "HOLD"}
            except BaseException:
                db.rollback()
                raise

    def acknowledge(self, module, bundle, challenge, proof, *,
                    verify_device, verify_sync_head,
                    verify_rotation_head, verify_lifecycle_head,
                    check_active_key):
        """Append one diagnostic receipt after fresh independent device proof.

        Proof must cryptographically bind the exact returned statement, challenge
        and module identity. No device signature implementation is provided.
        """
        _id(module)
        _bundle(bundle)
        if type(challenge) is not str or not re.fullmatch(
                r"[A-Za-z0-9_-]{40,128}", challenge):
            raise SyncError("INVALID_CHALLENGE")
        if type(proof) is not str or not 1 <= len(proof) <= 8192:
            raise SyncError("INVALID_PROOF")
        if not all(callable(fn) for fn in (
                verify_device, verify_sync_head, verify_rotation_head,
                verify_lifecycle_head, check_active_key)):
            raise SyncError("EXTERNAL_TRUST_REQUIRED")
        token_hash = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT module,generation,bundle_hash,prior_generation,"
                    "prior_receipt_hash,consumed FROM sync_challenges "
                    "WHERE token_hash=?", (token_hash,)).fetchone()
                if row is None:
                    raise SyncError("UNKNOWN_CHALLENGE")
                owner, generation, bundle_hash, old_gen, old_hash, consumed = row
                if consumed:
                    raise SyncError("REPLAYED_CHALLENGE")
                if (module != owner or generation != bundle["generation"] or
                        bundle_hash != bundle["bundle_sha256"]):
                    raise SyncError("CHALLENGE_BINDING_MISMATCH")
                gen, digest, rotation_seq, life_seq = self._latest(db, module)
                if (gen, digest) != (old_gen, old_hash) or generation != gen + 1:
                    raise SyncError("STALE_CHALLENGE")
                if (bundle["sequence"] <= rotation_seq or
                        bundle["lifecycle_sequence"] < life_seq):
                    raise SyncError("STALE_TRUST_ROOT")
                statement = _canonical({
                    "schema": SCHEMA, "module": module,
                    "challenge_sha256": token_hash,
                    "generation": generation, "bundle_sha256": bundle_hash,
                    "previous_receipt": digest,
                })
                try:
                    trusted = verify_sync_head(module, gen, digest)
                    valid = inspect_candidate(
                        bundle, verify_rotation_head=verify_rotation_head,
                        verify_lifecycle_head=verify_lifecycle_head,
                        check_active_key=check_active_key)
                    device = verify_device(module, statement, proof)
                except Exception as exc:
                    raise SyncError("TRUST_UNAVAILABLE") from exc
                if trusted is not True or valid is not True or device is not True:
                    raise SyncError("UNVERIFIED_ACKNOWLEDGMENT")
                receipt_hash = hashlib.sha256(DOMAIN + _canonical({
                    "module": module, "generation": generation,
                    "rotation_sequence": bundle["sequence"],
                    "rotation_head": bundle["head"],
                    "lifecycle_sequence": bundle["lifecycle_sequence"],
                    "lifecycle_head": bundle["lifecycle_head"],
                    "bundle_sha256": bundle_hash, "previous": digest,
                })).hexdigest()
                db.execute(
                    "INSERT INTO sync_receipts(module,generation,rotation_sequence,"
                    "rotation_head,lifecycle_sequence,lifecycle_head,bundle_hash,"
                    "receipt_hash) VALUES(?,?,?,?,?,?,?,?)",
                    (module, generation, bundle["sequence"], bundle["head"],
                     bundle["lifecycle_sequence"], bundle["lifecycle_head"],
                     bundle_hash, receipt_hash))
                db.execute(
                    "UPDATE sync_challenges SET consumed=1 WHERE token_hash=?",
                    (token_hash,))
                db.commit()
                return {"schema": "palaco-trust-sync-receipt/v32",
                        "module": module, "generation": generation,
                        "receipt_hash": receipt_hash,
                        "device_acknowledged": True,
                        "key_installed": False, "authorization": "DENY",
                        "release": "HOLD", "production_release_enabled": False}
            except BaseException:
                db.rollback()
                raise
