"""PALACO Bluetooth v7.2: local atomic checkpoint succession register.

Reference-only register; independently pinned Ed25519 signer, trust root and
out-of-database latest digest are mandatory. SQLite FULL synchronous write and
BEGIN IMMEDIATE serialize local writers, but cannot defend against a hostile
restoration of the complete SQLite file without an external high-water anchor.
One v7.1 successor follows a signed v7.0 checkpoint (not multi-generation).
HOLD/DENY throughout. No network, BLE, authority elevation or production use.
"""
from __future__ import annotations

from contextlib import closing
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import check_hex
from witness_checkpoint_v70 import verify as verify_checkpoint
from witness_succession_v71 import digest, verify_successor

SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoint_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 latest_digest TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation IN (0,1)),
 sequence INTEGER NOT NULL CHECK(sequence > 0),
 head TEXT NOT NULL,
 root_id TEXT NOT NULL,
 decision TEXT NOT NULL CHECK(decision='HOLD'),
 authorization TEXT NOT NULL CHECK(authorization='DENY')
);
CREATE TABLE IF NOT EXISTS transitions (
 generation INTEGER PRIMARY KEY CHECK(generation=1),
 predecessor_digest TEXT NOT NULL UNIQUE,
 successor_digest TEXT NOT NULL UNIQUE,
 successor BLOB NOT NULL,
 decision TEXT NOT NULL CHECK(decision='HOLD'),
 authorization TEXT NOT NULL CHECK(authorization='DENY')
);
"""

def connection(path: Path) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file():
        raise EvidenceRejected("checkpoint register absent or unsafe")
    con = sqlite3.connect(path, isolation_level=None, timeout=5)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA synchronous=FULL")
    return con


def initialize(path: Path, signed_checkpoint: bytes,
               trusted_signer: Ed25519PublicKey,
               independently_pinned_initial_digest: str) -> None:
    check_hex(independently_pinned_initial_digest)
    if digest(signed_checkpoint) != independently_pinned_initial_digest:
        raise EvidenceRejected("untrusted initial checkpoint")
    state = verify_checkpoint(signed_checkpoint, trusted_signer)
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise EvidenceRejected("register target already exists or unsafe")
    # Exclusive initial file creation. Failed setup must not be used as evidence.
    fd = path.open("xb")
    fd.close()
    with closing(sqlite3.connect(path, isolation_level=None)) as con:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        con.executescript(SCHEMA)
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT INTO checkpoint_state VALUES (1,?,?,?,?,?,?,?)",
                    (independently_pinned_initial_digest, 0,
                     state["sequence"], state["head"], state["root_id"],
                     "HOLD", "DENY"))
        con.execute("COMMIT")


def state(path: Path, independently_pinned_latest_digest: str) -> dict:
    check_hex(independently_pinned_latest_digest)
    with closing(connection(path)) as con:
        row = con.execute(
            "SELECT latest_digest,generation,sequence,head,root_id,decision,"
            "authorization FROM checkpoint_state WHERE id=1").fetchone()
        count = con.execute("SELECT COUNT(*) FROM checkpoint_state").fetchone()[0]
        if count != 1 or row is None:
            raise EvidenceRejected("checkpoint register integrity failure")
        latest, generation, sequence, head, root_id, decision, authorization = row
        if (latest != independently_pinned_latest_digest or
                type(generation) is not int or generation not in (0,1) or
                type(sequence) is not int or sequence < 1 or
                decision != "HOLD" or authorization != "DENY"):
            raise EvidenceRejected("checkpoint rollback or policy mismatch")
        check_hex(head)
        check_hex(root_id)
        receipts = con.execute(
            "SELECT generation,predecessor_digest,successor_digest,successor,"
            "decision,authorization FROM transitions").fetchall()
        if len(receipts) != generation:
            raise EvidenceRejected("missing or unexpected succession evidence")
        if generation == 1:
            g, previous, successor_digest, successor, d, a = receipts[0]
            if (g != 1 or successor_digest != latest or
                    digest(successor) != latest or d != "HOLD" or a != "DENY"):
                raise EvidenceRejected("transition history inconsistent")
            check_hex(previous)
        return {"latest_digest": latest, "generation": generation,
                "sequence": sequence, "head": head, "root_id": root_id,
                "decision": "HOLD", "authorization": "DENY"}


def advance(path: Path, signed_prior: bytes, signed_successor: bytes,
            trusted_signer: Ed25519PublicKey,
            independently_pinned_expected_digest: str) -> dict:
    check_hex(independently_pinned_expected_digest)
    prior_digest = digest(signed_prior)
    if prior_digest != independently_pinned_expected_digest:
        raise EvidenceRejected("external high-water reference changed")
    new_digest = digest(signed_successor)
    proposed = verify_successor(signed_prior, signed_successor,
                                trusted_signer, new_digest)
    prior = verify_checkpoint(signed_prior, trusted_signer)
    with closing(connection(path)) as con:
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT latest_digest,generation,sequence,head,root_id,"
                "decision,authorization FROM checkpoint_state WHERE id=1"
            ).fetchone()
            expected = (prior_digest, 0, prior["sequence"], prior["head"],
                        prior["root_id"], "HOLD", "DENY")
            if row != expected or con.execute(
                    "SELECT COUNT(*) FROM transitions").fetchone()[0] != 0:
                raise EvidenceRejected("stale, replayed or forked checkpoint")
            con.execute(
                "INSERT INTO transitions VALUES (1,?,?,?,?,?)",
                (prior_digest, new_digest, signed_successor, "HOLD", "DENY"))
            updated = con.execute(
                "UPDATE checkpoint_state SET latest_digest=?,generation=1,"
                "sequence=?,head=? WHERE id=1 AND latest_digest=? AND generation=0",
                (new_digest, proposed["sequence"], proposed["head"], prior_digest))
            if updated.rowcount != 1:
                raise EvidenceRejected("checkpoint compare-and-swap failed")
            con.execute("COMMIT")
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
    return state(path, new_digest)
