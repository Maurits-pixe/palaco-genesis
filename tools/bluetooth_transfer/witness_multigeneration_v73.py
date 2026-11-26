"""PALACO Bluetooth v7.3: multi-generation signed checkpoint chain, DENY-only.

Local SQLite transactions serialize competing writers; every historical signed
transition is re-verified from a separately pinned genesis digest and signer.
A separately pinned latest digest detects database rollback ONLY when that
external anchor itself remains trustworthy. No external atomic publication,
independent custody, real BLE transfer, or production authorization.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import check_hex, public_id, serialize, strictly_parse
from witness_checkpoint_v70 import verify as verify_genesis

VERSION = "PALACO-BT-CI-MULTI-CHECKPOINT-V1"
FIELDS = {"version", "generation", "previous_digest", "sequence", "head",
          "root_id", "signer_id", "decision", "authorization", "signature"}
SCHEMA = """
CREATE TABLE checkpoint_genesis (
 id INTEGER PRIMARY KEY CHECK(id=1), raw BLOB NOT NULL
);
CREATE TABLE checkpoint_events (
 generation INTEGER PRIMARY KEY CHECK(generation>0),
 raw BLOB NOT NULL
);
"""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def body(previous: bytes, previous_state: dict, generation: int,
         proposed: dict, signer: Ed25519PublicKey) -> dict:
    if type(generation) is not int or generation < 1:
        raise EvidenceRejected("invalid generation")
    if type(proposed) is not dict or set(proposed) != {"sequence", "head", "root_id"}:
        raise EvidenceRejected("invalid checkpoint shape")
    if type(proposed["sequence"]) is not int or (
            proposed["sequence"] <= previous_state["sequence"]):
        raise EvidenceRejected("non-advancing checkpoint sequence")
    check_hex(proposed["head"])
    check_hex(proposed["root_id"])
    if (proposed["root_id"] != previous_state["root_id"] or
            proposed["head"] == previous_state["head"]):
        raise EvidenceRejected("untrusted root or reused head")
    return {"version": VERSION, "generation": generation,
            "previous_digest": digest(previous), **proposed,
            "signer_id": public_id(signer), "decision": "HOLD",
            "authorization": "DENY"}


def sign(previous: bytes, previous_state: dict, generation: int,
         proposed: dict, signer: Ed25519PrivateKey) -> bytes:
    payload = body(previous, previous_state, generation, proposed,
                   signer.public_key())
    return serialize({**payload, "signature": base64.b64encode(
        signer.sign(serialize(payload))).decode("ascii")})


def verify(previous: bytes, previous_state: dict, generation: int,
           successor: bytes, trusted_signer: Ed25519PublicKey) -> dict:
    record = strictly_parse(successor, FIELDS)
    state = {k: record[k] for k in ("sequence", "head", "root_id")}
    expected = body(previous, previous_state, generation, state, trusted_signer)
    if {k: v for k, v in record.items() if k != "signature"} != expected:
        raise EvidenceRejected("checkpoint history fork or policy mismatch")
    try:
        if type(record["signature"]) is not str:
            raise ValueError("invalid signature type")
        signature = base64.b64decode(record["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        trusted_signer.verify(signature, serialize(expected))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise EvidenceRejected("checkpoint signature rejected") from exc
    return state


def connect(path: Path) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file():
        raise EvidenceRejected("checkpoint register absent or unsafe")
    con = sqlite3.connect(path, isolation_level=None, timeout=5)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA synchronous=FULL")
    return con


def initialize(path: Path, signed_genesis: bytes,
               trusted_signer: Ed25519PublicKey,
               pinned_genesis_digest: str) -> None:
    check_hex(pinned_genesis_digest)
    if digest(signed_genesis) != pinned_genesis_digest:
        raise EvidenceRejected("genesis anchor mismatch")
    verify_genesis(signed_genesis, trusted_signer)
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise EvidenceRejected("register target exists or unsafe")
    with path.open("xb"):
        pass
    with closing(sqlite3.connect(path, isolation_level=None)) as con:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        con.executescript(SCHEMA)
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT INTO checkpoint_genesis VALUES (1,?)", (signed_genesis,))
        con.execute("COMMIT")


def replay(con: sqlite3.Connection, trusted_signer: Ed25519PublicKey,
           pinned_genesis_digest: str, pinned_latest_digest: str) -> dict:
    check_hex(pinned_genesis_digest)
    check_hex(pinned_latest_digest)
    genesis_rows = con.execute("SELECT id,raw FROM checkpoint_genesis").fetchall()
    if len(genesis_rows) != 1 or genesis_rows[0][0] != 1:
        raise EvidenceRejected("missing or duplicate genesis")
    previous = genesis_rows[0][1]
    if digest(previous) != pinned_genesis_digest:
        raise EvidenceRejected("genesis replaced")
    state = verify_genesis(previous, trusted_signer)
    events = con.execute(
        "SELECT generation,raw FROM checkpoint_events ORDER BY generation").fetchall()
    if len(events) > 10000:
        raise EvidenceRejected("excessive checkpoint history")
    for expected_generation, (generation, raw) in enumerate(events, 1):
        if generation != expected_generation:
            raise EvidenceRejected("missing or reordered checkpoint generation")
        if type(raw) is not bytes:
            raise EvidenceRejected("checkpoint encoding invalid")
        state = verify(previous, state, generation, raw, trusted_signer)
        previous = raw
    latest = digest(previous)
    if latest != pinned_latest_digest:
        raise EvidenceRejected("latest checkpoint diverges from external anchor")
    return {"generation": len(events), "latest_digest": latest, **state,
            "decision": "HOLD", "authorization": "DENY"}


def inspect(path: Path, trusted_signer: Ed25519PublicKey,
            pinned_genesis_digest: str,
            independently_pinned_latest_digest: str) -> dict:
    with closing(connect(path)) as con:
        con.execute("BEGIN")  # Stable read snapshot for the entire replay.
        result = replay(con, trusted_signer, pinned_genesis_digest,
                        independently_pinned_latest_digest)
        con.execute("COMMIT")
        return result


def advance(path: Path, signed_successor: bytes,
            trusted_signer: Ed25519PublicKey,
            pinned_genesis_digest: str,
            independently_pinned_expected_digest: str) -> dict:
    # Validate all signed history under the same write lock as the insert.
    with closing(connect(path)) as con:
        try:
            con.execute("BEGIN IMMEDIATE")
            current = replay(con, trusted_signer, pinned_genesis_digest,
                             independently_pinned_expected_digest)
            if current["generation"] >= 10000:
                raise EvidenceRejected("history capacity reached")
            if current["generation"] == 0:
                prior = con.execute(
                    "SELECT raw FROM checkpoint_genesis WHERE id=1").fetchone()[0]
            else:
                prior = con.execute(
                    "SELECT raw FROM checkpoint_events WHERE generation=?",
                    (current["generation"],)).fetchone()[0]
            previous_state = {k: current[k] for k in ("sequence", "head", "root_id")}
            next_generation = current["generation"] + 1
            proposed = verify(prior, previous_state, next_generation,
                              signed_successor, trusted_signer)
            con.execute("INSERT INTO checkpoint_events VALUES (?,?)",
                        (next_generation, signed_successor))
            con.execute("COMMIT")
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
    # Return the new digest for independent publication; no external write
    # occurs here. Until that publication, receiver authorization stays DENY.
    return {"generation": next_generation, "latest_digest": digest(signed_successor),
            **proposed, "decision": "HOLD", "authorization": "DENY"}
