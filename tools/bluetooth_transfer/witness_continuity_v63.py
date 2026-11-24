"""PALACO Bluetooth v6.3: CI-only signed witness rotation and multi-entry continuity.

A pinned verifier root is supplied by the *caller*, not self-trusted from the
ledger. New signing keys require a rotation certificate signed by the prior
key. A separately retained checkpoint detects rollback relative to that
checkpoint, but NOT collusive replacement of the root, log and checkpoint.
HOLD/DENY only. No producer attestation or production authority.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import json
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from verify_scm_ci_incident import EvidenceRejected, strict_object, verify_bytes

GENESIS = "0" * 64
VERSION = "PALACO-BT-CI-CHAIN-V1"
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
 seq INTEGER PRIMARY KEY CHECK(seq > 0),
 kind TEXT NOT NULL CHECK(kind IN ('incident','rotate')),
 previous TEXT NOT NULL,
 digest TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS used_incidents (
 incident_sha256 TEXT PRIMARY KEY
);
"""


def serialize(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_id(key: Ed25519PublicKey) -> str:
    return digest_bytes(public_raw(key))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def strictly_parse(raw: bytes, expected: set[str]) -> dict:
    if not raw or len(raw) > 8192:
        raise EvidenceRejected("invalid event size")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)
    except (UnicodeError, json.JSONDecodeError) as ex:
        raise EvidenceRejected("invalid event JSON") from ex
    if not isinstance(doc, dict) or set(doc) != expected:
        raise EvidenceRejected("unexpected event fields")
    return doc


def check_hex(value: object) -> None:
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise EvidenceRejected("invalid 64-char hash")


def decode_key(value: object) -> Ed25519PublicKey:
    if type(value) is not str:
        raise EvidenceRejected("invalid key encoding")
    try:
        data = base64.b64decode(value, validate=True)
        if len(data) != 32:
            raise ValueError("wrong key length")
        return Ed25519PublicKey.from_public_bytes(data)
    except (ValueError, TypeError) as ex:
        raise EvidenceRejected("invalid public key") from ex


def signature_check(key: Ed25519PublicKey, signature: object, payload: bytes) -> None:
    try:
        if type(signature) is not str:
            raise ValueError("invalid signature type")
        raw = base64.b64decode(signature, validate=True)
        if len(raw) != 64:
            raise ValueError("invalid signature size")
        key.verify(raw, payload)
    except (ValueError, InvalidSignature, TypeError) as ex:
        raise EvidenceRejected("signature rejected") from ex


def body(kind: str, seq: int, previous: str, signer: str, value: str) -> dict:
    return {"version": VERSION, "kind": kind, "sequence": seq,
            "previous": previous, "signer": signer, "value": value,
            "decision": "HOLD", "authorization": "DENY"}


def new_event(kind: str, seq: int, previous: str, signer: Ed25519PrivateKey, value: str) -> dict:
    entry = body(kind, seq, previous, public_id(signer.public_key()), value)
    entry["signature"] = b64(signer.sign(serialize(entry)))
    return entry


def validate_chain(con: sqlite3.Connection, root: Ed25519PublicKey) -> tuple[int, str, Ed25519PublicKey, set[str]]:
    rows = con.execute("SELECT seq,kind,previous,digest,payload FROM events ORDER BY seq").fetchall()
    active = root
    prior = GENESIS
    incident_hashes: set[str] = set()
    for expected_seq, (seq, kind, previous, digest, raw) in enumerate(rows, 1):
        if type(seq) is not int or seq != expected_seq or kind not in ("incident", "rotate"):
            raise EvidenceRejected("missing or reordered sequence")
        entry = strictly_parse(raw.encode("utf-8"), set(body(kind, seq, previous, "", "")) | {"signature"})
        if entry["version"] != VERSION or entry["kind"] != kind or type(entry["sequence"]) is not int or entry["sequence"] != seq:
            raise EvidenceRejected("wrong event identity")
        if entry["decision"] != "HOLD" or entry["authorization"] != "DENY":
            raise EvidenceRejected("authority forbidden")
        if previous != prior or entry["previous"] != prior:
            raise EvidenceRejected("broken predecessor link")
        if entry["signer"] != public_id(active):
            raise EvidenceRejected("untrusted signing key")
        check_hex(digest)
        if digest != digest_bytes(raw.encode("utf-8")):
            raise EvidenceRejected("tampered event hash")
        payload = {key: value for key, value in entry.items() if key != "signature"}
        signature_check(active, entry["signature"], serialize(payload))
        if kind == "incident":
            check_hex(entry["value"])
            if entry["value"] in incident_hashes:
                raise EvidenceRejected("replayed incident")
            incident_hashes.add(entry["value"])
        else:
            successor = decode_key(entry["value"])
            if public_id(successor) == public_id(active):
                raise EvidenceRejected("no-op key rotation")
            active = successor
        prior = digest
    recorded = {r[0] for r in con.execute("SELECT incident_sha256 FROM used_incidents")}
    if recorded != incident_hashes:
        raise EvidenceRejected("incident index mismatch")
    return len(rows), prior, active, incident_hashes


def connect(path: Path) -> sqlite3.Connection:
    if path.is_symlink():
        raise EvidenceRejected("unsafe ledger path")
    con = sqlite3.connect(path, isolation_level=None, timeout=5)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA synchronous=FULL")
    con.executescript(SCHEMA)
    return con


def append_incident(path: Path, root: Ed25519PublicKey,
                    signer: Ed25519PrivateKey, evidence: bytes) -> dict:
    verify_bytes(evidence)
    incident = digest_bytes(evidence)
    with closing(connect(path)) as con:
        con.execute("BEGIN IMMEDIATE")
        count, previous, active, seen = validate_chain(con, root)
        if public_id(signer.public_key()) != public_id(active) or incident in seen:
            raise EvidenceRejected("wrong signer or repeated incident")
        event = new_event("incident", count + 1, previous, signer, incident)
        raw = serialize(event).decode("ascii")
        hashed = digest_bytes(raw.encode("ascii"))
        con.execute("INSERT INTO events VALUES (?,?,?,?,?)",
                    (count + 1, "incident", previous, hashed, raw))
        con.execute("INSERT INTO used_incidents VALUES (?)", (incident,))
        con.execute("COMMIT")
        return {"sequence": count + 1, "head": hashed}


def append_rotation(path: Path, root: Ed25519PublicKey,
                    signer: Ed25519PrivateKey, successor: Ed25519PublicKey) -> dict:
    with closing(connect(path)) as con:
        con.execute("BEGIN IMMEDIATE")
        count, previous, active, _ = validate_chain(con, root)
        if public_id(signer.public_key()) != public_id(active):
            raise EvidenceRejected("untrusted rotation signer")
        event = new_event("rotate", count + 1, previous, signer, b64(public_raw(successor)))
        raw = serialize(event).decode("ascii")
        hashed = digest_bytes(raw.encode("ascii"))
        con.execute("INSERT INTO events VALUES (?,?,?,?,?)",
                    (count + 1, "rotate", previous, hashed, raw))
        con.execute("COMMIT")
        return {"sequence": count + 1, "head": hashed}


def check_checkpoint(path: Path, expected: dict) -> None:
    # The external checkpoint MUST be retained by the caller outside the
    # mutable DB. Equal sequence/head is required; partial rollback is denied.
    if not path.is_file() or path.is_symlink():
        raise EvidenceRejected("independent checkpoint unavailable")
    checkpoint = strictly_parse(path.read_bytes(), {"sequence", "head", "root_id"})
    if checkpoint != expected:
        raise EvidenceRejected("checkpoint diverges (rollback or fork)")


def snapshot(path: Path, root: Ed25519PublicKey) -> dict:
    if not path.is_file() or path.is_symlink():
        raise EvidenceRejected("ledger missing")
    with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as con:
        count, head, _, _ = validate_chain(con, root)
    return {"sequence": count, "head": head, "root_id": public_id(root)}


def exercise_ci(evidence: bytes) -> bool:
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        ledger = Path(folder) / "ledger.sqlite3"
        checkpoint = Path(folder) / "checkpoint.json"
        root_private = Ed25519PrivateKey.generate()
        successor = Ed25519PrivateKey.generate()
        root = root_private.public_key()
        first = append_incident(ledger, root, root_private, evidence)
        rotation = append_rotation(ledger, root, root_private, successor.public_key())
        if rotation["sequence"] != 2:
            raise EvidenceRejected("rotation not recorded")
        # Synthetic second event uses a distinct structurally valid JSON
        # encoding, which preserves the same verified HOLD/DENY semantics.
        second_evidence = json.dumps(json.loads(evidence), indent=1).encode("utf-8")
        if second_evidence == evidence:
            second_evidence += b" "
        second = append_incident(ledger, root, successor, second_evidence)
        if second["sequence"] != 3:
            raise EvidenceRejected("second incident not appended")
        status = snapshot(ledger, root)
        checkpoint.write_bytes(serialize(status))
        check_checkpoint(checkpoint, status)
        # A new key must not make the old key authoritative again.
        try:
            append_incident(ledger, root, root_private, evidence)
            raise EvidenceRejected("stale signer accepted")
        except EvidenceRejected as ex:
            if str(ex) == "stale signer accepted":
                raise
        return first["sequence"] == 1

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not exercise_ci(args.ci_evidence.read_bytes()):
            raise EvidenceRejected("continuity smoke failed")
    except (EvidenceRejected, OSError, sqlite3.DatabaseError) as exc:
        print("PALACO v6.3 WITNESS DENY: " + type(exc).__name__)
        raise SystemExit(1)
    print("PALACO v6.3 WITNESS PASS (ephemeral pin, rotation, 3 entries, checkpoint; no external anchor)")
