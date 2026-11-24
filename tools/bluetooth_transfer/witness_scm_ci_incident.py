"""PALACO v6.2 CI-only Ed25519 witness receipt and SQLite replay ledger.

A fresh ephemeral signing key signs the VERIFIER'S receipt, not the origin
C# incident. Neither a generated key nor the local SQLite registry supplies
an independently anchored identity, trusted timestamp or rollback resistance.
All states remain HOLD / DENY; no production authorization is possible.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from verify_scm_ci_incident import EvidenceRejected, strict_object, verify_bytes

PROTOCOL = "PALACO-BT-CI-WITNESS-V1"
GENESIS = "0" * 64
RECEIPT_KEYS = frozenset({"protocol", "sequence", "incident_sha256", "previous_hash",
                           "entry_hash", "decision", "authorization", "signature"})
LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries(
  seq INTEGER PRIMARY KEY CHECK(seq > 0),
  incident_sha256 TEXT NOT NULL UNIQUE,
  previous_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL UNIQUE,
  receipt_json TEXT NOT NULL
);
"""


def canonical(seq: int, digest: str, previous: str) -> bytes:
    return f"{PROTOCOL}|{seq}|{digest}|{previous}|HOLD|DENY".encode("ascii")


def load_json(raw: bytes) -> dict:
    if not raw or len(raw) > 8192:
        raise EvidenceRejected("invalid receipt size")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceRejected("invalid receipt JSON") from exc
    if not isinstance(result, dict) or set(result) != RECEIPT_KEYS:
        raise EvidenceRejected("missing, duplicated or extra receipt fields")
    return result


def check_receipt(receipt: dict, public_key: Ed25519PublicKey) -> None:
    seq = receipt["sequence"]
    if type(seq) is not int or seq < 1:
        raise EvidenceRejected("invalid sequence")
    for name in ("incident_sha256", "previous_hash", "entry_hash"):
        value = receipt[name]
        if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise EvidenceRejected("invalid digest")
    if (receipt["protocol"], receipt["decision"], receipt["authorization"]) != (PROTOCOL, "HOLD", "DENY"):
        raise EvidenceRejected("policy mismatch")
    data = canonical(seq, receipt["incident_sha256"], receipt["previous_hash"])
    entry_hash = hashlib.sha256(data).hexdigest()
    if receipt["entry_hash"] != entry_hash:
        raise EvidenceRejected("entry hash mismatch")
    try:
        sig = base64.b64decode(receipt["signature"], validate=True)
        public_key.verify(sig, data)
    except (ValueError, TypeError, Exception) as exc:
        # Crypto signature validity must be proven; never accept a checksum as a signature.
        raise EvidenceRejected("Ed25519 signature invalid") from exc


def load_public_key(path: Path) -> Ed25519PublicKey:
    if not path.is_file() or path.is_symlink():
        raise EvidenceRejected("trusted public key missing")
    raw = path.read_bytes()
    if len(raw) != 32:
        raise EvidenceRejected("invalid Ed25519 key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_chain(connection: sqlite3.Connection, public_key: Ed25519PublicKey) -> tuple[int, str]:
    rows = connection.execute(
        "SELECT seq, incident_sha256, previous_hash, entry_hash, receipt_json "
        "FROM entries ORDER BY seq").fetchall()
    previous = GENESIS
    for number, (seq, incident, prior, entry, raw) in enumerate(rows, start=1):
        receipt = load_json(raw.encode("utf-8"))
        check_receipt(receipt, public_key)
        if (seq, incident, prior, entry) != (
            number, receipt["incident_sha256"], previous, receipt["entry_hash"]
        ):
            raise EvidenceRejected("broken ledger chain or gap")
        previous = entry
    return len(rows), previous


def attest(evidence_path: Path, ledger_path: Path, receipt_path: Path, pub_path: Path) -> None:
    if any(path.exists() or path.is_symlink() for path in (ledger_path, receipt_path, pub_path)):
        raise EvidenceRejected("witness files already exist; refusing overwrite/replay")
    if not evidence_path.is_file() or evidence_path.is_symlink():
        raise EvidenceRejected("incident missing")
    evidence = evidence_path.read_bytes()
    verify_bytes(evidence)
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    pub_bytes = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Public key is not a trust anchor until separately pinned and retained.
    with pub_path.open("xb") as file:
        file.write(pub_bytes)
        file.flush()
        os.fsync(file.fileno())
    with sqlite3.connect(ledger_path, timeout=5, isolation_level=None) as con:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        con.execute(LEDGER_SCHEMA)
        con.execute("BEGIN IMMEDIATE")
        digest = hashlib.sha256(evidence).hexdigest()
        data = canonical(1, digest, GENESIS)
        receipt = {
            "protocol": PROTOCOL,
            "sequence": 1,
            "incident_sha256": digest,
            "previous_hash": GENESIS,
            "entry_hash": hashlib.sha256(data).hexdigest(),
            "decision": "HOLD",
            "authorization": "DENY",
            "signature": base64.b64encode(private.sign(data)).decode("ascii"),
        }
        raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        con.execute("INSERT INTO entries VALUES (?, ?, ?, ?, ?)",
                    (1, digest, GENESIS, receipt["entry_hash"], raw))
        con.execute("COMMIT")
    with receipt_path.open("xb") as file:
        file.write(raw.encode("utf-8"))
        file.flush()
        os.fsync(file.fileno())


def verify(evidence_path: Path, ledger_path: Path, receipt_path: Path, pub_path: Path) -> None:
    if not all(path.is_file() and not path.is_symlink()
               for path in (evidence_path, ledger_path, receipt_path, pub_path)):
        raise EvidenceRejected("missing evidence, registry, receipt or public key")
    raw_evidence = evidence_path.read_bytes()
    verify_bytes(raw_evidence)
    public = load_public_key(pub_path)
    with sqlite3.connect(f"file:{ledger_path.as_posix()}?mode=ro", uri=True) as con:
        n, _ = verify_chain(con, public)
        if n != 1:
            raise EvidenceRejected("unexpected number of entries")
    receipt = load_json(receipt_path.read_bytes())
    check_receipt(receipt, public)
    if receipt["incident_sha256"] != hashlib.sha256(raw_evidence).hexdigest():
        raise EvidenceRejected("receipt does not bind incident")
    if receipt["sequence"] != 1 or receipt["previous_hash"] != GENESIS:
        raise EvidenceRejected("incorrect first receipt")
    with sqlite3.connect(f"file:{ledger_path.as_posix()}?mode=ro", uri=True) as con:
        row = con.execute("SELECT receipt_json FROM entries WHERE seq=1").fetchone()
        if row is None or load_json(row[0].encode("utf-8")) != receipt:
            raise EvidenceRejected("receipt not committed to ledger")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("attest", "verify"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "attest":
            attest(args.evidence, args.ledger, args.receipt, args.public_key)
        else:
            verify(args.evidence, args.ledger, args.receipt, args.public_key)
    except (EvidenceRejected, sqlite3.DatabaseError, OSError, ValueError) as exc:
        print("PALACO WITNESS DENY: " + type(exc).__name__)
        return 1
    print("PALACO WITNESS PASS (ephemeral Ed25519 verifier receipt; HOLD/DENY; not a trusted anchor)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
