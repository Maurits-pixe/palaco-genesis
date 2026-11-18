#!/usr/bin/env python3
"""ORCHEASTRA v0.43: random nonce issuer, signed provenance and recovery HOLD.

Disposable CI-only issuer: CSPRNG nonces, pinned issuer public key, signed
issuance record, SQLite single-use ledger and runner-local integrity pin.
No real witness challenge-response, trusted clock, HSM or external anchor.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_recovery_bundle_v036 import signature_valid

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v043"
DB = ROOT / "issuer-ledger.sqlite3"
ISSUANCE = ROOT / "signed-issuance.json"
SIGNATURE = ROOT / "issuance.sig"
PUB = ROOT / "issuer-public.pem"
PRIVATE = ROOT / "issuer-private.pem"
PIN = ROOT / "issuer-public-pin.sha256"
SNAPSHOT = ROOT / "ledger-high-water.sha256"
DOMAIN = "PALACO:ORCHEASTRA:NONCE_ISSUANCE:v1"
ISSUER = "palaco-orcheastra-ci-issuer"
NOW = 1794996000  # Test-only deterministic clock.
TTL = 120


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def openssl(*args: str) -> None:
    result = subprocess.run(["openssl", *args], check=False, text=True,
                            capture_output=True, timeout=20)
    if result.returncode:
        raise AssertionError("OpenSSL issuer signature failed")


def connect(*, existing: bool = True) -> sqlite3.Connection:
    if existing and not DB.is_file():
        raise AssertionError("issuer ledger missing: HOLD, no reinitialization")
    uri = f"file:{DB}?mode={'rw' if existing else 'rwc'}"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=10)
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def rows() -> list:
    with connect() as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AssertionError("issuer ledger corrupted")
        return db.execute(
            "SELECT scope,nonce,issuer,issued_at,expires_at,consumed_at "
            "FROM challenges ORDER BY scope,nonce"
        ).fetchall()


def ledger_digest() -> str:
    return sha(canonical({"format": DOMAIN, "rows": rows()}))


def trusted_verification() -> list:
    if PRIVATE.exists():
        raise AssertionError("issuer private key not retired")
    public = PUB.read_bytes()
    if sha(public) != PIN.read_text(encoding="ascii").strip():
        raise AssertionError("untrusted issuer key")
    raw = ISSUANCE.read_bytes()
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or canonical(parsed) != raw:
        raise AssertionError("noncanonical issuance record")
    if not signature_valid(raw, SIGNATURE.read_bytes(), public):
        raise AssertionError("unsigned or forged issuance record")
    if (parsed.get("format") != DOMAIN or parsed.get("issuer") != ISSUER
        or parsed.get("authorization") != "NONE"
        or parsed.get("execution") != "HOLD"
        or not isinstance(parsed.get("challenges"), list)
        or len(parsed["challenges"]) != 2):
        raise AssertionError("invalid issuance scope / authority")
    signed = parsed["challenges"]
    all_rows = rows()
    if len(all_rows) != 2:
        raise AssertionError("missing or extra ledger challenges")
    for entry in signed:
        if (not isinstance(entry, dict)
            or not isinstance(entry.get("scope"), str) or not entry["scope"]
            or not isinstance(entry.get("nonce"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["nonce"])
            or type(entry.get("issued_at")) is not int
            or type(entry.get("expires_at")) is not int
            or entry["expires_at"] - entry["issued_at"] != TTL):
            raise AssertionError("invalid signed random nonce record")
        matching = [r for r in all_rows if r[:5] == (
            entry["scope"], entry["nonce"], ISSUER,
            entry["issued_at"], entry["expires_at"])]
        if len(matching) != 1 or matching[0][5] not in (None, NOW):
            raise AssertionError("ledger differs from signed issuance")
    if ledger_digest() != SNAPSHOT.read_text(encoding="ascii").strip():
        raise AssertionError("ledger head does not match separately pinned snapshot")
    return signed


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing to overwrite issuer ledger")
    ROOT.mkdir(mode=0o700, parents=True)
    with connect(existing=False) as db:
        db.execute("""CREATE TABLE challenges(
          scope TEXT NOT NULL, nonce TEXT NOT NULL, issuer TEXT NOT NULL,
          issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
          consumed_at INTEGER, PRIMARY KEY(scope,nonce),
          CHECK(expires_at > issued_at))""")
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE))
    PRIVATE.chmod(0o600)
    openssl("pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUB))
    issued = []
    for scope in ("ORCHEASTRA:CI:witness", "ORCHEASTRA:CI:recovery"):
        nonce = secrets.token_hex(32)
        issued.append({"scope": scope, "nonce": nonce,
                       "issued_at": NOW - 10, "expires_at": NOW - 10 + TTL})
        with connect() as db:
            db.execute("INSERT INTO challenges VALUES(?,?,?,?,?,NULL)",
                       (scope, nonce, ISSUER, NOW - 10, NOW - 10 + TTL))
    if issued[0]["nonce"] == issued[1]["nonce"]:
        raise AssertionError("CSPRNG nonce collision")
    raw = canonical({"format": DOMAIN, "issuer": ISSUER,
                     "authorization": "NONE", "execution": "HOLD",
                     "challenges": issued})
    ISSUANCE.write_bytes(raw)
    with tempfile.TemporaryDirectory(dir=ROOT) as path:
        output = Path(path) / "sig"
        openssl("pkeyutl", "-sign", "-inkey", str(PRIVATE),
                "-rawin", "-in", str(ISSUANCE), "-out", str(output))
        SIGNATURE.write_bytes(output.read_bytes())
    PRIVATE.unlink()
    PIN.write_text(sha(PUB.read_bytes()) + "\n", encoding="ascii")

    # Atomic one-time consumption for an authenticated test receipt.
    # The fixed v0.41 signed challenge is NOT falsely claimed to match
    # either newly generated random nonce.
    first = issued[0]
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        updated = db.execute(
            "UPDATE challenges SET consumed_at=? WHERE scope=? AND nonce=? "
            "AND issuer=? AND consumed_at IS NULL "
            "AND issued_at <= ? AND expires_at > ?",
            (NOW, first["scope"], first["nonce"], ISSUER, NOW, NOW))
        if updated.rowcount != 1:
            raise AssertionError("initial controlled consume failed")
        db.execute("COMMIT")
    SNAPSHOT.write_text(ledger_digest() + "\n", encoding="ascii")
    trusted_verification()

    with connect() as db:
        changed = db.execute(
            "UPDATE challenges SET consumed_at=? WHERE scope=? AND nonce=? "
            "AND consumed_at IS NULL", (NOW + 1, first["scope"], first["nonce"]))
        if changed.rowcount:
            raise AssertionError("replayed nonce consumed twice")
    # Database tampering MUST fail even with a plausible schema.
    with connect() as db:
        db.execute("UPDATE challenges SET issuer='forged' WHERE nonce=?",
                   (issued[1]["nonce"],))
    try:
        trusted_verification()
    except AssertionError:
        pass
    else:
        raise AssertionError("modified issuer ledger accepted")
    with connect() as db:
        db.execute("UPDATE challenges SET issuer=? WHERE nonce=?",
                   (ISSUER, issued[1]["nonce"]))
    trusted_verification()

    # Preserve the live DB then simulate full loss. SQLite must not
    # silently recreate an empty store in recovery.
    backup = ROOT / "ledger-backup"
    shutil.copyfile(DB, backup)
    DB.unlink()
    try:
        trusted_verification()
    except AssertionError:
        pass
    else:
        raise AssertionError("deleted issuer ledger was silently recreated")
    shutil.move(backup, DB)
    trusted_verification()
    print("ORCHEASTRA v0.43: signed 256-bit CSPRNG issuance, tamper/loss "
          "and one-use ledger checks PASS")


def verify() -> None:
    signed = trusted_verification()
    first = signed[0]
    with connect() as db:
        res = db.execute("SELECT consumed_at FROM challenges "
                         "WHERE scope=? AND nonce=?",
                         (first["scope"], first["nonce"])).fetchone()
    if res != (NOW,):
        raise AssertionError("once-only issuance not retained after restart")
    print("ORCHEASTRA v0.43: signed issuer ledger preserved; replay HOLD")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated CI PostgreSQL required")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError,
            sqlite3.Error, subprocess.TimeoutExpired) as error:
        print(f"ORCHEASTRA v0.43 FAIL: {error}", file=sys.stderr)
        sys.exit(1)
