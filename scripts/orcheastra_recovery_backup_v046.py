#!/usr/bin/env python3
"""ORCHEASTRA v0.46: fail-closed recovery with a pinned local high-water head.

A consistent SQLite backup is made through sqlite3.Connection.backup().
The backup is *inspected* in a staging connection; this module never replaces
the live ledger or authorizes execution. A separately pinned runner-local
canonical high-water statement binds the exact consumed v0.45 row and backup
digest. Older, corrupt, absent or substituted copies fail closed.

CI fixture ONLY: the head is not independently hosted or authenticated.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_evidence_handoff_v037 import parse
from orcheastra_unified_authority_v045 import (
    DATABASE, REQUEST, RESPONSES, WITNESS_PINS, SNAPSHOT,
    NOW, authenticate, connect, ledger_state, denied,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v046"
BACKUP = ROOT / "authority-backup.sqlite3"
HEAD = ROOT / "recovery-high-water.json"
HEAD_PIN = ROOT / "trusted-head.sha256"
DOMAIN = "PALACO:ORCHEASTRA:RECOVERY_HIGH_WATER:v1"
SELECT = ("SELECT scope,nonce,issuer,request_sha256,issued_at,"
          "expires_at,consumed_at,outcome FROM admission ORDER BY scope,nonce")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_rows(path: Path) -> list:
    if not path.is_file():
        raise AssertionError("missing recovery database: HOLD")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AssertionError("recovery backup SQLite integrity mismatch")
        rows = db.execute(SELECT).fetchall()
        if len(rows) != 1:
            raise AssertionError("unexpected number of recovery records")
        return rows
    finally:
        db.close()


def verify_backup(path: Path, head_raw: bytes, independently_pinned_hash: str) -> dict:
    if sha(head_raw) != independently_pinned_hash:
        raise AssertionError("recovery head not pinned")
    head = parse(head_raw)
    if (set(head) != {
        "format", "sequence", "ledger_sha256", "backup_sha256",
        "scope", "nonce_sha256", "state", "authorization", "execution"
    } or head["format"] != DOMAIN or type(head["sequence"]) is not int
        or head["sequence"] != 1 or head["state"] != "VERIFIED_HOLD"
        or head["authorization"] != "NONE" or head["execution"] != "HOLD"):
        raise AssertionError("untrusted recovery head contents")
    if not path.is_file() or sha(path.read_bytes()) != head["backup_sha256"]:
        raise AssertionError("backup missing or changed against trusted head")
    rows = read_rows(path)
    raw = canonical({"rows": rows})
    if sha(raw) != head["ledger_sha256"]:
        raise AssertionError("stale or rewritten recovery state")
    row = rows[0]
    if (row[0] != head["scope"]
        or sha(row[1].encode("ascii")) != head["nonce_sha256"]
        or row[6] != NOW or row[7] != "VERIFIED_HOLD"):
        raise AssertionError("recovery would resurrect a consumed nonce")
    return {"status": "VERIFIED_HOLD", "recovery": "STAGED_ONLY",
            "authorization": "NONE", "execution": "HOLD"}


def fails(action, reason: str) -> None:
    try:
        action()
    except (AssertionError, ValueError, KeyError, TypeError, sqlite3.Error):
        return
    raise AssertionError("unsafe recovery accepted: " + reason)


def build() -> None:
    if ROOT.exists():
        raise AssertionError("refusing overwrite of recovery evidence")
    # v0.45 verifies signed witnesses, current original evidence and ledger.
    request = parse(REQUEST.read_bytes())
    responses = json.loads(RESPONSES.read_bytes())
    pins = parse(WITNESS_PINS.read_bytes())
    expected_request_hash = authenticate(request, responses, pins)
    live = ledger_state()
    if (len(live) != 1 or live[0][3] != expected_request_hash
        or live[0][6] != NOW or live[0][7] != "VERIFIED_HOLD"
        or sha(canonical({"rows": live})) != SNAPSHOT.read_text().strip()):
        raise AssertionError("unverified live authority cannot be backed up")

    ROOT.mkdir(parents=True, mode=0o700)
    # SQLite's online backup API produces a transactionally consistent file,
    # rather than a possibly torn raw copy of an active database.
    with connect() as source:
        with sqlite3.connect(BACKUP) as destination:
            source.backup(destination)
    if read_rows(BACKUP) != live:
        raise AssertionError("consistent backup differs from live authority")

    anchor = {
        "format": DOMAIN, "sequence": 1,
        "ledger_sha256": sha(canonical({"rows": live})),
        "backup_sha256": sha(BACKUP.read_bytes()),
        "scope": request["scope"],
        "nonce_sha256": sha(request["nonce"].encode("ascii")),
        "state": "VERIFIED_HOLD", "authorization": "NONE",
        "execution": "HOLD",
    }
    HEAD.write_bytes(canonical(anchor))
    HEAD_PIN.write_text(sha(HEAD.read_bytes()) + "\n", encoding="ascii")
    pinned = HEAD_PIN.read_text(encoding="ascii").strip()
    if verify_backup(BACKUP, HEAD.read_bytes(), pinned)["execution"] != "HOLD":
        raise AssertionError("initial recovery evidence invalid")

    # Corrupted copy: never open it as the live authority.
    corrupt = ROOT / "tampered.sqlite3"
    shutil.copyfile(BACKUP, corrupt)
    with corrupt.open("r+b") as stream:
        stream.seek(0)
        stream.write(b"X")
    fails(lambda: verify_backup(corrupt, HEAD.read_bytes(), pinned),
          "corrupted backup")

    # A syntactically valid but *older* backup is not acceptable either.
    stale = ROOT / "stale.sqlite3"
    shutil.copyfile(BACKUP, stale)
    with sqlite3.connect(stale) as db:
        db.execute("UPDATE admission SET consumed_at=NULL,outcome=NULL")
        db.commit()
    fails(lambda: verify_backup(stale, HEAD.read_bytes(), pinned),
          "valid but rolled-back database")

    fails(lambda: verify_backup(BACKUP, HEAD.read_bytes(), "00" * 32),
          "untrusted head fingerprint")
    replaced = canonical({**anchor, "sequence": 0})
    fails(lambda: verify_backup(BACKUP, replaced, pinned),
          "downgraded high-water sequence")
    missing = ROOT / "absent.sqlite3"
    fails(lambda: verify_backup(missing, HEAD.read_bytes(), pinned),
          "missing backup")

    # Simulated restore goes to a STAGING file. It never overwrites live.
    staged = ROOT / "staged-restore.sqlite3"
    shutil.copyfile(BACKUP, staged)
    verify_backup(staged, HEAD.read_bytes(), pinned)
    if ledger_state() != live:
        raise AssertionError("recovery staging changed the live authority")
    print("ORCHEASTRA v0.46: pinned, consistent backup; rollback/tamper/"
          "missing-head tests and staging-only recovery PASS")


def verify_after_restart() -> None:
    pinned = HEAD_PIN.read_text(encoding="ascii").strip()
    verified = verify_backup(BACKUP, HEAD.read_bytes(), pinned)
    request = parse(REQUEST.read_bytes())
    live = ledger_state()
    if (live != read_rows(BACKUP) or live[0][1] != request["nonce"]
        or sha(canonical({"rows": live})) != SNAPSHOT.read_text().strip()):
        raise AssertionError("live authority no longer matches trusted recovery head")
    if verified["recovery"] != "STAGED_ONLY":
        raise AssertionError("recovery attempted live activation")
    print("ORCHEASTRA v0.46: immutable consumed state and recovery HOLD after restart")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated loopback CI only")
    if sys.argv[1:] == ["--create"]:
        build()
    elif sys.argv[1:] == ["--verify"]:
        verify_after_restart()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError, KeyError,
            sqlite3.Error) as exc:
        print(f"ORCHEASTRA v0.46 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
