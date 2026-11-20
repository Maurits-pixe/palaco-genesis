#!/usr/bin/env python3
"""ORCHEASTRA v0.42: SQLite-atomic, one-time recovery challenge consumption.

CI-only replay ledger: verify v0.41 signatures *before* atomic consumption.
A SQLite BEGIN IMMEDIATE transaction updates an issued challenge exactly once,
and persists accepted state across a process restart. This is NOT production
nonce distribution, a trusted time service, or a task execution authority.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timezone

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_evidence_handoff_v037 import BUNDLE_COPY, PIN_COPY, HANDOFF, parse
from orcheastra_witness_quorum_v039 import TRUST
from orcheastra_witness_transport_v040 import REGISTRY, REQUEST
from orcheastra_witness_signed_transport_v041 import (
    TRUSTED, ENVELOPES, verify_signed,
)

STORE = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v042"
DB = STORE / "replay-ledger.sqlite3"
DOMAIN = "PALACO:ORCHEASTRA:REPLAY_LEDGER:v1"
CLOCK = 1794996000  # Deterministic CI fixture seconds UTC; not a trusted clock.
ISSUED = CLOCK - 120
EXPIRES = CLOCK + 120


def connection() -> sqlite3.Connection:
    db = sqlite3.connect(str(DB), timeout=12, isolation_level=None)
    db.execute("PRAGMA busy_timeout=12000")
    db.execute("PRAGMA synchronous=FULL")
    return db


def init() -> None:
    if STORE.exists():
        raise AssertionError("refusing overwrite of an existing replay ledger")
    STORE.mkdir(mode=0o700, parents=True)
    with connection() as db:
        db.execute("""CREATE TABLE challenges (
            scope TEXT NOT NULL,
            nonce TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            result TEXT,
            PRIMARY KEY(scope, nonce),
            CHECK(expires_at > issued_at),
            CHECK((consumed_at IS NULL AND result IS NULL)
               OR (consumed_at IS NOT NULL AND result = 'VERIFIED_HOLD'))
        )""")


def issue(scope: str, nonce: str, request_hash: str,
          issued_at: int, expires_at: int) -> None:
    if (not scope or not nonce or len(nonce) > 256
        or len(request_hash) != 64
        or type(issued_at) is not int or type(expires_at) is not int
        or expires_at <= issued_at or expires_at - issued_at > 300):
        raise AssertionError("challenge issuance contract invalid")
    with connection() as db:
        try:
            db.execute("INSERT INTO challenges "
                       "(scope,nonce,request_sha256,issued_at,expires_at) "
                       "VALUES (?,?,?,?,?)",
                       (scope, nonce, request_hash, issued_at, expires_at))
        except sqlite3.IntegrityError as err:
            raise AssertionError("duplicate challenge issuance") from err


def consume(scope: str, nonce: str, request_hash: str,
            clock: int, authenticated: bool) -> str:
    if not authenticated or type(clock) is not int:
        raise AssertionError("unverified witness response / invalid clock")
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            cur = db.execute(
                """UPDATE challenges
                   SET consumed_at=?, result='VERIFIED_HOLD'
                   WHERE scope=? AND nonce=? AND request_sha256=?
                     AND consumed_at IS NULL
                     AND issued_at <= ? AND expires_at > ?""",
                (clock, scope, nonce, request_hash, clock, clock),
            )
            if cur.rowcount != 1:
                raise AssertionError("unknown, expired, or already consumed challenge")
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return "VERIFIED_HOLD"


def fixture() -> tuple[dict, dict]:
    registry = parse(REGISTRY.read_bytes())
    request = parse(REQUEST.read_bytes())
    envelopes = json.loads(ENVELOPES.read_bytes())
    transport_pins = parse(TRUSTED.read_bytes())
    quorum_pins = parse(TRUST.read_bytes())
    result = verify_signed(
        registry, request, envelopes, transport_pins, quorum_pins,
        BUNDLE_COPY.read_bytes(),
        PIN_COPY.read_text(encoding="ascii").strip(),
        HANDOFF.read_bytes(),
    )
    if result["authorization"] != "NONE" or result["execution"] != "HOLD":
        raise AssertionError("witness verification attempted authority")
    return request, result


def must_reject(action, scenario: str) -> None:
    try:
        action()
    except (AssertionError, sqlite3.IntegrityError):
        return
    raise AssertionError("unsafe replay accepted: " + scenario)


def build() -> None:
    request, verified = fixture()
    if verified["transport_signatures"] != 3:
        raise AssertionError("signed witness quorum incomplete")
    init()
    scope = request["scope"]
    nonce = request["challenge"]
    request_hash = hashlib.sha256(canonical(request)).hexdigest()
    issue(scope, nonce, request_hash, ISSUED, EXPIRES)

    must_reject(lambda: consume(scope, nonce, request_hash, CLOCK, False),
                "unauthenticated response")
    must_reject(lambda: consume(scope, nonce, "00" * 32, CLOCK, True),
                "modified request hash")
    must_reject(lambda: consume(scope, nonce, request_hash, EXPIRES, True),
                "expiry boundary")
    must_reject(lambda: consume(scope, nonce, request_hash, ISSUED - 1, True),
                "before issuance")

    # Concurrent contenders use separate SQLite connections and cannot
    # both claim the same nonce. Exactly one UPDATE can commit.
    def contender(_: int) -> bool:
        try:
            return consume(scope, nonce, request_hash, CLOCK, True) == "VERIFIED_HOLD"
        except AssertionError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        winners = list(pool.map(contender, range(8)))
    if sum(winners) != 1:
        raise AssertionError("atomic once-only challenge invariant violated")
    must_reject(lambda: consume(scope, nonce, request_hash, CLOCK + 1, True),
                "post-commit replay")
    must_reject(lambda: issue(scope, nonce, request_hash, ISSUED, EXPIRES),
                "duplicate issue")
    must_reject(lambda: consume(scope, "unknown", request_hash, CLOCK, True),
                "unissued challenge")

    # Independently issued test nonce for timeout, expiry and boundaries.
    second = nonce + "-expiry"
    issue(scope, second, request_hash, ISSUED, EXPIRES)
    must_reject(lambda: consume(scope, second, request_hash, EXPIRES + 1, True),
                "expired unused challenge")
    must_reject(lambda: issue(scope, nonce + "-bad", request_hash, CLOCK, CLOCK),
                "empty validity window")
    must_reject(lambda: issue(scope, nonce + "-long", request_hash,
                              ISSUED, EXPIRES + 1000),
                "oversized validity window")

    with connection() as db:
        rows = db.execute("SELECT nonce, result FROM challenges ORDER BY nonce").fetchall()
        if len(rows) != 2 or sum(value == "VERIFIED_HOLD" for _, value in rows) != 1:
            raise AssertionError("replay ledger evidence inconsistent")
    print("ORCHEASTRA v0.42: 8 concurrent contenders, 1 acceptance; "
          "replay/expiry/issuance checks PASS")


def verify_restart() -> None:
    request, _ = fixture()
    scope, nonce = request["scope"], request["challenge"]
    request_hash = hashlib.sha256(canonical(request)).hexdigest()
    with connection() as db:
        record = db.execute(
            "SELECT request_sha256, consumed_at, result FROM challenges "
            "WHERE scope=? AND nonce=?", (scope, nonce),
        ).fetchone()
    if record != (request_hash, CLOCK, "VERIFIED_HOLD"):
        raise AssertionError("atomic replay ledger was not retained")
    must_reject(lambda: consume(scope, nonce, request_hash, CLOCK + 1, True),
                "replay after PostgreSQL restart")
    print("ORCHEASTRA v0.42: durable SQLite claim survives PostgreSQL restart; HOLD")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("only isolated loopback CI accepted")
    if sys.argv[1:] == ["--create"]:
        build()
    elif sys.argv[1:] == ["--verify"]:
        verify_restart()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError,
            sqlite3.Error) as error:
        print(f"ORCHEASTRA v0.42 FAILED: {error}", file=sys.stderr)
        sys.exit(1)
