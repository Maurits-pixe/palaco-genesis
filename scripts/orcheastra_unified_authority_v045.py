#!/usr/bin/env python3
"""ORCHEASTRA v0.45 -- unified, transactional CI nonce authority.

A *new* CSPRNG challenge is issued and consumed in ONE SQLite authority.
Domain-separated Ed25519 issuance and three witness transport signatures
are checked before single-use admission. Tests cover interrupted transactions,
concurrent contenders, replay, evidence tampering and missing database.
This is not a distributed service, trusted clock or execution authorization.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import sys

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_evidence_handoff_v037 import BUNDLE_COPY, PIN_COPY, HANDOFF, parse
from orcheastra_witness_quorum_v039 import IDS, RECORD, TRUST, verify_quorum
from orcheastra_witness_transport_v040 import REGISTRY
from orcheastra_end_to_end_nonce_v044 import openssl, sign, payload as witness_payload
from orcheastra_nonce_issuer_v043 import NOW

STORE = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v045"
DATABASE = STORE / "unified-authority.sqlite3"
ISSUANCE = STORE / "issued-challenge.json"
ISSUER_SIG = STORE / "issuer.sig"
ISSUER_PUB = STORE / "issuer-public.pem"
ISSUER_PIN = STORE / "issuer-public.sha256"
REQUEST = STORE / "request.json"
RESPONSES = STORE / "witness-responses.json"
WITNESS_PINS = STORE / "witness-pins.json"
SNAPSHOT = STORE / "unified-ledger-sha256.txt"
ISSUER_ID = "orcheastra-v045-isolated-ci"
ISSUE_DOMAIN = "PALACO:ORCHEASTRA:UNIFIED_ISSUER:v1"
REQUEST_DOMAIN = "PALACO:ORCHEASTRA:RANDOM_REQUEST:v1"
TTL = 120


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def connect() -> sqlite3.Connection:
    if not DATABASE.is_file():
        raise AssertionError("missing unified ledger: fail-closed HOLD")
    conn = sqlite3.connect(f"file:{DATABASE}?mode=rw", uri=True,
                           isolation_level=None, timeout=12)
    conn.execute("PRAGMA busy_timeout=12000")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def ledger_state() -> list:
    with connect() as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AssertionError("invalid SQLite integrity")
        return db.execute(
            "SELECT scope,nonce,issuer,request_sha256,issued_at,expires_at,"
            "consumed_at,outcome FROM admission ORDER BY scope,nonce"
        ).fetchall()


def signed_issuance() -> dict:
    if any(STORE.glob("*private.pem")):
        raise AssertionError("temporary signing key retained")
    raw = ISSUANCE.read_bytes()
    document = parse(raw)
    if (document.get("format") != ISSUE_DOMAIN
        or document.get("issuer") != ISSUER_ID
        or document.get("authorization") != "NONE"
        or document.get("execution") != "HOLD"):
        raise AssertionError("untrusted issuer document")
    if sha(ISSUER_PUB.read_bytes()) != ISSUER_PIN.read_text().strip():
        raise AssertionError("untrusted issuer public key")
    if not signature_valid(raw, ISSUER_SIG.read_bytes(), ISSUER_PUB.read_bytes()):
        raise AssertionError("issuer signature invalid")
    if not isinstance(document.get("challenge"), dict):
        raise AssertionError("missing issued challenge")
    item = document["challenge"]
    if (item.get("scope") != "ORCHEASTRA:CI:unified"
        or not isinstance(item.get("nonce"), str)
        or len(item["nonce"]) != 64
        or any(c not in "0123456789abcdef" for c in item["nonce"])
        or type(item.get("issued_at")) is not int
        or type(item.get("expires_at")) is not int
        or item["expires_at"] - item["issued_at"] != TTL):
        raise AssertionError("invalid signed challenge")
    return document


def expected_request() -> dict:
    item = signed_issuance()["challenge"]
    claim = parse(RECORD.read_bytes())["statements"][0]
    return {
        "format": REQUEST_DOMAIN,
        "nonce": item["nonce"],
        "scope": item["scope"],
        "issued_at": item["issued_at"],
        "expires_at": item["expires_at"],
        "issuer": ISSUER_ID,
        "claim_sha256": sha(canonical(claim)),
        "authorization": "NONE",
        "execution": "HOLD",
    }


def authenticate(request: dict, responses: list, pins: dict) -> str:
    if request != expected_request():
        raise AssertionError("unissued or altered request")
    if (not isinstance(pins, dict) or set(pins) != set(IDS)
        or len(set(pins.values())) != 3):
        raise AssertionError("untrusted witness pinset")
    if not isinstance(responses, list) or len(responses) != len(IDS):
        raise AssertionError("witness response count invalid")
    registry = parse(REGISTRY.read_bytes())
    record = parse(RECORD.read_bytes())
    votes = {vote["id"]: vote for vote in record["endorsements"]}
    seen = set()
    for response in responses:
        if not isinstance(response, dict):
            raise AssertionError("invalid response")
        identity = response.get("id")
        if identity not in IDS or identity in seen:
            raise AssertionError("repeated/unknown witness identity")
        seen.add(identity)
        signed = witness_payload(identity, request, registry, votes[identity])
        if response.get("payload") != signed:
            raise AssertionError("witness request signature binding invalid")
        try:
            public = bytes.fromhex(response["public_hex"])
            signature = bytes.fromhex(response["signature_hex"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AssertionError("malformed witness signature") from exc
        if sha(public) != pins[identity]:
            raise AssertionError("untrusted witness transport public key")
        if not signature_valid(canonical(signed), signature, public):
            raise AssertionError("witness response signature invalid")
    prior = verify_quorum(
        record, parse(TRUST.read_bytes()), BUNDLE_COPY.read_bytes(),
        PIN_COPY.read_text().strip(), HANDOFF.read_bytes()
    )
    if (prior["freshness"] != "CURRENT"
        or prior["authorization"] != "NONE"
        or prior["execution"] != "HOLD"
        or prior["witness_quorum"] != 3):
        raise AssertionError("original authenticated evidence unavailable")
    return sha(canonical(request))


def consume(request: dict, responses: list, pins: dict, now: int,
            simulate_interrupt: bool = False) -> str:
    request_digest = authenticate(request, responses, pins)
    if type(now) is not int:
        raise AssertionError("untrusted time type")
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            result = db.execute(
                """UPDATE admission SET consumed_at=?,outcome='VERIFIED_HOLD'
                   WHERE scope=? AND nonce=? AND issuer=? AND request_sha256=?
                   AND consumed_at IS NULL AND issued_at<=? AND expires_at>?""",
                (now, request["scope"], request["nonce"], ISSUER_ID,
                 request_digest, now, now)
            )
            if result.rowcount != 1:
                raise AssertionError("replayed, expired or missing challenge")
            if simulate_interrupt:
                raise AssertionError("injected pre-commit failure")
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return "VERIFIED_HOLD"


def denied(fn, label: str) -> None:
    try:
        fn()
    except (AssertionError, sqlite3.Error):
        return
    raise AssertionError("unsafe state accepted: " + label)


def build() -> None:
    if STORE.exists():
        raise AssertionError("refusing to overwrite unified test authority")
    STORE.mkdir(parents=True, mode=0o700)
    issuer_private = STORE / "issuer-private.pem"
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(issuer_private))
    issuer_private.chmod(0o600)
    openssl("pkey", "-in", str(issuer_private), "-pubout", "-out", str(ISSUER_PUB))
    issued = {
        "scope": "ORCHEASTRA:CI:unified", "nonce": secrets.token_hex(32),
        "issued_at": NOW - 10, "expires_at": NOW - 10 + TTL,
    }
    ISSUANCE.write_bytes(canonical({
        "format": ISSUE_DOMAIN, "issuer": ISSUER_ID,
        "challenge": issued, "authorization": "NONE", "execution": "HOLD"
    }))
    ISSUER_SIG.write_bytes(sign(issuer_private, ISSUANCE.read_bytes()))
    issuer_private.unlink()
    ISSUER_PIN.write_text(sha(ISSUER_PUB.read_bytes()) + "\n")
    request = expected_request()

    record = parse(RECORD.read_bytes())
    registry = parse(REGISTRY.read_bytes())
    fingerprints, responses = {}, []
    for vote in record["endorsements"]:
        identity = vote["id"]
        private = STORE / f"{identity}-private.pem"
        public = STORE / f"{identity}-public.pem"
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
        fingerprints[identity] = sha(public.read_bytes())
        signed = witness_payload(identity, request, registry, vote)
        responses.append({
            "id": identity, "payload": signed,
            "public_hex": public.read_bytes().hex(),
            "signature_hex": sign(private, canonical(signed)).hex(),
        })
        private.unlink()
    request_hash = authenticate(request, responses, fingerprints)

    # One authoritative SQLite table holds BOTH issuance and consumption.
    with sqlite3.connect(DATABASE) as db:
        db.execute("""CREATE TABLE admission(
            scope TEXT NOT NULL,nonce TEXT NOT NULL,issuer TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,consumed_at INTEGER,outcome TEXT,
            PRIMARY KEY(scope,nonce),CHECK(expires_at>issued_at),
            CHECK((consumed_at IS NULL AND outcome IS NULL) OR
                  (consumed_at IS NOT NULL AND outcome='VERIFIED_HOLD'))
        )""")
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO admission VALUES(?,?,?,?,?,?,NULL,NULL)",
                   (issued["scope"],issued["nonce"],ISSUER_ID,
                    request_hash,issued["issued_at"],issued["expires_at"]))
        db.commit()

    # Interrupted transaction must not consume the nonce.
    denied(lambda: consume(request, responses, fingerprints, NOW, True),
           "interrupted transaction")
    if ledger_state()[0][-2:] != (None, None):
        raise AssertionError("pre-commit rollback did not restore issue state")
    denied(lambda: consume(request, [
        {**responses[0], "signature_hex": "00" * 64}, *responses[1:]
    ], fingerprints, NOW), "bad witness signature")
    denied(lambda: consume(request, responses, fingerprints,
                           request["expires_at"]), "expiry boundary")
    denied(lambda: consume({**request, "nonce": "00" * 32},
                           responses, fingerprints, NOW), "unissued nonce")
    if ledger_state()[0][-2:] != (None, None):
        raise AssertionError("failed admissions mutated issuance record")

    def contender(_: int) -> bool:
        try:
            return consume(request, responses, fingerprints, NOW) == "VERIFIED_HOLD"
        except AssertionError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(contender, range(8)))
    if sum(outcomes) != 1:
        raise AssertionError("multiple consumers accepted same challenge")
    denied(lambda: consume(request, responses, fingerprints, NOW+1),
           "post-commit replay")
    REQUEST.write_bytes(canonical(request))
    RESPONSES.write_bytes(canonical(responses))
    WITNESS_PINS.write_bytes(canonical(fingerprints))
    SNAPSHOT.write_text(sha(canonical({"rows": ledger_state()})) + "\n")

    # Missing DB must never cause auto-create or an empty state downgrade.
    backup = STORE / "temporary-backup"
    shutil.copyfile(DATABASE, backup)
    DATABASE.unlink()
    denied(lambda: consume(request, responses, fingerprints, NOW+1),
           "database loss")
    if DATABASE.exists():
        raise AssertionError("lost database silently recreated")
    backup.rename(DATABASE)
    verify_restart()
    print("ORCHEASTRA v0.45: unified issuance/consume, rollback, 8-way "
          "race and missing-ledger HOLD PASS")


def verify_restart() -> None:
    request = parse(REQUEST.read_bytes())
    responses = json.loads(RESPONSES.read_bytes())
    pins = parse(WITNESS_PINS.read_bytes())
    digest = authenticate(request, responses, pins)
    data = ledger_state()
    if data != [[request["scope"], request["nonce"], ISSUER_ID, digest,
                 request["issued_at"], request["expires_at"], NOW,
                 "VERIFIED_HOLD"]] and data != [
        (request["scope"], request["nonce"], ISSUER_ID, digest,
         request["issued_at"], request["expires_at"], NOW, "VERIFIED_HOLD")
    ]:
        raise AssertionError("unexpected unified authority state")
    if sha(canonical({"rows": data})) != SNAPSHOT.read_text().strip():
        raise AssertionError("unified ledger differs from pinned digest")
    denied(lambda: consume(request, responses, pins, NOW+1),
           "restart replay")
    print("ORCHEASTRA v0.45: single authority retained; replay HOLD")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated CI PostgreSQL required")
    if sys.argv[1:] == ["--create"]:
        build()
    elif sys.argv[1:] == ["--verify"]:
        verify_restart()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            sqlite3.Error) as exc:
        print(f"ORCHEASTRA v0.45 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
