#!/usr/bin/env python3
"""ORCHEASTRA v0.44: issuer -> signed witnesses -> atomic one-use admission.

CI-only integration. The v0.43 signed random challenge is authenticated
before three *new* ephemeral Ed25519 transport keys sign its request.
Original v0.39 high-water endorsements remain separately verified.
An isolated SQLite store atomically consumes that exact issued challenge.
No live witness servers, trusted clock, external pin custody or execution.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_evidence_handoff_v037 import BUNDLE_COPY, PIN_COPY, HANDOFF, parse
from orcheastra_witness_quorum_v039 import (
    IDS, RECORD, TRUST, DOMAIN as QUORUM_DOMAIN, verify_quorum,
)
from orcheastra_witness_transport_v040 import REGISTRY
from orcheastra_nonce_issuer_v043 import (
    ISSUER, NOW, trusted_verification,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v044"
DB = ROOT / "atomic-admission.sqlite3"
REQUEST = ROOT / "signed-request-context.json"
RESPONSES = ROOT / "nonce-bound-responses.json"
PINSET = ROOT / "trusted-transport-keys.json"
DOMAIN = "PALACO:ORCHEASTRA:NONCE_BOUND_RESPONSE:v1"
REQUEST_DOMAIN = "PALACO:ORCHEASTRA:RANDOM_REQUEST:v1"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def openssl(*args: str) -> None:
    process = subprocess.run(["openssl", *args], capture_output=True,
                             text=True, check=False, timeout=20)
    if process.returncode:
        raise AssertionError("ephemeral witness signing failed")


def sign(private: Path, raw: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        source = Path(folder) / "document"
        target = Path(folder) / "signature"
        source.write_bytes(raw)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(source), "-out", str(target))
        return target.read_bytes()


def connect() -> sqlite3.Connection:
    if not DB.is_file():
        raise AssertionError("missing admission ledger: HOLD")
    db = sqlite3.connect(f"file:{DB}?mode=rw", uri=True,
                         isolation_level=None, timeout=12)
    db.execute("PRAGMA busy_timeout=12000")
    db.execute("PRAGMA synchronous=FULL")
    return db


def issued_nonce() -> dict:
    issuance = trusted_verification()
    available = [item for item in issuance
                 if item["scope"] == "ORCHEASTRA:CI:recovery"]
    if len(available) != 1:
        raise AssertionError("exactly one authenticated recovery nonce required")
    return available[0]


def claim_request() -> dict:
    issued = issued_nonce()
    claim = parse(RECORD.read_bytes())["statements"][0]
    return {
        "format": REQUEST_DOMAIN,
        "nonce": issued["nonce"],
        "scope": issued["scope"],
        "issued_at": issued["issued_at"],
        "expires_at": issued["expires_at"],
        "issuer": ISSUER,
        "claim_sha256": sha(canonical(claim)),
        "authorization": "NONE",
        "execution": "HOLD",
    }


def payload(identity: str, request: dict, registry: dict, vote: dict) -> dict:
    return {
        "format": DOMAIN,
        "identity": identity,
        "endpoint": registry["witnesses"][identity]["endpoint"],
        "nonce": request["nonce"],
        "request_sha256": sha(canonical(request)),
        "issuer": request["issuer"],
        "scope": request["scope"],
        "claim_sha256": request["claim_sha256"],
        "endorsement_sha256": sha(canonical(vote)),
        "authorization": "NONE",
        "execution": "HOLD",
    }


def authenticate(request: dict, responses: list, pins: dict) -> str:
    expected = claim_request()
    if request != expected:
        raise AssertionError("request does not match signed nonce issuance")
    if (not isinstance(pins, dict) or set(pins) != set(IDS)
        or len(set(pins.values())) != 3):
        raise AssertionError("missing independent transport pins")
    if not isinstance(responses, list) or len(responses) != 3:
        raise AssertionError("incomplete signed witness responses")
    registry = parse(REGISTRY.read_bytes())
    signed_claim = parse(RECORD.read_bytes())
    original_votes = {vote["id"]: vote for vote in signed_claim["endorsements"]}
    seen = set()
    for response in responses:
        if not isinstance(response, dict) or set(response) != {
            "id", "payload", "public_hex", "signature_hex"
        }:
            raise AssertionError("malformed witness envelope")
        identity = response["id"]
        if identity not in IDS or identity in seen:
            raise AssertionError("unknown or repeated witness")
        seen.add(identity)
        signed = response["payload"]
        if signed != payload(identity, request, registry, original_votes[identity]):
            raise AssertionError("nonce, issuer, endpoint or claim substitution")
        try:
            public = bytes.fromhex(response["public_hex"])
            signature = bytes.fromhex(response["signature_hex"])
        except (ValueError, TypeError) as exc:
            raise AssertionError("malformed transport signature") from exc
        if sha(public) != pins[identity]:
            raise AssertionError("transport signer outside pinned roster")
        if not signature_valid(canonical(signed), signature, public):
            raise AssertionError("invalid nonce-bound Ed25519 signature")
    # Original historical witness authority MUST still be independently checked.
    result = verify_quorum(
        signed_claim, parse(TRUST.read_bytes()), BUNDLE_COPY.read_bytes(),
        PIN_COPY.read_text(encoding="ascii").strip(), HANDOFF.read_bytes(),
    )
    if (result["freshness"] != "CURRENT" or result["execution"] != "HOLD"
        or result["authorization"] != "NONE" or result["witness_quorum"] != 3):
        raise AssertionError("historical witness quorum not trusted")
    return sha(canonical(request))


def consume(request: dict, responses: list, pins: dict, clock: int) -> str:
    # A failed signature verification CANNOT mark the nonce consumed.
    request_hash = authenticate(request, responses, pins)
    if type(clock) is not int:
        raise AssertionError("untrusted clock type")
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            changed = db.execute(
                """UPDATE admissions SET consumed_at=?, outcome='VERIFIED_HOLD'
                   WHERE scope=? AND nonce=? AND request_sha256=?
                   AND issuer=? AND consumed_at IS NULL
                   AND issued_at <= ? AND expires_at > ?""",
                (clock, request["scope"], request["nonce"], request_hash,
                 ISSUER, clock, clock),
            )
            if changed.rowcount != 1:
                raise AssertionError("replay, expiration or missing issuance")
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return "VERIFIED_HOLD"


def expect_denied(work, label: str) -> None:
    try:
        work()
    except (AssertionError, ValueError, TypeError, KeyError):
        return
    raise AssertionError("untrusted admission accepted: " + label)


def build() -> None:
    if ROOT.exists():
        raise AssertionError("refusing to overwrite admission evidence")
    request = claim_request()
    ROOT.mkdir(mode=0o700, parents=True)
    record = parse(RECORD.read_bytes())
    registry = parse(REGISTRY.read_bytes())
    responses, fingerprints = [], {}
    for vote in record["endorsements"]:
        identity = vote["id"]
        private = ROOT / f"{identity}-private.pem"
        public = ROOT / f"{identity}-public.pem"
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
        public_raw = public.read_bytes()
        fingerprints[identity] = sha(public_raw)
        signed = payload(identity, request, registry, vote)
        responses.append({
            "id": identity, "payload": signed,
            "public_hex": public_raw.hex(),
            "signature_hex": sign(private, canonical(signed)).hex(),
        })
    for identity in IDS:
        (ROOT / f"{identity}-private.pem").unlink()
    request_hash = authenticate(request, responses, fingerprints)

    db = sqlite3.connect(DB)
    try:
        db.execute("""CREATE TABLE admissions(
            scope TEXT NOT NULL, nonce TEXT NOT NULL, issuer TEXT NOT NULL,
            request_sha256 TEXT NOT NULL, issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, consumed_at INTEGER, outcome TEXT,
            PRIMARY KEY(scope,nonce),
            CHECK(expires_at > issued_at),
            CHECK((consumed_at IS NULL AND outcome IS NULL) OR
                  (consumed_at IS NOT NULL AND outcome='VERIFIED_HOLD'))
        )""")
        db.execute(
            "INSERT INTO admissions VALUES(?,?,?,?,?,?,NULL,NULL)",
            (request["scope"], request["nonce"], request["issuer"],
             request_hash, request["issued_at"], request["expires_at"]),
        )
        db.commit()
    finally:
        db.close()

    first = responses[0]
    def altered(field: str, value) -> list:
        return [{**first, field: value}, *responses[1:]]
    expect_denied(
        lambda: consume(request, altered("signature_hex", "00" * 64),
                        fingerprints, NOW), "forged witness signature")
    expect_denied(
        lambda: consume({**request, "nonce": "00" * 32},
                        responses, fingerprints, NOW), "unissued nonce")
    expect_denied(
        lambda: consume(request, altered("payload", {
            **first["payload"], "endpoint": "untrusted-endpoint",
        }), fingerprints, NOW), "endpoint substitution")
    expect_denied(
        lambda: consume(request, responses, fingerprints,
                        request["expires_at"]), "expired challenge")

    # The valid response races across independent DB connections; exactly
    # one commit can win. Signing keys were deleted before any consumption.
    def contender(_: int) -> bool:
        try:
            return consume(request, responses, fingerprints, NOW) == "VERIFIED_HOLD"
        except AssertionError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        won = list(pool.map(contender, range(8)))
    if sum(won) != 1:
        raise AssertionError("multiple authenticated consumers committed")
    expect_denied(lambda: consume(request, responses, fingerprints, NOW + 1),
                  "replay after acceptance")
    REQUEST.write_bytes(canonical(request))
    RESPONSES.write_bytes(canonical(responses))
    PINSET.write_bytes(canonical(fingerprints))
    print("ORCHEASTRA v0.44: signed RANDOM nonce -> 3 signed witnesses "
          "-> 1 of 8 atomic consumers PASS")


def verify_restart() -> None:
    request = parse(REQUEST.read_bytes())
    responses = json.loads(RESPONSES.read_bytes())
    pins = parse(PINSET.read_bytes())
    request_hash = authenticate(request, responses, pins)
    with connect() as db:
        found = db.execute(
            "SELECT request_sha256, consumed_at, outcome FROM admissions "
            "WHERE scope=? AND nonce=?",
            (request["scope"], request["nonce"]),
        ).fetchone()
    if found != (request_hash, NOW, "VERIFIED_HOLD"):
        raise AssertionError("signed random challenge not retained after restart")
    expect_denied(lambda: consume(request, responses, pins, NOW + 1),
                  "replay after PostgreSQL restart")
    print("ORCHEASTRA v0.44: signed issuance/witness/atomic replay HOLD after restart")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated loopback CI required")
    if sys.argv[1:] == ["--create"]:
        build()
    elif sys.argv[1:] == ["--verify"]:
        verify_restart()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError, KeyError,
            sqlite3.Error, subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.44 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
