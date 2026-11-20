#!/usr/bin/env python3
"""ORCHEASTRA v0.53 -- owner JA/NEE decision dossier, isolated CI only.

The alleged owner is a DISPOSABLE test key, never the real PALACO owner.
Signed YES/NO decisions are review records, NOT authorization. All appended
events remain in SQLite with update/delete guards and a SHA-256 hash chain.
The separately pinned head is CI-local, not an external transparency anchor.
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
from orcheastra_evidence_handoff_v037 import parse
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_root_incident_review_v052 import (
    CASE, VOTES, TRUST, EVIDENCE, custody_inputs, verify_review,
)
from orcheastra_root_custody_v051 import sign as unused_sign  # no live key reused

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v053"
DB = ROOT / "owner-decisions.sqlite3"
DOSSIER = ROOT / "owner-dossier.json"
PIN = ROOT / "owner-test-pin.json"
PUBLIC = ROOT / "owner-test-public.pem"
PRIVATE = ROOT / "owner-test-private.pem"
YES = ROOT / "yes-signed.json"
NO = ROOT / "no-signed.json"
HEAD = ROOT / "independent-ledger-head.json"
DOMAIN = "PALACO:ORCHEASTRA:OWNER_DECISION_DOSSIER:v1"
DECISION_DOMAIN = "PALACO:ORCHEASTRA:OWNER_DECISION:v1"
PIN_DOMAIN = "PALACO:ORCHEASTRA:OWNER_TEST_TRUST:v1"
HEAD_DOMAIN = "PALACO:ORCHEASTRA:OWNER_AUDIT_HEAD:v1"
GENESIS = "0" * 64


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def connection() -> sqlite3.Connection:
    if not DB.is_file():
        raise AssertionError("owner decision ledger missing: HOLD")
    db = sqlite3.connect(f"file:{DB}?mode=rw", uri=True,
                         isolation_level=None, timeout=15)
    db.execute("PRAGMA busy_timeout=15000")
    db.execute("PRAGMA synchronous=FULL")
    return db


def sign(private: Path, payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        input_file = Path(tmp) / "payload"
        output_file = Path(tmp) / "signature"
        input_file.write_bytes(payload)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(private),
             "-rawin", "-in", str(input_file), "-out", str(output_file)],
            capture_output=True, timeout=20, check=False,
        )
        if result.returncode:
            raise AssertionError("test owner signature failed")
        return output_file.read_bytes()


def validate_dossier(dossier: dict) -> None:
    if (not isinstance(dossier, dict)
        or set(dossier) != {"format", "case_sha256", "votes_sha256",
                            "review_trust_sha256", "evidence_sha256",
                            "custody_sha256", "scope", "risks",
                            "decision_options", "authorization", "execution"}
        or dossier["format"] != DOMAIN
        or dossier["decision_options"] != ["JA", "NEE"]
        or dossier["authorization"] != "NONE"
        or dossier["execution"] != "HOLD"
        or dossier["case_sha256"] != sha(CASE.read_bytes())
        or dossier["votes_sha256"] != sha(VOTES.read_bytes())
        or dossier["review_trust_sha256"] != sha(TRUST.read_bytes())
        or dossier["evidence_sha256"] != sha(EVIDENCE.read_bytes())
        or dossier["custody_sha256"] != sha(custody_inputs()[0])
        or dossier["scope"] != parse(CASE.read_bytes())["scope"]
        or dossier["risks"] != [
            "POSSIBLE_ROOT_COMPROMISE", "UNTRUSTED_REPLACEMENT",
            "LOCAL_CI_TRUST_ONLY", "NO_PRODUCTION_APPROVAL"
        ]):
        raise AssertionError("owner dossier differs from review evidence")
    verdict = verify_review(parse(CASE.read_bytes()), parse(VOTES.read_bytes()),
                            parse(TRUST.read_bytes()), EVIDENCE.read_bytes(),
                            custody_inputs())
    if verdict["decision"] != "REVIEW_READY_HOLD":
        raise AssertionError("unsigned or invalid original review")


def envelope(dossier: dict, choice: str, signer: str) -> dict:
    return {"format": DECISION_DOMAIN, "case_sha256": dossier["case_sha256"],
            "dossier_sha256": sha(canonical(dossier)), "choice": choice,
            "signer": signer, "authorization": "NONE",
            "execution": "HOLD", "root_activation": "DENIED"}


def verify_decision(signed: dict, dossier: dict, trust: dict) -> dict:
    if (not isinstance(trust, dict)
        or set(trust) != {"format", "test_owner_public_sha256", "signer",
                          "required_scope", "owner_authority"}
        or trust["format"] != PIN_DOMAIN
        or trust["owner_authority"] != "CI_FIXTURE_ONLY"
        or trust["required_scope"] != dossier["scope"]
        or not isinstance(trust["signer"], str)
        or not isinstance(signed, dict)
        or set(signed) != {"decision", "public_hex", "signature_hex"}):
        raise AssertionError("independently pinned owner test identity missing")
    decision = signed["decision"]
    if not isinstance(decision, dict) or decision.get("choice") not in ("JA", "NEE"):
        raise AssertionError("malformed JA/NEE decision")
    if decision != envelope(dossier, decision["choice"], trust["signer"]):
        raise AssertionError("decision does not bind dossier and HOLD policy")
    try:
        public = bytes.fromhex(signed["public_hex"])
        signature = bytes.fromhex(signed["signature_hex"])
    except (TypeError, ValueError, KeyError) as exc:
        raise AssertionError("malformed owner signature") from exc
    if sha(public) != trust["test_owner_public_sha256"]:
        raise AssertionError("untrusted owner fixture signer")
    if not signature_valid(canonical(decision), signature, public):
        raise AssertionError("invalid test-owner Ed25519 signature")
    return decision


def append_decision(signed: dict, dossier: dict, trusted: dict) -> str:
    validate_dossier(dossier)
    decision = verify_decision(signed, dossier, trusted)
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            previous = db.execute(
                "SELECT sequence,event_hash FROM history ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if previous is None or previous[0] != 1:
                raise AssertionError("owner decision already exists or history missing")
            payload = canonical({"choice": decision["choice"],
                                 "decision_sha256": sha(canonical(signed)),
                                 "case_sha256": decision["case_sha256"],
                                 "dossier_sha256": decision["dossier_sha256"],
                                 "authorization": "NONE", "execution": "HOLD"})
            new_hash = sha(canonical({"previous": previous[1], "event": payload.hex()}))
            db.execute("INSERT INTO history(sequence,previous_hash,event,event_hash) "
                       "VALUES(2,?,?,?)", (previous[1], payload, new_hash))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return "DECISION_RECORDED_HOLD"


def history() -> tuple:
    with connection() as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AssertionError("SQLite decision history corrupt")
        rows = db.execute("SELECT sequence,previous_hash,event,event_hash "
                          "FROM history ORDER BY sequence").fetchall()
    if not rows or len(rows) > 2:
        raise AssertionError("untrusted history length")
    previous = GENESIS
    for index, (seq, prev_hash, raw, event_hash) in enumerate(rows, 1):
        if seq != index or prev_hash != previous:
            raise AssertionError("missing or reordered audit event")
        if event_hash != sha(canonical({"previous": previous, "event": raw.hex()})):
            raise AssertionError("audit hash chain tampered")
        event = parse(raw)
        if (event.get("authorization") != "NONE" or event.get("execution") != "HOLD"):
            raise AssertionError("audit history authority escalation")
        if index == 1 and (event.get("type") != "DOSSIER_CREATED"
                           or event.get("dossier_sha256") != sha(DOSSIER.read_bytes())):
            raise AssertionError("untrusted genesis dossier")
        if index == 2 and (event.get("choice") not in ("JA", "NEE")
                           or event.get("dossier_sha256") != sha(DOSSIER.read_bytes())):
            raise AssertionError("invalid stored JA/NEE")
        previous = event_hash
    return rows, previous


def reject(fn, name: str) -> None:
    try:
        fn()
    except (AssertionError, sqlite3.Error, KeyError, ValueError, TypeError):
        return
    raise AssertionError("unsafe owner decision accepted: " + name)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing overwrite of original owner evidence")
    ROOT.mkdir(mode=0o700, parents=True)
    root_case = parse(CASE.read_bytes())
    dossier = {
        "format": DOMAIN, "case_sha256": sha(CASE.read_bytes()),
        "votes_sha256": sha(VOTES.read_bytes()),
        "review_trust_sha256": sha(TRUST.read_bytes()),
        "evidence_sha256": sha(EVIDENCE.read_bytes()),
        "custody_sha256": sha(custody_inputs()[0]),
        "scope": root_case["scope"],
        "risks": ["POSSIBLE_ROOT_COMPROMISE", "UNTRUSTED_REPLACEMENT",
                  "LOCAL_CI_TRUST_ONLY", "NO_PRODUCTION_APPROVAL"],
        "decision_options": ["JA", "NEE"], "authorization": "NONE",
        "execution": "HOLD",
    }
    validate_dossier(dossier)
    DOSSIER.write_bytes(canonical(dossier))
    openssl = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE)],
        capture_output=True, timeout=20, check=False)
    if openssl.returncode:
        raise AssertionError("test-owner key generation failed")
    PRIVATE.chmod(0o600)
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC)],
        capture_output=True, timeout=20, check=False)
    if result.returncode:
        raise AssertionError("test-owner public key extraction failed")
    public = PUBLIC.read_bytes()
    trusted = {
        "format": PIN_DOMAIN, "test_owner_public_sha256": sha(public),
        "signer": "ORCHEASTRA:DISPOSABLE_CI_OWNER", "required_scope": dossier["scope"],
        "owner_authority": "CI_FIXTURE_ONLY",
    }
    PIN.write_bytes(canonical(trusted))
    signed = {}
    for choice, path in (("JA", YES), ("NEE", NO)):
        decision = envelope(dossier, choice, trusted["signer"])
        signed[choice] = {"decision": decision, "public_hex": public.hex(),
                          "signature_hex": sign(PRIVATE, canonical(decision)).hex()}
        path.write_bytes(canonical(signed[choice]))
    PRIVATE.unlink()

    with sqlite3.connect(DB) as db:
        db.execute("""CREATE TABLE history(
            sequence INTEGER PRIMARY KEY,
            previous_hash TEXT NOT NULL,
            event BLOB NOT NULL,
            event_hash TEXT NOT NULL
        )""")
        db.execute("CREATE TRIGGER history_no_update BEFORE UPDATE ON history "
                   "BEGIN SELECT RAISE(ABORT,'immutable history'); END")
        db.execute("CREATE TRIGGER history_no_delete BEFORE DELETE ON history "
                   "BEGIN SELECT RAISE(ABORT,'immutable history'); END")
        raw = canonical({"type": "DOSSIER_CREATED",
                         "dossier_sha256": sha(DOSSIER.read_bytes()),
                         "authorization": "NONE", "execution": "HOLD"})
        event_hash = sha(canonical({"previous": GENESIS, "event": raw.hex()}))
        db.execute("INSERT INTO history VALUES(1,?,?,?)",
                   (GENESIS, raw, event_hash))
        db.commit()

    reject(lambda: append_decision(
        {**signed["JA"], "signature_hex": "00" * 64},
        dossier, trusted), "forged owner signature")
    reject(lambda: append_decision(
        signed["JA"], {**dossier, "case_sha256": "00" * 32},
        trusted), "substituted dossier")
    reject(lambda: append_decision(
        signed["JA"], dossier, {**trusted, "test_owner_public_sha256": "00" * 32}),
        "untrusted owner identity")
    reject(lambda: append_decision(
        {**signed["JA"], "decision": {
            **signed["JA"]["decision"], "root_activation": "ALLOW"}},
        dossier, trusted), "JA escalated into activation")
    reject(lambda: append_decision(
        {**signed["NO"], "decision": {
            **signed["NO"]["decision"], "authorization": "GRANTED"}},
        dossier, trusted), "NEE escalated into authorization")
    if len(history()[0]) != 1:
        raise AssertionError("denied decisions mutated audit trail")

    def contender(choice: str) -> bool:
        try:
            return append_decision(signed[choice], dossier, trusted) == "DECISION_RECORDED_HOLD"
        except (AssertionError, sqlite3.Error):
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        wins = list(pool.map(contender, ["JA", "NEE"] * 4))
    if sum(wins) != 1:
        raise AssertionError("conflicting decisions committed")
    reject(lambda: append_decision(signed["JA"], dossier, trusted),
           "duplicate or overwritten decision")
    reject(lambda: append_decision(signed["NO"], dossier, trusted),
           "conflicting follow-up decision")
    with connection() as db:
        reject(lambda: db.execute("UPDATE history SET event=? WHERE sequence=2",
                                  (b"tampered",)), "in-place history rewrite")
        reject(lambda: db.execute("DELETE FROM history WHERE sequence=2"),
               "history deletion")
    rows, last = history()
    HEAD.write_bytes(canonical({"format": HEAD_DOMAIN, "sequence": 2,
                                "event_hash": last,
                                "dossier_sha256": sha(DOSSIER.read_bytes()),
                                "authorization": "NONE", "execution": "HOLD"}))
    print("ORCHEASTRA v0.53: decision JA/NEE audit recorded once; "
          "8-way race, conflicting decisions and tampering denied; HOLD")


def verify_restart() -> None:
    if PRIVATE.exists():
        raise AssertionError("fixture owner private key retained")
    dossier = parse(DOSSIER.read_bytes())
    validate_dossier(dossier)
    trusted = parse(PIN.read_bytes())
    records, last = history()
    if len(records) != 2:
        raise AssertionError("owner decision missing after restart")
    head = parse(HEAD.read_bytes())
    if (head != {"format": HEAD_DOMAIN, "sequence": 2,
                 "event_hash": last, "dossier_sha256": sha(DOSSIER.read_bytes()),
                 "authorization": "NONE", "execution": "HOLD"}):
        raise AssertionError("local audit high-water changed")
    choice = parse(records[1][2])["choice"]
    signed = parse((YES if choice == "JA" else NO).read_bytes())
    verified = verify_decision(signed, dossier, trusted)
    if verified["choice"] != choice:
        raise AssertionError("stored decision signature invalid")
    reject(lambda: append_decision(signed, dossier, trusted),
           "post-restart decision replay")
    print("ORCHEASTRA v0.53: immutable local decision history verified after restart; HOLD")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires disposable loopback CI")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify_restart()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError, KeyError,
            sqlite3.Error, subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.53 FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
