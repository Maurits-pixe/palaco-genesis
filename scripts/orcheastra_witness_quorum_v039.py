#!/usr/bin/env python3
"""ORCHEASTRA v0.39: 2-of-3 independently keyed CI witness quorum.

Three distinct ephemeral Ed25519 identities sign the exact same high-water
claim. Only 2 unique pinned identities constitute a quorum; any authentic
conflicting statement fails closed. No real independent infrastructure yet.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_evidence_handoff_v037 import (
    BUNDLE_COPY, PIN_COPY, HANDOFF, HIGH_WATER, evaluate, parse,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v039"
RECORD = ROOT / "quorum-record.json"
TRUST = ROOT / "independent-trust-pins.json"
DOMAIN = "PALACO:ORCHEASTRA:WITNESS_QUORUM:v1"
IDS = ("witness-a", "witness-b", "witness-c")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def openssl(*args: str) -> None:
    done = subprocess.run(["openssl", *args], capture_output=True,
                          text=True, check=False, timeout=20)
    if done.returncode:
        raise AssertionError("OpenSSL Ed25519 operation failed")


def sign(private: Path, raw: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        source = Path(tmp) / "payload"
        target = Path(tmp) / "signature"
        source.write_bytes(raw)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(source), "-out", str(target))
        return target.read_bytes()


def verify_quorum(record: dict, pins: dict, bundle: bytes,
                  signer_pin: str, handoff: bytes) -> dict:
    if (not isinstance(pins, dict) or pins.get("format") != DOMAIN
        or type(pins.get("minimum_version")) is not int
        or pins["minimum_version"] < 1 or pins.get("quorum") != 2
        or not isinstance(pins.get("identities"), dict)
        or set(pins["identities"]) != set(IDS)):
        raise AssertionError("missing independently trusted quorum policy")
    # Distinct identities must have DISTINCT independently pinned keys.
    fingerprints = list(pins["identities"].values())
    if (len(set(fingerprints)) != len(IDS)
        or any(not isinstance(fp, str) or len(fp) != 64 for fp in fingerprints)):
        raise AssertionError("witness identities do not have distinct trusted keys")
    if (not isinstance(record, dict) or record.get("format") != DOMAIN
        or not isinstance(record.get("statements"), list)
        or not isinstance(record.get("endorsements"), list)):
        raise AssertionError("invalid quorum envelope")
    if len(record["statements"]) != 1:
        # Even when two witnesses agree, a third authentically signed but
        # conflicting claim must not be ignored as ordinary noise.
        raise AssertionError("conflicting high-water statement set")
    claim = record["statements"][0]
    if not isinstance(claim, dict):
        raise AssertionError("malformed signed high-water")
    if (claim.get("format") != DOMAIN
        or type(claim.get("version")) is not int
        or claim["version"] < pins["minimum_version"]
        or claim.get("authorization") != "NONE"
        or claim.get("execution") != "HOLD"
        or not isinstance(claim.get("high_water"), dict)):
        raise AssertionError("witness claim violates pinned policy")

    signed_bytes = canonical(claim)
    accepted = set()
    seen = set()
    if len(record["endorsements"]) > len(IDS):
        raise AssertionError("excessive witness signatures")
    for vote in record["endorsements"]:
        if not isinstance(vote, dict):
            raise AssertionError("invalid witness vote")
        identity = vote.get("id")
        if identity not in IDS or identity in seen:
            raise AssertionError("unknown or duplicate witness identity")
        seen.add(identity)
        try:
            public = bytes.fromhex(vote["public_hex"])
            signature = bytes.fromhex(vote["signature_hex"])
        except (ValueError, TypeError, KeyError) as err:
            raise AssertionError("malformed witness material") from err
        if digest(public) != pins["identities"][identity]:
            raise AssertionError("witness public key is not independently pinned")
        if not signature_valid(signed_bytes, signature, public):
            raise AssertionError("invalid quorum signature")
        accepted.add(identity)
    if len(accepted) < pins["quorum"]:
        raise AssertionError("insufficient independently keyed witness quorum")
    result = evaluate(bundle, signer_pin, handoff,
                      canonical(claim["high_water"]))
    if (result.get("authorization") != "NONE"
        or result.get("execution") != "HOLD"
        or result.get("read_only") is not True):
        raise AssertionError("witness quorum granted execution authority")
    return {**result, "witness_quorum": len(accepted)}


def rejects(record, pins, bundle, signer_pin, handoff, name):
    try:
        verify_quorum(record, pins, bundle, signer_pin, handoff)
    except (AssertionError, ValueError, TypeError, KeyError):
        return
    raise AssertionError("unsafe witness scenario accepted: " + name)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing to overwrite trust evidence")
    original = parse(HIGH_WATER.read_bytes())
    ROOT.mkdir(parents=True, mode=0o700)
    claim = {"format": DOMAIN, "version": 1,
             "authorization": "NONE", "execution": "HOLD",
             "high_water": original}
    signature_bytes = canonical(claim)
    votes = []
    key_pins = {}
    for identity in IDS:
        private = ROOT / f"{identity}-private.pem"
        public = ROOT / f"{identity}-public.pem"
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
        key_pins[identity] = digest(public.read_bytes())
        votes.append({"id": identity,
                      "public_hex": public.read_bytes().hex(),
                      "signature_hex": sign(private, signature_bytes).hex()})

    pins = {"format": DOMAIN, "minimum_version": 1, "quorum": 2,
            "identities": key_pins}
    record = {"format": DOMAIN, "statements": [claim],
              "endorsements": votes}
    bundle = BUNDLE_COPY.read_bytes()
    signer_pin = PIN_COPY.read_text(encoding="ascii").strip()
    handoff = HANDOFF.read_bytes()

    # Any contradictory statement fails closed; it must not be voted
    # through merely because two other identities agree.
    contradicted = {**claim, "high_water": {
        **original, "minimum_sequence": 2}}
    conflicting = dict(record)
    conflicting["statements"] = [claim, contradicted]
    rejects(conflicting, pins, bundle, signer_pin, handoff,
            "authenticated contradictory heads")

    if verify_quorum(record, pins, bundle, signer_pin, handoff)["freshness"] != "CURRENT":
        raise AssertionError("valid three-witness quorum rejected")
    two = {**record, "endorsements": votes[:2]}
    if verify_quorum(two, pins, bundle, signer_pin, handoff)["witness_quorum"] != 2:
        raise AssertionError("two-of-three availability failed")
    rejects({**record, "endorsements": votes[:1]}, pins,
            bundle, signer_pin, handoff, "one remaining witness")
    rejects({**record, "endorsements": [votes[0], votes[0]]}, pins,
            bundle, signer_pin, handoff, "duplicate witness votes")
    forged = {**votes[1], "signature_hex": "00" * 64}
    rejects({**record, "endorsements": [votes[0], forged]}, pins,
            bundle, signer_pin, handoff, "invalid signature")
    forged = {**votes[1], "public_hex": votes[0]["public_hex"]}
    rejects({**record, "endorsements": [votes[0], forged]}, pins,
            bundle, signer_pin, handoff, "duplicated public key")
    rejects(two, {**pins, "minimum_version": 2},
            bundle, signer_pin, handoff, "trusted version floor advanced")
    rejects({**record, "statements": [{**claim, "execution": "ALLOW"}]},
            pins, bundle, signer_pin, handoff, "authority forgery")
    rejects(record, {**pins, "identities": {"witness-a": key_pins["witness-a"]}},
            bundle, signer_pin, handoff, "incomplete independent pinset")
    rejects({**record, "endorsements": []}, pins,
            bundle, signer_pin, handoff, "all witnesses unavailable")

    # Destroy all three signing keys before storing the verifier fixture.
    for identity in IDS:
        (ROOT / f"{identity}-private.pem").unlink()
    RECORD.write_bytes(canonical(record))
    TRUST.write_bytes(canonical(pins))
    print("ORCHEASTRA v0.39: 2-of-3 quorum + 9 adversarial scenarios PASS")


def verify() -> None:
    if any((ROOT / f"{identity}-private.pem").exists() for identity in IDS):
        raise AssertionError("witness private keys retained")
    record = parse(RECORD.read_bytes())
    pins = parse(TRUST.read_bytes())
    result = verify_quorum(record, pins, BUNDLE_COPY.read_bytes(),
                           PIN_COPY.read_text(encoding="ascii").strip(),
                           HANDOFF.read_bytes())
    if result["freshness"] != "CURRENT" or result["witness_quorum"] != 3:
        raise AssertionError("witness quorum failed after PostgreSQL restart")
    print("ORCHEASTRA v0.39: signed 3-witness quorum reverified after restart")


def main() -> None:
    if len(sys.argv) == 7 and sys.argv[1] == "--verify-portable":
        result = verify_quorum(
            parse(Path(sys.argv[2]).read_bytes()),
            parse(Path(sys.argv[3]).read_bytes()),
            Path(sys.argv[4]).read_bytes(),
            Path(sys.argv[5]).read_text(encoding="ascii").strip(),
            Path(sys.argv[6]).read_bytes(),
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated loopback CI required")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create, --verify, --verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.39 FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
