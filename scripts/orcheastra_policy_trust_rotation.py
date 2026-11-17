#!/usr/bin/env python3
"""ORCHEASTRA v0.32: isolated, two-generation Ed25519 trust rotation.

A pinned v0.31 public key authorizes the next public key. Both signed
records are verified independently of PostgreSQL; highest seen version
is stored outside the database container. This is CI-only, not KMS.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import (
    STORE, PUB, PAYLOAD, SIGNATURE, canonical, checkpoint,
    verify_signature,
)

ROTATION = STORE / "rotation-v032.json"
ROT_SIG = STORE / "rotation-v032.sig"
SECOND_PUB = STORE / "trusted-key-v2.pem"
HEAD_V2 = STORE / "checkpoint-v2.json"
HEAD_V2_SIG = STORE / "checkpoint-v2.sig"
TRUST = STORE / "verified-high-water.json"
ROT_DOMAIN = "PALACO:ORCHEASTRA:KEY_ROTATION:v1"
HEAD_DOMAIN = "PALACO:ORCHEASTRA:POLICY:HEADS:v2"


def openssl(*args: str) -> None:
    done = subprocess.run(["openssl", *args], capture_output=True,
                          text=True, timeout=20, check=False)
    if done.returncode:
        raise AssertionError("Ed25519 operation failed")


def sign(private: Path, document: bytes, destination: Path) -> None:
    with tempfile.TemporaryDirectory(dir=STORE) as directory:
        payload = Path(directory) / "payload"
        payload.write_bytes(document)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(payload), "-out", str(destination))


def parse_canonical(raw: bytes) -> dict:
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical(value) != raw:
        raise AssertionError("noncanonical trust record")
    return value


def trusted_history() -> tuple[dict, dict, dict]:
    if not verify_signature(PAYLOAD.read_bytes(), SIGNATURE.read_bytes(), PUB):
        raise AssertionError("prior trusted checkpoint signature invalid")
    first = parse_canonical(PAYLOAD.read_bytes())
    if first.get("format") != "PALACO:ORCHEASTRA:POLICY:HEADS:v1":
        raise AssertionError("unexpected initial trust domain")

    rotation_bytes = ROTATION.read_bytes()
    if not verify_signature(rotation_bytes, ROT_SIG.read_bytes(), PUB):
        raise AssertionError("rotation was not authorized by original trusted key")
    rotation = parse_canonical(rotation_bytes)
    if (rotation.get("format") != ROT_DOMAIN
        or rotation.get("previous_version") != 1
        or rotation.get("new_version") != 2
        or rotation.get("new_public_key") != SECOND_PUB.read_text()
        or rotation.get("prior_heads") != first["heads"]):
        raise AssertionError("broken rotation trust chain")

    newest_bytes = HEAD_V2.read_bytes()
    if not verify_signature(newest_bytes, HEAD_V2_SIG.read_bytes(), SECOND_PUB):
        raise AssertionError("latest checkpoint is not signed by rotated key")
    newest = parse_canonical(newest_bytes)
    if (newest.get("format") != HEAD_DOMAIN
        or newest.get("version") != 2
        or newest.get("key_version") != 2
        or newest.get("previous_heads") != first["heads"]):
        raise AssertionError("invalid checkpoint generation and predecessor")
    return first, rotation, newest


def write_fixture() -> None:
    if any(p.exists() for p in (ROTATION, ROT_SIG, SECOND_PUB,
                                HEAD_V2, HEAD_V2_SIG, TRUST)):
        raise AssertionError("refusing to overwrite rotation evidence")
    current, entries = checkpoint()
    if not entries:
        raise AssertionError("no policy history")
    previous = parse_canonical(PAYLOAD.read_bytes())
    if previous["heads"] != current["heads"]:
        raise AssertionError("database differs from original signed heads")

    # In this disposable CI fixture only, create a short-lived successor key.
    # A simulated rotation is authorized using a fresh, distinct predecessor
    # signer whose public key MUST match the pinned v0.31 key. That v0.31
    # signing key was intentionally destroyed; therefore a genuine rotation
    # would need KMS or an offline signed rotation authority. Do not fabricate
    # authorization by replacing the pinned public key.
    raise AssertionError("v0.31 predecessor signing key unavailable; safe rotation requires separate authorized root")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("disposable loopback PostgreSQL is required")
    if len(sys.argv) != 2:
        raise AssertionError("expected --rotate or --verify")
    if sys.argv[1] == "--rotate":
        write_fixture()
    elif sys.argv[1] == "--verify":
        first, _, latest = trusted_history()
        observed, _ = checkpoint()
        if latest["heads"] != observed["heads"]:
            raise AssertionError("latest signed heads disagree with DB")
        pinned = parse_canonical(TRUST.read_bytes())
        if (pinned.get("version") != 2
            or pinned.get("heads") != latest["heads"]):
            raise AssertionError("high-water checkpoint mismatch")
        if first["heads"] != latest["previous_heads"]:
            raise AssertionError("inconsistent trust lineage")
        print("ORCHEASTRA v0.32: rotated trust chain verified")
    else:
        raise AssertionError("unknown operation")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, OSError) as exc:
        print(f"ORCHEASTRA v0.32: {exc}", file=sys.stderr)
        sys.exit(1)
