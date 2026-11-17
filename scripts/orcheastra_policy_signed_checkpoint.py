#!/usr/bin/env python3
"""ORCHEASTRA v0.31: CI-only Ed25519-signed policy-head manifest.

Authenticates a complete policy-hash head snapshot using an ephemeral
OpenSSL Ed25519 key outside the database container. This does NOT provide
remote publication, durable key custody, timestamp authority or recovery
from loss of the entire CI runner. Never deploy the ephemeral private key.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from orcheastra_policy_hash_verify import rows, verify

STORE = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v031"
PRIV = STORE / "ephemeral-ed25519-private.pem"
PUB = STORE / "trusted-ed25519-public.pem"
PAYLOAD = STORE / "signed-policy-heads.json"
SIGNATURE = STORE / "policy-heads.sig"
DOMAIN = "PALACO:ORCHEASTRA:POLICY:HEADS:v1"


def openssl(*args: str, expect_success: bool = True) -> bool:
    completed = subprocess.run(
        ["openssl", *args], capture_output=True, text=True,
        timeout=20, check=False,
    )
    if expect_success and completed.returncode != 0:
        raise AssertionError("OpenSSL verification/signing failed")
    return completed.returncode == 0


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def checkpoint() -> tuple[dict, list]:
    entries = rows()
    if not entries:
        raise AssertionError("cannot seal an empty journal")
    return {"format": DOMAIN, "heads": verify(entries)}, entries


def verify_signature(document: bytes, signature: bytes, public_key: Path) -> bool:
    # Never replace the pinned trusted public key with one from the signed
    # payload or a database value.
    with tempfile.TemporaryDirectory(dir=STORE) as d:
        material = Path(d)
        (material / "candidate.json").write_bytes(document)
        (material / "candidate.sig").write_bytes(signature)
        return openssl(
            "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
            "-rawin", "-in", str(material / "candidate.json"),
            "-sigfile", str(material / "candidate.sig"),
            expect_success=False,
        )


def seal() -> None:
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STORE, 0o700)
    if any(p.exists() for p in (PRIV, PUB, PAYLOAD, SIGNATURE)):
        raise AssertionError("refusing to overwrite an existing checkpoint")
    manifest, entries = checkpoint()
    if len(entries) < 2:
        raise AssertionError("need multiple policy events")
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(PRIV))
    PRIV.chmod(0o600)
    openssl("pkey", "-in", str(PRIV), "-pubout", "-out", str(PUB))
    payload = canonical(manifest)
    PAYLOAD.write_bytes(payload)
    openssl("pkeyutl", "-sign", "-inkey", str(PRIV),
            "-rawin", "-in", str(PAYLOAD), "-out", str(SIGNATURE))
    PRIV.unlink()  # A verifying runner has the public key, not the signer.
    if not verify_signature(payload, SIGNATURE.read_bytes(), PUB):
        raise AssertionError("generated checkpoint failed independent verification")

    # A correct chain recomputation alone would accept an older contiguous
    # prefix. Its head differs from the signed trusted checkpoint.
    scope = next((item[:2] for item in reversed(entries) if item[3] > 0), None)
    if scope is None:
        raise AssertionError("need a multi-link journal for rollback test")
    older = [item for item in entries
             if (item[0], item[1]) != scope
             or item[2] != max(e[2] for e in entries if e[:2] == scope)]
    old_heads = verify(older)
    if old_heads == manifest["heads"]:
        raise AssertionError("database rollback was not detected by pinned heads")

    # Payload and signature cannot be rewritten without the private key.
    forged = canonical({"format": DOMAIN, "heads": old_heads})
    if verify_signature(forged, SIGNATURE.read_bytes(), PUB):
        raise AssertionError("rollback manifest was accepted")
    mutated = bytearray(payload)
    mutated[0] ^= 1
    if verify_signature(bytes(mutated), SIGNATURE.read_bytes(), PUB):
        raise AssertionError("modified signed payload was accepted")
    with tempfile.TemporaryDirectory(dir=STORE) as d:
        wrong_pub = Path(d) / "wrong-pub.pem"
        wrong_priv = Path(d) / "wrong-key.pem"
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(wrong_priv))
        openssl("pkey", "-in", str(wrong_priv), "-pubout", "-out", str(wrong_pub))
        if verify_signature(payload, SIGNATURE.read_bytes(), wrong_pub):
            raise AssertionError("untrusted signing key accepted")
    print(f"ORCHEASTRA v0.31: sealed {len(entries)} events and verified rollback/tamper rejection")


def verify_restarted() -> None:
    if PRIV.exists():
        raise AssertionError("signing private key must not remain with verifier")
    signed = PAYLOAD.read_bytes()
    if not verify_signature(signed, SIGNATURE.read_bytes(), PUB):
        raise AssertionError("signed checkpoint cannot be authenticated")
    parsed = json.loads(signed)
    if parsed.get("format") != DOMAIN or canonical(parsed) != signed:
        raise AssertionError("invalid checkpoint version or canonical payload")
    latest, entries = checkpoint()
    if parsed != latest:
        raise AssertionError("database policy-heads differ from independently signed checkpoint")
    # The public key and signature are in the runner, NOT in PostgreSQL.
    print(f"ORCHEASTRA v0.31: {len(entries)} events match signed external-to-DB checkpoint after restart")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires isolated CI PostgreSQL")
    if len(sys.argv) != 2:
        raise AssertionError("expected --seal or --verify")
    if sys.argv[1] == "--seal":
        seal()
    elif sys.argv[1] == "--verify":
        verify_restarted()
    else:
        raise AssertionError("unknown mode")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.31 signed checkpoint FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
