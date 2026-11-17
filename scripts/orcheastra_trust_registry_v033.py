#!/usr/bin/env python3
"""ORCHEASTRA v0.33: isolated signed trust registry and fail-closed recovery.

A separate disposable CI signing root authorizes an exact key-status registry.
Verification requires a pinned root public key, signature, trusted clock,
high-water version and a matching v0.32 signed checkpoint. No code executes
recovered tasks. Not a production registry, KMS, time authority or witness.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from orcheastra_policy_signed_checkpoint import canonical, verify_signature
from orcheastra_policy_trust_rotation import (
    STORE as ROT_STORE, NEXT_PUBLIC, LATEST, LATEST_SIG, verify_all,
)

STORE = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v033"
PRIVATE = STORE / "temporary-registry-root.pem"
PUBLIC = STORE / "trusted-registry-root.pem"
DOCUMENT = STORE / "registry.json"
SIGNATURE = STORE / "registry.sig"
HIGH_WATER = STORE / "registry-high-water.json"
DOMAIN = "PALACO:ORCHEASTRA:TRUST_REGISTRY:v1"
FIXTURE_CLOCK = "2026-11-17T12:00:00Z"


def parse(raw: bytes) -> dict:
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or canonical(parsed) != raw:
        raise AssertionError("noncanonical trust registry")
    return parsed


def openssl(*args: str) -> None:
    p = subprocess.run(["openssl", *args], capture_output=True, text=True,
                       check=False, timeout=20)
    if p.returncode:
        raise AssertionError("OpenSSL operation failed")


def sign(raw: bytes) -> None:
    with tempfile.TemporaryDirectory(dir=STORE) as d:
        target = Path(d) / "input"
        target.write_bytes(raw)
        openssl("pkeyutl", "-sign", "-inkey", str(PRIVATE),
                "-rawin", "-in", str(target), "-out", str(SIGNATURE))


def instant(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AssertionError("non-UTC trust timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def authorize(registry: dict, key_id: str, checkpoint_version: int,
              now: datetime, high_water: dict) -> bool:
    if (registry.get("format") != DOMAIN or
        type(registry.get("registry_version")) is not int or
        type(high_water.get("registry_version")) is not int or
        registry["registry_version"] != high_water["registry_version"] or
        registry.get("checkpoint_digest") != high_water.get("checkpoint_digest") or
        type(checkpoint_version) is not int or
        checkpoint_version < high_water.get("checkpoint_version", 0)):
        return False

    keys = registry.get("keys")
    if not isinstance(keys, dict) or set(keys) != {
        "successor-v2", "retired-v1", "expired-v3"
    }:
        return False
    policy = keys.get(key_id)
    if not isinstance(policy, dict):
        return False
    if policy.get("status") != "active":
        return False
    if type(policy.get("min_version")) is not int:
        return False
    if checkpoint_version < policy["min_version"]:
        return False
    try:
        first = instant(policy["not_before"])
        last = instant(policy["not_after"])
    except (KeyError, TypeError, ValueError, AssertionError):
        return False
    return first <= now < last


def verify_registry() -> tuple[dict, dict]:
    if PRIVATE.exists():
        raise AssertionError("temporary registry signing key remained on disk")
    raw = DOCUMENT.read_bytes()
    if not verify_signature(raw, SIGNATURE.read_bytes(), PUBLIC):
        raise AssertionError("registry signature invalid")
    doc = parse(raw)
    pinned = parse(HIGH_WATER.read_bytes())
    if doc.get("registry_version") != 3 or pinned.get("registry_version") != 3:
        raise AssertionError("registry high-water rollback")
    return doc, pinned


def inspect() -> None:
    rotated = verify_all()
    doc, high_water = verify_registry()
    latest = LATEST.read_bytes()
    if not verify_signature(latest, LATEST_SIG.read_bytes(), NEXT_PUBLIC):
        raise AssertionError("checkpoint signer invalid")
    import hashlib
    expected_digest = hashlib.sha256(latest).hexdigest()
    if (doc.get("checkpoint_digest") != expected_digest or
        high_water.get("checkpoint_digest") != expected_digest or
        high_water.get("checkpoint_version") != rotated.get("version")):
        raise AssertionError("registry checkpoint binding mismatch")
    # This fixture's decision is READ/RECOVERY-ONLY; it does not authorize
    # execution of any recovered PALACO proposal or task.
    now = instant(FIXTURE_CLOCK)
    if not authorize(doc, "successor-v2", 2, now, high_water):
        raise AssertionError("current authorized verification denied")
    for key in ("retired-v1", "expired-v3", "missing-key"):
        if authorize(doc, key, 2, now, high_water):
            raise AssertionError(f"untrusted key unexpectedly accepted: {key}")
    if authorize(doc, "successor-v2", 1, now, high_water):
        raise AssertionError("older checkpoint version accepted")
    if authorize(doc, "successor-v2", 2,
                 instant("2028-01-01T00:00:00Z"), high_water):
        raise AssertionError("expired active key accepted")
    if authorize(doc, "successor-v2", 2,
                 instant("2025-01-01T00:00:00Z"), high_water):
        raise AssertionError("not-yet-valid key accepted")
    if authorize(doc, "successor-v2", 2, now,
                 {**high_water, "registry_version": 2}):
        raise AssertionError("stale trusted registry snapshot accepted")


def seal() -> None:
    if STORE.exists():
        raise AssertionError("refusing overwrite of existing trust store")
    if os.environ.get("PALACO_TEST_EPHEMERAL") != "YES":
        raise AssertionError("test guard absent")
    rotated = verify_all()
    STORE.mkdir(mode=0o700, parents=True)
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE))
    PRIVATE.chmod(0o600)
    openssl("pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC))
    import hashlib
    digest = hashlib.sha256(LATEST.read_bytes()).hexdigest()
    registry = {
        "format": DOMAIN, "registry_version": 3,
        "checkpoint_digest": digest,
        "keys": {
            "successor-v2": {
                "status": "active", "min_version": 2,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            },
            "retired-v1": {
                "status": "revoked", "min_version": 1,
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            },
            "expired-v3": {
                "status": "expired", "min_version": 3,
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2025-01-01T00:00:00Z",
            },
        },
    }
    DOCUMENT.write_bytes(canonical(registry))
    sign(DOCUMENT.read_bytes())
    HIGH_WATER.write_bytes(canonical({
        "registry_version": 3, "checkpoint_version": rotated["version"],
        "checkpoint_digest": digest,
    }))
    PRIVATE.unlink()
    inspect()

    # A forged status flip with the old signature must be rejected.
    changed = {**registry, "keys": {**registry["keys"]}}
    changed["keys"]["retired-v1"] = {
        **registry["keys"]["retired-v1"], "status": "active",
    }
    if verify_signature(canonical(changed), SIGNATURE.read_bytes(), PUBLIC):
        raise AssertionError("modified key status passed signature verification")
    altered = {**registry, "registry_version": 2}
    if verify_signature(canonical(altered), SIGNATURE.read_bytes(), PUBLIC):
        raise AssertionError("stale registry signature accepted")
    print("ORCHEASTRA v0.33: signed status registry and fail-closed recovery PASS")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES" or
        not uri.startswith("postgresql://") or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated loopback CI database required")
    if sys.argv[1:] == ["--seal"]:
        seal()
    elif sys.argv[1:] == ["--verify"]:
        inspect()
        print("ORCHEASTRA v0.33: signed trust states survive DB restart")
    else:
        raise AssertionError("expected --seal or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError,
            subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.33 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
