#!/usr/bin/env python3
"""v0.32 isolated Ed25519 root-verified rotation and anti-rollback fixture.

This starts a NEW independent test trust lineage, not the retired
v0.31 signing key. Root and successor private keys are deleted after
signing. Public keys and monotonic high water are pinned on the runner.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical, checkpoint, verify_signature

STORE = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v032"
ROOT_PRIVATE = STORE / "root-private.pem"
ROOT_PUBLIC = STORE / "root-public.pem"
NEXT_PRIVATE = STORE / "next-private.pem"
NEXT_PUBLIC = STORE / "next-public.pem"
ROTATION = STORE / "rotation.json"
ROTATION_SIG = STORE / "rotation.sig"
LATEST = STORE / "checkpoint.json"
LATEST_SIG = STORE / "checkpoint.sig"
HIGH_WATER = STORE / "high-water.json"
ROOT_DOMAIN = "PALACO:ORCHEASTRA:ROTATION:v1"
HEAD_DOMAIN = "PALACO:ORCHEASTRA:HEADS:v2"


def openssl(*args: str) -> None:
    done = subprocess.run(
        ["openssl", *args], capture_output=True, text=True,
        check=False, timeout=20,
    )
    if done.returncode:
        raise AssertionError("OpenSSL Ed25519 operation failed")


def generate(private: Path, public: Path) -> None:
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
    private.chmod(0o600)
    openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))


def sign(private: Path, raw: bytes, target: Path) -> None:
    with tempfile.TemporaryDirectory(dir=STORE) as d:
        source = Path(d) / "raw"
        source.write_bytes(raw)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(source), "-out", str(target))


def parse(raw: bytes) -> dict:
    result = json.loads(raw)
    if not isinstance(result, dict) or raw != canonical(result):
        raise AssertionError("noncanonical record")
    return result


def verify_all() -> dict:
    if any(key.exists() for key in (ROOT_PRIVATE, NEXT_PRIVATE)):
        raise AssertionError("private keys remained in verifier store")
    rotation_bytes = ROTATION.read_bytes()
    if not verify_signature(rotation_bytes, ROTATION_SIG.read_bytes(), ROOT_PUBLIC):
        raise AssertionError("root did not authorize rotation")
    rotation = parse(rotation_bytes)
    if (rotation.get("format") != ROOT_DOMAIN
        or rotation.get("from_version") != 1
        or rotation.get("to_version") != 2
        or rotation.get("new_key") != NEXT_PUBLIC.read_text(encoding="utf-8")):
        raise AssertionError("invalid signed rotation binding")

    latest_bytes = LATEST.read_bytes()
    if not verify_signature(latest_bytes, LATEST_SIG.read_bytes(), NEXT_PUBLIC):
        raise AssertionError("successor did not sign checkpoint")
    latest = parse(latest_bytes)
    if (latest.get("format") != HEAD_DOMAIN
        or latest.get("version") != 2
        or latest.get("key_version") != rotation["to_version"]
        or latest.get("previous_heads") != rotation.get("old_heads")):
        raise AssertionError("broken versioned trust lineage")
    pinned = parse(HIGH_WATER.read_bytes())
    if (pinned.get("version") != 2
        or pinned.get("heads") != latest.get("heads")):
        raise AssertionError("rollback against trusted high-water snapshot")
    current, _ = checkpoint()
    if latest["heads"] != current["heads"]:
        raise AssertionError("database heads differ from signed latest checkpoint")
    return latest


def seal() -> None:
    if STORE.exists():
        raise AssertionError("refusing overwrite of existing trust store")
    STORE.mkdir(parents=True, mode=0o700)
    latest, entries = checkpoint()
    if len(entries) < 2:
        raise AssertionError("insufficient policy events")
    generate(ROOT_PRIVATE, ROOT_PUBLIC)
    generate(NEXT_PRIVATE, NEXT_PUBLIC)
    root = {
        "format": ROOT_DOMAIN, "from_version": 1, "to_version": 2,
        "new_key": NEXT_PUBLIC.read_text(encoding="utf-8"),
        "old_heads": latest["heads"],
    }
    ROTATION.write_bytes(canonical(root))
    sign(ROOT_PRIVATE, ROTATION.read_bytes(), ROTATION_SIG)
    successor = {
        "format": HEAD_DOMAIN, "version": 2, "key_version": 2,
        "previous_heads": latest["heads"], "heads": latest["heads"],
    }
    LATEST.write_bytes(canonical(successor))
    sign(NEXT_PRIVATE, LATEST.read_bytes(), LATEST_SIG)
    HIGH_WATER.write_bytes(canonical({"version": 2, "heads": latest["heads"]}))
    ROOT_PRIVATE.unlink()
    NEXT_PRIVATE.unlink()
    verify_all()

    # Verify the most common downgrade and key-substitution attacks.
    if verify_signature(
        canonical({**root, "to_version": 3}), ROTATION_SIG.read_bytes(), ROOT_PUBLIC
    ):
        raise AssertionError("altered rotation accepted")
    if verify_signature(
        canonical({**successor, "version": 1}), LATEST_SIG.read_bytes(), NEXT_PUBLIC
    ):
        raise AssertionError("old checkpoint accepted")
    if verify_signature(
        ROTATION.read_bytes(), ROTATION_SIG.read_bytes(), NEXT_PUBLIC
    ):
        raise AssertionError("successor public key could impersonate root")
    original = HIGH_WATER.read_bytes()
    try:
        HIGH_WATER.write_bytes(canonical({"version": 1, "heads": latest["heads"]}))
        try:
            verify_all()
        except AssertionError:
            pass
        else:
            raise AssertionError("high-water downgrade undetected")
    finally:
        HIGH_WATER.write_bytes(original)
    print(f"ORCHEASTRA v0.32: signed rotation and anti-downgrade PASS ({len(entries)} events)")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated CI database required")
    if sys.argv[1:] == ["--seal"]:
        seal()
    elif sys.argv[1:] == ["--verify"]:
        verify_all()
        print("ORCHEASTRA v0.32: rotated key and high-water verified after restart")
    else:
        raise AssertionError("expected --seal or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.32 failure: {exc}", file=sys.stderr)
        sys.exit(1)
