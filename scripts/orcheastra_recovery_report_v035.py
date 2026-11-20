#!/usr/bin/env python3
"""ORCHEASTRA v0.35: reproducible, non-executable recovery evidence report.

The runner-local report includes cryptographic SHA-256 references to exact
existing signed artefacts and the trusted v0.34 recovery decision.
It is NOT a signed report or an independently retained external witness.
Only a disposable PostgreSQL CI fixture is accepted.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

from orcheastra_policy_signed_checkpoint import (
    canonical, PAYLOAD as SIGNED_HEADS, SIGNATURE as HEADS_SIG,
    PUB as HEADS_PUBLIC,
)
from orcheastra_policy_hash_verify import MANIFEST as HEADS_PIN
from orcheastra_policy_trust_rotation import (
    ROOT_PUBLIC, ROTATION, ROTATION_SIG, NEXT_PUBLIC,
    LATEST, LATEST_SIG, HIGH_WATER as ROTATION_PIN,
)
from orcheastra_trust_registry_v033 import (
    DOCUMENT as REGISTRY, SIGNATURE as REGISTRY_SIG,
    PUBLIC as REGISTRY_PUBLIC, HIGH_WATER as REGISTRY_PIN,
    FIXTURE_CLOCK,
)
from orcheastra_recovery_disposition_v034 import (
    RecoveryStatus, trusted_recovery,
)

REPORT_ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v035"
REPORT = REPORT_ROOT / "recovery-report.json"
DIGEST_FILE = REPORT_ROOT / "recovery-report.sha256"
DOMAIN = "PALACO:ORCHEASTRA:RECOVERY_REPORT:v1"

# Explicit allowlist: no credentials, private keys, database URI, or session tokens.
EVIDENCE = {
    "policy_heads_v030": HEADS_PIN,
    "signed_heads_v031": SIGNED_HEADS,
    "signed_heads_signature_v031": HEADS_SIG,
    "signed_heads_public_key_v031": HEADS_PUBLIC,
    "rotation_root_public_key_v032": ROOT_PUBLIC,
    "rotation_certificate_v032": ROTATION,
    "rotation_signature_v032": ROTATION_SIG,
    "checkpoint_public_key_v032": NEXT_PUBLIC,
    "checkpoint_v032": LATEST,
    "checkpoint_signature_v032": LATEST_SIG,
    "rotation_high_water_v032": ROTATION_PIN,
    "registry_v033": REGISTRY,
    "registry_signature_v033": REGISTRY_SIG,
    "registry_public_key_v033": REGISTRY_PUBLIC,
    "registry_high_water_v033": REGISTRY_PIN,
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def evidence_snapshot() -> dict:
    references = {}
    for identifier, path in sorted(EVIDENCE.items()):
        data = path.read_bytes()
        if not data:
            raise AssertionError(f"empty evidence: {identifier}")
        references[identifier] = {
            "sha256": sha(data),
            "size_bytes": len(data),
        }
    return references


def derive_report() -> dict:
    result = trusted_recovery()
    if result.status is not RecoveryStatus.VERIFIED:
        raise AssertionError(f"trusted recovery refused: {result.status.value}")
    if result.execution != "HOLD":
        raise AssertionError("execution authorization must remain HOLD")
    return {
        "format": DOMAIN,
        "scope": "ORCHEASTRA:isolated-ci:policy-evidence",
        "observed_at_fixture_utc": FIXTURE_CLOCK,
        "decision": {
            "status": result.status.value,
            "reason": result.reason,
            "execution": "HOLD",
        },
        "control_versions": {
            "policy_hash_chain": 30,
            "signed_checkpoint": 31,
            "key_rotation": 32,
            "trust_registry": 33,
            "recovery_disposition": 34,
            "recovery_report": 35,
        },
        "evidence": evidence_snapshot(),
        "authorization": "NONE",
        "execution": "HOLD",
    }


def validate(raw: bytes, claimed_hash: str) -> dict:
    if sha(raw) != claimed_hash:
        raise AssertionError("report SHA-256 mismatch")
    candidate = json.loads(raw)
    if not isinstance(candidate, dict) or canonical(candidate) != raw:
        raise AssertionError("report is not canonical JSON")
    if candidate != derive_report():
        raise AssertionError("report differs from independently verified evidence")
    if candidate["decision"]["execution"] != "HOLD" or candidate["execution"] != "HOLD":
        raise AssertionError("non-executing recovery invariant violated")
    return candidate


def expect_rejection(raw: bytes, claimed_hash: str, reason: str) -> None:
    try:
        validate(raw, claimed_hash)
    except (AssertionError, ValueError, TypeError, KeyError, OSError):
        return
    raise AssertionError(f"tampered report accepted: {reason}")


def create() -> None:
    if REPORT_ROOT.exists():
        raise AssertionError("refusing overwrite of existing recovery evidence")
    REPORT_ROOT.mkdir(mode=0o700, parents=True)
    report = derive_report()
    raw = canonical(report)
    digest = sha(raw)
    REPORT.write_bytes(raw)
    DIGEST_FILE.write_text(digest + "\n", encoding="ascii")
    validate(raw, digest)

    # Mutation with original digest must fail. Even with a recomputed digest,
    # the recovered decision must be reconstructed from trusted evidence.
    changed = {**report, "decision": {**report["decision"], "execution": "ALLOW"}}
    forged = canonical(changed)
    expect_rejection(forged, digest, "modified report content")
    expect_rejection(forged, sha(forged), "self-hashed unauthorized execution")
    changed = {**report, "evidence": {**report["evidence"]}}
    changed["evidence"].pop("registry_signature_v033")
    forged = canonical(changed)
    expect_rejection(forged, sha(forged), "missing evidence reference")
    changed = {**report, "control_versions": {**report["control_versions"],
                                              "trust_registry": 32}}
    forged = canonical(changed)
    expect_rejection(forged, sha(forged), "stale control version")
    expect_rejection(b"{}", sha(b"{}"), "missing report fields")
    print(f"ORCHEASTRA v0.35: reproducible report and 5 tamper scenarios PASS ({len(EVIDENCE)} evidence refs)")


def verify_after_restart() -> None:
    if not REPORT.is_file() or not DIGEST_FILE.is_file():
        raise AssertionError("recovery evidence report or digest absent")
    recorded = DIGEST_FILE.read_text(encoding="ascii").strip()
    if len(recorded) != 64:
        raise AssertionError("invalid stored report hash")
    result = validate(REPORT.read_bytes(), recorded)
    print("ORCHEASTRA v0.35: report, trusted evidence and HOLD verified after restart "
          f"({result['decision']['status']})")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires disposable loopback PostgreSQL")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify_after_restart()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError) as exc:
        print(f"ORCHEASTRA v0.35 report failed: {exc}", file=sys.stderr)
        sys.exit(1)
