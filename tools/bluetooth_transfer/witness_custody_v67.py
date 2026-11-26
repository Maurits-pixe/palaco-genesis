"""PALACO v6.7 CI-only provenance-bound custody receipts for quorum archives.

A two-of-three receipt quorum signs the *exact byte hash* of the frozen
archive manifest plus the observed GitHub checkout SHA and Actions run ID.
These are CI environment CLAIMS, not independently attested GitHub records.
The original Windows incident is unsigned. No external key custody,
production authorization or durable remote evidence is provided.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import (
    check_hex, public_id, serialize, strictly_parse
)
from witness_anchor_v64 import write_once

VERSION = "PALACO-BT-CI-CUSTODY-V1"
FIELDS = {"version", "manifest_sha256", "github_sha", "github_run_id",
          "custodian_id", "decision", "authorization", "signature"}
THRESHOLD = 2
ROSTER_SIZE = 3


def envelope(manifest_hash: str, git_sha: str, run_id: str,
             custodian: str) -> dict:
    check_hex(manifest_hash)
    if type(git_sha) is not str or len(git_sha) != 40 or any(
            c not in "0123456789abcdef" for c in git_sha):
        raise EvidenceRejected("invalid Git checkout SHA")
    if type(run_id) is not str or not run_id.isascii() or not run_id.isdecimal() or (
            len(run_id) > 20 or run_id.startswith("0")):
        raise EvidenceRejected("invalid workflow run ID")
    check_hex(custodian)
    return {"version": VERSION, "manifest_sha256": manifest_hash,
            "github_sha": git_sha, "github_run_id": run_id,
            "custodian_id": custodian, "decision": "HOLD",
            "authorization": "DENY"}


def sign(manifest: bytes, git_sha: str, run_id: str,
         private: Ed25519PrivateKey) -> bytes:
    payload = envelope(hashlib.sha256(manifest).hexdigest(),
                       git_sha, run_id, public_id(private.public_key()))
    payload["signature"] = base64.b64encode(
        private.sign(serialize(payload))).decode("ascii")
    return serialize(payload)


def verify(manifest_path: Path, github_sha: str, github_run_id: str,
           pinned: dict[str, Ed25519PublicKey],
           received: list[Path]) -> None:
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise EvidenceRejected("frozen archive manifest missing")
    if len(pinned) != ROSTER_SIZE or any(
            public_id(key) != kid for kid, key in pinned.items()):
        raise EvidenceRejected("untrusted custodian roster")
    if len(set(received)) != len(received):
        raise EvidenceRejected("duplicate receipt path")
    manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    seen: set[str] = set()
    for file in received:
        if not file.is_file() or file.is_symlink():
            raise EvidenceRejected("custody receipt missing")
        receipt = strictly_parse(file.read_bytes(), FIELDS)
        custodian = receipt["custodian_id"]
        if type(custodian) is not str or custodian not in pinned:
            raise EvidenceRejected("unknown custodian")
        if custodian in seen:
            raise EvidenceRejected("duplicate custodian")
        expected = envelope(manifest_hash, github_sha, github_run_id, custodian)
        if {k: v for k, v in receipt.items() if k != "signature"} != expected:
            raise EvidenceRejected("custody binding or policy mismatch")
        signature = receipt["signature"]
        try:
            if type(signature) is not str:
                raise ValueError("invalid signature type")
            raw = base64.b64decode(signature, validate=True)
            if len(raw) != 64:
                raise ValueError("wrong signature length")
            pinned[custodian].verify(raw, serialize(expected))
        except (ValueError, TypeError, Exception) as exc:
            raise EvidenceRejected("invalid custody signature") from exc
        seen.add(custodian)
    if len(seen) < THRESHOLD:
        raise EvidenceRejected("insufficient custody confirmations")


def exercise_ci(evidence: bytes, github_sha: str, run_id: str) -> bool:
    import tempfile
    import json
    from witness_anchor_v64 import sign_checkpoint
    from witness_archive_v66 import build_archive, channel_path, verify_archive
    from witness_continuity_v63 import append_incident, snapshot

    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        ledger = base / "ledger.sqlite3"
        chain_key = Ed25519PrivateKey.generate()
        append_incident(ledger, chain_key.public_key(), chain_key, evidence)
        state = snapshot(ledger, chain_key.public_key())
        witness_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        ordered = sorted((public_id(k.public_key()), k) for k in witness_keys)
        trusted_witnesses = {key_id: private.public_key()
                             for key_id, private in ordered}
        channels = base / "channels"
        manifest = base / "manifest.json"
        for index, (_, private) in enumerate(ordered[:2]):
            path = channel_path(channels, index)
            path.parent.mkdir(parents=True)
            write_once(path, sign_checkpoint(state, private))
        build_archive(ledger, chain_key.public_key(), trusted_witnesses,
                      channels, manifest, ("received", "received", "absent"))
        verify_archive(ledger, chain_key.public_key(), trusted_witnesses,
                       channels, manifest)

        custodians = [Ed25519PrivateKey.generate() for _ in range(3)]
        trusted = {public_id(k.public_key()): k.public_key() for k in custodians}
        paths = []
        for index, private in enumerate(custodians[:2]):
            path = base / f"custody-{index}.json"
            write_once(path, sign(manifest.read_bytes(), github_sha, run_id, private))
            paths.append(path)
        verify(manifest, github_sha, run_id, trusted, paths)
        # A same-run receipt is not proof of another commit/run.
        try:
            verify(manifest, github_sha, str(int(run_id) + 1), trusted, paths)
        except EvidenceRejected:
            return True
        raise EvidenceRejected("cross-run custody replay accepted")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-evidence", type=Path, required=True)
    args = parser.parse_args()
    sha = os.environ.get("GITHUB_SHA", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    try:
        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise EvidenceRejected("CI-only provenance exercise")
        if not exercise_ci(args.ci_evidence.read_bytes(), sha, run):
            raise EvidenceRejected("custody test incomplete")
    except (EvidenceRejected, OSError, ValueError) as exc:
        print("PALACO v6.7 CUSTODY DENY: " + type(exc).__name__)
        raise SystemExit(1)
    print("PALACO v6.7 CUSTODY PASS (2-of-3 signed manifest+checkout-SHA+run-ID; HOLD/DENY)")
