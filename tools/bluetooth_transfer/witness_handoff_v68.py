"""PALACO v6.8: offline transferable, fail-closed archive evidence handoff.

All input artifacts are byte-bound through a canonical envelope. A receiver
validates exact contents, a caller-supplied trusted 2-of-3 custody key roster,
and the frozen manifest/receipt binding against the observed GitHub context.
The GitHub context remains an untrusted CLAIM until independently checked.
The handoff is not an authority or attestation; HOLD/DENY is mandatory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verify_scm_ci_incident import EvidenceRejected, verify_bytes
from witness_continuity_v63 import serialize, strictly_parse, check_hex
from witness_custody_v67 import verify as verify_custody

PROTOCOL = "PALACO-BT-CI-HANDOFF-V1"
REQUIRED = ("incident.json", "archive.json", "custody-0.json", "custody-1.json")
HEADER_FIELDS = {"version", "github_sha", "github_run_id", "decision",
                 "authorization", "files"}
INDEX_FIELDS = {"name", "sha256", "size"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean_directory(directory: Path) -> None:
    if not directory.is_dir() or directory.is_symlink():
        raise EvidenceRejected("handoff directory unavailable")
    if set(item.name for item in directory.iterdir()) != set(REQUIRED) | {"index.json"}:
        raise EvidenceRejected("handoff missing or unexpected files")
    for name in REQUIRED + ("index.json",):
        file = directory / name
        if not file.is_file() or file.is_symlink():
            raise EvidenceRejected("unsafe handoff component")


def validate_context(sha: str, run: str) -> None:
    if type(sha) is not str or len(sha) != 40 or any(
            c not in "0123456789abcdef" for c in sha):
        raise EvidenceRejected("invalid checkout SHA")
    if type(run) is not str or not run.isascii() or not run.isdecimal() or (
            len(run) > 20 or run.startswith("0")):
        raise EvidenceRejected("invalid workflow run ID")


def prepare(directory: Path, incident: bytes, manifest: bytes,
            receipts: tuple[bytes, bytes], sha: str, run: str) -> None:
    validate_context(sha, run)
    verify_bytes(incident)
    if directory.exists() or directory.is_symlink():
        raise EvidenceRejected("handoff target exists")
    directory.mkdir(mode=0o700)
    inputs = (incident, manifest, *receipts)
    for name, content in zip(REQUIRED, inputs):
        if not content or len(content) > 8192:
            raise EvidenceRejected("oversized or empty handoff artifact")
        # Intentionally fixed filenames; no user-controlled archive paths.
        with (directory / name).open("xb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
    index = {
        "version": PROTOCOL,
        "github_sha": sha, "github_run_id": run,
        "decision": "HOLD", "authorization": "DENY",
        "files": [
            {"name": name, "size": len(content), "sha256": digest(content)}
            for name, content in zip(REQUIRED, inputs)
        ],
    }
    with (directory / "index.json").open("xb") as file:
        file.write(serialize(index))
        file.flush()
        os.fsync(file.fileno())


def inspect(directory: Path, expected_sha: str, expected_run: str,
            trusted: dict[str, Ed25519PublicKey]) -> dict:
    clean_directory(directory)
    validate_context(expected_sha, expected_run)
    index = strictly_parse((directory / "index.json").read_bytes(), HEADER_FIELDS)
    if (index["version"], index["github_sha"], index["github_run_id"],
            index["decision"], index["authorization"]) != (
            PROTOCOL, expected_sha, expected_run, "HOLD", "DENY"):
        raise EvidenceRejected("handoff context/policy mismatch")
    entries = index["files"]
    if type(entries) is not list or len(entries) != len(REQUIRED):
        raise EvidenceRejected("invalid handoff index")
    for name, entry in zip(REQUIRED, entries):
        if type(entry) is not dict or set(entry) != INDEX_FIELDS:
            raise EvidenceRejected("invalid handoff file entry")
        raw = (directory / name).read_bytes()
        check_hex(entry["sha256"])
        if (entry["name"] != name or type(entry["size"]) is not int
                or entry["size"] != len(raw) or entry["sha256"] != digest(raw)):
            raise EvidenceRejected("handoff item changed")
    verify_bytes((directory / "incident.json").read_bytes())
    verify_custody(directory / "archive.json", expected_sha, expected_run,
                   trusted, [directory / "custody-0.json", directory / "custody-1.json"])
    # The archive's original ledger is NOT included: this verifies exactly
    # the bounded handoff bytes and custody signatures, not chain continuity.
    return {"decision": "HOLD", "authorization": "DENY",
            "index_sha256": digest((directory / "index.json").read_bytes())}


def exercise_ci(evidence: bytes, sha: str, run: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from witness_custody_v67 import sign
    from witness_continuity_v63 import public_id
    with tempfile.TemporaryDirectory() as temporary:
        target = Path(temporary) / "handoff"
        # Build and verify an ACTUAL v6.6 frozen archive before handoff.
        # The transferred bundle still excludes the local source ledger.
        from witness_archive_v66 import build_archive, verify_archive, channel_path
        from witness_anchor_v64 import sign_checkpoint, write_once
        from witness_continuity_v63 import append_incident, snapshot
        ledger = Path(temporary) / "ledger.sqlite3"
        producer = Ed25519PrivateKey.generate()
        append_incident(ledger, producer.public_key(), producer, evidence)
        state = snapshot(ledger, producer.public_key())
        witness_signers = [Ed25519PrivateKey.generate() for _ in range(3)]
        ordered = sorted((public_id(key.public_key()), key)
                         for key in witness_signers)
        pinned_witnesses = {identity: key.public_key()
                            for identity, key in ordered}
        channels = Path(temporary) / "channels"
        archived_manifest = Path(temporary) / "frozen-manifest.json"
        for i, (_, key) in enumerate(ordered[:2]):
            checkpoint_path = channel_path(channels, i)
            checkpoint_path.parent.mkdir(parents=True)
            write_once(checkpoint_path, sign_checkpoint(state, key))
        build_archive(ledger, producer.public_key(), pinned_witnesses,
                      channels, archived_manifest,
                      ("received", "received", "absent"))
        verify_archive(ledger, producer.public_key(), pinned_witnesses,
                       channels, archived_manifest)
        manifest = archived_manifest.read_bytes()
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        trusted = {public_id(k.public_key()): k.public_key() for k in keys}
        signed = (sign(manifest, sha, run, keys[0]),
                  sign(manifest, sha, run, keys[1]))
        prepare(target, evidence, manifest, signed, sha, run)
        inspect(target, sha, run, trusted)
        try:
            inspect(target, sha, str(int(run) + 1), trusted)
        except EvidenceRejected:
            return True
        raise EvidenceRejected("other workflow run was admitted")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise EvidenceRejected("CI-only exercise")
        if not exercise_ci(args.ci_evidence.read_bytes(), os.environ.get("GITHUB_SHA", ""),
                           os.environ.get("GITHUB_RUN_ID", "")):
            raise EvidenceRejected("handoff exercise failed")
    except (EvidenceRejected, ValueError, OSError) as exc:
        print("PALACO v6.8 HANDOFF DENY: " + type(exc).__name__)
        raise SystemExit(1)
    print("PALACO v6.8 HANDOFF PASS (4 bounded artifacts; 2 signed custody receipts; HOLD/DENY)")
