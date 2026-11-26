"""PALACO v6.6 quorum evidence archive: isolated local channels, immutable manifest.

CI simulation ONLY: each witness delivers an Ed25519 checkpoint into its own
directory. An archive manifest commits hashes for every received envelope,
pinning the three-witness roster, channel status and observed chain head.
A missing channel may be explicitly marked absent; a delayed/pending channel
must fail closed instead of being silently ignored. No remote transfer,
independent custodians, trusted time or production authorization.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verify_scm_ci_incident import EvidenceRejected
from witness_anchor_v64 import FIELDS, verify_checkpoint, write_once
from witness_continuity_v63 import public_id, serialize, snapshot, strictly_parse, check_hex
from witness_quorum_v65 import ROSTER_SIZE, THRESHOLD

VERSION = "PALACO-BT-CI-QUORUM-ARCHIVE-V1"
MANIFEST_FIELDS = {"version", "sequence", "head", "root_id", "decision",
                   "authorization", "witnesses"}
ENTRY_FIELDS = {"witness_id", "channel", "state", "sha256"}
STATES = {"received", "absent", "pending"}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def channel_path(root: Path, ordinal: int) -> Path:
    return root / ("channel-" + str(ordinal)) / "checkpoint.json"


def build_archive(ledger: Path, chain_root: Ed25519PublicKey,
                  pinned: dict[str, Ed25519PublicKey], channel_root: Path,
                  manifest_path: Path, statuses: tuple[str, str, str]) -> None:
    if len(statuses) != 3 or len(pinned) != ROSTER_SIZE:
        raise EvidenceRejected("invalid archive roster")
    if any(s not in STATES for s in statuses):
        raise EvidenceRejected("unknown channel status")
    if channel_root.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise EvidenceRejected("archive target already exists or unsafe")
    state = snapshot(ledger, chain_root)
    entries = []
    for i, (witness_id, key) in enumerate(sorted(pinned.items())):
        if public_id(key) != witness_id:
            raise EvidenceRejected("pinned identity mismatch")
        status = statuses[i]
        filename = channel_path(channel_root, i)
        if filename.is_symlink():
            raise EvidenceRejected("symlinked receipt rejected")
        if status == "received":
            if not filename.is_file():
                raise EvidenceRejected("declared received checkpoint missing")
            raw = filename.read_bytes()
            verify_checkpoint(raw, state, key)
            digest = sha(raw)
        else:
            if filename.exists():
                raise EvidenceRejected("unlisted receipt unexpectedly present")
            digest = None
        entries.append({"witness_id": witness_id, "channel": i,
                        "state": status, "sha256": digest})
    payload = {"version": VERSION, **state, "decision": "HOLD",
               "authorization": "DENY", "witnesses": entries}
    write_once(manifest_path, serialize(payload))


def verify_archive(ledger: Path, chain_root: Ed25519PublicKey,
                   pinned: dict[str, Ed25519PublicKey], channel_root: Path,
                   manifest_path: Path) -> None:
    if (len(pinned) != ROSTER_SIZE or not manifest_path.is_file()
            or manifest_path.is_symlink() or channel_root.is_symlink()):
        raise EvidenceRejected("archive or witness roster missing")
    state = snapshot(ledger, chain_root)
    doc = strictly_parse(manifest_path.read_bytes(), MANIFEST_FIELDS)
    if ({field: doc[field] for field in ("sequence", "head", "root_id")} != state
            or doc["version"] != VERSION or doc["decision"] != "HOLD"
            or doc["authorization"] != "DENY"):
        raise EvidenceRejected("archive header mismatch")
    entries = doc["witnesses"]
    if type(entries) is not list or len(entries) != ROSTER_SIZE:
        raise EvidenceRejected("incomplete archive roster")
    accepted = 0
    for i, (witness_id, key) in enumerate(sorted(pinned.items())):
        if public_id(key) != witness_id:
            raise EvidenceRejected("untrusted witness roster")
        entry = entries[i]
        if type(entry) is not dict or set(entry) != ENTRY_FIELDS:
            raise EvidenceRejected("invalid archive entry")
        if (entry["witness_id"] != witness_id or type(entry["channel"]) is not int
                or entry["channel"] != i or entry["state"] not in STATES):
            raise EvidenceRejected("witness/channel mapping changed")
        receipt = channel_path(channel_root, i)
        if receipt.is_symlink():
            raise EvidenceRejected("unsafe channel file")
        if entry["state"] == "pending":
            raise EvidenceRejected("pending witness is not final evidence")
        if entry["state"] == "absent":
            if entry["sha256"] is not None or receipt.exists():
                raise EvidenceRejected("absent channel inconsistently recorded")
            continue
        if not receipt.is_file():
            raise EvidenceRejected("received witness file disappeared")
        raw = receipt.read_bytes()
        check_hex(entry["sha256"])
        if sha(raw) != entry["sha256"]:
            raise EvidenceRejected("witness envelope mutated after archive")
        verify_checkpoint(raw, state, key)
        accepted += 1
    if accepted < THRESHOLD:
        raise EvidenceRejected("quorum not reached")


def exercise_ci(evidence: bytes) -> bool:
    import tempfile
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from witness_anchor_v64 import sign_checkpoint
    from witness_continuity_v63 import append_incident

    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        ledger = base / "ledger.sqlite3"
        chain_signer = Ed25519PrivateKey.generate()
        append_incident(ledger, chain_signer.public_key(), chain_signer, evidence)
        state = snapshot(ledger, chain_signer.public_key())
        witnesses = [Ed25519PrivateKey.generate() for _ in range(3)]
        ordered = sorted((public_id(k.public_key()), k) for k in witnesses)
        pinned = {identity: key.public_key() for identity, key in ordered}
        channels = base / "channels"
        manifest = base / "manifest.json"
        for i, (_, key) in enumerate(ordered[:2]):
            file = channel_path(channels, i)
            file.parent.mkdir(parents=True, exist_ok=False)
            write_once(file, sign_checkpoint(state, key))
        build_archive(ledger, chain_signer.public_key(), pinned, channels,
                      manifest, ("received", "received", "absent"))
        verify_archive(ledger, chain_signer.public_key(), pinned, channels, manifest)
        # Third witness that arrives AFTER final archive invalidates it:
        # no silent late change of the already-verified witness set.
        late = channel_path(channels, 2)
        late.parent.mkdir(parents=True, exist_ok=False)
        write_once(late, sign_checkpoint(state, ordered[2][1]))
        try:
            verify_archive(ledger, chain_signer.public_key(), pinned, channels, manifest)
        except EvidenceRejected:
            return True
        raise EvidenceRejected("late unarchived witness silently accepted")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not exercise_ci(args.ci_evidence.read_bytes()):
            raise EvidenceRejected("archive test incomplete")
    except (EvidenceRejected, OSError, ValueError) as ex:
        print("PALACO v6.6 ARCHIVE DENY: " + type(ex).__name__)
        raise SystemExit(1)
    print("PALACO v6.6 ARCHIVE PASS (2-of-3 local channels, immutable manifest, late receipt DENY; HOLD/DENY)")
