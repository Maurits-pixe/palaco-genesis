"""PALACO Bluetooth v6.9: full historical handoff, verification-only, HOLD/DENY.

Receiver trust roots and the anti-rollback checkpoint MUST come from outside
the received bundle. This is a CI/reference implementation, not real BLE or
independent third-party archival custody.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import snapshot, strictly_parse, serialize, check_hex
from witness_archive_v66 import verify_archive, channel_path
from witness_handoff_v68 import prepare as prepare_v68, inspect as inspect_v68

VERSION = "PALACO-BT-CI-HISTORY-V1"
HISTORY = ("ledger.sqlite3", "channel-0.json", "channel-1.json", "history-index.json")
FIELDS = {"version", "ledger_sha256", "channel_sha256", "sequence", "head",
          "root_id", "decision", "authorization"}
LIMIT = 16 * 1024 * 1024


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvidenceRejected("missing or unsafe history artifact")
    if path.stat().st_size > LIMIT:
        raise EvidenceRejected("history artifact exceeds limit")
    return path.read_bytes()


def copy_ledger(source: Path, dest: Path) -> None:
    if source.is_symlink() or not source.is_file() or dest.exists():
        raise EvidenceRejected("unsafe ledger copy")
    # SQLite backup takes a consistent committed snapshot (including WAL state).
    with closing(sqlite3.connect(f"file:{source.resolve().as_posix()}?mode=ro",
                                 uri=True)) as read:
        with closing(sqlite3.connect(dest)) as write:
            read.backup(write)
    with closing(sqlite3.connect(f"file:{dest.resolve().as_posix()}?mode=ro",
                                 uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise EvidenceRejected("invalid SQLite backup")


def prepare(directory: Path, source_ledger: Path, channels: Path,
            incident: bytes, manifest: bytes, receipts: tuple[bytes, bytes],
            sha_commit: str, run_id: str, root: Ed25519PublicKey,
            witnesses: dict[str, Ed25519PublicKey]) -> None:
    if directory.exists() or directory.is_symlink():
        raise EvidenceRejected("history destination exists")
    # Preflight verification before any artifact is accepted.
    with tempfile.TemporaryDirectory() as temp:
        candidate = Path(temp)
        (candidate / "manifest.json").write_bytes(manifest)
        verify_archive(source_ledger, root, witnesses, channels,
                       candidate / "manifest.json")
    directory.mkdir(mode=0o700)
    prepare_v68(directory / "handoff", incident, manifest, receipts,
                sha_commit, run_id)
    copy_ledger(source_ledger, directory / "ledger.sqlite3")
    state = snapshot(directory / "ledger.sqlite3", root)
    entries = []
    for i in range(3):
        source = channel_path(channels, i)
        if source.is_symlink():
            raise EvidenceRejected("unsafe witness channel")
        if source.exists():
            if i > 1:
                # Protocol v6.9 deliberately supports the 2-of-3 layout only.
                raise EvidenceRejected("unsupported third channel")
            data = regular(source)
            dest = directory / f"channel-{i}.json"
            with dest.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            entries.append(sha(data))
        elif i < 2:
            raise EvidenceRejected("required witness channel missing")
    if len(entries) != 2:
        raise EvidenceRejected("incomplete history channels")
    index = {"version": VERSION, "ledger_sha256": sha(regular(directory / "ledger.sqlite3")),
             "channel_sha256": entries, **state, "decision": "HOLD",
             "authorization": "DENY"}
    with (directory / "history-index.json").open("xb") as handle:
        handle.write(serialize(index))
        handle.flush()
        os.fsync(handle.fileno())


def inspect(directory: Path, expected_sha: str, expected_run: str,
            custodians: dict[str, Ed25519PublicKey],
            root: Ed25519PublicKey, witnesses: dict[str, Ed25519PublicKey],
            independent_checkpoint: dict) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceRejected("history directory unavailable")
    if {p.name for p in directory.iterdir()} != set(HISTORY) | {"handoff"}:
        raise EvidenceRejected("missing or unexpected history item")
    if (directory / "handoff").is_symlink():
        raise EvidenceRejected("unsafe nested handoff")
    index = strictly_parse(regular(directory / "history-index.json"), FIELDS)
    if index["version"] != VERSION or index["decision"] != "HOLD" or index["authorization"] != "DENY":
        raise EvidenceRejected("history policy mismatch")
    for name in ("ledger_sha256", "head", "root_id"):
        check_hex(index[name])
    if type(index["sequence"]) is not int or index["sequence"] < 1:
        raise EvidenceRejected("invalid history sequence")
    channels = index["channel_sha256"]
    if type(channels) is not list or len(channels) != 2:
        raise EvidenceRejected("history channel set invalid")
    for i, expected in enumerate(channels):
        check_hex(expected)
        if sha(regular(directory / f"channel-{i}.json")) != expected:
            raise EvidenceRejected("history channel bytes changed")
    ledger = directory / "ledger.sqlite3"
    if sha(regular(ledger)) != index["ledger_sha256"]:
        raise EvidenceRejected("history ledger bytes changed")
    state = snapshot(ledger, root)  # Replays every signed incident and rotation.
    if state != {k: index[k] for k in ("sequence", "head", "root_id")}:
        raise EvidenceRejected("historical head mismatch")
    # Exact externally retained high-watermark: older/forked ledgers DENY.
    if type(independent_checkpoint) is not dict or independent_checkpoint != state:
        raise EvidenceRejected("missing or rolled-back independent checkpoint")
    inspect_v68(directory / "handoff", expected_sha, expected_run, custodians)
    with tempfile.TemporaryDirectory() as temp:
        channel_root = Path(temp)
        for i in range(2):
            dest = channel_path(channel_root, i)
            dest.parent.mkdir()
            dest.write_bytes(regular(directory / f"channel-{i}.json"))
        verify_archive(ledger, root, witnesses, channel_root,
                       directory / "handoff" / "archive.json")
    return {"decision": "HOLD", "authorization": "DENY",
            "sequence": state["sequence"], "head": state["head"]}
