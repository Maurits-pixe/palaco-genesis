"""Subprocess probe for SQLite fencing regression tests; not a production CLI.

Never use with privileged storage. All actions operate on development SQLite
files passed by the local test harness. This module exposes no repair/unlatch.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedSnapshot
from protocol import TransferError
from sqlite_fencing_reference import SQLiteFencingReference


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        return 2
    action, path, namespace_hex, *args = argv
    namespace = bytes.fromhex(namespace_hex)
    try:
        service = SQLiteFencingReference(Path(path), namespace)
        if action == "read":
            state = service.read()
        elif action == "advance":
            before_count, before_root, after_count, after_root = args
            current = service.read()
            expected = FencedSnapshot(
                namespace, int(args[4]) if len(args) > 4 else current.epoch,
                False, NativeCheckpoint(namespace, int(before_count), before_root),
            )
            state = service.compare_and_advance(
                expected, NativeCheckpoint(namespace, int(after_count), after_root),
            )
        elif action == "latch":
            state = service.latch_incident()
        elif action in ("crash_uncommitted", "crash_committed", "hold_lock"):
            ready = Path(args[0])
            with sqlite3.connect(str(path), timeout=5) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE fence SET count=1,root=? WHERE singleton=1",
                           ("e" * 64,))
                if action == "crash_committed":
                    db.commit()
                ready.write_text("ready", encoding="ascii")
                if action == "hold_lock":
                    release = Path(args[1])
                    for _ in range(500):
                        if release.exists():
                            break
                        time.sleep(0.01)
                    else:
                        return 3
                    db.rollback()
                    return 0
                os._exit(0)
        else:
            return 2
        print(json.dumps({
            "epoch": state.epoch, "held": state.incident_held,
            "count": state.checkpoint.count, "root": state.checkpoint.root,
        }), flush=True)
        return 0
    except (TransferError, OSError, sqlite3.Error, ValueError, TypeError) as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
