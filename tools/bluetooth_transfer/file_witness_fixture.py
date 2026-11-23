"""Untrusted file-backed witness fixture for crash testing ONLY.

This file fixture simulates persistence across processes. It is not a secure,
independent, monotonic or tamper-resistant witness. A malicious actor can edit
or replace its JSON file. Never use as production protection.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from protocol import TransferError
from witnessed_sqlite_fencing import FencingWitnessState


def _encode(value: FencingWitnessState) -> dict:
    return {
        "namespace": value.namespace.hex(), "revision": value.revision,
        "epoch": value.epoch, "held": value.held, "count": value.count,
        "root": value.root,
    }


class FileWitnessFixture:
    """Explicitly non-secure on-disk test double with atomic file replacement."""

    def __init__(self, path: Path, namespace: bytes, *, create=False):
        self.path = Path(path)
        self.namespace = namespace
        if (type(namespace) is not bytes or len(namespace) != 32 or
                not self.path.is_absolute() or not self.path.parent.is_dir() or
                self.path.is_symlink()):
            raise TransferError("invalid witness fixture location")
        if create:
            if self.path.exists():
                raise TransferError("witness fixture already exists")
            first = FencingWitnessState(namespace, 0, 1, False, 0,
                                        __import__("anchored_challenges").EMPTY_ROOT)
            with self.path.open("x", encoding="ascii") as output:
                json.dump(_encode(first), output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
        self.read()

    def read(self) -> FencingWitnessState:
        try:
            if self.path.is_symlink() or not self.path.is_file():
                raise TransferError("witness fixture removed or replaced")
            raw = json.loads(self.path.read_text(encoding="ascii"))
            if type(raw) is not dict or set(raw) != {
                "namespace", "revision", "epoch", "held", "count", "root"
            }:
                raise TransferError("malformed witness fixture")
            value = FencingWitnessState(
                bytes.fromhex(raw["namespace"]), raw["revision"], raw["epoch"],
                raw["held"], raw["count"], raw["root"],
            )
            if value.namespace != self.namespace:
                raise TransferError("witness fixture scope mismatch")
            return value
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise TransferError("untrusted witness fixture unavailable") from exc

    def advance(self, previous: FencingWitnessState, current: FencingWitnessState):
        if (type(previous) is not FencingWitnessState or
                type(current) is not FencingWitnessState or
                previous.namespace != self.namespace or
                current.namespace != self.namespace or
                current.revision != previous.revision + 1):
            raise TransferError("invalid witness fixture transition")
        if self.read() != previous:
            raise TransferError("stale witness fixture")
        # Atomic replacement only; NOT atomic with SQLite and NOT protected CAS.
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="ascii", dir=self.path.parent,
                prefix=".witness-", delete=False,
            ) as f:
                temp_path = Path(f.name)
                json.dump(_encode(current), f, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.path)
            # fsync parent so crash simulation models a committed file rename.
            if hasattr(os, "O_DIRECTORY"):
                fd = os.open(str(self.path.parent), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError as exc:
            raise TransferError("witness fixture update uncertain") from exc
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
