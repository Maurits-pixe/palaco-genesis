"""Second independent checkpoint witness, with an in-process sticky HOLD latch.

A separately protected monotonic witness is REQUIRED but NOT supplied here.
Two-store commits are not atomic; failures deny subsequent operations in the
same instance even if both stores later appear identical. This latch is NOT
durable across process restarts or secure against caller-created instances.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Protocol

from anchored_challenges import _validate_state
from protocol import TransferError


@dataclass(frozen=True)
class WitnessCheckpoint:
    namespace: bytes
    revision: int
    count: int
    root: str

    def __post_init__(self):
        if type(self.namespace) is not bytes or len(self.namespace) != 32:
            raise TransferError("invalid witness namespace")
        if type(self.revision) is not int or not 0 <= self.revision < 2**63:
            raise TransferError("invalid witness revision")
        _validate_state((self.count, self.root))


class ProtectedCheckpointWitness(Protocol):
    """Independent protected compare-and-increment service (NOT implemented)."""

    def read(self) -> WitnessCheckpoint: ...

    def advance(
        self, previous: WitnessCheckpoint, current: WitnessCheckpoint,
    ) -> None: ...


class WitnessedChallengeAnchor:
    """Block all further use of the instance after an uncertain operation."""

    def __init__(self, native_anchor, witness: ProtectedCheckpointWitness, namespace: bytes):
        if (type(namespace) is not bytes or len(namespace) != 32 or
                not callable(getattr(native_anchor, "read", None)) or
                not callable(getattr(native_anchor, "advance", None)) or
                not callable(getattr(witness, "read", None)) or
                not callable(getattr(witness, "advance", None))):
            raise TransferError("native anchor and independent witness required")
        self._native = native_anchor
        self._witness = witness
        self._namespace = namespace
        self._held = False
        self.read()

    @property
    def is_held(self) -> bool:
        """Sticky within this object; NOT a durable recovery or trust record."""
        return self._held

    def _require_live(self):
        if self._held:
            raise TransferError("witness session locked in HOLD")

    def _witness_snapshot(self):
        try:
            item = self._witness.read()
        except Exception as exc:
            raise TransferError("independent checkpoint witness unavailable: HOLD") from exc
        if (type(item) is not WitnessCheckpoint or
                not hmac.compare_digest(item.namespace, self._namespace)):
            raise TransferError("checkpoint witness namespace mismatch: HOLD")
        return item

    def read(self) -> tuple[int, str]:
        self._require_live()
        try:
            witness_before = self._witness_snapshot()
            try:
                native = _validate_state(self._native.read())
            except Exception as exc:
                raise TransferError("native checkpoint unavailable: HOLD") from exc
            witness_after = self._witness_snapshot()
            if (witness_after != witness_before or
                    native[0] != witness_before.count or
                    not hmac.compare_digest(native[1], witness_before.root)):
                raise TransferError("independent witness/native mismatch: HOLD")
            return native
        except TransferError:
            self._held = True
            raise

    def advance(self, previous: tuple[int, str], current: tuple[int, str]) -> None:
        self._require_live()
        try:
            before = _validate_state(previous)
            after = _validate_state(current)
            if after == before or after[0] not in (before[0], before[0] + 1):
                raise TransferError("invalid witnessed checkpoint transition")
            if self.read() != before:
                raise TransferError("stale witnessed checkpoint: HOLD")
            witness_before = self._witness_snapshot()
            if (witness_before.count != before[0] or
                    not hmac.compare_digest(witness_before.root, before[1]) or
                    witness_before.revision == 2**63 - 1):
                raise TransferError("witness CAS mismatch or exhausted: HOLD")
            witness_after = WitnessCheckpoint(
                self._namespace, witness_before.revision + 1, after[0], after[1],
            )
            try:
                self._witness.advance(witness_before, witness_after)
            except Exception as exc:
                raise TransferError("witness advancement uncertain: HOLD") from exc
            # The witness advances first. Never roll it back automatically.
            try:
                self._native.advance(before, after)
            except Exception as exc:
                raise TransferError("native advance after witness write failed: HOLD") from exc
            if self.read() != after:
                raise TransferError("post-write witness checkpoint disagreement: HOLD")
        except TransferError:
            self._held = True
            raise
