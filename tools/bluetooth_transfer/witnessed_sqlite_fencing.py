"""Independent witness adapter for the SQLite fencing development reference.

A separate protected monotonic witness must commit the COMPLETE checkpoint,
fence epoch and HOLD flag. Witness-first updates are not atomic with SQLite;
any partial failure produces HOLD and requires an authorized offline review.
NO protected witness implementation, TPM/KeyMint driver, or recovery API is
provided. Never use a witness stored in the same SQLite file as the ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import threading
from typing import Protocol

from anchored_challenges import _validate_state
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedSnapshot
from protocol import TransferError


@dataclass(frozen=True)
class FencingWitnessState:
    namespace: bytes
    revision: int
    epoch: int
    held: bool
    count: int
    root: str

    def __post_init__(self):
        if (type(self.namespace) is not bytes or len(self.namespace) != 32 or
                type(self.revision) is not int or not 0 <= self.revision < 2**63 or
                type(self.epoch) is not int or not 1 <= self.epoch < 2**63 or
                type(self.held) is not bool):
            raise TransferError("invalid independent fencing witness")
        _validate_state((self.count, self.root))


class ProtectedFencingWitness(Protocol):
    """Independently protected, durable atomic monotonic witness (not supplied)."""

    def read(self) -> FencingWitnessState: ...

    def advance(
        self, previous: FencingWitnessState, current: FencingWitnessState,
    ) -> None: ...


class WitnessedFencingService:
    """Detect SQLite rollback and incident suppression if witness is protected.

    This is intentionally a development composition, not a trust provider.
    """

    def __init__(self, sqlite_service, witness: ProtectedFencingWitness,
                 namespace: bytes):
        if (type(namespace) is not bytes or len(namespace) != 32 or
                not callable(getattr(sqlite_service, "read", None)) or
                not callable(getattr(sqlite_service, "compare_and_advance", None)) or
                not callable(getattr(sqlite_service, "latch_incident", None)) or
                not callable(getattr(witness, "read", None)) or
                not callable(getattr(witness, "advance", None))):
            raise TransferError("separate protected fencing witness required")
        self._sqlite = sqlite_service
        self._witness = witness
        self._namespace = namespace
        self._held_locally = False
        self._lock = threading.RLock()
        self.read()

    @property
    def is_held(self) -> bool:
        return self._held_locally

    def _require_live(self):
        if self._held_locally:
            raise TransferError("fencing witness session locked in HOLD")

    def _witness_state(self) -> FencingWitnessState:
        try:
            value = self._witness.read()
        except Exception as exc:
            raise TransferError("independent fencing witness unavailable: HOLD") from exc
        if (type(value) is not FencingWitnessState or
                not hmac.compare_digest(value.namespace, self._namespace)):
            raise TransferError("independent fencing witness scope mismatch: HOLD")
        return value

    def _sqlite_state(self) -> FencedSnapshot:
        try:
            value = self._sqlite.read()
        except Exception as exc:
            raise TransferError("SQLite fencing reference unavailable: HOLD") from exc
        if (type(value) is not FencedSnapshot or
                not hmac.compare_digest(value.namespace, self._namespace)):
            raise TransferError("SQLite fencing reference scope mismatch: HOLD")
        return value

    @staticmethod
    def _matches(snapshot: FencedSnapshot, witness: FencingWitnessState) -> bool:
        return (
            snapshot.epoch == witness.epoch and
            snapshot.incident_held is witness.held and
            snapshot.checkpoint.count == witness.count and
            hmac.compare_digest(snapshot.checkpoint.root, witness.root)
        )

    def read(self) -> FencedSnapshot:
        with self._lock:
            self._require_live()
            try:
                before = self._witness_state()
                local = self._sqlite_state()
                after = self._witness_state()
                if before != after or not self._matches(local, after):
                    raise TransferError("SQLite / independent witness mismatch: HOLD")
                return local
            except Exception as exc:
                self._held_locally = True
                raise TransferError("independent fencing validation failed: HOLD") from exc

    def _advance(self, expected: FencedSnapshot, new: FencedSnapshot,
                 writer) -> FencedSnapshot:
        with self._lock:
            self._require_live()
            try:
                if type(expected) is not FencedSnapshot or type(new) is not FencedSnapshot:
                    raise TransferError("invalid witnessed fencing transition")
                if (expected.namespace != self._namespace or
                        new.namespace != self._namespace):
                    raise TransferError("witnessed fencing scope mismatch")
                if expected.incident_held:
                    raise TransferError("incident already held: HOLD")
                cas_transition = (
                    new.epoch == expected.epoch and not new.incident_held and
                    new.checkpoint != expected.checkpoint and
                    new.checkpoint.count in (
                        expected.checkpoint.count, expected.checkpoint.count + 1
                    )
                )
                incident_transition = (
                    new.epoch == expected.epoch + 1 and new.incident_held and
                    new.checkpoint == expected.checkpoint
                )
                if not (cas_transition or incident_transition):
                    raise TransferError("invalid witnessed fencing transition: HOLD")
                if self.read() != expected:
                    raise TransferError("stale witnessed fencing state")
                before = self._witness_state()
                if before.revision == 2**63 - 1:
                    raise TransferError("fencing witness revision exhausted")
                after = FencingWitnessState(
                    self._namespace, before.revision + 1, new.epoch,
                    new.incident_held, new.checkpoint.count, new.checkpoint.root,
                )
                self._witness.advance(before, after)
                actual = writer()
                if actual != new or self.read() != new:
                    raise TransferError("fencing witness write not confirmed")
                return actual
            except Exception as exc:
                self._held_locally = True
                raise TransferError("witness/SQLite transition uncertain: HOLD") from exc

    def compare_and_advance(
        self, expected: FencedSnapshot, replacement: NativeCheckpoint,
    ) -> FencedSnapshot:
        with self._lock:
            self._require_live()
            if (type(expected) is not FencedSnapshot or
                    type(replacement) is not NativeCheckpoint or
                    expected.namespace != self._namespace or
                    replacement.namespace != self._namespace):
                self._held_locally = True
                raise TransferError("invalid witness CAS request: HOLD")
            new = FencedSnapshot(
                self._namespace, expected.epoch, expected.incident_held,
                replacement,
            )
            return self._advance(
                expected, new,
                lambda: self._sqlite.compare_and_advance(expected, replacement),
            )

    def latch_incident(self) -> FencedSnapshot:
        with self._lock:
            self._require_live()
            expected = self.read()
            if expected.incident_held:
                return expected
            if expected.epoch == 2**63 - 1:
                self._held_locally = True
                raise TransferError("fencing epoch exhausted: HOLD")
            new = FencedSnapshot(
                self._namespace, expected.epoch + 1, True, expected.checkpoint,
            )
            return self._advance(expected, new, self._sqlite.latch_incident)
