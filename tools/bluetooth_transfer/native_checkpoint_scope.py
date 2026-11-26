"""Scope-bound adapter for an externally secured challenge checkpoint.

The native backend MUST attest the immutable storage namespace together with
the count/root, and perform atomic compare-and-advance for that namespace.
This wrapper enforces one configured namespace but cannot prove backend
authenticity, stop rollback inside the backend or make SQLite atomic with it.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Protocol

from anchored_challenges import _validate_state
from protocol import TransferError

SCOPE_DOMAIN = b"PALACO:BT:CHALLENGE-LEDGER-SCOPE:V1\0"


@dataclass(frozen=True)
class NativeCheckpoint:
    namespace: bytes
    count: int
    root: str

    def __post_init__(self):
        if type(self.namespace) is not bytes or len(self.namespace) != 32:
            raise TransferError("invalid protected storage namespace")
        _validate_state((self.count, self.root))


class NativeCheckpointBackend(Protocol):
    """Privileged native service; must bind scope and CAS atomically."""

    def read(self) -> NativeCheckpoint: ...

    def advance(
        self, namespace: bytes, previous: NativeCheckpoint,
        current: NativeCheckpoint,
    ) -> None: ...


class ScopeBoundChallengeAnchor:
    """Pin backend namespace, fail closed on cross-storage replacement."""

    def __init__(self, backend: NativeCheckpointBackend, namespace: bytes):
        if type(namespace) is not bytes or len(namespace) != 32:
            raise TransferError("explicit 32-byte protected namespace required")
        if not callable(getattr(backend, "read", None)) or not callable(
            getattr(backend, "advance", None)
        ):
            raise TransferError("native checkpoint backend required")
        self._backend = backend
        self._namespace = namespace
        # Enforce correct namespace at initialization as well as on every read.
        self.read()

    def _snapshot(self) -> NativeCheckpoint:
        try:
            value = self._backend.read()
        except Exception as exc:
            raise TransferError("native checkpoint unavailable: HOLD") from exc
        if type(value) is not NativeCheckpoint or not hmac.compare_digest(
            value.namespace, self._namespace,
        ):
            raise TransferError("native checkpoint namespace mismatch: HOLD")
        return value

    def read(self) -> tuple[int, str]:
        snap = self._snapshot()
        return snap.count, snap.root

    def advance(
        self, previous: tuple[int, str], current: tuple[int, str],
    ) -> None:
        before = _validate_state(previous)
        after = _validate_state(current)
        if after == before:
            raise TransferError("checkpoint must change")
        # The consumed flag changes the root while keeping count constant.
        if after[0] not in (before[0], before[0] + 1):
            raise TransferError("invalid challenge checkpoint count transition")
        observed = self._snapshot()
        if observed.count != before[0] or not hmac.compare_digest(
            observed.root, before[1],
        ):
            raise TransferError("native checkpoint CAS precondition mismatch: HOLD")
        expected = NativeCheckpoint(self._namespace, *before)
        replacement = NativeCheckpoint(self._namespace, *after)
        try:
            self._backend.advance(self._namespace, expected, replacement)
        except Exception as exc:
            raise TransferError("native checkpoint write uncertain: HOLD") from exc
        committed = self._snapshot()
        if committed.count != after[0] or not hmac.compare_digest(
            committed.root, after[1],
        ):
            raise TransferError("native checkpoint write unconfirmed: HOLD")
