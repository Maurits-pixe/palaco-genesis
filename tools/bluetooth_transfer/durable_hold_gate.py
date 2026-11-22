"""Fail-closed incident/HOLD interface for an independently protected native store.

The native incident store MUST provide sticky, rollback-resistant state; it is
NOT implemented by this module. A process-local RLock serializes this wrapper
only, not another process/device or a native incident racing a checkpoint CAS.
External native code MUST make the incident check and privileged write
mutually exclusive or enforce a protected fencing token; this module cannot.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import threading
from typing import Protocol

from anchored_challenges import _validate_state
from protocol import TransferError


@dataclass(frozen=True)
class ProtectedHoldState:
    namespace: bytes
    held: bool
    incident_sequence: int

    def __post_init__(self):
        if (type(self.namespace) is not bytes or len(self.namespace) != 32 or
                type(self.held) is not bool or
                type(self.incident_sequence) is not int or
                not 0 <= self.incident_sequence < 2**63 or
                (self.held and self.incident_sequence == 0) or
                (not self.held and self.incident_sequence != 0)):
            raise TransferError("invalid protected HOLD incident state")


class ProtectedIncidentStore(Protocol):
    """Trusted durable monotonic latch, never clear through this interface."""

    def read(self) -> ProtectedHoldState: ...

    def latch(self, namespace: bytes) -> ProtectedHoldState:
        """Atomically persist HOLD and return authoritative held state."""


class DurableHoldChallengeAnchor:
    """Native checkpoint adapter with serialized and fail-closed local access."""

    def __init__(self, checkpoint_anchor, incident_store: ProtectedIncidentStore,
                 namespace: bytes):
        if (type(namespace) is not bytes or len(namespace) != 32 or
                not callable(getattr(checkpoint_anchor, "read", None)) or
                not callable(getattr(checkpoint_anchor, "advance", None)) or
                not callable(getattr(incident_store, "read", None)) or
                not callable(getattr(incident_store, "latch", None))):
            raise TransferError("protected HOLD store and checkpoint anchor required")
        self._checkpoint = checkpoint_anchor
        self._incident = incident_store
        self._namespace = namespace
        self._held_locally = False
        self._lock = threading.RLock()
        self.read()

    @property
    def is_held(self):
        """In-memory indicator only; externally protected state is decisive."""
        with self._lock:
            return self._held_locally

    def _state(self):
        if self._held_locally:
            raise TransferError("local incident HOLD active")
        try:
            state = self._incident.read()
        except Exception as exc:
            self._held_locally = True
            raise TransferError("protected incident store unavailable: HOLD") from exc
        if (type(state) is not ProtectedHoldState or
                not hmac.compare_digest(state.namespace, self._namespace)):
            self._held_locally = True
            raise TransferError("invalid incident store scope: HOLD")
        if state.held:
            self._held_locally = True
            raise TransferError("durable incident HOLD active")
        return state

    def _latch(self):
        self._held_locally = True
        try:
            result = self._incident.latch(self._namespace)
            if (type(result) is not ProtectedHoldState or
                    not hmac.compare_digest(result.namespace, self._namespace) or
                    not result.held):
                raise TransferError("protected incident latch unconfirmed")
        except Exception as exc:
            raise TransferError("incident checkpoint failed; native HOLD required") from exc

    def read(self):
        with self._lock:
            prior = self._state()
            try:
                value = _validate_state(self._checkpoint.read())
            except Exception as exc:
                self._latch()
                raise TransferError("checkpoint read failed; incident HOLD") from exc
            final = self._state()
            if final != prior:
                self._latch()
                raise TransferError("incident state changed during checkpoint read: HOLD")
            return value

    def advance(self, previous, current):
        with self._lock:
            prior = self._state()
            try:
                before = _validate_state(previous)
                after = _validate_state(current)
                if after == before or after[0] not in (before[0], before[0] + 1):
                    raise TransferError("invalid checkpoint transition")
                self._checkpoint.advance(before, after)
            except Exception as exc:
                self._latch()
                raise TransferError("checkpoint advancement failed; incident HOLD") from exc
            final = self._state()
            if final != prior:
                self._latch()
                raise TransferError("incident changed during checkpoint write: HOLD")
