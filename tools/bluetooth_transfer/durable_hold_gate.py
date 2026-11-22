"""Restart-persistent HOLD gate requiring an independently protected incident store.

An incident store MUST atomically latch HOLD in a protected, non-rollbackable
namespace, and MUST NOT expose release/clear through this interface. This
module supplies no secure storage or native hardware calls. The fake stores
used in tests DO NOT prove persistent or anti-rollback security.

On the first checkpoint failure, the wrapper attempts to persist HOLD, then
rejects operations unconditionally. If persisting fails, the same instance
stays locked; on restart the caller MUST fail closed until a trustworthy
protected incident source is again available. In a compromised backend,
neither persistent safety nor restart safety is guaranteed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Protocol

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
    """Native service: secure monotonic sticky HOLD, never clear via this API."""

    def read(self) -> ProtectedHoldState: ...

    def latch(self, namespace: bytes) -> ProtectedHoldState:
        """Atomically set durable HOLD, returning the authoritative state."""


class DurableHoldChallengeAnchor:
    """Fail-closed bridge from checkpoint IO to an external incident latch."""

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
        self.read()

    @property
    def is_held(self):
        """Only a local indicator; always consult native store for decisions."""
        return self._held_locally

    def _state(self):
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
        if self._held_locally:
            raise TransferError("local incident HOLD active")
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
        self._state()
        try:
            value = self._checkpoint.read()
        except Exception as exc:
            self._latch()
            raise TransferError("checkpoint read failed; incident HOLD") from exc
        self._state()
        return value

    def advance(self, previous, current):
        self._state()
        try:
            self._checkpoint.advance(previous, current)
        except Exception as exc:
            self._latch()
            raise TransferError("checkpoint advancement failed; incident HOLD") from exc
        # A concurrent incident or disappearing store must not be ignored.
        self._state()
