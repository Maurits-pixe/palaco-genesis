"""Native atomic fencing boundary for checkpoint and incident state.

The native service MUST implement one indivisible, durable transaction covering
checkpoint CAS, HOLD status and fence epoch, shared across ALL processes.
This Python adapter verifies preconditions and refuses lost/revoked fences;
it is NOT an OS/TPM/KeyMint implementation and CANNOT enforce atomicity in the
native service. No automatic unlock, migration or recovery authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Protocol

from anchored_challenges import _validate_state
from native_checkpoint_scope import NativeCheckpoint
from protocol import TransferError


@dataclass(frozen=True)
class FencedSnapshot:
    namespace: bytes
    epoch: int
    incident_held: bool
    checkpoint: NativeCheckpoint

    def __post_init__(self):
        if (type(self.namespace) is not bytes or len(self.namespace) != 32 or
                type(self.epoch) is not int or not 1 <= self.epoch < 2**63 or
                type(self.incident_held) is not bool or
                type(self.checkpoint) is not NativeCheckpoint or
                not hmac.compare_digest(self.namespace, self.checkpoint.namespace)):
            raise TransferError("invalid native fencing snapshot")


class AtomicFencingService(Protocol):
    """Independent privileged host, not implementable by an untrusted peer."""

    def read(self) -> FencedSnapshot: ...

    def compare_and_advance(
        self, expected: FencedSnapshot, replacement: NativeCheckpoint,
    ) -> FencedSnapshot:
        """One atomic operation: test epoch/incident/CAS and write checkpoint."""


class FencedChallengeAnchor:
    """Adapt a native atomic, incident-aware CAS to the challenge anchor API."""

    def __init__(self, service: AtomicFencingService, namespace: bytes):
        if (type(namespace) is not bytes or len(namespace) != 32 or
                not callable(getattr(service, "read", None)) or
                not callable(getattr(service, "compare_and_advance", None))):
            raise TransferError("protected atomic fencing service required")
        self._service = service
        self._namespace = namespace
        self._held_locally = False
        self._epoch = None
        self.read()

    @property
    def is_held(self):
        return self._held_locally

    def _snapshot(self) -> FencedSnapshot:
        if self._held_locally:
            raise TransferError("local fencing HOLD active")
        try:
            state = self._service.read()
        except Exception as exc:
            self._held_locally = True
            raise TransferError("atomic fencing service unavailable: HOLD") from exc
        if (type(state) is not FencedSnapshot or
                not hmac.compare_digest(state.namespace, self._namespace) or
                state.incident_held or
                (self._epoch is not None and state.epoch != self._epoch)):
            self._held_locally = True
            raise TransferError("native fence revoked, replaced or held: HOLD")
        return state

    def read(self) -> tuple[int, str]:
        before = self._snapshot()
        # Detect observable changes during a checkpoint read.
        after = self._snapshot()
        if before != after:
            self._held_locally = True
            raise TransferError("native fencing snapshot changed during read: HOLD")
        if self._epoch is None:
            self._epoch = after.epoch
        return after.checkpoint.count, after.checkpoint.root

    def advance(
        self, previous: tuple[int, str], current: tuple[int, str],
    ) -> None:
        if self._held_locally:
            raise TransferError("local fencing HOLD active")
        try:
            before = _validate_state(previous)
            after = _validate_state(current)
            if after == before or after[0] not in (before[0], before[0] + 1):
                raise TransferError("invalid fenced checkpoint transition")
            expected = self._snapshot()
            if expected.checkpoint != NativeCheckpoint(self._namespace, *before):
                raise TransferError("stale checkpoint fenced CAS precondition")
            replacement = NativeCheckpoint(self._namespace, *after)
            # Native must atomically check epoch + HOLD + checkpoint and apply CAS.
            result = self._service.compare_and_advance(expected, replacement)
            if (type(result) is not FencedSnapshot or
                    result.epoch != self._epoch or result.incident_held or
                    result.namespace != self._namespace or
                    result.checkpoint != replacement):
                raise TransferError("native fenced CAS result invalid")
            observed = self._snapshot()
            if observed != result:
                raise TransferError("native fenced CAS not confirmed")
        except Exception as exc:
            self._held_locally = True
            raise TransferError("fenced checkpoint write denied or uncertain: HOLD") from exc
