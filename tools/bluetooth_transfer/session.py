"""Fail-closed incremental transfer session, independent of Bluetooth hardware.

This is a single in-process stream, not a secure pairing or encryption layer.
An interrupted session must be restarted with a NEW transfer ID.
"""
from __future__ import annotations

from protocol import CHUNK_BYTES, Offer, Receiver, TransferError, _validate_offer


class TransferSession:
    """Bounded sequential receiving with explicit abort and no implicit resume."""

    def __init__(
        self, offer: Offer, replay_guard: Receiver, *,
        user_approved: bool, identity_verified: bool,
    ) -> None:
        _validate_offer(offer)
        if type(user_approved) is not bool or type(identity_verified) is not bool:
            raise TransferError("verification flags must be booleans")
        if not user_approved or not identity_verified:
            raise TransferError("authenticated peer and local consent required")
        if not isinstance(replay_guard, Receiver):
            raise TransferError("invalid replay guard")
        if replay_guard.has_seen(offer.transfer_id):
            raise TransferError("replayed transfer")
        self._offer = offer
        self._guard = replay_guard
        self._parts: list[bytes] = []
        self._closed = False
        self._received = 0

    @property
    def offered_bytes(self) -> int:
        """Immutable length bound from the validated offer."""
        return self._offer.payload_size

    @property
    def next_index(self) -> int:
        """Next required chunk index, starting at zero."""
        return len(self._parts)

    @property
    def received_bytes(self) -> int:
        """Received bytes retained by the current session."""
        return self._received

    @property
    def closed(self) -> bool:
        """True after completion, interruption, cancellation or invalid input."""
        return self._closed

    def _abort_with(self, message: str) -> None:
        self.abort()
        raise TransferError(message)

    def push(self, index: int, payload: bytes) -> None:
        """Accept only the exact next frame; reject, discard and close on errors."""
        if self._closed:
            raise TransferError("session closed")
        if type(index) is not int or index != len(self._parts):
            self._abort_with("out-of-order or duplicate chunk")
        if not isinstance(payload, bytes):
            self._abort_with("chunk must be immutable bytes")
        expected = min(CHUNK_BYTES, self._offer.payload_size - self._received)
        if expected <= 0 or len(payload) != expected:
            self._abort_with("invalid chunk size")
        self._parts.append(payload)
        self._received += len(payload)

    def finish(self) -> bytes:
        """Verify complete payload using the shared replay guard, then close."""
        if self._closed:
            raise TransferError("session closed")
        if len(self._parts) != self._offer.chunk_count:
            self._abort_with("incomplete transfer")
        try:
            return self._guard.accept(
                self._offer, tuple(self._parts),
                user_approved=True, identity_verified=True,
            )
        finally:
            self.abort()

    def abort(self) -> None:
        """Discard retained untrusted chunks; cannot resume this session."""
        self._parts.clear()
        self._received = 0
        self._closed = True

    def disconnect(self) -> None:
        """Treat a radio disconnect as cancellation, never automatic resumption."""
        self.abort()
