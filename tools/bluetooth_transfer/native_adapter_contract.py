"""Native BLE adapter boundary and scoped receive controller.

This is a protocol integration harness, NOT a native Bluetooth implementation.
The production adapter MUST supply independent cryptographic verification,
encryption and genuine consent; mocked evidence is only for regression tests.
"""
from __future__ import annotations

from enum import Enum

from ble_frames import BleTransferBridge, _check_value_limit
from ble_sender import AckingBleReceiver
from protocol import Offer, Receiver, TransferError
from transport_gate import VerifiedTransportEvidence, admit_receive_session


class ReceiveState(Enum):
    """Explicit lifecycle; none of these states grants import authority."""

    IDLE = "idle"
    RECEIVING = "receiving"
    RECEIVED_UNTRUSTED = "received_untrusted"
    ABORTED = "aborted"


class NativeReceiveController:
    """Single-session receiver facade for a future native GATT callback adapter."""

    def __init__(self, replay_guard: Receiver) -> None:
        if not isinstance(replay_guard, Receiver):
            raise TransferError("shared replay guard required")
        self._guard = replay_guard
        self._state = ReceiveState.IDLE
        self._receiver: AckingBleReceiver | None = None

    @property
    def state(self) -> ReceiveState:
        return self._state

    def begin(
        self, offer: Offer, evidence: VerifiedTransportEvidence, value_limit: int
    ) -> None:
        """Begin once, only after external secure-session evidence is assessed."""
        if self._state is not ReceiveState.IDLE:
            raise TransferError("controller cannot be reopened")
        _check_value_limit(value_limit)
        session = admit_receive_session(offer, self._guard, evidence)
        self._receiver = AckingBleReceiver(
            BleTransferBridge(session, offer.payload_size, value_limit)
        )
        self._state = ReceiveState.RECEIVING

    def on_notification(self, packet: bytes) -> bytes:
        """Consume radio packet and return ACK bytes for authenticated transport."""
        if self._state is not ReceiveState.RECEIVING or self._receiver is None:
            raise TransferError("receiver is not active")
        try:
            return self._receiver.receive(packet)
        except (TransferError, TypeError, ValueError):
            self.abort()
            raise

    def complete(self) -> bytes:
        """Close and return integrity-checked but *untrusted* payload bytes."""
        if self._state is not ReceiveState.RECEIVING or self._receiver is None:
            raise TransferError("receiver is not active")
        try:
            payload = self._receiver.finish()
        except (TransferError, TypeError, ValueError):
            self.abort()
            raise
        self._receiver = None
        self._state = ReceiveState.RECEIVED_UNTRUSTED
        return payload

    def disconnect(self) -> None:
        """Never auto-resume a disconnected transfer."""
        self.abort()

    def permission_revoked(self) -> None:
        """Revoke access and discard buffered frames immediately."""
        self.abort()

    def abort(self) -> None:
        """Idempotent cancellation; a new controller and new offer are required."""
        if self._receiver is not None:
            self._receiver.abort()
            self._receiver = None
        if self._state is not ReceiveState.RECEIVED_UNTRUSTED:
            self._state = ReceiveState.ABORTED
