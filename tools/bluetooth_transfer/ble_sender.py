"""Stop-and-wait sender reference for PALACO BLE frames.

ACKs are transport control hints, NOT authorization or authenticity proofs.
An authenticated encrypted transport MUST bind ACKs to the current peer,
transfer and session; this module does not implement that requirement.
"""
from __future__ import annotations

from ble_frames import VERSION, BleTransferBridge, encode_chunk, _check_value_limit
from protocol import TransferError, chunks

ACK_MAGIC = 0x41
ACK_SIZE = 6
DEFAULT_MAX_RETRIES = 3


def ack_for_frame(packet: bytes) -> bytes:
    """Encode a receiver-side ACK for a syntactically valid data header."""
    if not isinstance(packet, bytes) or len(packet) < 8 or packet[0] != 0x50:
        raise TransferError("invalid data frame")
    if packet[1] != VERSION or packet[6] not in (0, 1):
        raise TransferError("invalid frame header")
    return bytes((ACK_MAGIC, VERSION)) + packet[2:6]


class StopAndWaitSender:
    """One outstanding packet; bounded retransmissions on caller-driven timeout."""

    def __init__(self, payload: bytes, value_limit: int, *,
                 max_retries: int = DEFAULT_MAX_RETRIES) -> None:
        _check_value_limit(value_limit)
        if type(max_retries) is not int or not 0 <= max_retries <= 8:
            raise TransferError("invalid retry bound")
        self._parts = chunks(payload)
        self._value_limit = value_limit
        self._chunk_index = 0
        self._frames = encode_chunk(0, self._parts[0], value_limit)
        self._position = 0
        self._acknowledged = 0
        self._retries = 0
        self._max_retries = max_retries
        self._closed = False
        self._completed = False

    @property
    def done(self) -> bool:
        """True only after ACK of every frame."""
        return self._completed

    @property
    def closed(self) -> bool:
        """True after cancel, failed timeout limit or completion."""
        return self._closed

    @property
    def acknowledged_frames(self) -> int:
        return self._acknowledged

    def pending(self) -> bytes:
        """Get current packet; caller must send over authenticated BLE channel."""
        if self._closed:
            raise TransferError("sender closed")
        return self._frames[self._position]

    def acknowledge(self, ack: bytes) -> None:
        """Accept ACK only for current frame; reject spoofable malformed controls."""
        if self._closed:
            raise TransferError("sender closed")
        expected = ack_for_frame(self._frames[self._position])
        if not isinstance(ack, bytes) or ack != expected:
            self.cancel()
            raise TransferError("unexpected acknowledgement")
        self._position += 1
        self._acknowledged += 1
        self._retries = 0
        if self._position == len(self._frames):
            self._chunk_index += 1
            if self._chunk_index == len(self._parts):
                self._completed = True
                self.cancel()
            else:
                self._frames = encode_chunk(
                    self._chunk_index, self._parts[self._chunk_index],
                    self._value_limit,
                )
                self._position = 0

    def on_timeout(self) -> bytes:
        """Return exact same packet to retransmit, or abort after retry budget."""
        if self._closed:
            raise TransferError("sender closed")
        if self._retries >= self._max_retries:
            self.cancel()
            raise TransferError("retry budget exhausted")
        self._retries += 1
        return self.pending()

    def cancel(self) -> None:
        """Discard queued frames; no resume or automatic new session."""
        self._frames = ()
        self._parts = ()
        self._closed = True


class AckingBleReceiver:
    """Bridge wrapper allowing one identical immediate retransmission.

    ACK messages are not authenticated. A native implementation must deliver
    both packet and ACK on the same authenticated encrypted peer session.
    """

    def __init__(self, bridge: BleTransferBridge) -> None:
        if not isinstance(bridge, BleTransferBridge):
            raise TransferError("BLE transfer bridge required")
        self._bridge = bridge
        self._last: bytes | None = None
        self._closed = False

    def receive(self, frame: bytes) -> bytes:
        """ACK a new frame after ingest or re-ACK exact last packet only."""
        if self._closed:
            raise TransferError("receiver closed")
        if self._last is not None and frame == self._last:
            return ack_for_frame(frame)
        try:
            self._bridge.push(frame)
            ack = ack_for_frame(frame)
        except (TransferError, TypeError, ValueError):
            self.abort()
            raise
        self._last = frame
        return ack

    def finish(self) -> bytes:
        """Validate entire export, then disallow any further ACKs."""
        if self._closed:
            raise TransferError("receiver closed")
        try:
            return self._bridge.finish()
        finally:
            self._closed = True
            self._last = None

    def abort(self) -> None:
        """Cancel the complete downstream transfer."""
        self._bridge.abort()
        self._last = None
        self._closed = True
