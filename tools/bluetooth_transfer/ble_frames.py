"""Small BLE-GATT-value framing layer; NO radio, pairing or encryption here.

The caller MUST supply a negotiated maximum GATT application-value length.
A frame is: b'P' + protocol version(1 byte) + chunk index(u16 big endian)
+ segment index(u16 big endian) + final flag(1 byte) + payload.
A frame is deliberately unauthenticated; use only within an authenticated,
encrypted transport. The receiver always validates whole-export SHA-256
separately via TransferSession.finish().
"""
from __future__ import annotations

from protocol import CHUNK_BYTES, TransferError
from session import TransferSession

HEADER_SIZE = 7
MIN_VALUE_BYTES = HEADER_SIZE + 1
MAX_VALUE_BYTES = 512
MAGIC = 0x50
VERSION = 1


def _check_value_limit(value_limit: int) -> None:
    if type(value_limit) is not int or not MIN_VALUE_BYTES <= value_limit <= MAX_VALUE_BYTES:
        raise TransferError("unsupported negotiated GATT value length")


def encode_chunk(chunk_index: int, chunk: bytes, value_limit: int) -> tuple[bytes, ...]:
    """Produce monotonically numbered frames for exactly one transfer chunk."""
    _check_value_limit(value_limit)
    if type(chunk_index) is not int or not 0 <= chunk_index <= 65535:
        raise TransferError("invalid chunk index")
    if not isinstance(chunk, bytes) or not 1 <= len(chunk) <= CHUNK_BYTES:
        raise TransferError("invalid chunk payload")
    segment_size = value_limit - HEADER_SIZE
    packets = []
    for position, start in enumerate(range(0, len(chunk), segment_size)):
        end = min(start + segment_size, len(chunk))
        header = bytes((MAGIC, VERSION)) + chunk_index.to_bytes(2, "big")
        header += position.to_bytes(2, "big") + bytes((int(end == len(chunk)),))
        packets.append(header + chunk[start:end])
    return tuple(packets)


class BleChunkReassembler:
    """Strictly ordered single-chunk reassembler, bounded by expected length."""

    def __init__(self, chunk_index: int, expected_bytes: int, value_limit: int) -> None:
        _check_value_limit(value_limit)
        if type(chunk_index) is not int or not 0 <= chunk_index <= 65535:
            raise TransferError("invalid chunk index")
        if type(expected_bytes) is not int or not 1 <= expected_bytes <= CHUNK_BYTES:
            raise TransferError("invalid expected chunk length")
        self._chunk_index = chunk_index
        self._expected = expected_bytes
        self._limit = value_limit
        self._next_segment = 0
        self._buffer = bytearray()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def abort(self) -> None:
        """Discard buffered bytes and render this assembler unusable."""
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._buffer.clear()
        self._closed = True

    def push(self, packet: bytes) -> bytes | None:
        """Return full chunk only after a correctly placed terminal segment."""
        if self._closed:
            raise TransferError("assembler closed")
        if not isinstance(packet, bytes) or not HEADER_SIZE < len(packet) <= self._limit:
            self.abort()
            raise TransferError("invalid GATT frame size")
        if packet[0] != MAGIC or packet[1] != VERSION:
            self.abort()
            raise TransferError("unsupported frame protocol")
        chunk_index = int.from_bytes(packet[2:4], "big")
        segment_index = int.from_bytes(packet[4:6], "big")
        final = packet[6]
        if (chunk_index != self._chunk_index or
                segment_index != self._next_segment or final not in (0, 1)):
            self.abort()
            raise TransferError("unexpected frame index or flag")
        payload = packet[HEADER_SIZE:]
        new_length = len(self._buffer) + len(payload)
        if new_length > self._expected:
            self.abort()
            raise TransferError("chunk exceeds offered length")
        if final != int(new_length == self._expected):
            self.abort()
            raise TransferError("incorrect final-frame marker")
        if not final and len(payload) != self._limit - HEADER_SIZE:
            self.abort()
            raise TransferError("short nonterminal segment")
        self._buffer.extend(payload)
        self._next_segment += 1
        if final:
            result = bytes(self._buffer)
            self.abort()
            return result
        return None


class BleTransferBridge:
    """Sequential GATT-value ingress into an already approved transfer session."""

    def __init__(self, session: TransferSession, payload_size: int,
                 value_limit: int) -> None:
        if not isinstance(session, TransferSession) or session.closed:
            raise TransferError("active session required")
        _check_value_limit(value_limit)
        if type(payload_size) is not int or payload_size != session.offered_bytes:
            raise TransferError("GATT size is not bound to authenticated offer")
        self._session = session
        self._total = payload_size
        self._limit = value_limit
        self._current: BleChunkReassembler | None = None

    def push(self, packet: bytes) -> None:
        """Feed one frame; any invalid input cancels the entire transfer."""
        if self._session.closed:
            raise TransferError("transfer closed")
        try:
            if self._current is None:
                index = self._session.next_index
                remaining = self._total - self._session.received_bytes
                if remaining <= 0:
                    raise TransferError("unexpected frame after final chunk")
                self._current = BleChunkReassembler(
                    index, min(CHUNK_BYTES, remaining), self._limit,
                )
            data = self._current.push(packet)
            if data is not None:
                self._session.push(self._session.next_index, data)
                self._current = None
        except (TransferError, TypeError, ValueError):
            self.abort()
            raise

    def finish(self) -> bytes:
        """Complete only after no chunk is partially buffered."""
        if self._current is not None:
            self.abort()
            raise TransferError("incomplete last GATT chunk")
        try:
            return self._session.finish()
        except TransferError:
            self.abort()
            raise

    def abort(self) -> None:
        if self._current is not None:
            self._current.abort()
        self._current = None
        self._session.abort()
