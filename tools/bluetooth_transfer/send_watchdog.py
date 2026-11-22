"""Caller-polled monotonic ACK deadlines for a stop-and-wait BLE sender.

No radio, timer scheduler, authenticated ACK or encryption is implemented.
The native adapter must call poll() even when the peer remains silent.
"""
from __future__ import annotations

import math
from collections.abc import Callable

from ble_sender import StopAndWaitSender
from protocol import TransferError


class SendWatchdog:
    """Bounded monotonic sender with at most one outstanding frame."""

    def __init__(
        self, sender: StopAndWaitSender, clock: Callable[[], float], *,
        ack_seconds: int = 5, total_seconds: int = 600,
    ) -> None:
        if not isinstance(sender, StopAndWaitSender) or sender.closed:
            raise TransferError("open stop-and-wait sender required")
        if not callable(clock):
            raise TransferError("monotonic clock required")
        if type(ack_seconds) is not int or not 1 <= ack_seconds <= 60:
            raise TransferError("invalid ACK deadline")
        if type(total_seconds) is not int or not 1 <= total_seconds <= 3600:
            raise TransferError("invalid total deadline")
        if ack_seconds > total_seconds:
            raise TransferError("ACK deadline exceeds total deadline")
        self._sender = sender
        self._clock = clock
        self._ack_seconds = ack_seconds
        self._total_seconds = total_seconds
        self._started: float | None = None
        self._last_sent: float | None = None
        self._last_read: float | None = None

    def _now(self) -> float:
        try:
            now = self._clock()
        except Exception as exc:
            self._sender.cancel()
            raise TransferError("monotonic clock unavailable") from exc
        if type(now) not in (float, int) or not math.isfinite(now):
            self._sender.cancel()
            raise TransferError("invalid clock reading")
        now = float(now)
        if self._last_read is not None and now < self._last_read:
            self._sender.cancel()
            raise TransferError("monotonic clock regressed")
        self._last_read = now
        return now

    def _check(self) -> float:
        if self._started is None or self._last_sent is None:
            raise TransferError("send watchdog not started")
        if self._sender.closed:
            raise TransferError("sender closed")
        now = self._now()
        if now - self._started >= self._total_seconds:
            self._sender.cancel()
            raise TransferError("send session deadline exceeded")
        return now

    def start(self) -> bytes:
        """Return first frame to write via a separately authenticated adapter."""
        if self._started is not None or self._sender.closed:
            raise TransferError("send watchdog cannot restart")
        now = self._now()
        self._started = now
        self._last_sent = now
        return self._sender.pending()

    def acknowledge(self, ack: bytes) -> bytes | None:
        """On valid ACK, return next frame for immediate write, or None if done."""
        now = self._check()
        if now - self._last_sent >= self._ack_seconds:
            self._sender.cancel()
            raise TransferError("ACK arrived after deadline")
        self._sender.acknowledge(ack)
        if self._sender.done:
            return None
        self._last_sent = now
        return self._sender.pending()

    def poll(self) -> bytes | None:
        """Return overdue frame for retransmission; None if still waiting."""
        now = self._check()
        if now - self._last_sent < self._ack_seconds:
            return None
        frame = self._sender.on_timeout()
        self._last_sent = now
        return frame

    def disconnect(self) -> None:
        self._sender.cancel()

    def abort(self) -> None:
        self._sender.cancel()

    @property
    def done(self) -> bool:
        return self._sender.done

    @property
    def closed(self) -> bool:
        return self._sender.closed
