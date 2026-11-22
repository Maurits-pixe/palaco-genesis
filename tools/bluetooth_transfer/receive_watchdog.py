"""Caller-driven monotonic watchdog for the PALACO native receive controller.

No background timers or Bluetooth APIs. Native adapter MUST call poll() on a
trusted monotonic timer, including during radio silence. This is a testable
contract, not a proof of encrypted transport or device authentication.
"""
from __future__ import annotations

import math
from collections.abc import Callable

from native_adapter_contract import NativeReceiveController, ReceiveState
from protocol import TransferError


def _limit(value: int, maximum: int, name: str) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TransferError(f"invalid {name}")


class ReceiveWatchdog:
    """One-shot bounded receiver; timeout, invalid clock and errors abort."""

    def __init__(
        self,
        controller: NativeReceiveController,
        clock: Callable[[], float],
        *,
        idle_seconds: int = 15,
        total_seconds: int = 600,
    ) -> None:
        if not isinstance(controller, NativeReceiveController):
            raise TransferError("native receive controller required")
        if not callable(clock):
            raise TransferError("monotonic clock required")
        _limit(idle_seconds, 120, "idle deadline")
        _limit(total_seconds, 3600, "total deadline")
        if idle_seconds > total_seconds:
            raise TransferError("idle deadline exceeds total deadline")
        if controller.state is not ReceiveState.IDLE:
            raise TransferError("fresh controller required")
        self._controller = controller
        self._clock = clock
        self._idle_seconds = idle_seconds
        self._total_seconds = total_seconds
        self._started: float | None = None
        self._last_progress: float | None = None
        self._last_frame: bytes | None = None

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception as exc:
            self._controller.abort()
            raise TransferError("trusted clock unavailable") from exc
        if (type(value) not in (float, int) or
                not math.isfinite(value)):
            self._controller.abort()
            raise TransferError("invalid clock value")
        return float(value)

    def begin(self, offer, evidence, value_limit: int) -> None:
        """Begin only once, after the existing secure-admission policy gate."""
        if self._started is not None:
            raise TransferError("watchdog cannot restart")
        now = self._now()
        self._controller.begin(offer, evidence, value_limit)
        self._started = now
        self._last_progress = now

    def _check(self) -> float:
        if self._controller.state is not ReceiveState.RECEIVING:
            raise TransferError("watchdog receiver not active")
        if self._started is None or self._last_progress is None:
            self._controller.abort()
            raise TransferError("watchdog not started")
        now = self._now()
        if (now < self._last_progress or
                now - self._started >= self._total_seconds or
                now - self._last_progress >= self._idle_seconds):
            self._controller.abort()
            raise TransferError("transfer deadline exceeded or clock regressed")
        return now

    def poll(self) -> None:
        """Native timer calls this even when no GATT notification arrives."""
        self._check()

    def on_notification(self, packet: bytes) -> bytes:
        """Do not extend inactivity deadline for identical duplicate frames."""
        now = self._check()
        try:
            ack = self._controller.on_notification(packet)
        except (TransferError, TypeError, ValueError):
            self._controller.abort()
            raise
        if packet != self._last_frame:
            self._last_progress = now
            self._last_frame = packet
        return ack

    def complete(self) -> bytes:
        """Check deadlines before returning integrity-checked untrusted bytes."""
        self._check()
        return self._controller.complete()

    def abort(self) -> None:
        """Explicit cancellation always wins over a pending completion."""
        self._controller.abort()

    @property
    def state(self) -> ReceiveState:
        return self._controller.state
