"""Fail-closed versioned incident policy gate with external monotonic pin.

Both policy snapshots and monotonic pin MUST originate from independently
protected native services. No such service is supplied here. Checking an
untrusted JSON file, SQLite database or in-memory fake does NOT provide
anti-rollback security. This gate never signs, repairs or authorizes execution.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import threading
from typing import Protocol

from incident_reviewer_registry import (
    IncidentKeyPolicy, IncidentReviewerRegistry,
)
from protocol import TransferError

DOMAIN = b"PALACO:BT:INCIDENT-POLICY:V1\0"


@dataclass(frozen=True)
class PolicyPin:
    """Native protected monotonically advanced revision and canonical digest."""

    revision: int
    digest: str

    def __post_init__(self):
        if (type(self.revision) is not int or not 1 <= self.revision < 2**63 or
                type(self.digest) is not str or len(self.digest) != 64 or
                any(c not in "0123456789abcdef" for c in self.digest)):
            raise TransferError("invalid protected incident policy pin")


@dataclass(frozen=True)
class PolicySnapshot:
    """Explicit revision plus immutable-copy-compatible key entries."""

    revision: int
    keys: Mapping[str, IncidentKeyPolicy]

    def __post_init__(self):
        if (type(self.revision) is not int or not 1 <= self.revision < 2**63 or
                not isinstance(self.keys, Mapping) or
                not 1 <= len(self.keys) <= 1024):
            raise TransferError("invalid incident policy snapshot")
        # Keys and entries are validated by IncidentReviewerRegistry.


def policy_digest(snapshot: PolicySnapshot) -> str:
    """Canonical digest of exact key policy; a digest is NOT a signature."""
    if type(snapshot) is not PolicySnapshot:
        raise TransferError("versioned incident policy required")
    # Validate keys and entry shapes before canonical serialization.
    checked = IncidentReviewerRegistry(snapshot.keys, lambda: 0)
    del checked
    rows = [{
        "key_id": key_id, "public_key": entry.public_key.hex(),
        "role": entry.role, "revoked": entry.revoked,
        "valid_from": entry.valid_from, "valid_until": entry.valid_until,
    } for key_id, entry in sorted(snapshot.keys.items())]
    payload = json.dumps(
        {"revision": snapshot.revision, "keys": rows},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(DOMAIN + payload).hexdigest()


class ProtectedPolicySource(Protocol):
    """External authenticated policy distribution; NOT implemented."""

    def read(self) -> PolicySnapshot: ...


class ProtectedPolicyPin(Protocol):
    """Independent monotonic protected policy pin; NOT implemented."""

    def read(self) -> PolicyPin: ...


class VersionedIncidentReviewerGate:
    """Recheck both stores before EVERY evidence-verification decision.

    Fail-closed after any outage/mismatch/revision change, even if sources
    later look healthy. Reopen against the new pinned version explicitly.
    A native atomic policy update and trusted rollout remain external.
    """

    def __init__(self, source: ProtectedPolicySource,
                 monotonic_pin: ProtectedPolicyPin, trusted_clock):
        if (not callable(getattr(source, "read", None)) or
                not callable(getattr(monotonic_pin, "read", None)) or
                not callable(trusted_clock)):
            raise TransferError("protected policy source, pin and clock required")
        self._source = source
        self._pin = monotonic_pin
        self._clock = trusted_clock
        self._held = False
        self._lock = threading.RLock()
        self._registry = None
        self._revision = None
        self._verified_snapshot()

    @property
    def is_held(self) -> bool:
        with self._lock:
            return self._held

    def _verified_snapshot(self):
        with self._lock:
            if self._held:
                raise TransferError("incident policy gate locally held")
            try:
                pin_before = self._pin.read()
                snapshot = self._source.read()
                pin_after = self._pin.read()
                if (type(pin_before) is not PolicyPin or
                        type(pin_after) is not PolicyPin or
                        type(snapshot) is not PolicySnapshot or
                        pin_before != pin_after or
                        pin_after.revision != snapshot.revision or
                        not hmac.compare_digest(pin_after.digest,
                                                policy_digest(snapshot)) or
                        (self._revision is not None and
                         self._revision != snapshot.revision)):
                    raise TransferError("protected policy changed or mismatched")
                # A different policy at the same revision is also detected:
                # live reads always compare the pinned canonical digest.
                registry = IncidentReviewerRegistry(snapshot.keys, self._clock)
                self._registry = registry
                self._revision = snapshot.revision
                return registry
            except Exception as exc:
                self._held = True
                raise TransferError("incident policy rollback or outage: HOLD") from exc

    def verify_observation(self, signed, reviewer_nonce: bytes) -> bool:
        with self._lock:
            try:
                return self._verified_snapshot().verify_observation(
                    signed, reviewer_nonce,
                )
            except TransferError:
                return False

    def reviewer_can_inspect(self, reviewer_key_id: str) -> bool:
        with self._lock:
            try:
                return self._verified_snapshot().reviewer_can_inspect(
                    reviewer_key_id,
                )
            except TransferError:
                return False
