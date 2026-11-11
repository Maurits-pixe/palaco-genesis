"""WNRA-04E disposable lease state-machine MODEL, NOT a production issuer.

All times, claims, and CAS revisions come from a test harness. This module
does not authenticate source statements, issue credentials, lock across
processes, persist state, touch files, or grant authority.
"""

from dataclasses import dataclass, replace

ISSUED = "ISSUED"
REDEEMING = "REDEEMING"
CONSUMED = "CONSUMED"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"
DENIED = "DENIED"
_TERMINAL = frozenset((CONSUMED, REVOKED, EXPIRED, DENIED))


class LeaseDenied(ValueError):
    """No capability may be yielded by this simulated transition."""


@dataclass(frozen=True)
class TestLease:
    lease_id: str
    statement_id: str
    consumer_id: str
    not_before: int
    expires_at: int
    state: str = ISSUED
    revision: int = 0
    last_time: int = 0


class TestLeaseLedger:
    """In-memory deterministic CAS MODEL; never suitable as a trust store."""

    def __init__(self):
        self._records = {}

    def issue(self, lease):
        if not isinstance(lease, TestLease):
            raise LeaseDenied("test lease required")
        if (
            not lease.lease_id or not lease.statement_id or not lease.consumer_id
            or type(lease.not_before) is not int
            or type(lease.expires_at) is not int
            or lease.not_before >= lease.expires_at
            or lease.state != ISSUED or lease.revision != 0
            or lease.last_time != 0
            or lease.lease_id in self._records
        ):
            raise LeaseDenied("invalid or duplicate test lease")
        self._records[lease.lease_id] = lease

    def inspect(self, lease_id):
        return self._records.get(lease_id)

    def _advance(self, lease_id, expected_revision, now, allowed, target, consumer_id=None):
        lease = self._records.get(lease_id)
        if lease is None:
            raise LeaseDenied("missing lease")
        if type(expected_revision) is not int or expected_revision != lease.revision:
            raise LeaseDenied("stale revision or concurrent redemption")
        if type(now) is not int or now < lease.last_time:
            raise LeaseDenied("untrusted or backward time")
        if lease.state in _TERMINAL:
            raise LeaseDenied("terminal lease cannot be reused")
        if now >= lease.expires_at:
            self._records[lease_id] = replace(
                lease, state=EXPIRED, revision=lease.revision + 1, last_time=now
            )
            raise LeaseDenied("lease expired")
        if now < lease.not_before:
            raise LeaseDenied("lease not yet valid")
        if lease.state not in allowed:
            raise LeaseDenied("invalid transition or replay")
        if consumer_id is not None and consumer_id != lease.consumer_id:
            raise LeaseDenied("consumer binding mismatch")
        updated = replace(lease, state=target, revision=lease.revision + 1, last_time=now)
        self._records[lease_id] = updated
        return updated

    def redeem(self, lease_id, expected_revision, now, consumer_id):
        """Model an atomic compare-and-set: ISSUED -> REDEEMING."""
        return self._advance(
            lease_id, expected_revision, now, frozenset((ISSUED,)),
            REDEEMING, consumer_id
        )

    def handoff(self, lease_id, expected_revision, now, consumer_id):
        """Model checked handoff: REDEEMING -> CONSUMED, never AUTHORIZED."""
        return self._advance(
            lease_id, expected_revision, now, frozenset((REDEEMING,)),
            CONSUMED, consumer_id
        )

    def revoke(self, lease_id, expected_revision, now):
        lease = self._records.get(lease_id)
        if lease is None or type(expected_revision) is not int or expected_revision != lease.revision:
            raise LeaseDenied("unknown or stale lease")
        if type(now) is not int or now < lease.last_time:
            raise LeaseDenied("untrusted or backward time")
        if lease.state in _TERMINAL:
            raise LeaseDenied("terminal lease")
        updated = replace(lease, state=REVOKED, revision=lease.revision + 1, last_time=now)
        self._records[lease_id] = updated
        return updated

    def interrupt(self, lease_id, expected_revision, now):
        """Fail closed: an interrupted redemption cannot become reusable."""
        return self._advance(
            lease_id, expected_revision, now, frozenset((REDEEMING,)), DENIED
        )
