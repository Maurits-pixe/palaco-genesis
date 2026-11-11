"""Disposable WNRA-04O pin-custody state model; not a trusted custodian.

No real identity, signature, durable external anchor, clock, or authorization.
A fixture writer must not treat this in-process simulation as independent proof.
"""
from dataclasses import dataclass
import re


SCHEMA = "WNRA-04N-PIN-v0.1"
DOMAIN = "PALACO-WNRA-04L-TEST-SNAPSHOT-v1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")


class CustodyDenied(ValueError):
    """Fail-closed rejection of a test-only custody candidate."""


@dataclass(frozen=True)
class PinRecord:
    fixture_id: str
    snapshot_digest: str
    source_commit: str
    sequence: int
    predecessor_digest: str | None
    evidence_ref: str
    custody_status: str = "REVIEWED"
    schema: str = SCHEMA
    algorithm: str = "sha256"
    snapshot_domain: str = DOMAIN


class DisposableCustody:
    """Append-only *in-memory* model, scoped to one fixture and test domain."""

    def __init__(self, fixture_id: str):
        if not fixture_id or fixture_id.strip() != fixture_id:
            raise CustodyDenied("invalid fixture identity")
        self._fixture_id = fixture_id
        self._history: tuple[PinRecord, ...] = ()

    @property
    def history(self) -> tuple[PinRecord, ...]:
        return self._history

    def accept(self, record: PinRecord, *, simulated_reviewer_acceptance: bool) -> None:
        if not simulated_reviewer_acceptance:
            raise CustodyDenied("missing simulated review acceptance")
        if record.schema != SCHEMA or record.algorithm != "sha256" or record.snapshot_domain != DOMAIN:
            raise CustodyDenied("schema, algorithm or domain mismatch")
        if record.fixture_id != self._fixture_id or record.custody_status != "REVIEWED":
            raise CustodyDenied("fixture identity or custody status mismatch")
        if not _HEX64.fullmatch(record.snapshot_digest) or not _COMMIT.fullmatch(record.source_commit):
            raise CustodyDenied("invalid digest or source commit")
        if not record.evidence_ref or record.evidence_ref.strip() != record.evidence_ref:
            raise CustodyDenied("missing evidence reference")
        prior = self._history[-1] if self._history else None
        expected_sequence = 1 if prior is None else prior.sequence + 1
        expected_predecessor = None if prior is None else prior.snapshot_digest
        if type(record.sequence) is not int or record.sequence != expected_sequence:
            raise CustodyDenied("sequence gap, replay or rollback")
        if record.predecessor_digest != expected_predecessor:
            raise CustodyDenied("predecessor mismatch")
        # The tuple is replaced only after all validation has succeeded.
        self._history = (*self._history, record)

    def compare(self, fixture_id: str, snapshot_digest: str, *, simulated_custodian_available: bool) -> bool:
        if not simulated_custodian_available:
            raise CustodyDenied("custodian unavailable; no trust conclusion")
        if fixture_id != self._fixture_id or not self._history:
            raise CustodyDenied("unknown fixture or absent pin")
        if not _HEX64.fullmatch(snapshot_digest):
            raise CustodyDenied("invalid snapshot digest")
        return self._history[-1].snapshot_digest == snapshot_digest


def authorization_from_test_result(_matches: bool) -> str:
    """A successful fixture comparison never grants PALACO authority."""
    return "DENY"
