"""Privileged policy gate for HOLD-only signed fencing incident observations.

Immutable snapshot of externally provisioned signer/reviewer public key policy.
An incident signer may attest to the bytes of a HOLD report; a reviewer may be
recognized as eligible to INSPECT but gains no authority to repair or unlock.
Key provisioning, secure distribution/revocation, trusted clock, and pinning
remain external native responsibilities. Never enroll keys from signed reports.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from protocol import TransferError
from signed_fencing_incident import (
    SignedFencingIncidentEvidence, _validate_id,
    verify_signed_fencing_incident,
)

INCIDENT_SIGNER_ROLE = "incident_evidence_signer"
INCIDENT_REVIEWER_ROLE = "incident_evidence_reviewer"
MAX_ENTRIES = 1024


@dataclass(frozen=True)
class IncidentKeyPolicy:
    public_key: bytes
    role: str
    revoked: bool
    valid_from: int
    valid_until: int

    def __post_init__(self):
        if (type(self.public_key) is not bytes or len(self.public_key) != 32 or
                type(self.role) is not str or self.role not in (
                    INCIDENT_SIGNER_ROLE, INCIDENT_REVIEWER_ROLE,
                ) or type(self.revoked) is not bool or
                type(self.valid_from) is not int or
                type(self.valid_until) is not int or
                not 0 <= self.valid_from < self.valid_until < 2**63):
            raise TransferError("invalid incident key policy")


class IncidentReviewerRegistry:
    """HOLD-only read/verify facade over an externally trusted policy snapshot."""

    def __init__(self, trusted_keys: Mapping[str, IncidentKeyPolicy],
                 trusted_clock: Callable[[], int]):
        if (not isinstance(trusted_keys, Mapping) or
                not 1 <= len(trusted_keys) <= MAX_ENTRIES or
                not callable(trusted_clock)):
            raise TransferError("protected policy registry and trusted clock required")
        snapshot = {}
        for key_id, entry in trusted_keys.items():
            if not _validate_id(key_id) or type(entry) is not IncidentKeyPolicy:
                raise TransferError("invalid trusted incident registry entry")
            snapshot[key_id] = entry
        # This prevents ordinary caller mutation, not privileged rollback.
        self._keys = MappingProxyType(snapshot)
        self._clock = trusted_clock

    def _eligible(self, key_id: str, role: str) -> IncidentKeyPolicy | None:
        if not _validate_id(key_id):
            return None
        entry = self._keys.get(key_id)
        if entry is None or entry.revoked or entry.role != role:
            return None
        try:
            now = self._clock()
        except Exception:
            return None
        if type(now) is not int or not entry.valid_from <= now < entry.valid_until:
            return None
        return entry

    def verify_observation(self, signed: SignedFencingIncidentEvidence,
                           expected_reviewer_nonce: bytes) -> bool:
        """Check signer policy and detached signature; NEVER an authorization."""
        if type(signed) is not SignedFencingIncidentEvidence:
            return False
        entry = self._eligible(signed.signer_id, INCIDENT_SIGNER_ROLE)
        if entry is None:
            return False
        return verify_signed_fencing_incident(
            signed, {signed.signer_id: entry.public_key}, expected_reviewer_nonce,
        )

    def reviewer_can_inspect(self, reviewer_key_id: str) -> bool:
        """Only inspection eligibility; does not accept a review or unlock HOLD."""
        return self._eligible(reviewer_key_id, INCIDENT_REVIEWER_ROLE) is not None
