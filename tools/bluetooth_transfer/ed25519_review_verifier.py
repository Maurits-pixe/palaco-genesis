"""Ed25519 reviewer verification with explicitly provisioned public keys.

Uses the audited cryptography package, not a custom signature algorithm.
Trusted key enrollment, secure role assignment, revocation distribution and
clock attestation are OFFLINE NATIVE RESPONSIBILITIES, not implemented here.
Keys/role entries passed to this constructor must come from a privileged,
integrity-protected source. A user-provided registry is NOT trust.

A valid signature admits HOLD_REVIEWABLE only via signed_review_gate;
it does not grant import, recovery, merge or release authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from protocol import TransferError

REVIEW_ROLE = "recovery_reviewer"
MAX_KEY_ID = 128


@dataclass(frozen=True)
class ReviewerPublicKey:
    """Privileged immutable reviewer entry, not derived from a BLE peer."""

    public_key_raw: bytes
    role: str
    revoked: bool
    valid_from: int
    valid_until: int

    def __post_init__(self) -> None:
        if (type(self.public_key_raw) is not bytes or
                len(self.public_key_raw) != 32 or
                type(self.role) is not str or
                type(self.revoked) is not bool or
                type(self.valid_from) is not int or
                type(self.valid_until) is not int or
                not 0 <= self.valid_from < self.valid_until < 2**63):
            raise TransferError("invalid reviewer public-key policy")


class Ed25519ReviewVerifier:
    """Fail-closed key-allowlist verifier with exact role and validity window."""

    def __init__(
        self,
        trusted_keys: Mapping[str, ReviewerPublicKey],
        trusted_clock: Callable[[], int],
    ) -> None:
        if not isinstance(trusted_keys, Mapping) or not callable(trusted_clock):
            raise TransferError("trusted keys and trusted UTC clock required")
        if not trusted_keys or len(trusted_keys) > 1024:
            raise TransferError("invalid trusted reviewer registry size")
        snapshot = {}
        for key_id, entry in trusted_keys.items():
            if (type(key_id) is not str or not 1 <= len(key_id) <= MAX_KEY_ID or
                    not all(c.isascii() and (c.isalnum() or c in "-_.") for c in key_id)
                    or type(entry) is not ReviewerPublicKey):
                raise TransferError("invalid trusted reviewer entry")
            snapshot[key_id] = entry
        self._keys = MappingProxyType(snapshot)
        self._clock = trusted_clock

    def verify(self, reviewer_key_id: str, message: bytes, signature: bytes) -> bool:
        """Validate actual Ed25519 signature and privileged reviewer policy."""
        if (type(reviewer_key_id) is not str or
                type(message) is not bytes or
                not 1 <= len(message) <= 4096 or
                type(signature) is not bytes or len(signature) != 64):
            return False
        entry = self._keys.get(reviewer_key_id)
        if entry is None or entry.revoked or entry.role != REVIEW_ROLE:
            return False
        try:
            now = self._clock()
        except Exception:
            return False
        if type(now) is not int or not entry.valid_from <= now < entry.valid_until:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(entry.public_key_raw).verify(
                signature, message,
            )
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True
