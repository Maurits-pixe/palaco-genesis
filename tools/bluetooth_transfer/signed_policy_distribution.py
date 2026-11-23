"""Signed transport boundary for versioned incident-policy snapshots.

The policy distribution signing key MUST be installed from a separate
privileged trust root. Neither this adapter nor its tests provide trusted key
enrollment, native hardware custody, secure revocation delivery or an
independent monotonic pin. Verification is read-only and HOLD-only.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from protocol import TransferError
from signed_fencing_incident import _validate_id
from versioned_incident_policy import PolicySnapshot, policy_digest

POLICY_SIGNATURE_DOMAIN = b"PALACO:BT:SIGNED-INCIDENT-POLICY:V1\0"


@dataclass(frozen=True)
class SignedPolicyEnvelope:
    policy: PolicySnapshot
    issuer_key_id: str
    signature: bytes

    def __post_init__(self):
        if (type(self.policy) is not PolicySnapshot or
                not _validate_id(self.issuer_key_id) or
                type(self.signature) is not bytes or len(self.signature) != 64):
            raise TransferError("invalid signed incident policy envelope")


def policy_signature_message(policy: PolicySnapshot, issuer_key_id: str) -> bytes:
    """Sign exact canonical policy digest, revision and issuer identity."""
    if type(policy) is not PolicySnapshot or not _validate_id(issuer_key_id):
        raise TransferError("invalid incident policy signature input")
    digest = bytes.fromhex(policy_digest(policy))
    key_id = issuer_key_id.encode("ascii")
    return (POLICY_SIGNATURE_DOMAIN + len(key_id).to_bytes(2, "big") +
            key_id + policy.revision.to_bytes(8, "big") + digest)


class SignedPolicyTransport(Protocol):
    """Untrusted transport; its envelope is never an authority by itself."""

    def read(self) -> SignedPolicyEnvelope: ...


class VerifiedSignedPolicySource:
    """Verify publisher signature on EVERY read before returning policy.

    Publisher keys are supplied independently and snapshotted at creation.
    The caller MUST ALSO use VersionedIncidentReviewerGate with a separate
    protected monotonic PolicyPin, because signatures alone allow replay of
    previously legitimate, now-revoked policy snapshots.
    """

    def __init__(self, transport: SignedPolicyTransport,
                 pinned_issuer_keys: Mapping[str, bytes]):
        if (not callable(getattr(transport, "read", None)) or
                not isinstance(pinned_issuer_keys, Mapping) or
                not 1 <= len(pinned_issuer_keys) <= 64):
            raise TransferError("signed policy transport and independent pinset required")
        keys = {}
        for issuer_id, public_key in pinned_issuer_keys.items():
            if (not _validate_id(issuer_id) or type(public_key) is not bytes or
                    len(public_key) != 32):
                raise TransferError("invalid protected policy publisher key")
            keys[issuer_id] = public_key
        self._transport = transport
        self._keys = MappingProxyType(keys)

    def read(self) -> PolicySnapshot:
        try:
            envelope = self._transport.read()
            if type(envelope) is not SignedPolicyEnvelope:
                raise TransferError("invalid signed policy transport response")
            key = self._keys.get(envelope.issuer_key_id)
            if key is None:
                raise TransferError("untrusted policy publisher")
            message = policy_signature_message(
                envelope.policy, envelope.issuer_key_id,
            )
            Ed25519PublicKey.from_public_bytes(key).verify(
                envelope.signature, message,
            )
            # Freeze the entries after signature verification; a mutable
            # transport object must not modify the policy after read.
            return PolicySnapshot(
                envelope.policy.revision,
                MappingProxyType(dict(envelope.policy.keys)),
            )
        except (InvalidSignature, ValueError, TypeError, TransferError) as exc:
            raise TransferError("policy publisher signature invalid: HOLD") from exc
        except Exception as exc:
            raise TransferError("signed policy transport unavailable: HOLD") from exc
