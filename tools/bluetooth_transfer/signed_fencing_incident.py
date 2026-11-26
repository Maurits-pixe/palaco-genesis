"""Reviewer-challenged Ed25519 verification of HOLD-only fencing incident evidence.

The signer key is selected from an INDEPENDENTLY PINNED trusted registry.
The reviewer supplies an unpredictable 32-byte nonce and verifies exact
nonce equality to prevent replay across reviewer requests. No signing private
keys or automatic key enrollment live here. Signer possession is NOT proof of
hardware identity, witness independence, secure time or truthful observations.
Every valid document remains decision HOLD and authorization DENY.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fencing_incident_evidence import (
    FencingIncidentEvidence, verify_fencing_incident_evidence,
)
from protocol import TransferError

SIGNED_DOMAIN = b"PALACO:BT:SIGNED-FENCING-INCIDENT:V1\0"
MAX_REPORT_BYTES = 8192
MAX_SIGNER_ID = 128


@dataclass(frozen=True)
class SignedFencingIncidentEvidence:
    """Immutable detached signature; never claims recovery authorization."""

    evidence: FencingIncidentEvidence
    signer_id: str
    reviewer_nonce: bytes
    signature: bytes


def _validate_id(signer_id: str) -> bool:
    return (
        type(signer_id) is str and 1 <= len(signer_id) <= MAX_SIGNER_ID and
        all(c.isascii() and (c.isalnum() or c in "_.-") for c in signer_id)
    )


def signing_message(evidence: FencingIncidentEvidence, signer_id: str,
                    reviewer_nonce: bytes) -> bytes:
    """Unambiguous bytes to be signed by an external trustworthy issuer."""
    if (not verify_fencing_incident_evidence(evidence) or
            not _validate_id(signer_id) or
            type(reviewer_nonce) is not bytes or len(reviewer_nonce) != 32):
        raise TransferError("invalid signed incident evidence binding")
    payload = evidence.canonical_json.encode("ascii")
    if len(payload) > MAX_REPORT_BYTES:
        raise TransferError("incident evidence exceeds signed size limit")
    key = signer_id.encode("ascii")
    return (
        SIGNED_DOMAIN + len(key).to_bytes(2, "big") + key +
        reviewer_nonce + len(payload).to_bytes(4, "big") + payload
    )


def attach_incident_signature(evidence: FencingIncidentEvidence, signer_id: str,
                              reviewer_nonce: bytes,
                              signature: bytes) -> SignedFencingIncidentEvidence:
    """Attach a native-produced signature; never derive or enroll signing keys."""
    signing_message(evidence, signer_id, reviewer_nonce)
    if type(signature) is not bytes or len(signature) != 64:
        raise TransferError("invalid detached incident signature")
    return SignedFencingIncidentEvidence(
        evidence, signer_id, reviewer_nonce, signature,
    )


def verify_signed_fencing_incident(
    signed: SignedFencingIncidentEvidence,
    trusted_signer_keys: dict[str, bytes],
    expected_nonce: bytes,
) -> bool:
    """Verify signature with independently provisioned pinned signer key.

    A caller-provided untrusted registry is NOT a trust root. This verifies
    a signature, not accuracy of incident readings; ALL cases remain HOLD.
    """
    if (type(signed) is not SignedFencingIncidentEvidence or
            type(trusted_signer_keys) is not dict or
            type(expected_nonce) is not bytes or len(expected_nonce) != 32 or
            type(signed.reviewer_nonce) is not bytes or
            not hmac.compare_digest(signed.reviewer_nonce, expected_nonce) or
            not _validate_id(signed.signer_id) or
            type(signed.signature) is not bytes or len(signed.signature) != 64):
        return False
    key = trusted_signer_keys.get(signed.signer_id)
    if type(key) is not bytes or len(key) != 32:
        return False
    try:
        message = signing_message(signed.evidence, signed.signer_id,
                                  signed.reviewer_nonce)
        Ed25519PublicKey.from_public_bytes(key).verify(signed.signature, message)
        return True
    except (InvalidSignature, TransferError, ValueError, TypeError):
        return False
