"""Conservative native-adapter admission boundary for PALACO Bluetooth.

This does NOT verify signatures, perform pairing, or encrypt data. All evidence
must be supplied by a separately trusted platform/cryptographic verifier.
Never derive verified flags from user input or radio-visible device names.
"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass

from protocol import Offer, TransferError, _validate_offer, offer_json
from session import TransferSession
from protocol import Receiver

_HEX = re.compile(r"^[0-9a-f]{64}$")
_CONTEXT_DOMAIN = b"PALACO:BT:SESSION:CONTEXT:V1\0"


@dataclass(frozen=True)
class VerifiedTransportEvidence:
    """Attestations asserted by a separate, trusted native verifier.

    This dataclass is NOT proof that those attestations are genuine.
    A production adapter must protect its construction from untrusted callers.
    """

    peer_identity_verified: bool
    local_identity_verified: bool
    authenticated_key_agreement: bool
    encrypted_channel_verified: bool
    offer_authenticated: bool
    consent_for_exact_offer: bool
    revocation_current: bool
    trusted_time_current: bool
    peer_key_fingerprint: str
    bound_offer_digest: str


def offer_binding_digest(offer: Offer) -> str:
    """Digest for an offer to be authenticated by a separate crypto verifier."""
    import hashlib

    _validate_offer(offer)
    return hashlib.sha256(
        _CONTEXT_DOMAIN + offer_json(offer).encode("utf-8")
    ).hexdigest()


def assess_transport(offer: Offer, evidence: VerifiedTransportEvidence) -> None:
    """Deny all missing, malformed, or mismatched transport claims."""
    _validate_offer(offer)
    if type(evidence) is not VerifiedTransportEvidence:
        raise TransferError("trusted verifier evidence required")
    booleans = (
        evidence.peer_identity_verified,
        evidence.local_identity_verified,
        evidence.authenticated_key_agreement,
        evidence.encrypted_channel_verified,
        evidence.offer_authenticated,
        evidence.consent_for_exact_offer,
        evidence.revocation_current,
        evidence.trusted_time_current,
    )
    if any(type(value) is not bool or not value for value in booleans):
        raise TransferError("transport admission gate DENY")
    if (not isinstance(evidence.peer_key_fingerprint, str)
            or not _HEX.fullmatch(evidence.peer_key_fingerprint)):
        raise TransferError("invalid peer key fingerprint")
    if (not isinstance(evidence.bound_offer_digest, str)
            or not _HEX.fullmatch(evidence.bound_offer_digest)
            or not hmac.compare_digest(
                evidence.bound_offer_digest, offer_binding_digest(offer)
            )):
        raise TransferError("offer not bound to verified secure session")


def admit_receive_session(
    offer: Offer, replay_guard: Receiver, evidence: VerifiedTransportEvidence
) -> TransferSession:
    """Gate session construction; returns only untrusted reassembled bytes.

    Even successful admission is NOT permission to import or execute records.
    """
    assess_transport(offer, evidence)
    return TransferSession(
        offer, replay_guard,
        user_approved=True, identity_verified=True,
    )
