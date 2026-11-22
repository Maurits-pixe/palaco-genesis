"""Fresh Ed25519-attested native checkpoint snapshots (optional boundary).

An independently pinned signer key is REQUIRED. The native service must sign
each freshly challenged platform identity AND checkpoint state, not its own
untrusted self-declared key. Signatures establish key possession and message
integrity, NOT hardware-backed keys, TPM attestation, CAS atomicity, protected
clock, or anti-rollback. The native service must provide those separately.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from native_checkpoint_scope import NativeCheckpoint, ScopeBoundChallengeAnchor
from platform_checkpoint_bridge import NativeStorageIdentity, NativePlatform
from protocol import TransferError

DOMAIN = b"PALACO:BT:NATIVE-CHECKPOINT-ATTESTATION:V1\0"


@dataclass(frozen=True)
class SignedCheckpointSnapshot:
    """Native response to a caller-created challenge."""

    identity: NativeStorageIdentity
    checkpoint: NativeCheckpoint
    challenge: bytes
    signature: bytes


class AttestingNativeService(Protocol):
    """Native service; private signing key custody and CAS are out of scope."""

    def attest(self, challenge: bytes) -> SignedCheckpointSnapshot: ...

    def advance(
        self, namespace: bytes, previous: NativeCheckpoint,
        current: NativeCheckpoint,
    ) -> None: ...


def signed_snapshot_message(
    identity: NativeStorageIdentity, checkpoint: NativeCheckpoint,
    challenge: bytes,
) -> bytes:
    """Unique binary encoding for platform, scope, generation and checkpoint."""
    if (type(identity) is not NativeStorageIdentity or
            type(checkpoint) is not NativeCheckpoint or
            type(challenge) is not bytes or len(challenge) != 32 or
            not hmac.compare_digest(identity.namespace, checkpoint.namespace)):
        raise TransferError("invalid attested native snapshot")
    platform = (
        b"\x01" if identity.platform is NativePlatform.WINDOWS_TPM
        else b"\x02" if identity.platform is NativePlatform.ANDROID_KEYMINT
        else None
    )
    if platform is None:
        raise TransferError("unknown native platform")
    return (
        DOMAIN + platform + identity.namespace + identity.device_binding +
        identity.generation.to_bytes(8, "big") +
        checkpoint.count.to_bytes(8, "big") +
        bytes.fromhex(checkpoint.root) + challenge
    )


class AttestedCheckpointBackend:
    """Verify a new signer-attested identity+checkpoint for every native read."""

    def __init__(
        self, service: AttestingNativeService,
        protected_identity: NativeStorageIdentity,
        pinned_signer_public_key: bytes,
    ):
        if (type(protected_identity) is not NativeStorageIdentity or
                type(pinned_signer_public_key) is not bytes or
                len(pinned_signer_public_key) != 32 or
                not callable(getattr(service, "attest", None)) or
                not callable(getattr(service, "advance", None))):
            raise TransferError("trusted native identity, pinned key and service required")
        self._service = service
        self._identity = protected_identity
        self._public_key = pinned_signer_public_key
        self.read()

    def _verify_snapshot(self) -> NativeCheckpoint:
        challenge = secrets.token_bytes(32)
        try:
            response = self._service.attest(challenge)
        except Exception as exc:
            raise TransferError("native attestation unavailable: HOLD") from exc
        if (type(response) is not SignedCheckpointSnapshot or
                type(response.identity) is not NativeStorageIdentity or
                type(response.checkpoint) is not NativeCheckpoint or
                type(response.challenge) is not bytes or
                not hmac.compare_digest(response.challenge, challenge) or
                type(response.signature) is not bytes or
                len(response.signature) != 64):
            raise TransferError("invalid or replayed native attestation: HOLD")
        identity = response.identity
        expected = self._identity
        if (identity.platform is not expected.platform or
                identity.generation != expected.generation or
                not hmac.compare_digest(identity.namespace, expected.namespace) or
                not hmac.compare_digest(identity.device_binding, expected.device_binding)):
            raise TransferError("native attested storage identity mismatch: HOLD")
        try:
            message = signed_snapshot_message(
                identity, response.checkpoint, challenge,
            )
            Ed25519PublicKey.from_public_bytes(self._public_key).verify(
                response.signature, message,
            )
        except (InvalidSignature, TypeError, ValueError, TransferError) as exc:
            raise TransferError("native attestation signature invalid: HOLD") from exc
        return response.checkpoint

    def read(self) -> NativeCheckpoint:
        return self._verify_snapshot()

    def advance(
        self, namespace: bytes, previous: NativeCheckpoint,
        current: NativeCheckpoint,
    ) -> None:
        if (type(namespace) is not bytes or
                not hmac.compare_digest(namespace, self._identity.namespace) or
                type(previous) is not NativeCheckpoint or
                type(current) is not NativeCheckpoint or
                not hmac.compare_digest(previous.namespace, namespace) or
                not hmac.compare_digest(current.namespace, namespace)):
            raise TransferError("invalid native attested CAS binding: HOLD")
        seen = self._verify_snapshot()
        if seen != previous:
            raise TransferError("attested checkpoint CAS precondition changed: HOLD")
        try:
            self._service.advance(namespace, previous, current)
        except Exception as exc:
            raise TransferError("attested checkpoint write uncertain: HOLD") from exc
        if self._verify_snapshot() != current:
            raise TransferError("attested checkpoint write not confirmed: HOLD")


def bind_attested_native_checkpoint(
    service: AttestingNativeService,
    protected_identity: NativeStorageIdentity,
    pinned_signer_public_key: bytes,
) -> ScopeBoundChallengeAnchor:
    """Explicitly use signed native snapshots; never fall back to unsigned."""
    return ScopeBoundChallengeAnchor(
        AttestedCheckpointBackend(
            service, protected_identity, pinned_signer_public_key,
        ),
        protected_identity.namespace,
    )
