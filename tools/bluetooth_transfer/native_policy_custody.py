"""Freshly challenged native policy-custody boundary for Windows and Android.

The native implementation MUST supply hardware-backed key custody, trust
provisioning, protected monotonic policy and issuer pins and rollback resistance.
None are implemented by this Python module. A signed response establishes
possession of a PRE-PINNED key, NOT proof of TPM/KeyMint hardware or a secure
monotonic counter. This module never grants import, unlock or release.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import secrets
import threading
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from versioned_incident_policy import PolicyPin

DOMAIN = b"PALACO:BT:NATIVE-POLICY-CUSTODY:V1\0"


@dataclass(frozen=True)
class NativePolicyCustodyEvidence:
    identity: NativeStorageIdentity
    policy_pin: PolicyPin
    issuer_pin: PolicyPin
    challenge: bytes
    signature: bytes


def custody_message(identity: NativeStorageIdentity, policy_pin: PolicyPin,
                    issuer_pin: PolicyPin, challenge: bytes) -> bytes:
    if (type(identity) is not NativeStorageIdentity or
            type(policy_pin) is not PolicyPin or
            type(issuer_pin) is not PolicyPin or
            type(challenge) is not bytes or len(challenge) != 32):
        raise TransferError("invalid native policy custody evidence")
    tag = (b"\x01" if identity.platform is NativePlatform.WINDOWS_TPM else
           b"\x02" if identity.platform is NativePlatform.ANDROID_KEYMINT else
           None)
    if tag is None:
        raise TransferError("unsupported native policy platform")
    return (DOMAIN + tag + identity.namespace + identity.device_binding +
            identity.generation.to_bytes(8, "big") +
            policy_pin.revision.to_bytes(8, "big") +
            bytes.fromhex(policy_pin.digest) +
            issuer_pin.revision.to_bytes(8, "big") +
            bytes.fromhex(issuer_pin.digest) + challenge)


class NativePolicyCustodyService(Protocol):
    """Native privileged bridge: must enforce genuine protected pins itself."""

    def attest(self, challenge: bytes) -> NativePolicyCustodyEvidence: ...


class AttestedNativePolicyPins:
    """Two coherent, challenged policy pins with a sticky local HOLD latch."""

    def __init__(self, native_service: NativePolicyCustodyService,
                 protected_identity: NativeStorageIdentity,
                 pinned_attestation_public_key: bytes):
        if (type(protected_identity) is not NativeStorageIdentity or
                type(pinned_attestation_public_key) is not bytes or
                len(pinned_attestation_public_key) != 32 or
                not callable(getattr(native_service, "attest", None))):
            raise TransferError("explicit privileged native policy custody required")
        self._native = native_service
        self._identity = protected_identity
        self._public_key = pinned_attestation_public_key
        self._held = False
        self._lock = threading.RLock()
        self._baseline = None
        self.read_pair()

    @property
    def is_held(self) -> bool:
        with self._lock:
            return self._held

    def read_pair(self) -> tuple[PolicyPin, PolicyPin]:
        with self._lock:
            if self._held:
                raise TransferError("native policy custody HOLD active")
            try:
                nonce = secrets.token_bytes(32)
                response = self._native.attest(nonce)
                if (type(response) is not NativePolicyCustodyEvidence or
                        type(response.identity) is not NativeStorageIdentity or
                        type(response.policy_pin) is not PolicyPin or
                        type(response.issuer_pin) is not PolicyPin or
                        type(response.challenge) is not bytes or
                        not hmac.compare_digest(response.challenge, nonce) or
                        type(response.signature) is not bytes or
                        len(response.signature) != 64):
                    raise TransferError("native policy custody response malformed")
                actual, expected = response.identity, self._identity
                if (actual.platform is not expected.platform or
                        actual.generation != expected.generation or
                        not hmac.compare_digest(actual.namespace, expected.namespace) or
                        not hmac.compare_digest(actual.device_binding,
                                                expected.device_binding)):
                    raise TransferError("native policy custody identity replaced")
                message = custody_message(
                    actual, response.policy_pin, response.issuer_pin, nonce,
                )
                Ed25519PublicKey.from_public_bytes(self._public_key).verify(
                    response.signature, message,
                )
                pair = (response.policy_pin, response.issuer_pin)
                if self._baseline is None:
                    self._baseline = pair
                elif pair != self._baseline:
                    # No implicit acceptance of rotations in a live session.
                    # Human-reviewed reopening requires new pinned observations.
                    raise TransferError("native policy custody revision changed")
                return pair
            except Exception as exc:
                self._held = True
                raise TransferError("native policy custody unavailable or changed: HOLD") from exc

    def policy_pin(self) -> PolicyPin:
        return self.read_pair()[0]

    def issuer_pin(self) -> PolicyPin:
        return self.read_pair()[1]


class _PinView:
    def __init__(self, custody: AttestedNativePolicyPins, index: int):
        self._custody = custody
        self._index = index

    def read(self) -> PolicyPin:
        return self._custody.read_pair()[self._index]


def bind_native_policy_pin_views(
    native_service: NativePolicyCustodyService,
    protected_identity: NativeStorageIdentity,
    pinned_attestation_public_key: bytes,
):
    """Return a pair of read-only pin providers for existing policy gates."""
    custody = AttestedNativePolicyPins(
        native_service, protected_identity, pinned_attestation_public_key,
    )
    return custody, _PinView(custody, 0), _PinView(custody, 1)
