"""Windows TPM / Android Keystore privileged checkpoint bridge contract.

A platform bridge is injected by native privileged code, never built from a
BLE peer, JSON payload or caller-provided capability flags. It must implement
hardware-bound atomic CAS and rollback-resistant state independently.
Windows DPAPI and ordinary AndroidKeyStore do NOT automatically provide an
anti-rollback monotonic checkpoint. This module is a strict integration gate,
not a TPM or KeyMint driver.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hmac
from typing import Protocol

from native_checkpoint_scope import NativeCheckpoint, ScopeBoundChallengeAnchor
from protocol import TransferError


class NativePlatform(Enum):
    WINDOWS_TPM = "windows_tpm"
    ANDROID_KEYMINT = "android_keymint"


@dataclass(frozen=True)
class NativeStorageIdentity:
    """Independent native-provisioned binding for one protected ledger."""

    platform: NativePlatform
    namespace: bytes
    device_binding: bytes
    generation: int

    def __post_init__(self):
        if (type(self.platform) is not NativePlatform or
                type(self.namespace) is not bytes or len(self.namespace) != 32 or
                type(self.device_binding) is not bytes or len(self.device_binding) != 32 or
                type(self.generation) is not int or
                not 1 <= self.generation < 2**63):
            raise TransferError("invalid native storage identity")


class PrivilegedCheckpointService(Protocol):
    """Privileged implementation backed by real TPM/KeyMint protected state.

    A deployment must separately prove its native device binding, monotonic
    generation, atomic compare-and-advance and anti-rollback properties.
    """

    def identity(self) -> NativeStorageIdentity: ...
    def read(self) -> NativeCheckpoint: ...
    def advance(
        self, namespace: bytes, previous: NativeCheckpoint,
        current: NativeCheckpoint,
    ) -> None: ...


class PlatformCheckpointBackend:
    """Block mismatched native identity around every checkpoint operation."""

    def __init__(
        self, service: PrivilegedCheckpointService,
        expected_identity: NativeStorageIdentity,
    ):
        if type(expected_identity) is not NativeStorageIdentity:
            raise TransferError("explicit protected native identity required")
        if not all(callable(getattr(service, method, None)) for method in (
            "identity", "read", "advance",
        )):
            raise TransferError("privileged native service required")
        self._service = service
        self._expected = expected_identity
        self._assert_identity()

    def _assert_identity(self):
        try:
            actual = self._service.identity()
        except Exception as exc:
            raise TransferError("native storage identity unavailable: HOLD") from exc
        expected = self._expected
        if (type(actual) is not NativeStorageIdentity or
                actual.platform is not expected.platform or
                actual.generation != expected.generation or
                not hmac.compare_digest(actual.namespace, expected.namespace) or
                not hmac.compare_digest(actual.device_binding, expected.device_binding)):
            raise TransferError("native storage identity changed: HOLD")

    def read(self) -> NativeCheckpoint:
        self._assert_identity()
        try:
            state = self._service.read()
        except Exception as exc:
            raise TransferError("native storage checkpoint unavailable: HOLD") from exc
        self._assert_identity()
        if type(state) is not NativeCheckpoint:
            raise TransferError("native checkpoint malformed: HOLD")
        if not hmac.compare_digest(state.namespace, self._expected.namespace):
            raise TransferError("native checkpoint scope mismatch: HOLD")
        return state

    def advance(
        self, namespace: bytes, previous: NativeCheckpoint,
        current: NativeCheckpoint,
    ) -> None:
        if (type(namespace) is not bytes or
                not hmac.compare_digest(namespace, self._expected.namespace) or
                type(previous) is not NativeCheckpoint or
                type(current) is not NativeCheckpoint or
                not hmac.compare_digest(previous.namespace, namespace) or
                not hmac.compare_digest(current.namespace, namespace)):
            raise TransferError("native checkpoint binding invalid: HOLD")
        self._assert_identity()
        try:
            self._service.advance(namespace, previous, current)
        except Exception as exc:
            raise TransferError("privileged native checkpoint write uncertain: HOLD") from exc
        self._assert_identity()


def bind_windows_tpm(
    service: PrivilegedCheckpointService,
    protected_identity: NativeStorageIdentity,
) -> ScopeBoundChallengeAnchor:
    """Use only a trusted Win32 native service with TPM-backed CAS semantics."""
    if type(protected_identity) is not NativeStorageIdentity or (
        protected_identity.platform is not NativePlatform.WINDOWS_TPM
    ):
        raise TransferError("Windows TPM identity required")
    return ScopeBoundChallengeAnchor(
        PlatformCheckpointBackend(service, protected_identity),
        protected_identity.namespace,
    )


def bind_android_keymint(
    service: PrivilegedCheckpointService,
    protected_identity: NativeStorageIdentity,
) -> ScopeBoundChallengeAnchor:
    """Use only a trusted KeyMint/StrongBox service with anti-rollback guarantees."""
    if type(protected_identity) is not NativeStorageIdentity or (
        protected_identity.platform is not NativePlatform.ANDROID_KEYMINT
    ):
        raise TransferError("Android KeyMint identity required")
    return ScopeBoundChallengeAnchor(
        PlatformCheckpointBackend(service, protected_identity),
        protected_identity.namespace,
    )
