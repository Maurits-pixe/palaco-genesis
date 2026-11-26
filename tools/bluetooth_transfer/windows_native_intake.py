"""Windows TPM native service intake boundary — diagnostic only, never authority.

This module DOES NOT speak TPM, Windows RPC, CNG or DPAPI. A privileged,
independently installed native service must be built and verified separately.
A challenge response supplied by Python/user space is not TPM attestation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError

PROTOCOL = "PALACO-BT-WINDOWS-NATIVE-INTAKE-V1"
DOMAIN = b"PALACO:BT:WIN-NATIVE-INTAKE:V1\0"


@dataclass(frozen=True)
class WindowsNativeProbe:
    """Untrusted diagnostic snapshot; no boolean granting access."""
    identity: NativeStorageIdentity
    challenge: bytes
    response_digest: bytes
    service_version: str

    def __post_init__(self):
        if (type(self.identity) is not NativeStorageIdentity or
                self.identity.platform is not NativePlatform.WINDOWS_TPM or
                type(self.challenge) is not bytes or len(self.challenge) != 32 or
                type(self.response_digest) is not bytes or len(self.response_digest) != 32 or
                type(self.service_version) is not str or
                not 1 <= len(self.service_version) <= 64 or
                any(not (c.isascii() and (c.isalnum() or c in ".-_"))
                    for c in self.service_version)):
            raise TransferError("invalid Windows native diagnostic probe: HOLD")


@dataclass(frozen=True)
class WindowsNativeIntakeReport:
    canonical_json: str
    sha256: str


def inspect_windows_native_probe(
    probe: WindowsNativeProbe,
    expected_identity: NativeStorageIdentity,
    expected_challenge: bytes,
) -> WindowsNativeIntakeReport:
    """Check identity/nonce shape, NOT response signature, TPM or hardware.

    The caller MUST provision expected_identity and expected_challenge separately
    from the untrusted probe. Even matching bytes cannot establish provenance.
    All outputs are HOLD/DENY regardless of matching evidence.
    """
    if (type(probe) is not WindowsNativeProbe or
            type(expected_identity) is not NativeStorageIdentity or
            expected_identity.platform is not NativePlatform.WINDOWS_TPM or
            type(expected_challenge) is not bytes or len(expected_challenge) != 32):
        raise TransferError("Windows native expected identity/challenge required: HOLD")

    identity_matches = (
        probe.identity.platform is expected_identity.platform
        and probe.identity.generation == expected_identity.generation
        and hmac.compare_digest(probe.identity.namespace, expected_identity.namespace)
        and hmac.compare_digest(probe.identity.device_binding, expected_identity.device_binding)
    )
    challenge_matches = hmac.compare_digest(probe.challenge, expected_challenge)
    record = {
        "protocol": PROTOCOL,
        "platform": "windows_tpm",
        "expected_namespace": expected_identity.namespace.hex(),
        "expected_device_binding": expected_identity.device_binding.hex(),
        "expected_generation": expected_identity.generation,
        "challenge_sha256": hashlib.sha256(expected_challenge).hexdigest(),
        "identity_matches_claimed": identity_matches,
        "challenge_matches_claimed": challenge_matches,
        "response_digest_present": any(probe.response_digest),
        "service_version_claimed": probe.service_version,
        "origin_authenticated": False,
        "tpm_attested": False,
        "rollback_resistant": False,
        "hardware_verified_by_this_module": False,
        "decision": "HOLD",
        "authorization": "DENY",
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return WindowsNativeIntakeReport(
        raw, hashlib.sha256(DOMAIN + raw.encode("ascii")).hexdigest()
    )
