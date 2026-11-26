"""Windows IPC-to-native-probe correlation: diagnostic and fail-closed.

This function correlates untrusted user-space IPC fields and claimed native
probe data. It does NOT authenticate a named pipe, caller, service or TPM.
The issuer must separately provision the expected challenge and hardware
identity; both are still only expected values, not attestations.
Every outcome explicitly remains HOLD/DENY.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from windows_native_intake import WindowsNativeProbe
from windows_native_ipc_contract import (
    WindowsInspectRequest, decode_windows_inspect_request,
)

DOMAIN = b"PALACO:BT:WIN-IPC-CORRELATION:V1\0"


@dataclass(frozen=True)
class WindowsCorrelationReport:
    canonical_json: str
    sha256: str


def correlate_windows_probe(
    request_frame: bytes,
    probe: WindowsNativeProbe,
    expected_identity: NativeStorageIdentity,
    expected_challenge: bytes,
) -> WindowsCorrelationReport:
    """Compare scope and nonce without exposing an authorization capability."""
    if (type(probe) is not WindowsNativeProbe
            or type(expected_identity) is not NativeStorageIdentity
            or expected_identity.platform is not NativePlatform.WINDOWS_TPM
            or type(expected_challenge) is not bytes
            or len(expected_challenge) != 32):
        raise TransferError("invalid Windows correlation input: HOLD")

    request = decode_windows_inspect_request(request_frame)
    if type(request) is not WindowsInspectRequest:
        raise TransferError("invalid decoded request: HOLD")

    expected_match = (
        hmac.compare_digest(request.namespace, expected_identity.namespace)
        and hmac.compare_digest(request.device_binding, expected_identity.device_binding)
        and request.generation == expected_identity.generation
        and hmac.compare_digest(probe.identity.namespace, expected_identity.namespace)
        and hmac.compare_digest(probe.identity.device_binding, expected_identity.device_binding)
        and probe.identity.generation == expected_identity.generation
        and probe.identity.platform is NativePlatform.WINDOWS_TPM
    )
    nonce_match = (
        hmac.compare_digest(request.challenge, expected_challenge)
        and hmac.compare_digest(probe.challenge, expected_challenge)
    )
    # A response digest is NOT evidence of a TPM quote or authenticated IPC.
    response_present = any(probe.response_digest)
    record = {
        "protocol": "PALACO-BT-WINDOWS-CORRELATION-V1",
        "request_sha256": hashlib.sha256(request_frame).hexdigest(),
        "expected_namespace": expected_identity.namespace.hex(),
        "expected_device_binding": expected_identity.device_binding.hex(),
        "expected_generation": expected_identity.generation,
        "expected_challenge_sha256": hashlib.sha256(expected_challenge).hexdigest(),
        "scope_matches_claimed": expected_match,
        "challenge_matches_claimed": nonce_match,
        "response_digest_present": response_present,
        "input_correlated": expected_match and nonce_match and response_present,
        "ipc_peer_authenticated": False,
        "service_identity_authenticated": False,
        "tpm_attested": False,
        "replay_resistance_verified": False,
        "hardware_verified_by_this_module": False,
        "decision": "HOLD",
        "authorization": "DENY",
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return WindowsCorrelationReport(
        raw, hashlib.sha256(DOMAIN + raw.encode("ascii")).hexdigest()
    )
