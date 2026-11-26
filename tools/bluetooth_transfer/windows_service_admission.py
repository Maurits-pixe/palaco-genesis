"""Windows privileged-service admission evidence boundary (DRAFT, non-native).

An OS-owned Windows token / named-pipe peer identity cannot be proven by
caller-controlled Python input. This module checks completeness and consistency
of external native review assertions for triage ONLY. It never grants an IPC
session, TPM access, checkpoint advancement, import, or release permission.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import re

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from windows_native_correlation import correlate_windows_probe
from windows_native_intake import WindowsNativeProbe
from windows_native_ipc_contract import decode_windows_inspect_request

DOMAIN = b"PALACO:BT:WINDOWS-SERVICE-ADMISSION:V1\0"
PROTOCOL = "PALACO-BT-WINDOWS-SERVICE-ADMISSION-V1"
REQUIRED_CONTROLS = (
    "windows_service_sid",
    "named_pipe_dacl",
    "caller_token_verified",
    "impersonation_boundary",
    "service_binary_integrity",
    "privilege_minimization",
    "session_replay_protection",
    "tpm_trust_root",
)
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)


class ControlClaim(Enum):
    NOT_REVIEWED = "not_reviewed"
    EXTERNAL_PASS_CLAIM = "external_pass_claim"
    FAILED = "failed"


@dataclass(frozen=True)
class WindowsServiceReview:
    expected_identity: NativeStorageIdentity
    controls: dict[str, ControlClaim]
    evidence_refs: dict[str, str]

    def __post_init__(self):
        if (type(self.expected_identity) is not NativeStorageIdentity or
                self.expected_identity.platform is not NativePlatform.WINDOWS_TPM or
                type(self.controls) is not dict or
                type(self.evidence_refs) is not dict or
                set(self.controls) != set(REQUIRED_CONTROLS) or
                set(self.evidence_refs) != set(REQUIRED_CONTROLS)):
            raise TransferError("invalid Windows service review inventory: HOLD")
        for key in REQUIRED_CONTROLS:
            value = self.controls[key]
            ref = self.evidence_refs[key]
            if (type(value) is not ControlClaim or type(ref) is not str or
                    (ref != "" and not _REF.fullmatch(ref)) or
                    (value is ControlClaim.EXTERNAL_PASS_CLAIM and not ref)):
                raise TransferError("invalid Windows service review entry: HOLD")


@dataclass(frozen=True)
class WindowsServiceAdmissionReport:
    canonical_json: str
    sha256: str


def inspect_windows_service_admission(
    request_frame: bytes,
    probe: WindowsNativeProbe,
    review: WindowsServiceReview,
    expected_challenge: bytes,
) -> WindowsServiceAdmissionReport:
    """Diagnostic only: no capability or permission is returned."""
    if type(review) is not WindowsServiceReview:
        raise TransferError("explicit native service review required: HOLD")
    # Correlation always stays HOLD, even when all claims match.
    match_report = correlate_windows_probe(
        request_frame, probe, review.expected_identity, expected_challenge)
    data = json.loads(match_report.canonical_json)
    complete = all(review.controls[key] is ControlClaim.EXTERNAL_PASS_CLAIM
                   for key in REQUIRED_CONTROLS)
    record = {
        "protocol": PROTOCOL,
        "platform": NativePlatform.WINDOWS_TPM.value,
        "device_binding": review.expected_identity.device_binding.hex(),
        "generation": review.expected_identity.generation,
        "request_sha256": hashlib.sha256(request_frame).hexdigest(),
        "correlation_sha256": match_report.sha256,
        "input_correlated_claimed": data["input_correlated"],
        "review_complete_claimed": complete,
        "controls": {
            key: {"status": review.controls[key].value,
                  "reference": review.evidence_refs[key]}
            for key in REQUIRED_CONTROLS
        },
        "windows_service_running": False,
        "os_peer_identity_verified": False,
        "tpm_attested": False,
        "hardware_verified_by_this_module": False,
        "ipc_session_opened": False,
        "decision": "HOLD",
        "authorization": "DENY",
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return WindowsServiceAdmissionReport(
        raw, hashlib.sha256(DOMAIN + raw.encode("ascii")).hexdigest())
