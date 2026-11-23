"""Windows-first native adapter readiness inspection; NEVER deployment authorization.

This is an evidence completeness checker, not TPM/KeyMint attestation or an
OS security service. A caller can forge its input, including all PASS values.
Only an independently trusted native verifier can attest those claims.
All results remain HOLD / DENY irrespective of check completeness.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError


class NativeEvidenceStatus(Enum):
    VERIFIED = "verified_by_external_review"
    MISSING = "missing"
    FAILED = "failed"


REQUIRED_CHECKS = (
    "privileged_service_identity",
    "device_hardware_binding",
    "hardware_key_nonexportability",
    "independent_monotonic_pin",
    "rollback_after_restart",
    "atomic_compare_and_advance",
    "tamper_and_replay_rejection",
    "trust_root_provisioning",
)

DOMAIN = b"PALACO:BT:NATIVE-READINESS:V1\0"


@dataclass(frozen=True)
class NativeCapabilityEvidence:
    identity: NativeStorageIdentity
    check_results: dict[str, NativeEvidenceStatus]
    evidence_refs: dict[str, str]

    def __post_init__(self):
        if (type(self.identity) is not NativeStorageIdentity or
                type(self.check_results) is not dict or
                type(self.evidence_refs) is not dict or
                set(self.check_results) != set(REQUIRED_CHECKS) or
                set(self.evidence_refs) != set(REQUIRED_CHECKS)):
            raise TransferError("incomplete native capability evidence")
        for name in REQUIRED_CHECKS:
            state = self.check_results[name]
            reference = self.evidence_refs[name]
            if (type(state) is not NativeEvidenceStatus or
                    type(reference) is not str or len(reference) > 128 or
                    any(not (c.isascii() and (c.isalnum() or c in "-_.:/"))
                        for c in reference) or
                    (state is NativeEvidenceStatus.VERIFIED and not reference)):
                raise TransferError("invalid native capability evidence entry")


@dataclass(frozen=True)
class NativeReadinessReport:
    canonical_json: str
    sha256: str


def inspect_native_readiness(evidence: NativeCapabilityEvidence,
                             expected_identity: NativeStorageIdentity,
                             expected_platform: NativePlatform) -> NativeReadinessReport:
    """Build a diagnostic report even for externally claimed complete evidence.

    'complete' is merely an input-completeness indicator, NOT a trust judgment.
    Never expose a boolean ready-to-deploy flag.
    """
    if (type(evidence) is not NativeCapabilityEvidence or
            type(expected_identity) is not NativeStorageIdentity or
            type(expected_platform) is not NativePlatform or
            expected_identity.platform is not expected_platform):
        raise TransferError("explicit platform and identity required")
    match = evidence.identity == expected_identity
    complete = match and all(
        evidence.check_results[name] is NativeEvidenceStatus.VERIFIED
        for name in REQUIRED_CHECKS
    )
    record = {
        "protocol": "PALACO-BT-NATIVE-READINESS-V1",
        "platform": expected_platform.value,
        "namespace": expected_identity.namespace.hex(),
        "device_binding": expected_identity.device_binding.hex(),
        "generation": expected_identity.generation,
        "identity_matches": match,
        "evidence_complete_claimed": complete,
        "checks": {name: {
            "status": evidence.check_results[name].value,
            "ref": evidence.evidence_refs[name],
        } for name in REQUIRED_CHECKS},
        "decision": "HOLD",
        "authorization": "DENY",
        "origin_authenticated": False,
        "hardware_verified_by_this_module": False,
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return NativeReadinessReport(
        raw, hashlib.sha256(DOMAIN + raw.encode("ascii")).hexdigest(),
    )
