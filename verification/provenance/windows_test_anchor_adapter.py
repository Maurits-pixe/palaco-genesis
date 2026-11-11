"""WNRA-04Z: isolated fake anchor response validation; NO independent trust.

This module cannot attest, issue an anchor, or authorize production. The
locally controlled marker is deliberately non-cryptographic and test-only.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Optional

PROTOCOL = "WNRA-04Y-ANCHOR-PROPOSAL-v0.1"
MOCK_CUSTODIAN = "SIMULATED-LOCAL-CUSTODIAN"
MOCK_KEY = "SIMULATED-LOCAL-KEY"
MOCK_POLICY = "SIMULATED-POLICY-v0"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FULL_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class AnchorRequest:
    protocol: str
    request_id: str
    fixture_domain: str
    source_commit: str
    record_digest: str
    predecessor_anchor_id: str
    sequence: int
    evidence_ref: str
    actor_id: str


@dataclass(frozen=True)
class AnchorResponse:
    request_id: str
    decision: str
    anchor_id: str
    anchor_digest: str
    predecessor_anchor_id: str
    custodian_id: str
    key_id: str
    signature: str
    policy_version: str
    evidence_ref: str
    fixture_domain: str
    source_commit: str
    record_digest: str
    sequence: int


@dataclass(frozen=True)
class AnchorObservation:
    fixture_valid: bool
    reason: str
    authorization: str = "DENY"
    independent_verification: str = "NOT_EXECUTED"


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _request_valid(request: AnchorRequest) -> bool:
    return (
        request.protocol == PROTOCOL
        and all(_nonempty(value) for value in (
            request.request_id, request.fixture_domain, request.predecessor_anchor_id,
            request.evidence_ref, request.actor_id,
        ))
        and request.fixture_domain.startswith("TEST-")
        and bool(FULL_COMMIT.fullmatch(request.source_commit))
        and bool(HEX64.fullmatch(request.record_digest))
        and type(request.sequence) is int
        and request.sequence > 0
    )


def _binding_digest(request: AnchorRequest) -> str:
    payload = {
        "protocol": request.protocol,
        "request_id": request.request_id,
        "fixture_domain": request.fixture_domain,
        "source_commit": request.source_commit,
        "record_digest": request.record_digest,
        "predecessor_anchor_id": request.predecessor_anchor_id,
        "sequence": request.sequence,
        "evidence_ref": request.evidence_ref,
        "actor_id": request.actor_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def make_simulated_response(request: AnchorRequest) -> AnchorResponse:
    """Produce a local fixture only; SIMULATED is not a signature or trust root."""
    if not _request_valid(request):
        raise ValueError("invalid test request")
    digest = _binding_digest(request)
    return AnchorResponse(
        request_id=request.request_id,
        decision="ACCEPTED",
        anchor_id="SIMULATED-" + request.request_id,
        anchor_digest=digest,
        predecessor_anchor_id=request.predecessor_anchor_id,
        custodian_id=MOCK_CUSTODIAN,
        key_id=MOCK_KEY,
        signature="SIMULATED-NOT-A-SIGNATURE:" + digest,
        policy_version=MOCK_POLICY,
        evidence_ref="SIMULATED-AUDIT:" + request.request_id,
        fixture_domain=request.fixture_domain,
        source_commit=request.source_commit,
        record_digest=request.record_digest,
        sequence=request.sequence,
    )


class SimulatedAnchorAdapter:
    """Fail closed for invalid fixtures; track replay inside one test instance."""

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}
        self._sequences: dict[str, int] = {}

    def verify(
        self,
        request: AnchorRequest,
        response: Optional[AnchorResponse],
        *,
        available: bool = True,
        mock_key_trusted: bool = True,
    ) -> AnchorObservation:
        denied = lambda reason: AnchorObservation(False, reason)
        if not available:
            return denied("CUSTODIAN_UNAVAILABLE")
        if not _request_valid(request):
            return denied("INVALID_REQUEST")
        if response is None or not isinstance(response, AnchorResponse):
            return denied("MISSING_RESPONSE")
        if response.decision != "ACCEPTED":
            return denied("RESPONSE_NOT_ACCEPTED")
        if not mock_key_trusted:
            return denied("UNTRUSTED_MOCK_KEY")
        digest = _binding_digest(request)
        if self._seen.get(request.request_id) is not None:
            return denied("REPLAY_OR_CONFLICT")
        if request.sequence <= self._sequences.get(request.fixture_domain, 0):
            return denied("ROLLBACK_OR_DUPLICATE_SEQUENCE")
        expected = make_simulated_response(request)
        if response != expected:
            return denied("INVALID_OR_UNBOUND_RESPONSE")
        self._seen[request.request_id] = digest
        self._sequences[request.fixture_domain] = request.sequence
        return AnchorObservation(True, "SIMULATED_FIXTURE_MATCH_ONLY")
