"""Deterministic, read-only PALACO receipt recovery evidence envelope.

No repair, authorization, signature, secure clock, or trusted external anchor
is provided. A SHA-256 fingerprint detects incidental report changes but is
NOT proof of authenticity; signed provenance must be supplied separately.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from protocol import TransferError
from recovery_inspection import RecoveryReport, RecoveryStatus, inspect_checkpoint

VERSION = "PALACO-BT-RECOVERY-EVIDENCE-V1"
DOMAIN = b"PALACO:BT:RECOVERY-EVIDENCE:V1\0"


@dataclass(frozen=True)
class RecoveryEvidence:
    """Immutable canonical evidence with a content fingerprint."""

    canonical_json: str
    sha256: str


def _record(report: RecoveryReport) -> dict:
    if not isinstance(report, RecoveryReport) or not isinstance(
        report.status, RecoveryStatus
    ):
        raise TransferError("valid recovery inspection report required")
    statuses = {
        RecoveryStatus.MATCH, RecoveryStatus.DATABASE_AHEAD,
        RecoveryStatus.ANCHOR_AHEAD, RecoveryStatus.CONTENT_MISMATCH,
        RecoveryStatus.UNAVAILABLE,
    }
    if report.status not in statuses:
        raise TransferError("unknown recovery status")
    count_fields = (report.database_count, report.anchor_count)
    root_fields = (report.database_root, report.anchor_root)
    if report.status is RecoveryStatus.UNAVAILABLE:
        if any(value is not None for value in (*count_fields, *root_fields)):
            raise TransferError("unavailable report must not assert evidence")
    else:
        if (any(type(x) is not int or not 0 <= x <= 100_000 for x in count_fields)
                or any(type(x) is not str or len(x) != 64 or
                       any(c not in "0123456789abcdef" for c in x)
                       for x in root_fields)):
            raise TransferError("incomplete or malformed checkpoint evidence")
        counts_match = report.database_count == report.anchor_count
        roots_match = report.database_root == report.anchor_root
        expected = (
            RecoveryStatus.DATABASE_AHEAD if report.database_count > report.anchor_count
            else RecoveryStatus.ANCHOR_AHEAD if report.database_count < report.anchor_count
            else RecoveryStatus.MATCH if counts_match and roots_match
            else RecoveryStatus.CONTENT_MISMATCH
        )
        if report.status is not expected:
            raise TransferError("inconsistent recovery classification")
    return {
        "anchor_count": report.anchor_count,
        "anchor_root": report.anchor_root,
        "database_count": report.database_count,
        "database_root": report.database_root,
        "decision": "HOLD",
        "protocol": VERSION,
        "status": report.status.value,
    }


def build_evidence(report: RecoveryReport) -> RecoveryEvidence:
    """Create canonical local diagnostic record; HOLD even on MATCH."""
    canonical_json = json.dumps(
        _record(report), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    fingerprint = hashlib.sha256(DOMAIN + canonical_json.encode("ascii")).hexdigest()
    return RecoveryEvidence(canonical_json, fingerprint)


def inspect_evidence(database_path, anchor) -> RecoveryEvidence:
    """Read-only inspector wrapper; no DB schema creation or anchor advancement."""
    return build_evidence(inspect_checkpoint(database_path, anchor))


def verify_evidence(evidence: RecoveryEvidence) -> bool:
    """Check report consistency and checksum; not authenticating a signer."""
    if not isinstance(evidence, RecoveryEvidence):
        return False
    try:
        doc = json.loads(evidence.canonical_json)
        if not isinstance(doc, dict) or set(doc) != {
            "anchor_count", "anchor_root", "database_count", "database_root",
            "decision", "protocol", "status",
        }:
            return False
        if doc["protocol"] != VERSION or doc["decision"] != "HOLD":
            return False
        if type(doc["status"]) is not str:
            return False
        report = RecoveryReport(
            RecoveryStatus(doc["status"]),
            doc["database_count"], doc["anchor_count"],
            doc["database_root"], doc["anchor_root"],
        )
        expected = build_evidence(report)
        return (expected.canonical_json == evidence.canonical_json and
                expected.sha256 == evidence.sha256)
    except (TypeError, ValueError, AttributeError, KeyError, TransferError):
        return False
