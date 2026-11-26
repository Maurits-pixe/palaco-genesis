"""Read-only, HOLD-only evidence for split SQLite / fencing-witness incidents.

No repair, incident clearing, private key, signature, authorization, secure
time, or cryptographic authenticity is provided. The digest detects accidental
report changes ONLY. A report cannot attest to the independence of its witness.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json

from native_fencing_gate import FencedSnapshot
from witnessed_sqlite_fencing import FencingWitnessState
from protocol import TransferError

DOMAIN = b"PALACO:BT:FENCING-INCIDENT-EVIDENCE:V1\0"
VERSION = "PALACO-BT-FENCING-INCIDENT-EVIDENCE-V1"


@dataclass(frozen=True)
class FencingIncidentEvidence:
    canonical_json: str
    sha256: str


def _status(sqlite: FencedSnapshot | None,
            witness: FencingWitnessState | None) -> str:
    if sqlite is None or witness is None:
        return "unavailable"
    if (sqlite.namespace != witness.namespace or
            sqlite.epoch != witness.epoch or
            sqlite.incident_held is not witness.held or
            sqlite.checkpoint.count != witness.count or
            not hmac.compare_digest(sqlite.checkpoint.root, witness.root)):
        return "mismatch"
    return "match"


def _record(namespace: bytes, sqlite: FencedSnapshot | None,
            witness: FencingWitnessState | None, status: str) -> dict:
    if type(namespace) is not bytes or len(namespace) != 32:
        raise TransferError("invalid inspection scope")
    if sqlite is not None and (type(sqlite) is not FencedSnapshot or
                               sqlite.namespace != namespace):
        raise TransferError("invalid local fencing snapshot")
    if witness is not None and (type(witness) is not FencingWitnessState or
                                witness.namespace != namespace):
        raise TransferError("invalid witness inspection scope")
    if status not in ("match", "mismatch", "unavailable", "changed_during_read"):
        raise TransferError("unknown incident inspection status")
    if status in ("match", "mismatch") and status != _status(sqlite, witness):
        raise TransferError("inconsistent inspection classification")
    if status == "unavailable" and sqlite is not None and witness is not None:
        raise TransferError("unavailable requires a missing snapshot")
    if status == "changed_during_read" and (sqlite is None or witness is None):
        raise TransferError("changed read requires complete snapshots")
    return {
        "protocol": VERSION,
        "scope": namespace.hex(),
        "decision": "HOLD",
        "authorization": "DENY",
        "status": status,
        "sqlite": None if sqlite is None else {
            "epoch": sqlite.epoch, "held": sqlite.incident_held,
            "count": sqlite.checkpoint.count, "root": sqlite.checkpoint.root,
        },
        "witness": None if witness is None else {
            "revision": witness.revision, "epoch": witness.epoch,
            "held": witness.held, "count": witness.count, "root": witness.root,
        },
    }


def _build(namespace, sqlite, witness, status) -> FencingIncidentEvidence:
    payload = json.dumps(_record(namespace, sqlite, witness, status),
                         sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return FencingIncidentEvidence(
        payload, hashlib.sha256(DOMAIN + payload.encode("ascii")).hexdigest(),
    )


def inspect_fencing_incident(sqlite_service, witness_service,
                            namespace: bytes) -> FencingIncidentEvidence:
    """No writes. Double-read both stores, detect observable concurrent changes.

    Failure to read either store is reported as unavailable without leaking
    exception contents. No automatic state synchronization or HOLD release.
    """
    if type(namespace) is not bytes or len(namespace) != 32:
        raise TransferError("explicit inspection namespace required")
    local = independent = None
    try:
        first_w = witness_service.read()
        first_s = sqlite_service.read()
        second_s = sqlite_service.read()
        second_w = witness_service.read()
        if (type(first_w) is not FencingWitnessState or
                type(second_w) is not FencingWitnessState or
                type(first_s) is not FencedSnapshot or
                type(second_s) is not FencedSnapshot or
                first_w.namespace != namespace or second_w.namespace != namespace or
                first_s.namespace != namespace or second_s.namespace != namespace):
            return _build(namespace, None, None, "unavailable")
        local, independent = second_s, second_w
        if first_s != second_s or first_w != second_w:
            return _build(namespace, local, independent, "changed_during_read")
        return _build(namespace, local, independent, _status(local, independent))
    except Exception:
        return _build(namespace, None, None, "unavailable")


def verify_fencing_incident_evidence(evidence: FencingIncidentEvidence) -> bool:
    """Validate canonical report and checksum, NOT the trustworthiness of stores."""
    if type(evidence) is not FencingIncidentEvidence:
        return False
    try:
        data = json.loads(evidence.canonical_json)
        if type(data) is not dict or set(data) != {
            "protocol", "scope", "decision", "authorization",
            "status", "sqlite", "witness",
        } or data["protocol"] != VERSION or data["decision"] != "HOLD" or (
            data["authorization"] != "DENY"
        ):
            return False
        scope = bytes.fromhex(data["scope"])
        def reconstruct_local(obj):
            if obj is None:
                return None
            if type(obj) is not dict or set(obj) != {"epoch", "held", "count", "root"}:
                raise ValueError("invalid local evidence fields")
            from native_checkpoint_scope import NativeCheckpoint
            return FencedSnapshot(
                scope, obj["epoch"], obj["held"],
                NativeCheckpoint(scope, obj["count"], obj["root"]),
            )
        def reconstruct_witness(obj):
            if obj is None:
                return None
            if type(obj) is not dict or set(obj) != {
                "revision", "epoch", "held", "count", "root"
            }:
                raise ValueError("invalid witness evidence fields")
            return FencingWitnessState(scope, obj["revision"], obj["epoch"],
                                       obj["held"], obj["count"], obj["root"])
        rebuilt = _build(scope, reconstruct_local(data["sqlite"]),
                         reconstruct_witness(data["witness"]), data["status"])
        return (rebuilt.canonical_json == evidence.canonical_json and
                hmac.compare_digest(rebuilt.sha256, evidence.sha256))
    except (TypeError, ValueError, KeyError, AttributeError, TransferError):
        return False
