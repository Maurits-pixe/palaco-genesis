"""Pinned issuer key rotation for HOLD-only policy distribution.

The trusted issuer registry and the independent monotonic pin MUST come from
protected native custody; neither backend exists here. A mutable fake can
roll back both. This adapter supplies no enrollment, key generation, unlock,
automatic repair, or security authority.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
import hashlib
import hmac
import json
import threading

from protocol import TransferError
from signed_fencing_incident import _validate_id
from signed_policy_distribution import VerifiedSignedPolicySource
from versioned_incident_policy import PolicyPin

DOMAIN = b"PALACO:BT:ISSUER-ROTATION:V1\0"


@dataclass(frozen=True)
class IssuerKeyRecord:
    public_key: bytes
    revoked: bool

    def __post_init__(self):
        if (type(self.public_key) is not bytes or len(self.public_key) != 32 or
                type(self.revoked) is not bool):
            raise TransferError("invalid policy publisher record")


@dataclass(frozen=True)
class IssuerRotationSnapshot:
    revision: int
    keys: Mapping[str, IssuerKeyRecord]

    def __post_init__(self):
        if (type(self.revision) is not int or
                not 1 <= self.revision < 2**63 or
                not isinstance(self.keys, Mapping) or
                not 1 <= len(self.keys) <= 64):
            raise TransferError("invalid publisher rotation snapshot")


def issuer_rotation_digest(snapshot: IssuerRotationSnapshot) -> str:
    if type(snapshot) is not IssuerRotationSnapshot:
        raise TransferError("invalid publisher rotation snapshot")
    records = []
    for key_id, entry in sorted(snapshot.keys.items()):
        if not _validate_id(key_id) or type(entry) is not IssuerKeyRecord:
            raise TransferError("invalid publisher rotation entry")
        records.append({
            "id": key_id, "key": entry.public_key.hex(), "revoked": entry.revoked,
        })
    data = json.dumps({"revision": snapshot.revision, "issuers": records},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(DOMAIN + data.encode("ascii")).hexdigest()


class RotationPinnedPolicySource:
    """Recheck publisher rotation pin on every signed policy read.

    The returned source can feed VersionedIncidentReviewerGate, which MUST
    additionally enforce its own protected *incident policy* revision pin.
    Existing instances latch HOLD when publisher rotation changes; a fresh
    instance can use the latest protected publisher registry.
    """

    def __init__(self, transport, protected_issuers, protected_issuer_pin):
        if (not callable(getattr(transport, "read", None)) or
                not callable(getattr(protected_issuers, "read", None)) or
                not callable(getattr(protected_issuer_pin, "read", None))):
            raise TransferError("protected publisher source and pin required")
        self._transport = transport
        self._source = protected_issuers
        self._pin = protected_issuer_pin
        self._held = False
        self._lock = threading.RLock()
        self._revision = None
        self._verify_registry()

    @property
    def is_held(self):
        with self._lock:
            return self._held

    def _verify_registry(self):
        if self._held:
            raise TransferError("publisher rotation HOLD active")
        try:
            before = self._pin.read()
            snapshot = self._source.read()
            after = self._pin.read()
            if (type(before) is not PolicyPin or
                    type(after) is not PolicyPin or
                    type(snapshot) is not IssuerRotationSnapshot or
                    before != after or
                    after.revision != snapshot.revision or
                    not hmac.compare_digest(after.digest,
                                            issuer_rotation_digest(snapshot)) or
                    (self._revision is not None and
                     self._revision != snapshot.revision)):
                raise TransferError("publisher rotation pin mismatch")
            active = {
                key_id: record.public_key for key_id, record in snapshot.keys.items()
                if not record.revoked
            }
            if not active:
                raise TransferError("no active trusted policy publishers")
            self._revision = snapshot.revision
            return MappingProxyType(active)
        except Exception as exc:
            self._held = True
            raise TransferError("protected publisher rotation unavailable: HOLD") from exc

    def read(self):
        with self._lock:
            keys = self._verify_registry()
            try:
                policy = VerifiedSignedPolicySource(self._transport, keys).read()
                # Detect revocation/rotation during signature verification.
                if self._verify_registry() != keys:
                    raise TransferError("publisher changed during verified read")
                return policy
            except Exception as exc:
                self._held = True
                raise TransferError("publisher verification uncertain: HOLD") from exc
