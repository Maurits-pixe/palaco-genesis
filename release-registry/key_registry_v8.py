"""PALACO v8 snapshot key registry: local policy only after external anchoring.

This is a candidate for *verification*, not a trust root or revocation service.
It cannot make a stale offline key-registry snapshot current.
"""
import base64
import hashlib
import json
import re

from ed25519_trust_v7 import Ed25519TrustAdapter
from offline_stage import _canonical

SCHEMA = "palaco-key-registry/v8"
KEY = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
SCOPE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
PREFIX = b"PALACO-KEY-REGISTRY-v8:SNAPSHOT\x00"


class RegistryError(ValueError):
    pass


def _snapshot(snapshot):
    if type(snapshot) is not dict or set(snapshot) != {"schema", "version", "keys"}:
        raise RegistryError("INVALID_SNAPSHOT")
    if snapshot["schema"] != SCHEMA or type(snapshot["version"]) is not int or snapshot["version"] < 1:
        raise RegistryError("INVALID_VERSION")
    records = snapshot["keys"]
    if type(records) is not list or not 1 <= len(records) <= 512:
        raise RegistryError("INVALID_KEY_SET")
    pinned, allowed, seen = {}, {}, set()
    for item in records:
        if type(item) is not dict or set(item) != {"key_id", "public_key_b64", "status", "scopes"}:
            raise RegistryError("INVALID_KEY_RECORD")
        kid = item["key_id"]
        if type(kid) is not str or not KEY.fullmatch(kid) or kid in seen:
            raise RegistryError("DUPLICATE_OR_INVALID_KEY_ID")
        seen.add(kid)
        if item["status"] not in ("active", "revoked") or type(item["status"]) is not str:
            raise RegistryError("INVALID_KEY_STATUS")
        scopes = item["scopes"]
        if (type(scopes) is not list or not scopes or len(scopes) > 32 or
                any(type(s) is not str or not SCOPE.fullmatch(s) for s in scopes) or
                len(scopes) != len(set(scopes))):
            raise RegistryError("INVALID_SCOPES")
        encoded = item["public_key_b64"]
        if type(encoded) is not str or len(encoded) != 44:
            raise RegistryError("INVALID_PUBLIC_KEY")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise RegistryError("INVALID_PUBLIC_KEY") from exc
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != encoded:
            raise RegistryError("INVALID_PUBLIC_KEY")
        pinned[kid] = raw
        allowed[kid] = (item["status"], frozenset(scopes))
    return pinned, allowed


def snapshot_digest(snapshot):
    """Digest of strict snapshot contents, NOT evidence of authenticity."""
    _snapshot(snapshot)
    return hashlib.sha256(PREFIX + _canonical(snapshot)).hexdigest()


class AnchoredRegistry:
    """Construct a verifier only after independent external anchor checking.

    get_anchor() MUST return (version, sha256hex) from a monotonic and
    independently authenticated source, not from the submitted snapshot.
    check_current(version, scope) MUST confirm current freshness, key-policy,
    revocation and trusted time. Both are runtime checks per verification.
    No always-true callbacks should ever be used outside synthetic tests.
    """
    def __init__(self, snapshot, *, scope, get_anchor, check_current):
        if type(scope) is not str or not SCOPE.fullmatch(scope):
            raise RegistryError("INVALID_SCOPE")
        if not callable(get_anchor) or not callable(check_current):
            raise RegistryError("EXTERNAL_TRUST_REQUIRED")
        pinned, records = _snapshot(snapshot)
        self._digest = snapshot_digest(snapshot)
        self._version = snapshot["version"]
        self._scope = scope
        self._records = records
        self._get_anchor = get_anchor
        self._check_current = check_current
        self._adapter = Ed25519TrustAdapter(
            pinned, verify_policy=self._policy)

    def _policy(self, key_id, statement):
        if type(statement) is not bytes:
            return False
        record = self._records.get(key_id)
        if record is None or record[0] != "active" or self._scope not in record[1]:
            return False
        try:
            anchor = self._get_anchor()
            if (type(anchor) is not tuple or len(anchor) != 2 or
                    type(anchor[0]) is not int or type(anchor[1]) is not str or
                    not HEX.fullmatch(anchor[1]) or
                    anchor != (self._version, self._digest)):
                return False
            return self._check_current(self._version, self._scope) is True
        except Exception:
            return False

    def __call__(self, statement, signature, key_id):
        return self._adapter(statement, signature, key_id)

    @property
    def fingerprint(self):
        return self._digest
