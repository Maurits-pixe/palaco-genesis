"""PALACO v7 Ed25519 verifier candidate: detached signatures, never authority.

Public key records must come from an independently authenticated policy source,
not from the received evidence package. Caller must supply a current revocation
and policy decision. This class NEVER signs, grants release, or manages keys.
"""
import base64
import binascii
import re

KEY_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


class TrustAdapterError(ValueError):
    pass


def _decode_signature(value):
    if type(value) is not str or not value or len(value) > 128:
        raise TrustAdapterError("INVALID_SIGNATURE_ENCODING")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TrustAdapterError("INVALID_SIGNATURE_ENCODING") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise TrustAdapterError("INVALID_SIGNATURE_ENCODING")
    return raw


class Ed25519TrustAdapter:
    """Verify only using caller-pinned keys and an independent policy callback.

    verify_policy(key_id, statement) must assess CURRENT key revocation,
    scope, policy and freshness at verification time. No cached/offline
    policy may silently succeed. Only literal True is accepted.
    No private keys are accepted or stored.
    """
    def __init__(self, pinned_keys, *, verify_policy):
        if type(pinned_keys) is not dict or not pinned_keys or not callable(verify_policy):
            raise TrustAdapterError("TRUST_POLICY_REQUIRED")
        keys = {}
        for key_id, key_bytes in pinned_keys.items():
            if type(key_id) is not str or not KEY_ID.fullmatch(key_id):
                raise TrustAdapterError("INVALID_KEY_ID")
            if type(key_bytes) is not bytes or len(key_bytes) != 32:
                raise TrustAdapterError("INVALID_PUBLIC_KEY")
            keys[key_id] = key_bytes
        self._pinned_keys = keys
        self._verify_policy = verify_policy

    def __call__(self, statement, signature, key_id):
        if type(statement) is not bytes or type(key_id) is not str:
            return False
        if key_id not in self._pinned_keys:
            return False
        try:
            raw_sig = _decode_signature(signature)
            if self._verify_policy(key_id, statement) is not True:
                return False
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            except ImportError:
                return False
            key = Ed25519PublicKey.from_public_bytes(self._pinned_keys[key_id])
            key.verify(raw_sig, statement)
            return True
        except Exception:
            # Invalid signatures, inaccessible policy, and unavailable crypto fail closed.
            return False
