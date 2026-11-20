"""PALACO v20 Ed25519 signed coordinator receipts: draft-only adapter.

The signature is cryptographic. Signer identity, key custody/revocation,
committed decision history and a monotonic external anchor are NOT provided.
Do not accept a receipt merely because its signature is mathematically valid.
"""
import base64
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from distributed_replay_v18 import (
    DOMAIN, CoordinationError, receipt_statement,
)
from ed25519_trust_v7 import Ed25519TrustAdapter, TrustAdapterError
from offline_stage import _canonical

KEY_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
MAX_PROOF = 1024


class SignedReceiptError(ValueError):
    pass


def _statement_valid(statement):
    """Allow only exact canonical v18 decision statements (not arbitrary bytes)."""
    if type(statement) is not bytes or not statement.startswith(DOMAIN):
        return False
    try:
        payload = statement[len(DOMAIN):]
        item = json.loads(payload.decode("ascii"))
        if type(item) is not dict or set(item) != {
            "schema", "claim", "authority_sequence", "decision"
        } or _canonical(item) != payload:
            return False
        return receipt_statement(
            item["claim"], authority_sequence=item["authority_sequence"],
            decision=item["decision"]) == statement
    except (CoordinationError, ValueError, TypeError, UnicodeError, OverflowError, KeyError):
        return False


def _key_id(value):
    if type(value) is not str or not KEY_ID.fullmatch(value):
        raise SignedReceiptError("INVALID_KEY_ID")


class SignedReceiptIssuer:
    """Callable v19 sign_receipt adapter.

    authorize_sign(statement, key_id) is a required independent current
    signer-authorization policy. This class receives a private key but never
    generates, exports or stores it in a file.
    """
    def __init__(self, private_key, *, key_id, authorize_sign):
        _key_id(key_id)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise SignedReceiptError("INVALID_SIGNING_KEY")
        if not callable(authorize_sign):
            raise SignedReceiptError("SIGNING_POLICY_REQUIRED")
        self._private_key = private_key
        self._key_id = key_id
        self._authorize_sign = authorize_sign

    def __call__(self, statement):
        if not _statement_valid(statement):
            raise SignedReceiptError("INVALID_STATEMENT")
        try:
            allowed = self._authorize_sign(statement, self._key_id)
        except Exception as exc:
            raise SignedReceiptError("SIGNING_POLICY_UNAVAILABLE") from exc
        if allowed is not True:
            raise SignedReceiptError("SIGNING_DENIED")
        signature = self._private_key.sign(statement)
        return _canonical({
            "key_id": self._key_id,
            "signature_b64": base64.b64encode(signature).decode("ascii")
        }).decode("ascii")


class SignedReceiptVerifier:
    """Callable v18 verify_authority(statement, opaque_receipt) adapter.

    verify_key_policy(key_id, statement) MUST authenticate the signer, current
    revocation and intended receipt scope; verify_committed(statement) MUST
    independently establish that the decision was committed to a durable,
    externally anchored monotonic authority history. Only literal True
    from both independent providers is accepted. No trust on its own.
    """
    def __init__(self, pinned_public_keys, *, verify_key_policy,
                 verify_committed):
        if not callable(verify_key_policy) or not callable(verify_committed):
            raise SignedReceiptError("EXTERNAL_TRUST_REQUIRED")
        try:
            self._verifier = Ed25519TrustAdapter(
                pinned_public_keys, verify_policy=verify_key_policy)
        except TrustAdapterError as exc:
            raise SignedReceiptError("INVALID_TRUST_STORE") from exc
        self._verify_committed = verify_committed

    def __call__(self, statement, proof):
        if not _statement_valid(statement) or type(proof) is not str or (
                not 1 <= len(proof) <= MAX_PROOF):
            return False
        try:
            document = json.loads(proof)
            if type(document) is not dict or set(document) != {
                "key_id", "signature_b64"
            } or _canonical(document).decode("ascii") != proof:
                return False
            key_id, signature = document["key_id"], document["signature_b64"]
            _key_id(key_id)
            if self._verifier(statement, signature, key_id) is not True:
                return False
            return self._verify_committed(statement) is True
        except Exception:
            return False
