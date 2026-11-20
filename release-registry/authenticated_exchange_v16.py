"""PALACO v16 authenticated evidence-envelope candidate.

Ed25519 signs the entire canonical v15 encrypted envelope plus recipient and
unique message identifier. An external, independently trusted signer verifier
and atomic replay registry are REQUIRED for receiving. No authority granted.
"""
import base64
import hashlib
import json
import re
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from offline_stage import _canonical
from secure_evidence_exchange_v15 import seal_bundle, open_bundle, ExchangeError

SCHEMA = "palaco-authenticated-exchange/v16"
DOMAIN = b"PALACO-AUTHENTICATED-EXCHANGE-v16:SIGNATURE\x00"
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
MAX_BYTES = 4_000_000


class AuthenticatedExchangeError(ValueError):
    pass


def _id(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise AuthenticatedExchangeError("INVALID_IDENTIFIER")
    return value


def _statement(*, sender_id, recipient_id, message_id, envelope):
    return DOMAIN + _canonical({
        "schema": SCHEMA, "sender_id": sender_id,
        "recipient_id": recipient_id, "message_id": message_id,
        "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
    })


def sign_exchange(bundle, *, sender_id, sender_private_key, recipient_id,
                  recipient_public_key, authorize_send, message_id=None):
    """Produce an authenticated wrapper for v15 ciphertext, not user consent.

    Signing key custody and authorization policy remain external obligations.
    Only synthetic keys should be used until end-to-end governance review.
    """
    _id(sender_id)
    _id(recipient_id)
    if not isinstance(sender_private_key, Ed25519PrivateKey):
        raise AuthenticatedExchangeError("INVALID_SENDER_KEY")
    if message_id is None:
        message_id = secrets.token_hex(24)
    _id(message_id)
    try:
        encrypted = seal_bundle(
            bundle, recipient_id=recipient_id,
            recipient_public_key=recipient_public_key,
            authorize_send=authorize_send)
        statement = _statement(
            sender_id=sender_id, recipient_id=recipient_id,
            message_id=message_id, envelope=encrypted)
        signature = sender_private_key.sign(statement)
        document = {
            "schema": SCHEMA, "sender_id": sender_id,
            "recipient_id": recipient_id, "message_id": message_id,
            "envelope_b64": base64.b64encode(encrypted).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        encoded = _canonical(document)
        if len(encoded) > MAX_BYTES:
            raise AuthenticatedExchangeError("SIGNED_ENVELOPE_TOO_LARGE")
        return encoded
    except AuthenticatedExchangeError:
        raise
    except (ExchangeError, ValueError, TypeError) as exc:
        raise AuthenticatedExchangeError("SEAL_DENIED") from exc


def receive_exchange(data, *, expected_recipient_id, recipient_private_key,
                     verify_sender=None, claim_replay=None):
    """Verify sender, decrypt, then atomically claim message ID to prevent replay.

    verify_sender(statement, signature_b64, sender_id) MUST independently
    authenticate signing key, current revocation, scope and trusted time.
    claim_replay(sender_id, recipient_id, message_id, digest) MUST atomically
    persist a single-use reservation in an independently durable registry.
    Returning literal True means first claim only; other results deny.
    No built-in replay database, trusted clock or key registry exists.
    """
    _id(expected_recipient_id)
    if not callable(verify_sender) or not callable(claim_replay):
        raise AuthenticatedExchangeError("TRUST_SERVICES_REQUIRED")
    if type(data) is not bytes or not 1 <= len(data) <= MAX_BYTES:
        raise AuthenticatedExchangeError("INVALID_PACKAGE")
    try:
        obj = json.loads(data.decode("ascii"))
        if type(obj) is not dict or set(obj) != {
            "schema", "sender_id", "recipient_id", "message_id",
            "envelope_b64", "signature_b64"
        } or _canonical(obj) != data or obj["schema"] != SCHEMA:
            raise AuthenticatedExchangeError("INVALID_PACKAGE")
        sender_id = _id(obj["sender_id"])
        recipient_id = _id(obj["recipient_id"])
        message_id = _id(obj["message_id"])
        if recipient_id != expected_recipient_id:
            raise AuthenticatedExchangeError("RECIPIENT_MISMATCH")
        def decode(value, *, maximum):
            if type(value) is not str or len(value) > ((maximum + 2)//3)*4:
                raise AuthenticatedExchangeError("INVALID_BASE64")
            raw = base64.b64decode(value, validate=True)
            if base64.b64encode(raw).decode("ascii") != value or len(raw) > maximum:
                raise AuthenticatedExchangeError("INVALID_BASE64")
            return raw
        encrypted = decode(obj["envelope_b64"], maximum=3_000_000)
        signature = decode(obj["signature_b64"], maximum=64)
        if len(signature) != 64:
            raise AuthenticatedExchangeError("INVALID_SIGNATURE")
        statement = _statement(
            sender_id=sender_id, recipient_id=recipient_id,
            message_id=message_id, envelope=encrypted)
        try:
            accepted = verify_sender(statement, obj["signature_b64"], sender_id)
        except Exception as exc:
            raise AuthenticatedExchangeError("SENDER_UNVERIFIED") from exc
        if accepted is not True:
            raise AuthenticatedExchangeError("SENDER_UNVERIFIED")
        plaintext = open_bundle(encrypted, expected_recipient_id=recipient_id,
                                recipient_private_key=recipient_private_key)
        digest = hashlib.sha256(data).hexdigest()
        try:
            claimed = claim_replay(sender_id, recipient_id, message_id, digest)
        except Exception as exc:
            raise AuthenticatedExchangeError("REPLAY_SERVICE_UNAVAILABLE") from exc
        if claimed is not True:
            raise AuthenticatedExchangeError("REPLAY_DENIED")
        return plaintext, {
            "schema": "palaco-exchange-inspection/v16",
            "sender_id": sender_id, "recipient_id": recipient_id,
            "message_id": message_id, "package_sha256": digest,
            "sender_callback_accepted": True, "replay_callback_accepted": True,
            "authorization": "DENY", "release": "HOLD",
            "production_release_enabled": False,
        }
    except AuthenticatedExchangeError:
        raise
    except (ExchangeError, ValueError, TypeError, UnicodeError) as exc:
        raise AuthenticatedExchangeError("PACKAGE_REJECTED") from exc
