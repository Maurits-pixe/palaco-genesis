"""PALACO v15 confidential transport candidate for a v14 proof bundle.

X25519 + HKDF-SHA256 + AES-256-GCM, with authenticated envelope metadata.
This does NOT authenticate the sender, prove receiver identity, distribute
trusted keys, or authorize release, recovery or access to source evidence.
"""
import base64
import binascii
import hashlib
import json
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from offline_stage import _canonical
from governance_proof_bundle_v14 import MAX_BUNDLE_BYTES

SCHEMA = "palaco-secure-evidence-exchange/v15"
DOMAIN = b"PALACO-EVIDENCE-EXCHANGE-v15:ENVELOPE\x00"
INFO = b"PALACO-EVIDENCE-EXCHANGE-v15:HKDF-AES256GCM\x00"
RECIPIENT = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
MAX_ENVELOPE_BYTES = 3_000_000


class ExchangeError(ValueError):
    pass


def _encode(raw):
    return base64.b64encode(raw).decode("ascii")


def _decode(value, *, exact=None, max_size=None):
    if type(value) is not str or len(value) > 4 * MAX_ENVELOPE_BYTES:
        raise ExchangeError("INVALID_ENCODING")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ExchangeError("INVALID_ENCODING") from exc
    if _encode(decoded) != value or (
        exact is not None and len(decoded) != exact
    ) or (max_size is not None and len(decoded) > max_size):
        raise ExchangeError("INVALID_ENCODING")
    return decoded


def _recipient_id(identifier):
    if type(identifier) is not str or not RECIPIENT.fullmatch(identifier):
        raise ExchangeError("INVALID_RECIPIENT")
    return identifier


def _derive(shared, *, recipient_id, sender_public, receiver_public):
    salt = hashlib.sha256(DOMAIN + _canonical({
        "recipient_id": recipient_id,
        "sender_pub_b64": _encode(sender_public),
        "receiver_pub_b64": _encode(receiver_public),
    })).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(shared)


def _aad(header):
    return DOMAIN + _canonical(header)


def seal_bundle(bundle_bytes, *, recipient_id, recipient_public_key,
                authorize_send=None):
    """Encrypt only after external recipient key and send-policy confirmation.

    authorize_send(id, keybytes) must authenticate the intended recipient and
    independently check current consent/policy. Literal True is required.
    """
    _recipient_id(recipient_id)
    if type(bundle_bytes) is not bytes or not 1 <= len(bundle_bytes) <= MAX_BUNDLE_BYTES:
        raise ExchangeError("INVALID_BUNDLE")
    if type(recipient_public_key) is not bytes or len(recipient_public_key) != 32:
        raise ExchangeError("INVALID_RECIPIENT_KEY")
    if not callable(authorize_send):
        raise ExchangeError("SEND_POLICY_REQUIRED")
    try:
        if authorize_send(recipient_id, recipient_public_key) is not True:
            raise ExchangeError("SEND_DENIED")
        receiver = X25519PublicKey.from_public_bytes(recipient_public_key)
        sender = X25519PrivateKey.generate()
        sender_public = sender.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        key = _derive(sender.exchange(receiver), recipient_id=recipient_id,
                      sender_public=sender_public, receiver_public=recipient_public_key)
        header = {"schema": SCHEMA, "recipient_id": recipient_id,
                  "ephemeral_public_key_b64": _encode(sender_public)}
        nonce = __import__("os").urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, bundle_bytes, _aad(header))
        envelope = {**header, "nonce_b64": _encode(nonce),
                    "ciphertext_b64": _encode(ciphertext)}
        result = _canonical(envelope)
        if len(result) > MAX_ENVELOPE_BYTES:
            raise ExchangeError("ENVELOPE_TOO_LARGE")
        return result
    except ExchangeError:
        raise
    except Exception as exc:
        raise ExchangeError("ENCRYPTION_UNAVAILABLE") from exc


def open_bundle(envelope_bytes, *, expected_recipient_id, recipient_private_key):
    """Decrypt for externally authenticated receiver; do NOT grant trust.

    Returned v14 bytes MUST be checked with verify_bundle and independent
    role/anchor sources. No sender authentication or replay protection exists.
    """
    _recipient_id(expected_recipient_id)
    if (type(envelope_bytes) is not bytes or
            not 1 <= len(envelope_bytes) <= MAX_ENVELOPE_BYTES):
        raise ExchangeError("INVALID_ENVELOPE")
    if not isinstance(recipient_private_key, X25519PrivateKey):
        raise ExchangeError("INVALID_PRIVATE_KEY")
    try:
        envelope = json.loads(envelope_bytes.decode("ascii"))
        if type(envelope) is not dict or set(envelope) != {
            "schema", "recipient_id", "ephemeral_public_key_b64",
            "nonce_b64", "ciphertext_b64"
        } or _canonical(envelope) != envelope_bytes:
            raise ExchangeError("INVALID_ENVELOPE_SCHEMA")
        if envelope["schema"] != SCHEMA or envelope["recipient_id"] != expected_recipient_id:
            raise ExchangeError("RECIPIENT_MISMATCH")
        sender_public = _decode(envelope["ephemeral_public_key_b64"], exact=32)
        nonce = _decode(envelope["nonce_b64"], exact=12)
        ciphertext = _decode(envelope["ciphertext_b64"], max_size=MAX_BUNDLE_BYTES + 16)
        receiver_public = recipient_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        sender = X25519PublicKey.from_public_bytes(sender_public)
        key = _derive(recipient_private_key.exchange(sender),
                      recipient_id=expected_recipient_id,
                      sender_public=sender_public, receiver_public=receiver_public)
        plaintext = AESGCM(key).decrypt(
            nonce, ciphertext, _aad({
                "schema": SCHEMA, "recipient_id": expected_recipient_id,
                "ephemeral_public_key_b64": envelope["ephemeral_public_key_b64"],
            }))
        if not 1 <= len(plaintext) <= MAX_BUNDLE_BYTES:
            raise ExchangeError("INVALID_DECRYPTED_SIZE")
        return plaintext
    except ExchangeError:
        raise
    except Exception as exc:
        # Intentionally uniform failure for wrong keys or altered ciphertext.
        raise ExchangeError("DECRYPTION_DENIED") from exc
