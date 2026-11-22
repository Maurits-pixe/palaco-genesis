#!/usr/bin/env python3
"""Ed25519 evidence-envelope verification (HOLD).

Cryptographically checks signatures over narrowly defined, canonical metadata.
It does NOT authenticate a person's identity, grant trust, check revocation, or
authorize execution. A supplied trust map must come from an independently
authenticated source; without that, verification fails closed.
"""
import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEX64 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
FIELDS = {"schema_version", "record_id", "lineage_id", "payload_sha256"}
ENVELOPE = {"metadata", "key_id", "signature_b64"}


def canonical_metadata(metadata):
    if not isinstance(metadata, dict) or set(metadata) != FIELDS:
        raise ValueError("unsupported-metadata-schema")
    if metadata.get("schema_version") != "0.1.0":
        raise ValueError("unsupported-metadata-schema")
    if any(not isinstance(metadata.get(k), str) or not IDENTIFIER.fullmatch(metadata[k])
           for k in ("record_id", "lineage_id")):
        raise ValueError("invalid-provenance")
    digest = metadata.get("payload_sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("invalid-payload-digest")
    return json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def verify(envelope, trusted_public_keys):
    """Verify a candidate envelope; successful result remains pending-review.

    trusted_public_keys: mapping of lower-case SHA256 key fingerprint to a
    32-byte Ed25519 public key (bytes). Callers must authenticate this mapping.
    """
    result = {"release_gate": "HOLD", "authorization_granted": False,
              "signature_valid": False, "state": "quarantined"}
    def reject(reason):
        return {**result, "reason": reason}

    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE:
        return reject("invalid-envelope")
    if not isinstance(trusted_public_keys, dict):
        return reject("missing-trust-map")
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or not HEX64.fullmatch(key_id):
        return reject("invalid-key-id")
    try:
        signed = canonical_metadata(envelope["metadata"])
    except (ValueError, TypeError, OverflowError) as exc:
        return reject(str(exc))
    key = trusted_public_keys.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32:
        return reject("untrusted-key")
    if hashlib.sha256(key).hexdigest() != key_id:
        return reject("key-fingerprint-mismatch")
    encoded = envelope.get("signature_b64")
    if not isinstance(encoded, str) or len(encoded) > 96:
        return reject("invalid-signature-format")
    try:
        sig = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return reject("invalid-signature-format")
    if len(sig) != 64:
        return reject("invalid-signature-format")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, signed)
    except (InvalidSignature, ValueError):
        return reject("invalid-signature")
    return {**result, "signature_valid": True, "state": "pending-review",
            "reason": "signature-valid-authority-unverified",
            "record_id": envelope["metadata"]["record_id"]}


def verify_candidate(envelope, candidate, trusted_public_keys):
    """Bind signed digest to a local candidate's *actual* payload bytes.

    Avoid accepting a valid signature on metadata for a different payload.
    """
    verdict = verify(envelope, trusted_public_keys)
    if not verdict["signature_valid"]:
        return verdict
    if not isinstance(candidate, dict):
        return {**verdict, "signature_valid": False, "state": "quarantined",
                "reason": "invalid-candidate"}
    import importlib.util
    from pathlib import Path
    module = Path(__file__).with_name("local_evidence_intake.py")
    spec = importlib.util.spec_from_file_location("palaco_intake_binding", module)
    intake = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(intake)
    meta, error = intake._check(candidate)
    if error or meta != envelope["metadata"]:
        return {**verdict, "signature_valid": False, "state": "quarantined",
                "reason": "candidate-binding-failed"}
    return verdict
