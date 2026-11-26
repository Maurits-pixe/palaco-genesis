"""PALACO Bluetooth v7.0: externally signed receiver high-watermark.

The checkpoint SIGNER is caller-pinned independently of the received history.
Signature proves checkpoint authorship, not trustworthy time or fresh storage.
HOLD/DENY only; no automatic checkpoint creation or promotion by the receiver.
"""
from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import (
    check_hex, public_id, serialize, strictly_parse,
)
from witness_history_v69 import inspect as inspect_history

PROTOCOL = "PALACO-BT-CI-EXTERNAL-CHECKPOINT-V1"
FIELDS = {"version", "sequence", "head", "root_id", "signer_id",
          "decision", "authorization", "signature"}


def payload(state: dict, key: Ed25519PublicKey) -> dict:
    if type(state) is not dict or set(state) != {"sequence", "head", "root_id"}:
        raise EvidenceRejected("invalid independent checkpoint state")
    if type(state["sequence"]) is not int or state["sequence"] < 1:
        raise EvidenceRejected("invalid independent sequence")
    check_hex(state["head"])
    check_hex(state["root_id"])
    return {"version": PROTOCOL, **state, "signer_id": public_id(key),
            "decision": "HOLD", "authorization": "DENY"}


def sign(state: dict, signer: Ed25519PrivateKey) -> bytes:
    body = payload(state, signer.public_key())
    signature = signer.sign(serialize(body))
    return serialize({**body, "signature": base64.b64encode(signature).decode("ascii")})


def verify(raw: bytes, trusted_signer: Ed25519PublicKey) -> dict:
    doc = strictly_parse(raw, FIELDS)
    state = {k: doc[k] for k in ("sequence", "head", "root_id")}
    expected = payload(state, trusted_signer)
    if {k: v for k, v in doc.items() if k != "signature"} != expected:
        raise EvidenceRejected("external checkpoint authority mismatch")
    try:
        if type(doc["signature"]) is not str:
            raise ValueError("invalid signature type")
        raw_signature = base64.b64decode(doc["signature"], validate=True)
        if len(raw_signature) != 64:
            raise ValueError("invalid signature length")
        trusted_signer.verify(raw_signature, serialize(expected))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise EvidenceRejected("external checkpoint signature invalid") from exc
    return state


def inspect(directory: Path, expected_sha: str, expected_run: str,
            custodians: dict, chain_root: Ed25519PublicKey,
            witnesses: dict, external_checkpoint: Path,
            independently_pinned_signer: Ed25519PublicKey) -> dict:
    if (external_checkpoint.is_symlink() or not external_checkpoint.is_file()
            or external_checkpoint.resolve().is_relative_to(directory.resolve())):
        raise EvidenceRejected("checkpoint not independently retained")
    if external_checkpoint.stat().st_size > 8192:
        raise EvidenceRejected("checkpoint too large")
    state = verify(external_checkpoint.read_bytes(), independently_pinned_signer)
    return inspect_history(directory, expected_sha, expected_run, custodians,
                           chain_root, witnesses, state)
