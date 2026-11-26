"""PALACO Bluetooth v7.1: signed, linked checkpoint succession (DENY-only).

A receiver MUST obtain the trusted signer and *latest transition digest* from
separate durable custody. This module verifies succession but never advances
that independently retained high-water mark. No storage durability is claimed.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import check_hex, public_id, serialize, strictly_parse
from witness_checkpoint_v70 import verify as verify_checkpoint
from witness_history_v69 import inspect as inspect_history

VERSION = "PALACO-BT-CI-CHECKPOINT-SUCCESSION-V1"
FIELDS = {"version", "generation", "prior_sha256", "sequence", "head",
          "root_id", "signer_id", "decision", "authorization", "signature"}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def envelope(prior: bytes, next_state: dict,
             signer: Ed25519PublicKey) -> dict:
    preceding = verify_checkpoint(prior, signer)
    if type(next_state) is not dict or set(next_state) != {
            "sequence", "head", "root_id"}:
        raise EvidenceRejected("invalid next checkpoint")
    if type(next_state["sequence"]) is not int or (
            next_state["sequence"] <= preceding["sequence"]):
        raise EvidenceRejected("non-advancing checkpoint")
    check_hex(next_state["head"])
    check_hex(next_state["root_id"])
    if (next_state["root_id"] != preceding["root_id"]
            or next_state["head"] == preceding["head"]):
        raise EvidenceRejected("checkpoint root changed or head reused")
    return {"version": VERSION, "generation": 1,
            "prior_sha256": digest(prior), **next_state,
            "signer_id": public_id(signer), "decision": "HOLD",
            "authorization": "DENY"}


def sign_successor(prior: bytes, next_state: dict,
                   signer: Ed25519PrivateKey) -> bytes:
    body = envelope(prior, next_state, signer.public_key())
    return serialize({**body, "signature": base64.b64encode(
        signer.sign(serialize(body))).decode("ascii")})


def verify_successor(prior: bytes, successor: bytes,
                     trusted_signer: Ed25519PublicKey,
                     independently_pinned_latest_digest: str) -> dict:
    check_hex(independently_pinned_latest_digest)
    if digest(successor) != independently_pinned_latest_digest:
        raise EvidenceRejected("rollback or unknown successor")
    parsed = strictly_parse(successor, FIELDS)
    state = {k: parsed[k] for k in ("sequence", "head", "root_id")}
    expected = envelope(prior, state, trusted_signer)
    if {k: v for k, v in parsed.items() if k != "signature"} != expected:
        raise EvidenceRejected("checkpoint succession binding mismatch")
    try:
        if type(parsed["signature"]) is not str:
            raise ValueError("signature must be text")
        signature = base64.b64decode(parsed["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("signature wrong size")
        trusted_signer.verify(signature, serialize(expected))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise EvidenceRejected("checkpoint succession signature rejected") from exc
    return state


def inspect(directory: Path, expected_sha: str, expected_run: str,
            custodians: dict, chain_root: Ed25519PublicKey, witnesses: dict,
            independently_retained_prior: Path,
            independently_retained_successor: Path,
            independently_pinned_signer: Ed25519PublicKey,
            independently_pinned_latest_digest: str) -> dict:
    for source in (independently_retained_prior,
                   independently_retained_successor):
        if (source.is_symlink() or not source.is_file()
                or source.resolve().is_relative_to(directory.resolve())
                or source.stat().st_size > 8192):
            raise EvidenceRejected("external succession record unsafe or missing")
    if independently_retained_prior.resolve() == independently_retained_successor.resolve():
        raise EvidenceRejected("successor and predecessor must differ")
    state = verify_successor(independently_retained_prior.read_bytes(),
                             independently_retained_successor.read_bytes(),
                             independently_pinned_signer,
                             independently_pinned_latest_digest)
    return inspect_history(directory, expected_sha, expected_run, custodians,
                           chain_root, witnesses, state)
