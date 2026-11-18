"""PALACO v21 independently anchored monotonic authority checkpoint contract.

This module checks v19 decision history and v20 receipt verification through
external callbacks. A local hash chain alone is NOT trusted provenance.
No permission to execute, release, receive or restore is ever granted.
"""
import hashlib
import json
import re

from distributed_replay_v18 import CoordinationError, receipt_statement, _tuple
from offline_stage import _canonical

SCHEMA = "palaco-authority-checkpoint/v21"
GENESIS = hashlib.sha256(b"PALACO-AUTHORITY-CHECKPOINT-v21:GENESIS").hexdigest()
DOMAIN = b"PALACO-AUTHORITY-CHECKPOINT-v21:STEP\x00"
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_DECISIONS = 10000


class CheckpointError(ValueError):
    pass


def _walk(claims, receipts, verify_receipt=None):
    if (type(claims) not in (list, tuple) or
            type(receipts) not in (list, tuple) or
            len(claims) != len(receipts) or len(claims) > MAX_DECISIONS):
        raise CheckpointError("INVALID_HISTORY")
    head = GENESIS
    seen = {}
    statements = []
    for sequence, (claim, receipt) in enumerate(zip(claims, receipts), 1):
        if type(receipt) is not dict or set(receipt) != {
            "schema", "authority_sequence", "decision", "proof"
        } or receipt["schema"] != "palaco-distributed-replay-receipt/v18":
            raise CheckpointError("INVALID_RECEIPT")
        if type(receipt["authority_sequence"]) is not int or receipt["authority_sequence"] != sequence:
            raise CheckpointError("NONMONOTONIC_SEQUENCE")
        proof = receipt["proof"]
        if type(proof) is not str or not 1 <= len(proof) <= 8192:
            raise CheckpointError("INVALID_RECEIPT_PROOF")
        try:
            statement = receipt_statement(
                claim, authority_sequence=sequence, decision=receipt["decision"])
        except (ValueError, TypeError, CoordinationError) as exc:
            raise CheckpointError("INVALID_DECISION_STATEMENT") from exc
        key = _tuple(claim)
        previous = seen.get(key)
        expected = ("first-claim" if previous is None else
                    "duplicate" if previous == claim["package_sha256"] else "conflict")
        if receipt["decision"] != expected:
            raise CheckpointError("INCONSISTENT_FIRST_CLAIM")
        seen.setdefault(key, claim["package_sha256"])
        if verify_receipt is not None:
            try:
                checked = verify_receipt(statement, proof)
            except Exception as exc:
                raise CheckpointError("RECEIPT_PROVIDER_UNAVAILABLE") from exc
            if checked is not True:
                raise CheckpointError("UNVERIFIED_SIGNATURE")
        head = hashlib.sha256(DOMAIN + _canonical({
            "previous": head, "sequence": sequence,
            "statement_sha256": hashlib.sha256(statement).hexdigest(),
            "receipt_sha256": hashlib.sha256(proof.encode("utf-8")).hexdigest(),
        })).hexdigest()
        statements.append(statement)
    return head, tuple(statements)


def checkpoint_candidate(claims, receipts):
    """Build deterministic local checkpoint proposal; NOT a trusted anchor."""
    head, _ = _walk(claims, receipts)
    return {"schema": SCHEMA, "sequence": len(claims), "head": head}


def verify_checkpoint(claims, receipts, *, get_trusted_checkpoint,
                      verify_receipt):
    """Require independently authenticated exact (sequence, head) anchor.

    get_trusted_checkpoint() MUST read a monotonic checkpoint from an
    independently secured source, not compute from locally supplied history.
    verify_receipt(statement, proof) MUST cryptographically check a pinned
    authority key, current revocation, signer scope and policy; never simply
    compare a checksum. Literal True is required from both trust providers.
    """
    if not callable(get_trusted_checkpoint) or not callable(verify_receipt):
        raise CheckpointError("EXTERNAL_TRUST_REQUIRED")
    if not claims:
        raise CheckpointError("EMPTY_HISTORY_NOT_TRUSTED")
    head, _ = _walk(claims, receipts, verify_receipt=verify_receipt)
    try:
        pinned = get_trusted_checkpoint()
    except Exception as exc:
        raise CheckpointError("CHECKPOINT_PROVIDER_UNAVAILABLE") from exc
    if (type(pinned) is not tuple or len(pinned) != 2 or
            type(pinned[0]) is not int or type(pinned[1]) is not str or
            pinned != (len(claims), head)):
        raise CheckpointError("CHECKPOINT_MISMATCH")
    return {"schema": "palaco-authority-checkpoint-inspection/v21",
            "sequence": len(claims), "head": head,
            "external_callbacks_accepted": True, "authorization": "DENY",
            "release": "HOLD", "production_release_enabled": False}


class AnchoredCommitInspector:
    """Read fresh v19 snapshots on each check; no cached trust decision.

    verify_receipt must be ONLY Ed25519+current-key-policy verification,
    not v20's verifier that recursively calls this inspector.
    """
    def __init__(self, authority, *, get_trusted_checkpoint, verify_receipt):
        if not hasattr(authority, "read_decisions") or not callable(get_trusted_checkpoint) or not callable(verify_receipt):
            raise CheckpointError("EXTERNAL_TRUST_REQUIRED")
        self._authority = authority
        self._checkpoint = get_trusted_checkpoint
        self._receipt = verify_receipt

    def __call__(self, statement):
        if type(statement) is not bytes:
            return False
        try:
            claims, receipts = self._authority.read_decisions()
            verify_checkpoint(claims, receipts,
                              get_trusted_checkpoint=self._checkpoint,
                              verify_receipt=self._receipt)
            for claim, receipt in zip(claims, receipts):
                expected = receipt_statement(
                    claim, authority_sequence=receipt["authority_sequence"],
                    decision=receipt["decision"])
                if expected == statement:
                    return True
            return False
        except Exception:
            return False
