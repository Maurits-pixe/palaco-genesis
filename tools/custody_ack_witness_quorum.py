#!/usr/bin/env python3
"""Fail-closed multi-witness agreement on one custody-acknowledgement chain head.

This is evidence quorum, never an authorization quorum. All witness keys,
allowed identities, revocations and count thresholds are supplied from an
independently authenticated source. No signing, publishing, or remote storage.
"""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "palaco_multi_ack_witness", Path(__file__).with_name("signed_custody_ack_anchor.py"))
signed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(signed)

MAX_WITNESSES = 16


def _base(**fields):
    return {"release_gate": "HOLD", "authorization_granted": False,
            "recovery_approved": False, "automatic_restore": False,
            "quorum_valid": False, "state": "quarantined", **fields}


def verify(receipt_db, envelopes, witness_roots, allowed_witness_ids,
           revoked_witness_ids, required_signatures, minimum_events):
    """Every submitted witness must independently authenticate exactly one head.

    Reject conflicting but authentic witnesses (no majority override). This
    prevents a caller suppressing a dissenting signed statement *within the
    submitted set*. It cannot detect withheld statements outside that set.
    """
    def deny(reason):
        return _base(reason=reason)
    if (not isinstance(witness_roots, dict)
        or not isinstance(allowed_witness_ids, (set, frozenset))
        or not isinstance(revoked_witness_ids, (set, frozenset))
        or any(not isinstance(k, str) or not signed.chain.HEX.fullmatch(k)
               for k in allowed_witness_ids | revoked_witness_ids)):
        return deny("missing-independent-witness-policy")
    if (type(required_signatures) is not int or not 2 <= required_signatures <= MAX_WITNESSES
        or type(minimum_events) is not int
        or not 1 <= minimum_events <= signed.chain.MAX_EVENTS):
        return deny("invalid-quorum-or-history-floor")
    if len(allowed_witness_ids - revoked_witness_ids) < required_signatures:
        return deny("insufficient-eligible-witness-roots")
    if not isinstance(envelopes, list) or not required_signatures <= len(envelopes) <= MAX_WITNESSES:
        return deny("insufficient-or-excess-witness-statements")
    seen = set()
    agreed = None
    for envelope in envelopes:
        if not isinstance(envelope, dict) or set(envelope) != signed.ENVELOPE_FIELDS:
            return deny("invalid-witness-envelope")
        key_id = envelope.get("witness_key_id")
        if not isinstance(key_id, str) or not signed.chain.HEX.fullmatch(key_id):
            return deny("invalid-witness-key-id")
        if key_id in seen:
            return deny("duplicate-witness")
        seen.add(key_id)
        if key_id not in allowed_witness_ids:
            return deny("witness-not-allowed")
        if key_id in revoked_witness_ids:
            return deny("witness-revoked")
        checked = signed.verify(receipt_db, envelope, witness_roots,
                                revoked_witness_ids, minimum_events)
        if not checked["anchor_valid"]:
            # Valid but divergent signatures can still be identified as an
            # explicit conflict without ever accepting the diverging chain.
            if checked["reason"] in ("ack-chain-head-mismatch", "signed-ack-count-mismatch"):
                return deny("conflicting-witness-anchor")
            return deny(checked["reason"])
        position = (checked["entries"], checked["head_hash"])
        if agreed is not None and position != agreed:
            return deny("conflicting-witness-anchor")
        agreed = position
    if len(seen) < required_signatures:
        return deny("insufficient-independent-witnesses")
    return {**_base(), "quorum_valid": True, "state": "pending-review",
            "reason": "multi-witness-ack-evidence-only-no-authority",
            "witnesses": len(seen), "entries": agreed[0], "head_hash": agreed[1]}
