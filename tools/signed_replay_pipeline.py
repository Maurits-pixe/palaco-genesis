#!/usr/bin/env python3
"""HOLD-gated signed candidate intake then local replay screening.

This is a local review queue prototype, NOT an authenticated signing-authority
registry or production replay defense. A signed payload remains UNTRUSTED.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAX_BATCH = 10000


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


signed = _load("palaco_signed_envelope_pipeline", "signed_evidence_envelope.py")
replay = _load("palaco_replay_index_pipeline", "local_replay_index.py")


def inspect_and_index(database, items, trusted_public_keys):
    """Order: payload/metadata binding -> signature -> SQLite replay index.

    Invalid or unsigned candidates are NEVER added to the index. No result
    grants identity/authority; a caller-provided key map is not independently
    authenticated. Successful IDs become locally seen, not globally trusted.
    """
    if not isinstance(items, list) or len(items) > MAX_BATCH:
        raise ValueError("items must be a bounded array")
    if not isinstance(trusted_public_keys, dict):
        raise ValueError("trusted_public_keys must be a key map")
    valid = []
    positions = []
    decisions = [None] * len(items)
    for pos, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != {"candidate", "envelope"}:
            decisions[pos] = {"index": pos, "state": "quarantined", "reason": "invalid-item"}
            continue
        verdict = signed.verify_candidate(
            item["envelope"], item["candidate"], trusted_public_keys
        )
        if not verdict["signature_valid"]:
            decisions[pos] = {
                "index": pos, "state": "quarantined", "reason": verdict["reason"]
            }
            continue
        valid.append(item["candidate"])
        positions.append(pos)
    # Only cryptographically intact candidate IDs reach local replay screening.
    # sqlite primary key provides local uniqueness for concurrent writers to
    # this same file. Invalid signatures do not poison the index.
    indexed = replay.index_candidates(database, valid) if valid else None
    if indexed:
        for local_idx, original_idx in enumerate(positions):
            item = indexed["decisions"][local_idx]
            decisions[original_idx] = {**item, "index": original_idx}
    return {
        "schema_version": "0.1.0", "release_gate": "HOLD",
        "authorization_granted": False, "evidence_verified": False,
        "signer_authority_verified": False, "local_index_updated": bool(indexed),
        "decisions": decisions,
    }
