#!/usr/bin/env python3
"""PALACO reviewer-gated local replay intake (prototype; HOLD).

Required sequence: signed registry snapshot -> reviewer status/key binding ->
candidate integrity and Ed25519 signature -> local SQLite replay index.
No live issuer trust roots, trusted clock or authenticated revision store.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAX_BATCH = 10000


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reviewers = _load("palaco_reviewer_gate_registry", "signed_reviewer_registry.py")
pipeline = _load("palaco_reviewer_gate_pipeline", "signed_replay_pipeline.py")


def inspect_and_index(database, items, reviewer_snapshot, issuer_roots,
                      evidence_public_keys, at_utc, minimum_revision):
    """Gate local intake on reviewer status without issuing authority.

    Both the issuer roots and reviewer public keys MUST be authenticated by
    an external authority. A valid snapshot alone is not authorization.
    """
    if not isinstance(items, list) or len(items) > MAX_BATCH:
        raise ValueError("items must be a bounded array")
    if not isinstance(issuer_roots, dict) or not isinstance(evidence_public_keys, dict):
        raise ValueError("key registries must be dictionaries")
    allowed, positions = [], []
    decisions = [None] * len(items)
    for pos, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != {"reviewer_id", "candidate", "envelope"}:
            decisions[pos] = {"index": pos, "state": "quarantined", "reason": "invalid-item"}
            continue
        envelope = item["envelope"]
        key_id = envelope.get("key_id") if isinstance(envelope, dict) else None
        decision = reviewers.evaluate(
            reviewer_snapshot, issuer_roots, item["reviewer_id"], key_id,
            at_utc, minimum_revision
        )
        if not decision["reviewer_eligible_for_manual_review"]:
            decisions[pos] = {"index": pos, "state": "quarantined",
                              "reason": decision["reason"]}
            continue
        allowed.append({"candidate": item["candidate"], "envelope": item["envelope"]})
        positions.append(pos)
    result = pipeline.inspect_and_index(database, allowed, evidence_public_keys) if allowed else None
    if result:
        for local_idx, pos in enumerate(positions):
            decisions[pos] = {**result["decisions"][local_idx], "index": pos}
    return {
        "schema_version": "0.1.0", "release_gate": "HOLD",
        "authorization_granted": False, "evidence_verified": False,
        "signer_authority_verified": False, "local_index_updated": bool(result),
        "decisions": decisions,
    }
