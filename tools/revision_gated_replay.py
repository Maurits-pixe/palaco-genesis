#!/usr/bin/env python3
"""Local revision-floor + reviewer-gated replay intake; HOLD prototype.

Enforces a signed registry revision floor BEFORE reviewer checks and replay
indexing. This does not make separate SQLite databases globally atomic.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


floor = _load("palaco_revision_floor_integrated", "local_reviewer_revision_floor.py")
gate = _load("palaco_reviewer_gate_integrated", "reviewer_gated_replay.py")


def inspect_and_index(revision_database, replay_database, items, reviewer_snapshot,
                      issuer_roots, evidence_public_keys, at_utc, minimum_revision):
    """Persist signed revision floor first; refuse stale/equivocated snapshots.

    This is a local advisory safeguard, NOT an authoritative permission engine.
    Both trust roots and time must be independently verified by a future service.
    """
    if not isinstance(items, list) or len(items) > gate.MAX_BATCH:
        raise ValueError("items must be a bounded array")
    if type(minimum_revision) is not int or minimum_revision < 1:
        raise ValueError("trusted minimum_revision required")
    if not isinstance(issuer_roots, dict) or not isinstance(evidence_public_keys, dict):
        raise ValueError("authenticated key maps required")
    if not isinstance(revision_database, (str, Path)) or not isinstance(replay_database, (str, Path)):
        raise ValueError("database paths required")
    if str(revision_database) == str(replay_database):
        raise ValueError("separate local databases required for this prototype")
    floor_verdict = floor.observe(revision_database, reviewer_snapshot, issuer_roots)
    if not floor_verdict["revision_recorded"]:
        return {
            "schema_version": "0.1.0", "release_gate": "HOLD",
            "authorization_granted": False, "evidence_verified": False,
            "signer_authority_verified": False, "local_index_updated": False,
            "revision_floor_checked": False,
            "decisions": [
                {"index": i, "state": "quarantined", "reason": floor_verdict["reason"]}
                for i in range(len(items))
            ],
        }
    # The externally supplied floor is independent and can be stricter than
    # the local floor. Never silently lower it.
    local_revision = reviewer_snapshot["snapshot"]["revision"]
    required_revision = max(minimum_revision, local_revision)
    result = gate.inspect_and_index(
        replay_database, items, reviewer_snapshot, issuer_roots,
        evidence_public_keys, at_utc, required_revision,
    )
    return {**result, "revision_floor_checked": True}
