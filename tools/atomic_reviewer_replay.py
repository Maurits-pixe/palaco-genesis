#!/usr/bin/env python3
"""Atomic local reviewer revision + candidate replay intake; advisory HOLD only."""
import importlib.util
import sqlite3
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


floor = _load("palaco_atomic_floor", "local_reviewer_revision_floor.py")
reviewers = _load("palaco_atomic_reviewer", "signed_reviewer_registry.py")
signed = _load("palaco_atomic_signed", "signed_evidence_envelope.py")
intake = _load("palaco_atomic_intake", "local_evidence_intake.py")
MAX_BATCH = 10000


def inspect_and_index(database, items, registry, issuer_roots, evidence_keys,
                      at_utc, minimum_revision):
    """One BEGIN IMMEDIATE controls revision floor and replay IDs.

    Snapshot and candidates must pass cryptographic checks before mutation.
    Individual invalid candidates quarantine; valid IDs are indexed atomically
    with the signed revision floor. Never grants authority or evidence trust.
    """
    if not isinstance(items, list) or len(items) > MAX_BATCH:
        raise ValueError("items must be a bounded array")
    if not isinstance(database, (str, Path)) or str(database) == ":memory:":
        raise ValueError("persistent database path required")
    if type(minimum_revision) is not int or minimum_revision < 1:
        raise ValueError("trusted minimum revision required")
    if not isinstance(evidence_keys, dict):
        raise ValueError("key map required")
    verified = floor.verify_snapshot(registry, issuer_roots)
    decisions = [None] * len(items)
    base = {"schema_version": "0.1.0", "release_gate": "HOLD",
            "authorization_granted": False, "evidence_verified": False,
            "signer_authority_verified": False}
    def deny_all(reason):
        return {**base, "local_state_updated": False, "decisions": [
            {"index": i, "state": "quarantined", "reason": reason}
            for i in range(len(items))
        ]}
    if verified is None:
        return deny_all("invalid-snapshot-signature")
    issuer_id, digest = verified
    revision = registry["snapshot"]["revision"]
    if revision < minimum_revision:
        return deny_all("stale-registry-revision")

    accepted = []
    for pos, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != {"reviewer_id", "candidate", "envelope"}:
            decisions[pos] = {"index": pos, "state": "quarantined", "reason": "invalid-item"}
            continue
        envelope = item["envelope"]
        key_id = envelope.get("key_id") if isinstance(envelope, dict) else None
        reviewer = reviewers.evaluate(registry, issuer_roots, item["reviewer_id"],
                                      key_id, at_utc, minimum_revision)
        if not reviewer["reviewer_eligible_for_manual_review"]:
            decisions[pos] = {"index": pos, "state": "quarantined", "reason": reviewer["reason"]}
            continue
        verdict = signed.verify_candidate(envelope, item["candidate"], evidence_keys)
        if not verdict["signature_valid"]:
            decisions[pos] = {"index": pos, "state": "quarantined", "reason": verdict["reason"]}
            continue
        meta, error = intake._check(item["candidate"])
        if error or meta is None:
            decisions[pos] = {"index": pos, "state": "quarantined",
                              "reason": error or "invalid-candidate"}
            continue
        accepted.append((pos, meta))
    counts = Counter(meta["record_id"] for _, meta in accepted)
    candidate_ids = [meta["record_id"] for _, meta in accepted]
    if any(count > 1 for count in counts.values()):
        for pos, meta in accepted:
            if counts[meta["record_id"]] > 1:
                decisions[pos] = {"index": pos, "state": "quarantined",
                                  "reason": "duplicate-record-id", "record_id": meta["record_id"]}
        accepted = [(pos, meta) for pos, meta in accepted if counts[meta["record_id"]] == 1]

    conn = sqlite3.connect(str(database), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        floor._schema(conn)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS seen_candidate_ids(
                record_id TEXT PRIMARY KEY NOT NULL,
                lineage_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            )
        """)
        row = conn.execute(
            "SELECT revision, snapshot_digest FROM reviewer_revision_floor WHERE issuer_key_id=?",
            (issuer_id,)
        ).fetchone()
        if row and revision < row[0]:
            conn.rollback()
            return deny_all("registry-rollback")
        if row and revision == row[0] and digest != row[1]:
            conn.rollback()
            return deny_all("registry-equivocation")
        if not row or revision > row[0]:
            conn.execute("""
                INSERT INTO reviewer_revision_floor(issuer_key_id, revision, snapshot_digest)
                VALUES (?, ?, ?)
                ON CONFLICT(issuer_key_id) DO UPDATE SET
                revision=excluded.revision, snapshot_digest=excluded.snapshot_digest
            """, (issuer_id, revision, digest))
        for pos, meta in accepted:
            try:
                conn.execute("""
                    INSERT INTO seen_candidate_ids(record_id, lineage_id, payload_sha256)
                    VALUES (?, ?, ?)
                """, (meta["record_id"], meta["lineage_id"], meta["payload_sha256"]))
            except sqlite3.IntegrityError:
                decisions[pos] = {"index": pos, "state": "quarantined",
                                  "reason": "previously-seen-record-id",
                                  "record_id": meta["record_id"]}
            else:
                decisions[pos] = {"index": pos, "state": "pending-review",
                                  "reason": "integrity-and-signature-only-authority-unverified",
                                  "record_id": meta["record_id"]}
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {**base, "local_state_updated": True, "decisions": decisions}
