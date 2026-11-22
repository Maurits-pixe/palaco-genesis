#!/usr/bin/env python3
"""Local SQLite replay index for untrusted evidence candidate IDs.

Only local record identifiers are persisted. No evidence acceptance, signature
verification, identity, authorization, or trusted reconciliation is performed.
SQLite locking/uniqueness applies to processes sharing the SAME database file.
"""
import importlib.util
import json
import sqlite3
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("local_evidence_intake.py")
_spec = importlib.util.spec_from_file_location("palaco_local_evidence_intake", MODULE_PATH)
_intake = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_intake)


def _create_schema(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS seen_candidate_ids (
            record_id TEXT PRIMARY KEY NOT NULL,
            lineage_id TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
        )
    """)


def index_candidates(db_path, records):
    """Atomically index distinct locally-intact candidates as UNTRUSTED.

    A duplicate ID is quarantined and never replaces its previous index entry.
    This index is *not* a trusted server replay defense: deletion/rollback/copying
    the SQLite file, or inspecting from a different machine, can bypass it.
    """
    # Validate first: no database is created for malformed batch input.
    initial = _intake.inspect(records)
    candidates = [_intake._check(record) for record in records]
    if not isinstance(db_path, (str, Path)) or str(db_path) == ":memory:":
        raise ValueError("db_path must reference a persistent local file")
    decisions = []
    conn = sqlite3.connect(str(db_path), timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _create_schema(conn)
        for item, (meta, error) in zip(initial["decisions"], candidates):
            if item["state"] != "pending-review" or meta is None or error is not None:
                decisions.append(dict(item))
                continue
            try:
                conn.execute(
                    "INSERT INTO seen_candidate_ids(record_id, lineage_id, payload_sha256) VALUES (?, ?, ?)",
                    (meta["record_id"], meta["lineage_id"], meta["payload_sha256"]),
                )
            except sqlite3.IntegrityError:
                decisions.append({
                    "index": item["index"], "record_id": meta["record_id"],
                    "state": "quarantined", "reason": "previously-seen-record-id"
                })
            else:
                decisions.append(dict(item))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "schema_version": "0.1.0", "release_gate": "HOLD",
        "authorization_granted": False, "evidence_persisted": False,
        "local_replay_index_updated": True, "decisions": decisions,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Index locally intact, untrusted candidate IDs (HOLD)")
    parser.add_argument("database", type=Path, help="local SQLite file, not an authority database")
    parser.add_argument("records", type=Path, help="JSON array of candidate records")
    args = parser.parse_args()
    try:
        records = json.loads(args.records.read_text(encoding="utf-8"))
        report = index_candidates(args.database, records)
    except (OSError, UnicodeError, ValueError, sqlite3.Error, json.JSONDecodeError) as exc:
        parser.exit(2, f"FAIL: {exc}\n")
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
