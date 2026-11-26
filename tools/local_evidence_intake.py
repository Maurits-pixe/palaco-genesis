#!/usr/bin/env python3
"""PALACO local evidence intake: deterministic, side-effect-free prototype.

Input is untrusted. This module neither writes records nor grants trust,
reconciles server state, issues identities, or verifies signatures.
"""
import hashlib
import json
import re
from collections import Counter

IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_RECORDS = 10000
MAX_PAYLOAD_BYTES = 1024 * 1024


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _check(record):
    if not isinstance(record, dict):
        return None, "malformed-record"
    if set(record) != {"record_id", "lineage_id", "payload", "payload_sha256", "schema_version"}:
        return None, "unsupported-schema"
    if record.get("schema_version") != "0.1.0":
        return None, "unsupported-schema"
    if any(not isinstance(record.get(field), str) or not IDENTIFIER.fullmatch(record[field])
           for field in ("record_id", "lineage_id")):
        return None, "missing-provenance"
    digest = record.get("payload_sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        return None, "integrity-failure"
    try:
        encoded = _canonical(record["payload"])
    except (TypeError, ValueError, OverflowError):
        return None, "malformed-payload"
    if len(encoded) > MAX_PAYLOAD_BYTES:
        return None, "payload-too-large"
    if hashlib.sha256(encoded).hexdigest() != digest:
        return None, "integrity-failure"
    return {"record_id": record["record_id"], "lineage_id": record["lineage_id"],
            "payload_sha256": digest}, None


def inspect(records, previously_seen=None):
    """Return stable intake decisions without persisting or elevating trust.

    Even a locally intact digest is not an authentic signature: valid records
    remain pending-review. Duplicates always quarantine, including identical
    copies, to avoid ambiguous reconciliation.
    """
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("records must be an array of at most 10000 items")
    # Caller-supplied snapshot is read-only and deliberately never authoritative.
    # A real replay defense still requires an authenticated durable atomic index.
    if previously_seen is None:
        seen_ids = set()
    elif not isinstance(previously_seen, (list, tuple, set, frozenset)) or len(previously_seen) > MAX_RECORDS:
        raise ValueError("previously_seen must be a bounded collection of record IDs")
    elif any(not isinstance(x, str) or not IDENTIFIER.fullmatch(x) for x in previously_seen):
        raise ValueError("previously_seen contains invalid record ID")
    else:
        seen_ids = set(previously_seen)
    checked = [_check(r) for r in records]
    counts = Counter(meta["record_id"] for meta, error in checked if meta is not None)
    decisions = []
    for index, (meta, error) in enumerate(checked):
        if error:
            decisions.append({"index": index, "state": "quarantined", "reason": error})
        elif meta["record_id"] in seen_ids:
            decisions.append({"index": index, "record_id": meta["record_id"],
                              "state": "quarantined", "reason": "previously-seen-record-id"})
        elif counts[meta["record_id"]] > 1:
            decisions.append({"index": index, "record_id": meta["record_id"],
                              "state": "quarantined", "reason": "duplicate-record-id"})
        else:
            decisions.append({"index": index, "record_id": meta["record_id"],
                              "state": "pending-review", "reason": "integrity-only-not-authenticated"})
    return {"schema_version": "0.1.0", "release_gate": "HOLD",
            "authorization_granted": False, "persisted": False, "decisions": decisions}


def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Inspect local untrusted evidence without persistence")
    parser.add_argument("input", type=Path, help="JSON array of local candidate records")
    parser.add_argument("--seen-ids", type=Path, help="Optional JSON array of previously seen record IDs (untrusted snapshot)")
    args = parser.parse_args()
    try:
        candidate = json.loads(args.input.read_text(encoding="utf-8"))
        seen = None
        if args.seen_ids is not None:
            seen = json.loads(args.seen_ids.read_text(encoding="utf-8"))
        report = inspect(candidate, seen)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.exit(2, f"FAIL: {exc}\n")
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
