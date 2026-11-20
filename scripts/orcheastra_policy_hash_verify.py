#!/usr/bin/env python3
"""Independent byte-level policy hash verifier for ORCHEASTRA v0.30.

This standalone Python client recalculates SHA-256 without PostgreSQL
pgcrypto. A pinned manifest persists outside the disposable DB container
for restart and rollback comparison; it is NOT an external trust service.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

URI = os.environ.get("PALACO_TEST_PG_URI", "")
MANIFEST = Path("/tmp/orcheastra-v030-policy-heads.json")
SCHEMA = "palaco_orcheastra_audit"


def rows() -> list[tuple[str, str, int, int, bytes, bytes, bytes, bytes]]:
    query = (
        "SELECT h.journal_id,h.category,h.epoch,e.old_epoch,"
        "encode(h.previous_digest,'hex'),encode(h.payload,'hex'),"
        "encode(h.event_digest,'hex'),"
        "encode(convert_to(jsonb_build_array("
        "'PALACO:ORCHEASTRA:POLICY:v1',e.journal_id,e.category,"
        "e.epoch,e.old_epoch,e.previous_key_id,e.current_key_id,"
        "e.changed_by_db_role,e.observed_generation,"
        "to_char(e.observed_at AT TIME ZONE 'UTC',"
        "'YYYY-MM-DD\"T\"HH24:MI:SS.US'))::text,'UTF8'),'hex') "
        f"FROM {SCHEMA}.policy_hash_chain h "
        f"JOIN {SCHEMA}.policy_change_history e USING (journal_id,category,epoch) "
        "ORDER BY h.journal_id,h.category,h.epoch"
    )
    result = subprocess.run(
        ["psql", "-X", "-A", "-t", "-F", "\t", "-v", "ON_ERROR_STOP=1",
         URI, "-c", query],
        capture_output=True, text=True, timeout=40, check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr.strip())
    parsed = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 8:
            raise AssertionError("unexpected policy evidence row layout")
        journal, category, epoch, old_epoch, previous, payload, digest, canonical = fields
        parsed.append((journal, category, int(epoch), int(old_epoch),
                       bytes.fromhex(previous), bytes.fromhex(payload),
                       bytes.fromhex(digest), bytes.fromhex(canonical)))
    return parsed


def verify(data: list[tuple[str, str, int, int, bytes, bytes, bytes, bytes]]
           ) -> dict[str, dict[str, object]]:
    heads: dict[str, dict[str, object]] = {}
    for journal, category, epoch, old_epoch, previous, payload, digest, canonical in data:
        scope = f"{journal}:{category}"
        state = heads.get(scope)
        prior_digest = bytes.fromhex(str(state["digest"])) if state else bytes(32)
        prior_epoch = int(state["epoch"]) if state else 0
        if epoch <= prior_epoch or old_epoch != prior_epoch:
            raise AssertionError(f"broken epoch lineage: {scope}")
        if previous != prior_digest:
            raise AssertionError(f"broken previous digest: {scope}")
        if payload != canonical:
            raise AssertionError(f"policy event payload mismatch: {scope}")
        if hashlib.sha256(previous + payload).digest() != digest:
            raise AssertionError(f"policy event hash mismatch: {scope}")
        heads[scope] = {"epoch": epoch, "digest": digest.hex()}
    return heads


def fails(mutated: list, test_name: str) -> None:
    try:
        verify(mutated)
    except AssertionError:
        return
    raise AssertionError(f"failed to detect mutation: {test_name}")


def main() -> None:
    if (
        os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not URI.startswith("postgresql://")
        or "@127.0.0.1:" not in URI
    ):
        raise AssertionError("requires isolated local CI PostgreSQL")

    data = rows()
    if not data:
        raise AssertionError("policy hash chain empty")
    heads = verify(data)

    # Independent verification detects in-memory mutation or omission of a
    # link, without relying on PostgreSQL to calculate its own checksum.
    changed = list(data)
    entry = changed[0]
    changed[0] = (*entry[:5], entry[5] + b"altered", *entry[6:])
    fails(changed, "altered payload")

    linked = next(
        (event for event in data if event[3] > 0),
        None,
    )
    if linked is None:
        raise AssertionError("need a multi-link chain for deletion test")
    missing = [
        event for event in data
        if not (event[0] == linked[0]
                and event[1] == linked[1]
                and event[2] == linked[3])
    ]
    fails(missing, "removed predecessor of a linked event")

    if len(sys.argv) == 2 and sys.argv[1] == "--pin":
        MANIFEST.write_text(json.dumps(heads, sort_keys=True) + "\n", encoding="utf-8")
        print(f"ORCHEASTRA v0.30: verified {len(data)} events; pinned {len(heads)} heads")
    elif len(sys.argv) == 2 and sys.argv[1] == "--verify":
        pinned = json.loads(MANIFEST.read_text(encoding="utf-8"))
        if pinned != heads:
            raise AssertionError("pinned hash heads disagree after database restart")
        print(f"ORCHEASTRA v0.30: {len(data)} policy events survive restart with pinned heads")
    else:
        raise AssertionError("expected --pin or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA policy-hash verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
