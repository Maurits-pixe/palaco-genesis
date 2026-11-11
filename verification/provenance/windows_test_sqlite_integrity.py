"""WNRA-04K test-only structural integrity verifier for disposable lease fixtures.

This is neither a cryptographic seal nor protection against a writer who can
alter both the lease and its audit consistently. It returns no authority.
"""

import sqlite3

from windows_test_lease_model import LeaseDenied

_ALLOWED = frozenset((
    ("ISSUED", "REDEEMING"), ("REDEEMING", "CONSUMED"),
    ("ISSUED", "REVOKED"), ("REDEEMING", "REVOKED"),
    ("REDEEMING", "DENIED"),
))


def verify_fixture_integrity(ledger):
    """Fail closed on malformed SQLite pages or inconsistent test-only lineage."""
    try:
        check = ledger.connection.execute("PRAGMA integrity_check").fetchall()
        if check != [("ok",)]:
            raise LeaseDenied("SQLite fixture integrity check failed")
        rows = ledger.connection.execute(
            "SELECT lease_id, state, revision FROM fixture_lease"
        ).fetchall()
        audit_rows = ledger.connection.execute(
            "SELECT transition_id, lease_id, previous_state, new_state, revision "
            "FROM fixture_audit ORDER BY lease_id, revision"
        ).fetchall()
        by_id = {}
        transitions = set()
        for transition_id, lease_id, before, after, revision in audit_rows:
            if not transition_id or transition_id in transitions:
                raise LeaseDenied("duplicate or empty fixture audit identity")
            transitions.add(transition_id)
            by_id.setdefault(lease_id, []).append((before, after, revision))
        for lease_id, state, revision in rows:
            if not lease_id or type(revision) is not int or revision < 0:
                raise LeaseDenied("invalid fixture state identity")
            expected = "ISSUED"
            events = by_id.pop(lease_id, [])
            for index, (before, after, event_revision) in enumerate(events, 1):
                if before != expected or (before, after) not in _ALLOWED:
                    raise LeaseDenied("fixture audit state discontinuity")
                if event_revision != index:
                    raise LeaseDenied("fixture audit revision discontinuity")
                expected = after
            if revision != len(events) or state != expected:
                raise LeaseDenied("fixture state disagrees with audit")
        if by_id:
            raise LeaseDenied("orphan fixture audit entry")
        return True
    except sqlite3.Error as exc:
        raise LeaseDenied("fixture storage unavailable or corrupt") from exc
