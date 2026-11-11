"""WNRA-04L TEST ONLY: externally pinned digest for disposable lease snapshots.

The caller must protect the expected digest independently from the database.
No signing, issuer authentication, trusted time, production gate or authority.
"""

import hashlib
import hmac
import json
import sqlite3

from windows_test_lease_model import LeaseDenied
from windows_test_sqlite_integrity import verify_fixture_integrity


def fixture_snapshot_digest(ledger):
    """Compute a deterministic snapshot digest; return no capability or token."""
    verify_fixture_integrity(ledger)
    try:
        leases = ledger.connection.execute(
            "SELECT lease_id, statement_id, consumer_id, not_before, expires_at, "
            "state, revision, last_time FROM fixture_lease ORDER BY lease_id"
        ).fetchall()
        audit = ledger.connection.execute(
            "SELECT transition_id, lease_id, previous_state, new_state, revision "
            "FROM fixture_audit ORDER BY transition_id"
        ).fetchall()
    except sqlite3.Error as exc:
        raise LeaseDenied("fixture snapshot unavailable") from exc
    document = {
        "domain": "PALACO-WNRA-04L-TEST-SNAPSHOT-v1",
        "leases": leases,
        "audit": audit,
    }
    encoded = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def verify_pinned_fixture_snapshot(ledger, independently_pinned_digest):
    """Reject a mismatch against the independent, caller-held baseline."""
    if (
        not isinstance(independently_pinned_digest, str)
        or len(independently_pinned_digest) != 64
        or any(c not in "0123456789abcdef" for c in independently_pinned_digest)
    ):
        raise LeaseDenied("invalid independent fixture digest")
    observed = fixture_snapshot_digest(ledger)
    if not hmac.compare_digest(observed, independently_pinned_digest):
        raise LeaseDenied("fixture snapshot differs from pinned baseline")
    return True
