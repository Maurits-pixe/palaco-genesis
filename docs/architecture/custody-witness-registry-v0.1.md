# PALACO Custody Witness Organization Registry v0.1 — DRAFT / GO-13 HOLD

`tools/custody_witness_registry.py` verifies a detached Ed25519
governance-signed list of organizations and acknowledgement witness keys.
Each fingerprint belongs to exactly one organization ID, and only one
key per organization may be active in a given signed revision. The
registry is sorted canonically by fingerprint, strictly schema-checked,
and bounded to 64 historical entries.

Signed revision changes support key rotation by revoking a former key
and adding an active successor under the same organization. A separately
authenticated minimum registry revision is required to reject obsolete
snapshots. The verifier applies external issuer/witness revocations and
an external minimum receipt event count, then delegates all actual
witness signatures and ledger hash verification to the existing
multi-witness quorum module. Only distinct, active organization IDs
count toward the required quorum. Revoked keys never count.

**Do not confuse registry IDs with independently verified organizations.**
This module cannot check legal identity, beneficial ownership, organizational
control or whether keys are held by separate humans. Those assertions
require governance verification outside this module. It also cannot
prevent an adversary from hiding other valid witness statements,
provision key custody, distribute/retain the register independently,
implement trusted time or do global replay detection. This is evidence
verification only, never permission to restore, merge, release or deploy.
A passing outcome is `pending-review`, while GO-13 remains HOLD.

Tests: `python3 -m unittest discover -s tests -p 'test_custody_witness_registry.py' -v`.
